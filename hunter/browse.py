"""hbrowse: a scope-proxied headless browser for the AI phases.

Curl cannot show client-side behaviour. This runs a real Chromium (Playwright)
for the things that only happen in a browser - DOM / client-side XSS, open
redirects that land, postMessage and window.name PoCs, and authenticated or
stored-XSS flows (pass a session cookie) - and it reports what happened as JSON.

SAFETY: the browser is forced through the run's scope proxy (HUNTER_PROXY).
Every request it makes is therefore inspected, scope-checked, rate-limited and
logged exactly like curl, and routed through the residential egress if one is
set. It refuses to run if no scope proxy is present, so it can never reach a
target un-proxied. It does not weaponise anything: it loads a page, optionally
performs the one interaction you ask for, and reports.

Usage:
  hbrowse <url> [--window-name NAME] [--cookie 'k=v; k2=v2'] [--header 'K: V']
          [--eval 'JS expression'] [--click 'CSS selector'] [--wait MS]
          [--screenshot] [--out DIR] [--timeout MS]

Output (stdout, JSON): url, final_url, status, title, dialogs (a fired
alert/confirm/prompt is XSS proof), console, oob_hits (callbacks the page made
to your OOB / blind-XSS host), eval_result, dom_file, screenshot.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.parse import urlsplit


def _parse_cookies(raw: str, url: str) -> list[dict]:
    host = urlsplit(url if "://" in url else "http://" + url).hostname or ""
    out: list[dict] = []
    for pair in raw.split(";"):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        name, value = pair.split("=", 1)
        out.append({"name": name.strip(), "value": value.strip(), "domain": host, "path": "/"})
    return out


def _parse_headers(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items or []:
        if ":" in item:
            key, value = item.split(":", 1)
            out[key.strip()] = value.strip()
    return out


def build_plan(argv: list[str], env: dict) -> dict:
    """Turn argv + environment into a launch plan (pure, so it is testable
    without a browser installed)."""
    ap = argparse.ArgumentParser(prog="hbrowse", add_help=True)
    ap.add_argument("url")
    ap.add_argument("--window-name", dest="window_name", default=None)
    ap.add_argument("--cookie", default=None, help="'name=value; name2=value2' for the target host")
    ap.add_argument("--header", action="append", default=[], help="extra request header 'K: V' (repeatable)")
    ap.add_argument("--eval", dest="eval_js", default=None, help="JS expression to evaluate after load")
    ap.add_argument("--click", default=None, help="CSS selector to click after load")
    ap.add_argument("--wait", type=int, default=1500, help="ms to wait after load for async activity")
    ap.add_argument("--timeout", type=int, default=30000, help="ms navigation timeout")
    ap.add_argument("--screenshot", action="store_true")
    ap.add_argument("--out", default=".", help="directory for dom.html / screenshot")
    args = ap.parse_args(argv)

    proxy = env.get("HUNTER_PROXY") or env.get("HTTPS_PROXY") or env.get("https_proxy")
    oob_hosts: list[str] = []
    if env.get("HUNTER_OOB_HOST"):
        oob_hosts.append(env["HUNTER_OOB_HOST"].lower())
    if env.get("HUNTER_BLIND_XSS_URL"):
        host = urlsplit(env["HUNTER_BLIND_XSS_URL"]).hostname
        if host:
            oob_hosts.append(host.lower())
    return {
        "url": args.url,
        "proxy": proxy,
        "ca_bundle": env.get("SSL_CERT_FILE") or env.get("REQUESTS_CA_BUNDLE"),
        "user_agent": env.get("HUNTER_USER_AGENT") or "Mozilla/5.0",
        "window_name": args.window_name,
        "cookies": _parse_cookies(args.cookie, args.url) if args.cookie else [],
        "headers": _parse_headers(args.header),
        "eval_js": args.eval_js,
        "click": args.click,
        "wait": args.wait,
        "timeout": args.timeout,
        "screenshot": args.screenshot,
        "out": args.out,
        "oob_hosts": oob_hosts,
        "enabled": env.get("HUNTER_BROWSER", "1") != "0",
    }


def _fail(message: str, code: int = 3) -> int:
    print(json.dumps({"error": message}), flush=True)
    return code


def run(plan: dict) -> int:
    if not plan["enabled"]:
        return _fail("the headless browser is disabled in settings (hunt: browser.enabled=false)")
    if not plan["proxy"]:
        return _fail("no scope proxy in the environment; refusing to browse un-proxied")
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return _fail("Playwright is not installed. Run: "
                     ".venv/bin/python -m playwright install --with-deps chromium", code=4)

    out_dir = plan["out"]
    os.makedirs(out_dir, exist_ok=True)
    dialogs: list[dict] = []
    console: list[dict] = []
    oob_hits: list[str] = []
    oob_hosts = plan["oob_hosts"]

    def on_request(req):
        host = (urlsplit(req.url).hostname or "").lower()
        if any(host == h or host.endswith("." + h) for h in oob_hosts):
            oob_hits.append(req.url)

    result: dict = {"url": plan["url"], "final_url": None, "status": None, "title": None,
                    "dialogs": dialogs, "console": console, "oob_hits": oob_hits,
                    "eval_result": None, "dom_file": None, "screenshot": None}
    try:
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(
                    headless=True,
                    proxy={"server": plan["proxy"]},
                    args=["--no-sandbox", "--disable-dev-shm-usage"],
                )
            except Exception as exc:
                return _fail(f"could not launch Chromium ({exc}). Run: "
                             ".venv/bin/python -m playwright install --with-deps chromium", code=4)
            context = browser.new_context(
                user_agent=plan["user_agent"],
                ignore_https_errors=True,   # the scope proxy MITMs TLS; it is the trust boundary
                extra_http_headers=plan["headers"] or None,
            )
            if plan["cookies"]:
                try:
                    context.add_cookies(plan["cookies"])
                except Exception as exc:
                    console.append({"type": "cookie-error", "text": str(exc)})
            if plan["window_name"]:
                context.add_init_script(f"try{{window.name={json.dumps(plan['window_name'])}}}catch(e){{}}")
            page = context.new_page()
            page.on("console", lambda m: console.append({"type": m.type, "text": m.text}))
            page.on("dialog", lambda d: (dialogs.append({"type": d.type, "message": d.message}), d.dismiss()))
            page.on("request", on_request)
            try:
                resp = page.goto(plan["url"], timeout=plan["timeout"], wait_until="load")
                result["status"] = resp.status if resp else None
            except Exception as exc:
                console.append({"type": "navigation-error", "text": str(exc)})
            page.wait_for_timeout(plan["wait"])
            if plan["click"]:
                try:
                    page.click(plan["click"], timeout=5000)
                    page.wait_for_timeout(plan["wait"])
                except Exception as exc:
                    console.append({"type": "click-error", "text": str(exc)})
            if plan["eval_js"]:
                try:
                    result["eval_result"] = page.evaluate(plan["eval_js"])
                except Exception as exc:
                    console.append({"type": "eval-error", "text": str(exc)})
            try:
                result["final_url"] = page.url
                result["title"] = page.title()
                dom_path = os.path.join(out_dir, "dom.html")
                with open(dom_path, "w", encoding="utf-8") as fh:
                    fh.write(page.content())
                result["dom_file"] = dom_path
                if plan["screenshot"]:
                    shot = os.path.join(out_dir, "screenshot.png")
                    page.screenshot(path=shot, full_page=True)
                    result["screenshot"] = shot
            except Exception as exc:
                console.append({"type": "capture-error", "text": str(exc)})
            context.close()
            browser.close()
    except Exception as exc:
        return _fail(f"browser session failed: {exc}")

    print(json.dumps(result, default=str), flush=True)
    return 0


def main(argv: list[str]) -> int:
    plan = build_plan(argv, dict(os.environ))
    return run(plan)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
