"""Second look at subdomain-takeover candidates found by recon.

Recon flags a host when its CNAME points at a provider where a forgotten
record can sometimes be claimed. Most such hosts are simply in use. This
check keeps a candidate only with real evidence:

- the CNAME target itself does not resolve (the provider-side name is gone), or
- the page shows the provider's own "no such site / shop / app" message.

A host that serves a normal page (including a login or password page, as a
password-protected shop does) is cleared, with the reason recorded.
"""

from __future__ import annotations

import socket
import urllib.error
import urllib.request

# Provider messages shown when nothing is attached to the name.
UNCLAIMED = {
    "myshopify.com": ("Sorry, this shop is currently unavailable", "Only one step left"),
    "github.io": ("There isn't a GitHub Pages site here",),
    "herokuapp.com": ("No such app", "herokucdn.com/error-pages/no-such-app"),
    "herokudns.com": ("No such app", "herokucdn.com/error-pages/no-such-app"),
    "wordpress.com": ("Do you want to register",),
    "ghost.io": ("The thing you were looking for is no longer here",),
    "surge.sh": ("project not found",),
    "bitbucket.io": ("Repository not found",),
    "readthedocs.io": ("unknown to Read the Docs",),
    "pantheonsite.io": ("The gods are wise",),
    "zendesk.com": ("Help Center Closed",),
    "fastly.net": ("Fastly error: unknown domain",),
    "helpscoutdocs.com": ("No settings were found for this company",),
    "azurewebsites.net": ("404 Web Site not found",),
    "netlify.app": ("Not Found - Request ID",),
    "statuspage.io": ("Status page not found", "Better Status Communication"),
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 - keep the 3xx as the answer
        return None


def resolves(name: str) -> bool:
    try:
        return bool(socket.getaddrinfo(name.rstrip("."), None))
    except (OSError, UnicodeError):
        return False


def check(host: str, cname: str, opener) -> tuple[str, str]:
    """Return (verdict, reason). verdict: "candidate" (keep, with evidence)
    or "cleared" (in use) or "unknown" (no answer; keep as is)."""
    cname = (cname or "").rstrip(".").lower()
    if cname and not resolves(cname):
        return "candidate", f"CNAME target {cname} does not resolve"
    fingerprints = next((v for k, v in UNCLAIMED.items() if cname == k or cname.endswith("." + k)), ())
    answer = None
    for scheme in ("https", "http"):
        try:
            with opener.open(f"{scheme}://{host}/", timeout=15) as resp:
                answer = (resp.status, resp.read(30000).decode("utf-8", "replace"), "")
        except urllib.error.HTTPError as exc:
            body = exc.read(30000).decode("utf-8", "replace") if hasattr(exc, "read") else ""
            answer = (exc.code, body, exc.headers.get("location", "") if exc.headers else "")
        except (urllib.error.URLError, OSError, ValueError):
            continue
        break
    if answer is None:
        return "unknown", "no HTTP answer"
    status, body, location = answer
    for text in fingerprints:
        if text.lower() in body.lower():
            return "candidate", f"provider says: \"{text}\" (HTTP {status})"
    where = f" -> {location}" if location else ""
    return "cleared", f"in use: HTTP {status}{where}"


def opener_for(proxy) -> urllib.request.OpenerDirector:
    import ssl
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy.url, "https": proxy.url}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(proxy.ca_bundle))),
        _NoRedirect())
