"""`hk`: the toolkit AI agents use inside a phase.

The agent decides what to do; hk gives it safe, consistent building blocks:
the shared inventory (hosts, services, endpoints, leads) with a scope check
on every write, importers for tool output, the scope-checked port scanner,
"not found" baselines, content checks for sensitive files, the takeover
check, noise filters, progress for `hunt status`, and Discord messages.

Run `hk help` for the list. Every command prints plain text by default and
JSON with --json, so a model can read either.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.request
from pathlib import Path

from . import assets as A
from . import config
from . import paths
from . import importers
from . import scope as sc
from . import state as st
from .target import Target

HELP = """hk - toolkit for this phase (all writes are scope-checked)

Scope
  hk scope                         in scope, out of scope, rules, rate
  hk scope check <url|host|ip>     allowed or not, and why

Inventory (read)
  hk stats                         counts of everything
  hk hosts [--resolved] [--unprobed] [--limit N]
  hk services [--todo crawled|discovered] [--limit N]     highest priority first
  hk endpoints [--host H] [--source S] [--limit N]
  hk leads [--status S]
  hk finding add --title T --kind K --severity S --url U [--summary ..] [--steps ..] [--impact ..] [--cvss ..]
  hk finding list|show <id>|set <id> --status validated|confirmed|disproved
  hk handoff                       what earlier phases reported

Inventory (write)
  hk import subfinder|dnsx|httpx|katana|ffuf <file>      tool output -> inventory
  hk add host <name> [--source S]
  hk add endpoint <METHOD> <url> [--source S] [--body B]
  hk add lead <kind> <url> --evidence "..." [--confirmed]
  hk mark crawled|discovered <service-id>...             done with these services
  hk priority <host|*.root> <0-100>                     reorder (100 = first)
  hk filter <host|*> <status> <length> --reason "..."   ignore a noise signature

Built-in checks
  hk portscan [--ports 80,443,...]   scan in-scope IPs/CIDRs (scope-checked, rate-limited)
  hk baseline                      record each new site's "not found" answer
  hk check-content <url>           does a sensitive file really contain what its name says
  hk takeover                      re-check subdomain-takeover candidates
  hk wordlist                      path of the built-in discovery list

Reporting
  hk progress "<step>" <done> <total> <unit>   shown in hunt status
  hk notify "<title>" "<message>" [--warn]     Discord (secrets are masked)
  hk note "<text>"                 add a line to this phase's notes
"""


class Kit:
    def __init__(self):
        folder = os.environ.get("HUNTER_TARGET_DIR")
        if not folder:
            raise SystemExit("hk must run inside a hunter-ai phase (HUNTER_TARGET_DIR is not set)")
        self.target = Target(Path(folder))
        self.state = st.State(self.target.state_db)
        self.store = A.Assets(self.state.db)
        self.phase = os.environ.get("HUNTER_PHASE", "")

    def scope(self) -> sc.Scope:
        return sc.load(self.target.scope_file)

    def opener(self) -> urllib.request.OpenerDirector:
        proxy = os.environ.get("HUNTER_PROXY", "")
        bundle = os.environ.get("SSL_CERT_FILE")
        handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {})]
        if bundle:
            handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=bundle)))
        return urllib.request.build_opener(*handlers)

    def focus(self):
        from .instructions import Operator
        return Operator(self.target, self.state).is_focus


def _print(data, as_json: bool, text: str | None = None) -> None:
    if as_json:
        print(json.dumps(data, indent=1, default=str))
    else:
        print(text if text is not None else json.dumps(data, indent=1, default=str))


def _rows(rows, limit) -> list[dict]:
    return [dict(r) for r in rows][: limit or None]


def cmd_scope(kit: Kit, args) -> int:
    s = kit.scope()
    if args.check:
        value = args.check
        decision = s.decide_url(value) if "://" in value else s.decide(value)
        print(("ALLOWED" if decision.allowed else "BLOCKED") + f": {decision.reason}"
              + (f" ({decision.matched})" if decision.matched else ""))
        return 0 if decision.allowed else 1
    data = {"in_scope": [a.raw for a in s.in_scope], "out_of_scope": [a.raw for a in s.out_of_scope],
            "avoid (operator)": [a.raw for a in s.operator_out], "rate_per_second": s.rate_limit_rps,
            "required_headers": s.required_headers, "forbidden_actions": s.forbidden_actions,
            "excluded_vulnerabilities": s.excluded_vulnerabilities, "other_rules": s.other_rules}
    _print(data, True)
    return 0


def cmd_stats(kit: Kit, args) -> int:
    store = kit.store
    data = {"hosts": store.host_counts(),
            "resolved_in_scope": len(store.hosts(scope=A.IN, resolved=True)),
            "unprobed": len(store.unprobed_hosts()),
            "services": store.service_count(),
            "services_not_crawled": kit.state.db.execute("SELECT COUNT(*) FROM services WHERE crawled=0").fetchone()[0],
            "services_not_discovered": kit.state.db.execute(
                "SELECT COUNT(*) FROM services WHERE discovered=0").fetchone()[0],
            "endpoints": store.endpoint_count(),
            "leads": {r["status"]: r["n"] for r in kit.state.db.execute(
                "SELECT status, COUNT(*) AS n FROM leads GROUP BY status")}}
    _print(data, True)
    return 0


def cmd_hosts(kit: Kit, args) -> int:
    if args.unprobed:
        rows = [{"host": h} for h in kit.store.unprobed_hosts()]
    else:
        rows = _rows(kit.store.hosts(scope=A.IN, resolved=True if args.resolved else None), 0)
    rows = rows[: args.limit or None]
    _print(rows, args.json, "\n".join(r["host"] for r in rows))
    return 0


def cmd_services(kit: Kit, args) -> int:
    rows = kit.store.work_services(kit.scope(), args.todo) if args.todo else kit.store.services()
    rows = _rows(rows, args.limit)
    text = "\n".join(f"{r['id']:>5} {r['priority']:>3} {r['url']} [{r['status']}] {(r['title'] or '')[:60]}"
                     for r in rows)
    _print(rows, args.json, text)
    return 0


def cmd_endpoints(kit: Kit, args) -> int:
    rows = [r for r in kit.store.endpoints(args.host) if not args.source or r["source"] == args.source]
    rows = _rows(rows, args.limit)
    text = "\n".join(f"{r['method']:<6} {r['status'] or '-':<4} {r['url']}" + (f"  [{r['body']}]" if r["body"] else "")
                     for r in rows)
    _print(rows, args.json, text)
    return 0


def cmd_leads(kit: Kit, args) -> int:
    rows = _rows(kit.store.leads(args.status), 0)
    _print(rows, args.json, "\n".join(f"{r['id']:>4} [{r['status']}] {r['kind']} {r['url']} - {r['evidence'] or ''}"
                                     for r in rows))
    return 0


def cmd_handoff(kit: Kit, args) -> int:
    folder = kit.target.output / "handoff"
    files = sorted(folder.glob("*.md")) if folder.is_dir() else []
    if not files:
        print("No earlier phase has reported yet.")
    for path in files:
        print(f"===== {path.stem} =====\n{path.read_text(encoding='utf-8')}\n")
    return 0


def cmd_import(kit: Kit, args) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"no such file: {path}")
        return 1
    scope = kit.scope()
    if args.tool == "httpx":
        result = importers.httpx(kit.store, scope, path, kit.focus())
    elif args.tool == "ffuf":
        from urllib.parse import urlsplit
        from .review import SCHEMA, same_response
        kit.state.db.executescript(SCHEMA)
        hosts = {(urlsplit(str(r.get("url") or "")).hostname or "").lower() for r in importers._records(path)}
        ignore = set()
        for host in hosts:
            ignore |= {(r["status"], r["length"]) for r in kit.state.db.execute(
                "SELECT status, length FROM response_filters WHERE host=? OR host='*'", (host,))}
        result = importers.ffuf(kit.store, scope, path, ignore)
        trip = same_response(result["hits"], min_records=25, share=0.6)
        result = {k: v for k, v in result.items() if k != "hits"} | {"hits": len(result["hits"])}
        if trip:
            result["warning"] = (f"{trip.detail}. If this is one catch-all page, run: hk filter <host> "
                                 f"{trip.data['status']} {trip.data['length']} --reason \"catch-all\"")
    else:
        result = importers.IMPORTERS[args.tool](kit.store, scope, path)
    _print(result, True)
    return 0


def cmd_add(kit: Kit, args) -> int:
    scope = kit.scope()
    if args.what == "host":
        name = args.values[0]
        if not scope.decide(name).allowed:
            print(f"BLOCKED: {name} is not in scope")
            return 1
        kit.store.add_host(name, A.IN, args.source or f"ai:{kit.phase}")
        print(f"added {name}")
    elif args.what == "endpoint":
        method, url = args.values[0].upper(), args.values[1]
        if not scope.decide_url(url).allowed:
            print(f"BLOCKED: {url} is not in scope")
            return 1
        new = kit.store.add_endpoint(method, url, args.source or f"ai:{kit.phase}", body=args.body)
        print("added" if new else "already known")
    elif args.what == "lead":
        kind, url = args.values[0], args.values[1]
        check = scope.decide_url(url) if "://" in url else scope.decide(url.split("://")[-1].split(":")[0])
        if not check.allowed:
            print(f"BLOCKED: {url} is not in scope")
            return 1
        from .review import mask
        kit.store.add_lead(kind, url, f"ai:{kit.phase}", mask(args.evidence or ""),
                           status="signature-match" if args.confirmed else "unverified")
        print(f"lead recorded: {kind} {url}")
    return 0


def cmd_mark(kit: Kit, args) -> int:
    for value in args.ids:
        kit.store.mark_service(int(value), args.column)
    print(f"marked {len(args.ids)} service(s) {args.column}")
    return 0


def cmd_priority(kit: Kit, args) -> int:
    n = kit.store.set_priority(args.host, max(0, min(100, args.value)))
    print(f"{n} service(s) updated")
    return 0


def cmd_filter(kit: Kit, args) -> int:
    from .review import SCHEMA
    kit.state.db.executescript(SCHEMA)
    kit.state.db.execute(
        "INSERT OR IGNORE INTO response_filters(host, status, length, reason, created) VALUES(?,?,?,?,?)",
        (args.host, args.status, args.length, args.reason, st.now()))
    query = "DELETE FROM endpoints WHERE source='discover' AND status=? AND length=?"
    params = [args.status, args.length]
    if args.host != "*":
        query += " AND host=?"
        params.append(args.host)
    removed = kit.state.db.execute(query, params).rowcount
    print(f"filter saved; {removed} matching result(s) removed")
    return 0


def cmd_portscan(kit: Kit, args) -> int:
    from . import portscan
    scope = kit.scope()
    seeds = [line.strip() for line in kit.target.input_text("ips.txt").splitlines()
             if line.strip() and not line.startswith("#")]
    ports = [int(p) for p in args.ports.split(",")] if args.ports else None
    work = portscan.plan(scope, seeds, ports=ports)
    if not work.addresses:
        print(json.dumps({"addresses": 0, "note": "no IP or CIDR in scope"}))
        return 0
    rate = max(1.0, float(scope.rate_limit_rps))
    total = len(work.addresses) * len(work.ports)
    kit.state.set_progress(kit.phase, "port scan", 0, total, "checks")
    found = portscan.scan(work.addresses, work.ports, rate,
                          on_progress=lambda n: kit.state.set_progress(kit.phase, "port scan", n, total, "checks"))
    ua = os.environ.get("HUNTER_USER_AGENT", "Mozilla/5.0")
    catch_all, verified, real = [], [], {}
    for address, open_ports in found.items():
        kit.store.add_host(address, A.IN, "portscan")
        kit.store.set_resolution(address, [address])
        kit.store.mark_probed([address], False)
        if portscan.accepts_everything(open_ports, len(work.ports)):
            catch_all.append(address)
            keep = [p for p in (443, 80, 8443, 8080) if p in open_ports]
            kit.store.set_host_note(address, open_ports=keep, accepts_all=True, ports_answering=len(open_ports))
            continue
        real[address] = open_ports
        kit.store.set_host_note(address, open_ports=open_ports, accepts_all=False)
        for port in open_ports:
            label = portscan.SENSITIVE_PORTS.get(port)
            if label:
                evidence = portscan.verify(address, port, ua)
                kit.store.add_lead("exposed-service", f"tcp://{address}:{port}", f"ai:{kit.phase}",
                                   f"{label}: {evidence}" if evidence else f"port {port} open ({label}); "
                                   "did not identify itself", status="signature-match" if evidence else "unverified")
                if evidence:
                    verified.append(f"{address}:{port} {label} - {evidence}")
    result = {"addresses_scanned": len(work.addresses), "ports_each": len(work.ports),
              "addresses_open": len(real), "open_ports": sum(len(p) for p in real.values()),
              "catch_all_addresses (answer every port, ignored)": len(catch_all),
              "verified_services": verified, "note": work.reduced or "",
              "web_targets_for_httpx": [f"{a}:{p}" for a, ps in real.items() for p in ps
                                        if p in portscan.WEB_PORTS] + [f"{a}:{p}" for a in catch_all
                                                                       for p in (443, 80)]}
    print(json.dumps(result, indent=1))
    return 0


def cmd_baseline(kit: Kit, args) -> int:
    from . import webprobe
    scope = kit.scope()
    opener = webprobe.opener_through(os.environ.get("HUNTER_PROXY", ""), os.environ.get("SSL_CERT_FILE"))
    done = webprobe.build_baselines(kit.store, scope, opener,
                                    lambda i, n: kit.state.set_progress(kit.phase, "not-found baselines", i, n, "sites"))
    kinds = {}
    for svc in kit.store.services():
        kind = json.loads(svc["baseline"]).get("kind") if svc["baseline"] else None
        kinds[kind] = kinds.get(kind, 0) + 1
    print(json.dumps({"baselined_now": done, "baseline_kinds": kinds}))
    return 0


def cmd_check_content(kit: Kit, args) -> int:
    from . import signatures, webprobe
    if not kit.scope().decide_url(args.url).allowed:
        print("BLOCKED: not in scope")
        return 1
    opener = webprobe.opener_through(os.environ.get("HUNTER_PROXY", ""), os.environ.get("SSL_CERT_FILE"))
    try:
        with opener.open(args.url, timeout=20) as resp:
            body = resp.read(65536)
    except Exception as exc:  # noqa: BLE001
        print(f"could not fetch: {exc}")
        return 1
    path = args.url.split("?", 1)[0]
    matches = signatures.check(path, body)
    if not matches:
        print("no signature match (not a known sensitive file, or not what the name suggests)")
        return 0
    for kind, evidence in matches:
        kit.store.add_lead(kind, args.url, f"ai:{kit.phase}", evidence, status="signature-match")
        print(f"CONFIRMED lead: {kind} - {evidence}")
    return 0


def cmd_takeover(kit: Kit, args) -> int:
    from . import takeover
    opener = urllib.request.build_opener(*kit.opener().handlers, takeover._NoRedirect())
    out = []
    for row in kit.store.takeover_candidates():
        verdict, reason = takeover.check(row["host"], row["cname"], opener)
        if verdict == "cleared":
            kit.store.clear_takeover(row["host"], reason)
        elif verdict == "candidate":
            kit.store.set_host_note(row["host"], takeover_check=reason)
            kit.store.add_lead("takeover", f"https://{row['host']}/", f"ai:{kit.phase}",
                               f"CNAME {row['cname']}: {reason}", status="signature-match")
        out.append({"host": row["host"], "cname": row["cname"], "verdict": verdict, "reason": reason})
    print(json.dumps(out, indent=1))
    return 0


def cmd_finding(kit: Kit, args) -> int:
    from .review import mask
    store = kit.store
    if args.action == "add":
        if not args.title:
            print("finding add needs --title")
            return 1
        fid = store.add_finding(kit.phase, args.title, kind=args.kind, severity=args.severity,
                                url=args.url, host=(args.host or ""), summary=mask(args.summary or ""),
                                steps=mask(args.steps or ""), impact=mask(args.impact or ""),
                                cvss=args.cvss, evidence=mask(args.evidence or ""), status="candidate")
        print(json.dumps({"finding_id": fid}))
    elif args.action == "set":
        fields = {k: getattr(args, k) for k in ("title", "kind", "severity", "status", "host", "url",
                                                "summary", "steps", "impact", "cvss", "evidence")
                  if getattr(args, k) is not None}
        for k in ("summary", "steps", "impact", "evidence"):
            if k in fields:
                fields[k] = mask(fields[k])
        store.set_finding(int(args.id), **fields)
        print(f"finding {args.id} updated")
    elif args.action == "show":
        row = store.finding(int(args.id))
        print(json.dumps(dict(row) if row else {}, indent=1, default=str))
    else:
        rows = store.findings(args.status)
        text = "\n".join(f"{r['id']:>4} [{r['status']}] {r['severity'] or '-':<8} {r['kind'] or '-':<12} "
                         f"{r['title']}  {r['url'] or ''}" for r in rows)
        _print([dict(r) for r in rows], args.json, text)
    return 0


def cmd_wordlist(kit: Kit, args) -> int:
    from . import fuzzing
    settings = config.load_settings()
    if args.list:
        import os
        seen = set()
        for base in fuzzing.dirs_from(settings):
            if base.is_dir():
                files = sorted(f.name for f in base.iterdir() if f.is_file())
                if files:
                    print(f"{base}:")
                    for f in files:
                        if f not in seen:
                            print(f"  {f}")
                            seen.add(f)
        return 0
    if args.extensions:
        print(fuzzing.EXTENSIONS.get(args.extensions, fuzzing.EXTENSIONS["general"]))
        return 0
    if args.kind:
        path = fuzzing.resolve(args.kind, settings)
        print(path or fuzzing.general(settings))
        return 0
    print(fuzzing.general(settings))
    return 0


def cmd_fuzzplan(kit: Kit, args) -> int:
    """What to fuzz a given live service with: profile, wordlists, extensions,
    and the params wordlist - chosen from its fingerprint."""
    from . import fuzzing
    settings = config.load_settings()
    svc = kit.state.db.execute("SELECT * FROM services WHERE id=?", (int(args.service_id),)).fetchone()
    if not svc:
        print(json.dumps({"error": f"no service #{args.service_id} (see hk services)"}))
        return 1
    tech = ""
    try:
        tech = " ".join(json.loads(svc["tech"])) if svc["tech"] else ""
    except ValueError:
        tech = svc["tech"] or ""
    plan = fuzzing.plan(settings, server=svc["server"] or "", tech=tech, host=svc["host"],
                        content_type=svc["content_type"] or "")
    plan["service"] = {"id": svc["id"], "url": svc["url"], "server": svc["server"], "tech": tech}
    print(json.dumps(plan, indent=1))
    return 0


def cmd_playbook(kit: Kit, args) -> int:
    from . import paths
    print(paths.REPO_DIR / "hunter" / "data" / "fuzzing_playbook.md")
    return 0


def cmd_progress(kit: Kit, args) -> int:
    kit.state.set_progress(kit.phase, args.step, args.done, args.total, args.unit)
    return 0


def cmd_notify(kit: Kit, args) -> int:
    from .notify import Notifier
    from .review import mask
    settings, secrets = config.load_settings(), config.load_secrets()
    Notifier(secrets, settings["notify"].get("discord", True)).send(
        mask(args.title)[:200], mask(args.message)[:3500], "warn" if args.warn else "info", target=kit.target.name)
    print("sent")
    return 0


def cmd_note(kit: Kit, args) -> int:
    path = Path(os.environ.get("HUNTER_NOTES_FILE") or (kit.target.output / "notes.md"))
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"- {args.text}\n")
    print("noted")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hk", add_help=False)
    sub = p.add_subparsers(dest="cmd")
    a = sub.add_parser("scope"); a.add_argument("action", nargs="?"); a.add_argument("check", nargs="?")
    a.set_defaults(func=lambda k, x: cmd_scope(k, argparse.Namespace(check=x.check if x.action == "check" else None)))
    sub.add_parser("stats").set_defaults(func=cmd_stats)
    a = sub.add_parser("hosts"); a.add_argument("--resolved", action="store_true")
    a.add_argument("--unprobed", action="store_true"); a.add_argument("--limit", type=int, default=0)
    a.add_argument("--json", action="store_true"); a.set_defaults(func=cmd_hosts)
    a = sub.add_parser("services"); a.add_argument("--todo", choices=["crawled", "discovered"])
    a.add_argument("--limit", type=int, default=0); a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_services)
    a = sub.add_parser("endpoints"); a.add_argument("--host"); a.add_argument("--source")
    a.add_argument("--limit", type=int, default=0); a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_endpoints)
    a = sub.add_parser("leads"); a.add_argument("--status"); a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_leads)
    sub.add_parser("handoff").set_defaults(func=cmd_handoff)
    a = sub.add_parser("import"); a.add_argument("tool", choices=sorted(importers.IMPORTERS))
    a.add_argument("file"); a.set_defaults(func=cmd_import)
    a = sub.add_parser("add"); a.add_argument("what", choices=["host", "endpoint", "lead"])
    a.add_argument("values", nargs="+"); a.add_argument("--source"); a.add_argument("--body")
    a.add_argument("--evidence"); a.add_argument("--confirmed", action="store_true"); a.set_defaults(func=cmd_add)
    a = sub.add_parser("mark"); a.add_argument("column", choices=["crawled", "discovered"])
    a.add_argument("ids", nargs="+"); a.set_defaults(func=cmd_mark)
    a = sub.add_parser("priority"); a.add_argument("host"); a.add_argument("value", type=int)
    a.set_defaults(func=cmd_priority)
    a = sub.add_parser("filter"); a.add_argument("host"); a.add_argument("status", type=int)
    a.add_argument("length", type=int); a.add_argument("--reason", default=""); a.set_defaults(func=cmd_filter)
    a = sub.add_parser("portscan"); a.add_argument("--ports"); a.set_defaults(func=cmd_portscan)
    sub.add_parser("baseline").set_defaults(func=cmd_baseline)
    a = sub.add_parser("check-content"); a.add_argument("url"); a.set_defaults(func=cmd_check_content)
    sub.add_parser("takeover").set_defaults(func=cmd_takeover)
    a = sub.add_parser("wordlist")
    a.add_argument("--kind"); a.add_argument("--extensions"); a.add_argument("--list", action="store_true")
    a.set_defaults(func=cmd_wordlist)
    a = sub.add_parser("fuzzplan"); a.add_argument("service_id"); a.set_defaults(func=cmd_fuzzplan)
    sub.add_parser("playbook").set_defaults(func=cmd_playbook)
    a = sub.add_parser("finding"); a.add_argument("action", choices=["add", "set", "list", "show"])
    a.add_argument("id", nargs="?"); a.add_argument("--title"); a.add_argument("--kind")
    a.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"])
    a.add_argument("--status", choices=["candidate", "validated", "confirmed", "disproved", "reported"])
    a.add_argument("--host"); a.add_argument("--url"); a.add_argument("--summary"); a.add_argument("--steps")
    a.add_argument("--impact"); a.add_argument("--cvss"); a.add_argument("--evidence")
    a.add_argument("--json", action="store_true"); a.set_defaults(func=cmd_finding)
    a = sub.add_parser("progress"); a.add_argument("step"); a.add_argument("done", type=int)
    a.add_argument("total", type=int); a.add_argument("unit", nargs="?", default="items")
    a.set_defaults(func=cmd_progress)
    a = sub.add_parser("notify"); a.add_argument("title"); a.add_argument("message")
    a.add_argument("--warn", action="store_true"); a.set_defaults(func=cmd_notify)
    a = sub.add_parser("note"); a.add_argument("text"); a.set_defaults(func=cmd_note)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("help", "-h", "--help"):
        print(HELP)
        return 0
    try:
        args = build_parser().parse_args(argv)
    except SystemExit:
        print("\n" + HELP)
        return 2
    if not getattr(args, "func", None):
        print(HELP)
        return 2
    kit = Kit()
    try:
        return int(args.func(kit, args) or 0)
    finally:
        kit.state.close()


if __name__ == "__main__":
    raise SystemExit(main())
