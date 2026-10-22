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
  hk unlock <url>                  try path/header bypasses on a 401/403 (records a lead if one works)
  hk secrets <file|dir>            scan for leaked keys/tokens (reports kinds, values masked)
  hk vhost <ip-url>                find virtual hosts on an IP (Host-header fuzz, in-scope names)
  hk cache <url>                   probe web-cache poisoning / deception (detect-only, records a lead)
  hk techhints                     tech-specific test hints for the stacks found on this target
  hk cluster [--apply]             show infrastructure clone groups (same backend); --apply parks them
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

    def focus_hosts(self) -> list[str]:
        from .instructions import Operator
        return Operator(self.target, self.state).focus()


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
    data = {"in_scope": [a.raw for a in s.in_scope],
            # Domains the discovery phase proved and added: test them like in_scope.
            "discovered_in_scope": [a.raw for a in s.expanded],
            # Every root to enumerate (policy wildcards + discovered ones).
            "wildcard_roots": s.wildcard_roots(),
            "out_of_scope": [a.raw for a in s.out_of_scope],
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
    if args.todo:
        rows = kit.store.work_services(kit.scope(), args.todo)
    else:
        # Hide parked infra clones (priority 0) by default; --all shows them.
        rows = kit.store.services(min_priority=0 if args.all else 1)
    hidden = 0
    if not args.todo and not args.all:
        hidden = len([r for r in kit.store.services() if r["priority"] == 0])
    rows = _rows(rows, args.limit)
    text = "\n".join(f"{r['id']:>5} {r['priority']:>3} {r['url']} [{r['status']}] {(r['title'] or '')[:60]}"
                     for r in rows)
    if hidden and not args.json:
        text += f"\n({hidden} parked clone service(s) hidden; `hk services --all` to show, "
        text += "`hk cluster --restore <parent>` to un-park)"
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


def cmd_unlock(kit: Kit, args) -> int:
    from . import unlock
    if not kit.scope().decide_url(args.url).allowed:
        print("BLOCKED: not in scope")
        return 1
    opener = webprobe.opener_through(os.environ.get("HUNTER_PROXY", ""), os.environ.get("SSL_CERT_FILE"))
    result = unlock.probe(args.url, opener)
    if args.json:
        print(json.dumps(result, indent=1))
        return 0
    if result.get("note"):
        print(result["note"])
        return 0
    bypasses = result["bypasses"]
    if not bypasses:
        print(f"{args.url}: baseline {result['baseline'].get('status')}, "
              f"no bypass in {result['tried']} variants")
        return 0
    for b in bypasses:
        hdr = f"  headers={b['headers']}" if b["headers"] else ""
        print(f"BYPASS {b['status']}: {b['how']} -> {b['url']} (len {b['len']}){hdr}")
        # Record a lead so later phases / the operator see it.
        kit.store.add_lead("403-bypass", b["url"], f"ai:{kit.phase}",
                           f"{result['baseline'].get('status')} bypassed via {b['how']} -> {b['status']}",
                           status="signature-match")
    return 0


def cmd_cache(kit: Kit, args) -> int:
    from . import cachecheck
    if not kit.scope().decide_url(args.url).allowed:
        print("BLOCKED: not in scope")
        return 1
    opener = webprobe.opener_through(os.environ.get("HUNTER_PROXY", ""), os.environ.get("SSL_CERT_FILE"))
    result = cachecheck.probe(args.url, opener)
    if args.json:
        print(json.dumps(result, indent=1))
        return 0
    found = False
    for p in result["poisoning"]:
        found = True
        print(f"CACHE-POISONING candidate: {p['header']} reflected"
              f"{' + cacheable' if p['cacheable'] else ''} ({p['cache_headers'] or 'no cache headers'})")
        kit.store.add_lead("cache-poisoning", args.url, f"ai:{kit.phase}",
                           f"unkeyed {p['header']} reflected; {p['note']}", status="unverified")
    for d in result["deception"]:
        found = True
        print(f"CACHE-DECEPTION candidate: suffix {d['suffix']} -> dynamic page cacheable "
              f"({d['cache_headers'] or 'no cache headers'})")
        kit.store.add_lead("cache-deception", args.url + d["suffix"], f"ai:{kit.phase}",
                           d["note"], status="unverified")
    if not found:
        print(f"{args.url}: no cache poisoning/deception signal")
    return 0


def cmd_vhost(kit: Kit, args) -> int:
    from . import vhost
    scope = kit.scope()
    # The IP (or ip:port) must be in scope.
    host = args.ip_url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    if not scope.decide(host).allowed:
        print(f"BLOCKED: {host} is not in scope")
        return 1
    ip_url = args.ip_url if "://" in args.ip_url else f"http://{args.ip_url}"
    # Candidate host names: in-scope known hosts + wildcard roots + a few common
    # names under each root. Only in-scope names are tried.
    candidates: list[str] = []
    roots = scope.wildcard_roots()
    for row in kit.store.hosts(scope=A.IN):
        candidates.append(row["host"])
    common = ("internal", "staging", "stage", "dev", "preprod", "uat", "test",
              "admin", "api", "corp", "intranet", "portal", "vpn", "jenkins", "git")
    for root in roots:
        candidates.extend(f"{c}.{root}" for c in common)
    # Deduplicate, keep only in-scope, cap to a sane number.
    seen, final = set(), []
    for name in candidates:
        name = name.strip().lower()
        if name and name not in seen and scope.decide(name).allowed:
            seen.add(name)
            final.append(name)
    final = final[:400]
    opener = webprobe.opener_through(os.environ.get("HUNTER_PROXY", ""), os.environ.get("SSL_CERT_FILE"))
    result = vhost.probe(ip_url, final, opener)
    if args.json:
        print(json.dumps(result, indent=1))
        return 0
    if result.get("note"):
        print(result["note"])
        return 0
    vhosts = result["vhosts"]
    if not vhosts:
        print(f"{ip_url}: no distinct virtual host in {result['tried']} in-scope names")
        return 0
    for v in vhosts:
        print(f"VHOST {v['status']}: {v['host']} on {ip_url} (len {v['len']})")
        kit.store.add_lead("vhost", f"http://{v['host']}/", f"ai:{kit.phase}",
                           f"distinct virtual host on {ip_url} (status {v['status']})",
                           status="signature-match")
    return 0


def cmd_secrets(kit: Kit, args) -> int:
    from . import secretscan
    root = Path(args.path).expanduser()
    if not root.exists():
        print(f"no such file or directory: {root}")
        return 1
    results = secretscan.scan_path(root)
    if args.json:
        print(json.dumps(results, indent=1))
        return 0
    if not results:
        print("no secrets detected")
        return 0
    for entry in results:
        kinds = ", ".join(sorted({h["kind"] for h in entry["hits"]}))
        print(f"{entry['file']}: {kinds}")
        for h in entry["hits"]:
            print(f"    {h['kind']}: {h['masked']}")
    print(f"\n{len(results)} file(s) with secrets. Record the real ones with "
          f"`hk add lead secret-in-js <url> --evidence \"<kind>\"` (kind only, never the value).")
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


def cmd_dorks(kit: Kit, args) -> int:
    from . import paths
    print(paths.REPO_DIR / "hunter" / "data" / "github_dorks.md")
    return 0


def cmd_depconf(kit: Kit, args) -> int:
    from . import paths
    print(paths.REPO_DIR / "hunter" / "data" / "depconf_playbook.md")
    return 0


def _cluster_cfg():
    try:
        from . import config
        return config.load_settings().get("cluster", {}) or {}
    except Exception:  # noqa: BLE001
        return {}


def _cluster_plan(kit: Kit, cfg: dict):
    from . import cluster, scope as sc
    services = [dict(r) for r in kit.store.services()]
    # join each service with its host's IPs/CNAME for infra proof
    host_res = {r["host"]: r for r in kit.store.hosts(scope=A.IN)}
    for s in services:
        hr = host_res.get(s["host"])
        if hr:
            s["addresses"] = hr["addresses"]
            s["cname"] = hr["cname"]
    scope = kit.scope()
    protected = cluster_protected_hosts(kit, scope)
    apex_roots = set(scope.wildcard_roots()) | {a.host for a in scope.in_scope if a.host}
    echo_hosts = set(_cluster_echo_hosts(kit))
    report = cluster.plan(
        services, protected=protected, echo_hosts=echo_hosts, apex_roots=apex_roots,
        min_cluster=int(cfg.get("min_cluster", cluster.DEFAULT_MIN_CLUSTER)),
        keep=int(cfg.get("keep", cluster.DEFAULT_KEEP)))
    return services, report


def cluster_protected_hosts(kit: Kit, scope) -> set[str]:
    """Hosts that must never be parked: explicit policy assets, operator-focused
    hosts, and hosts that already carry a lead/finding/takeover flag."""
    protected: set[str] = set()
    for a in scope.in_scope:
        if a.host and not getattr(a, "wildcard_host", False) and a.kind in ("domain", "url"):
            protected.add(a.host.lower())
    try:
        protected.update(h.lower() for h in kit.focus_hosts())
    except Exception:  # noqa: BLE001
        pass
    for lead in kit.store.leads():
        if lead["host"]:
            protected.add(lead["host"].lower())
    for f in kit.store.findings():
        if f["host"]:
            protected.add(f["host"].lower())
    for h in kit.store.takeover_candidates():
        protected.add(h["host"].lower())
    return protected


def _cluster_echo_hosts(kit: Kit) -> list[str]:
    row = kit.store.db.execute("SELECT value FROM meta WHERE key='cluster_echo_hosts'").fetchone()
    if not row:
        return []
    try:
        return json.loads(row["value"])
    except (ValueError, TypeError):
        return []


def cmd_cluster(kit: Kit, args) -> int:
    from . import cluster
    cfg = _cluster_cfg()

    if args.restore:
        n = kit.store.unpark_family(args.restore, remember=True)
        print(f"restored {n} service(s) under {args.restore}; it will not be auto-parked again")
        return 0
    if args.probe_wildcards:
        return _cmd_cluster_probe_wildcards(kit, cfg)

    services, report = _cluster_plan(kit, cfg)

    if args.approve:
        grp = next((g for g in report["review"] if g["parent"] == args.approve), None)
        if not grp:
            print(f"no platform-instance group under {args.approve} to approve")
            return 1
        n = cluster.apply_review_group(kit.store, grp)
        print(f"approved: parked {n} clone(s) under {args.approve}, kept {len(grp['kept'])} representative(s)")
        return 0

    if args.apply:
        n = cluster.apply_auto(kit.store, services, report)
        kit.store.reconcile_parked()
        if args.json:
            print(json.dumps({"auto_parked": n, "review": report["review"]}, indent=1))
            return 0
        print(f"auto-parked {n} clone service(s) (wildcard-echo + exact-dup).")
        if report["review"]:
            print(f"\n{len(report['review'])} platform-instance group(s) need your judgment "
                  f"(same backend, but real per-instance content):")
            for g in report["review"]:
                print(f"  {g['parent']}: {g['size']} hosts, infra={g['infra']}, "
                      f"titles~{g['sample_titles'][:2]} -> would park {g['parked_count']}, keep {len(g['kept'])}")
            print("Approve a group with: hk cluster --approve <parent>  (keeps 3 reps, parks the rest)")
        return 0

    # default / --review : show the plan, park nothing
    if args.json or args.review:
        print(json.dumps(report, indent=1))
        return 0
    if not report["auto"] and not report["review"]:
        print("no infrastructure clone groups found")
        return 0
    for g in report["auto"]:
        print(f"[AUTO {g['proof']}] {g['parent']}: {g['size']} hosts -> park {g['parked_count']}")
    for g in report["review"]:
        print(f"[REVIEW platform-instance] {g['parent']}: {g['size']} hosts, infra={g['infra']}, "
              f"titles~{g['sample_titles'][:2]} -> would park {g['parked_count']}, keep {len(g['kept'])}")
    print("\nRun `hk cluster --apply` to auto-park the strong proofs and list the review groups.")
    return 0


def _cmd_cluster_probe_wildcards(kit: Kit, cfg: dict) -> int:
    """For each large parent, probe random non-existent names; if they resolve
    and return the same response as members, the parent is a catch-all and its
    matching members are wildcard echoes -> record them for auto-parking."""
    from . import cluster, webprobe
    from collections import defaultdict
    services = [dict(r) for r in kit.store.services()]
    by_parent = defaultdict(list)
    for s in services:
        by_parent[cluster.parent_of(s["host"])].append(s)
    min_cluster = int(cfg.get("min_cluster", cluster.DEFAULT_MIN_CLUSTER))
    opener = webprobe.opener_through(os.environ.get("HUNTER_PROXY", ""), os.environ.get("SSL_CERT_FILE"))
    echo_hosts: list[str] = []
    checked = 0
    for parent, members in by_parent.items():
        if len(members) < min_cluster:
            continue
        checked += 1
        # fetch the catch-all signature from random names
        sigs = []
        for name in cluster.random_probe_names(parent, 3):
            res = webprobe.fetch(opener, f"https://{name}/")
            if res.get("blocked") or "error" in res:
                continue
            sigs.append((res.get("status"), res.get("hash")))
        if not sigs or len({s for s in sigs}) != 1:
            continue  # names did not resolve consistently -> not a catch-all
        catch_all = sigs[0]
        # a member is an echo if its own response matches the catch-all
        for m in members:
            if (m.get("status"), m.get("body_hash")) == catch_all:
                echo_hosts.append(m["host"])
    kit.store.db.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('cluster_echo_hosts', ?)",
                         (json.dumps(echo_hosts),))
    print(f"wildcard probe: checked {checked} parent(s), found {len(echo_hosts)} echo host(s). "
          f"Run `hk cluster --apply` to park them.")
    return 0


def cmd_techhints(kit: Kit, args) -> int:
    from . import techhints
    fps: list[str] = []
    for row in kit.store.services():
        for col in ("server", "tech", "title"):
            try:
                v = row[col]
            except (KeyError, IndexError):
                v = None
            if v:
                fps.append(str(v))
    hints = techhints.hints_for(fps)
    if args.json:
        print(json.dumps([{"tech": k, "hint": h} for k, h in hints], indent=1))
        return 0
    if not hints:
        print("no known technology-specific hints for this target's fingerprints")
        return 0
    for keyword, hint in hints:
        print(f"[{keyword}] {hint}")
    return 0


def cmd_jsintel(kit: Kit, args) -> int:
    from . import paths
    print(paths.REPO_DIR / "hunter" / "data" / "jsintel_playbook.md")
    return 0


def cmd_authflows(kit: Kit, args) -> int:
    from . import paths
    print(paths.REPO_DIR / "hunter" / "data" / "authflows_playbook.md")
    return 0


def cmd_graphql(kit: Kit, args) -> int:
    from . import paths
    print(paths.REPO_DIR / "hunter" / "data" / "graphql_playbook.md")
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


def cmd_candidate(kit: Kit, args) -> int:
    """Discovery candidates. The agent proposes with `add` (code scores the
    evidence and records the tier - the agent cannot set it); the agent can
    `approve`/`reject` a review-tier candidate with a reason. Code, not the
    agent, decides auto-add. Admitted candidates are synced into scope by the
    phase/orchestrator, never written to scope.json by this command."""
    from . import expand
    action = args.action

    if action == "list":
        rows = kit.store.candidates(tier=args.tier)
        if args.json:
            print(json.dumps([dict(r) for r in rows], indent=1))
            return 0
        if not rows:
            print("no scope candidates recorded yet")
            return 0
        for r in rows:
            print(f"  {r['tier']:9} {r['domain']:40} {r['source']:14} {r['reason'] or ''}")
        return 0

    if action == "recheck":
        # Re-score every candidate under the CURRENT scope rule and drop any that
        # no longer qualify (e.g. a sibling brand added before the brand-TLD gate
        # existed). Then re-sync scope.json so the running proxy drops them too.
        owner = expand.load_owner_context(kit.state.db) or _owner_context(kit)
        settings_cfg = config.load_settings().get("scope_expand", {}) or {}
        auto_mode = expand.auto_mode_for(settings_cfg, bool(owner.get("is_ownership")))
        brand_gate = bool(owner.get("brand")) and not owner.get("is_ownership")
        changed = dropped = 0
        for r in kit.store.candidates():
            try:
                ev = json.loads(r["evidence"]) if r["evidence"] else {}
            except (json.JSONDecodeError, TypeError):
                ev = {}
            verdict = expand.decide(r["domain"], ev, owner)
            # Map the scoring verdict to a stored tier. A brand-mismatch on a
            # brand-TLD scope is a hard reject (decide already returns DECLINE
            # for it, but be explicit).
            if brand_gate and not expand._brand_token_matches(r["domain"], owner):
                new_tier = "reject"
            else:
                new_tier = expand.stored_tier(verdict.tier, auto_mode)
            # Keep an agent decision that the recheck does not contradict: an
            # approved same-brand domain stays approved; an agent rejection stays.
            if r["tier"] == "approved" and new_tier in expand.ADMITTED_TIERS:
                new_tier = "approved"
            if r["tier"] == "rejected-by-agent":
                continue
            if new_tier == r["tier"]:
                continue
            if r["tier"] in expand.ADMITTED_TIERS and new_tier not in expand.ADMITTED_TIERS:
                dropped += 1
            kit.store.set_candidate_tier(r["domain"], new_tier, "code-recheck", verdict.reason)
            changed += 1
        kit.state.db.commit()
        scope = kit.scope()
        added = expand.sync_scope_expanded(kit.store, scope, kit.target.scope_file, sc.save)
        print(f"rechecked: {changed} candidate(s) re-tiered, {dropped} dropped from scope; "
              f"{added} now in scope")
        return 0

    domain = (getattr(args, "domain", "") or "").strip().lower().rstrip(".")
    if not domain:
        print("usage: hk candidate <add|approve|reject> <domain> ...")
        return 1

    if action == "add":
        evidence = {}
        if args.evidence:
            try:
                evidence = json.loads(args.evidence)
            except json.JSONDecodeError as exc:
                print(f"evidence must be valid JSON: {exc}")
                return 1
        # Same owner context the phase learned (seed nameservers etc.), else a
        # basic one built from the scope.
        owner = expand.load_owner_context(kit.state.db) or _owner_context(kit)
        verdict = expand.decide(domain, evidence, owner)
        scope = kit.scope()
        cfg = config.load_settings().get("scope_expand", {}) or {}
        tier = expand.stored_tier(verdict.tier, expand.auto_mode_for(
            cfg, bool(scope.rules.get("ownership_scope"))))
        if verdict.tier == expand.DECLINE and not any(s.strength == expand.REJECT for s in verdict.signals):
            tier = "unverified"   # no evidence either way yet - not a final rejection
        existing = kit.store.candidate(domain)
        if existing is not None and existing["tier"] in expand.ADMITTED_TIERS and tier not in expand.ADMITTED_TIERS \
                and not any(s.strength == expand.REJECT for s in verdict.signals):
            # Already admitted on stronger evidence: a later, thinner submission
            # must not silently drop it from scope. Only real counter-evidence
            # (parked, different registrant) or an explicit reject can.
            print(f"{domain}: already {existing['tier']} on earlier evidence; kept ({verdict.reason})")
            return 0
        kit.store.record_candidate(
            domain, pattern=args.pattern or (owner.get("brand") or "ownership"),
            source=args.source or "agent", tier=tier, subdomains=not args.apex_only,
            evidence=evidence, signals=[s.to_dict() for s in verdict.signals],
            reason=verdict.reason, decided_by="code")
        kit.state.db.commit()
        print(f"{domain}: {tier}  ({verdict.reason})")
        return 0

    if action in ("approve", "reject"):
        row = kit.store.candidate(domain)
        if row is None:
            print(f"no candidate '{domain}' recorded; add it first with: hk candidate add {domain} ...")
            return 1
        if action == "approve":
            # Guard: the agent may only approve a candidate that already carries
            # at least one real ownership signal (tier review). It can never
            # approve something code rejected or that has no evidence.
            if row["tier"] not in ("review", "approved"):
                print(f"cannot approve '{domain}': its evidence tier is '{row['tier']}', not 'review'. "
                      f"Code only lets you approve candidates with real but partial ownership proof.")
                return 1
            # Re-check the scope-type gate on approve: on a brand-TLD scope a
            # different-brand domain can never be approved, whatever the agent
            # believes about common ownership. Only enforced when we actually
            # know the brand (a pattern scope); with no brand there is nothing
            # to compare against, so the normal review guard above applies.
            owner = expand.load_owner_context(kit.state.db) or _owner_context(kit)
            if (owner.get("brand") and not owner.get("is_ownership")
                    and not expand._brand_token_matches(domain, owner)):
                print(f"cannot approve '{domain}': it is a different brand from "
                      f"'{owner.get('brand')}'. This program's scope is the brand on its TLDs, not other "
                      f"brands the same company owns. Only an 'all assets owned by X' program would allow it.")
                return 1
            kit.store.set_candidate_tier(domain, "approved", "agent", args.reason or "")
            kit.state.db.commit()
            print(f"approved {domain} (will be added to scope)")
        else:
            kit.store.set_candidate_tier(domain, "rejected-by-agent", "agent", args.reason or "")
            kit.state.db.commit()
            print(f"rejected {domain}")
        return 0


    print("usage: hk candidate <add|approve|reject|list|recheck> ...")
    return 1


def _owner_context(kit: Kit) -> dict:
    """Build the owner context the scoring engine needs, from the scope's
    recorded patterns/ownership plus any seed hosts already in the inventory."""
    scope = kit.scope()
    rules = scope.rules
    own = rules.get("ownership_scope") or {}
    patterns = rules.get("scope_patterns") or []
    brand = (patterns[0]["brand"] if patterns else "") or ""
    seed_domains = set(own.get("seed_domains") or [])
    for a in scope.in_scope:
        if a.host and a.kind in ("domain", "wildcard"):
            seed_domains.add(a.host)
    from .expand import _registrable_root
    return {
        "brand": brand,
        "brand_aliases": [],
        "legal_names": own.get("legal_names") or ([] if not brand else []),
        "seed_domains": {d for d in seed_domains},
        "seed_ns_roots": set(),          # filled by the phase from live NS lookups
        "seed_soa_rnames": set(),
        "seed_spf_includes": set(),
        "seed_asns": set(),
        "is_ownership": bool(own),
    }


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
    a.add_argument("--all", action="store_true", help="include parked infra clones")
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
    a = sub.add_parser("unlock"); a.add_argument("url"); a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_unlock)
    a = sub.add_parser("secrets"); a.add_argument("path"); a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_secrets)
    a = sub.add_parser("vhost"); a.add_argument("ip_url"); a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_vhost)
    a = sub.add_parser("cache"); a.add_argument("url"); a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_cache)
    a = sub.add_parser("wordlist")
    a.add_argument("--kind"); a.add_argument("--extensions"); a.add_argument("--list", action="store_true")
    a.set_defaults(func=cmd_wordlist)
    a = sub.add_parser("fuzzplan"); a.add_argument("service_id"); a.set_defaults(func=cmd_fuzzplan)
    sub.add_parser("playbook").set_defaults(func=cmd_playbook)
    sub.add_parser("dorks").set_defaults(func=cmd_dorks)
    sub.add_parser("depconf").set_defaults(func=cmd_depconf)
    a = sub.add_parser("techhints"); a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_techhints)
    a = sub.add_parser("cluster")
    a.add_argument("--apply", action="store_true", help="auto-park strong proofs; list review groups")
    a.add_argument("--review", action="store_true", help="JSON of platform-instance groups for judgment")
    a.add_argument("--approve", metavar="PARENT", help="park an agent-approved platform-instance group")
    a.add_argument("--restore", metavar="PARENT", help="un-park a family and never auto-park it again")
    a.add_argument("--probe-wildcards", action="store_true", help="detect catch-all parents (Proof A)")
    a.add_argument("--json", action="store_true"); a.set_defaults(func=cmd_cluster)
    sub.add_parser("jsintel").set_defaults(func=cmd_jsintel)
    sub.add_parser("authflows").set_defaults(func=cmd_authflows)
    sub.add_parser("graphql").set_defaults(func=cmd_graphql)
    a = sub.add_parser("candidate")
    a.add_argument("action", choices=["add", "approve", "reject", "list", "recheck"])
    a.add_argument("domain", nargs="?")
    a.add_argument("--source", help="how it was found (tld-sweep, crt.sh, reverse-whois, hreflang, agent)")
    a.add_argument("--pattern", help="the brand/pattern it came from")
    a.add_argument("--evidence", help="JSON evidence dict for scoring")
    a.add_argument("--reason", help="reason for approve/reject")
    a.add_argument("--apex-only", action="store_true", help="add only the apex, not *.domain")
    a.add_argument("--tier", help="filter for list")
    a.add_argument("--json", action="store_true"); a.set_defaults(func=cmd_candidate)
    a = sub.add_parser("candidates"); a.add_argument("--tier"); a.add_argument("--json", action="store_true")
    a.set_defaults(func=lambda k, x: cmd_candidate(k, argparse.Namespace(
        action="list", domain=None, tier=x.tier, json=x.json, source=None, pattern=None,
        evidence=None, reason=None, apex_only=False)))
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
