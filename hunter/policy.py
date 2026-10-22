"""Policy reader: turns the pasted program page into scope.json.

The AI only does the reading. Everything that decides what may be touched
is checked again here in code:
- every in-scope entry must parse cleanly and must be named in policy.txt,
  otherwise it is moved to "unclear" (treated as out of scope);
- out-of-scope entries always win;
- operator overrides (scope-overrides.txt) are applied last;
- the rate limit can only go down from the policy value, never up.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import scope as sc

PLATFORMS = ("intigriti", "bugcrowd", "hackerone", "yeswehack", "external", "unknown")
SCANNING = ("allowed", "limited", "forbidden", "not_mentioned")
REGISTRATION = ("allowed", "forbidden", "not_mentioned")

PLATFORM_EMAIL_DOMAIN = {
    "intigriti": "intigriti.me",
    "bugcrowd": "bugcrowdninja.com",
    "hackerone": "wearehackerone.com",
    "yeswehack": "yeswehack.ninja",
}

DRAFT_FILE = "scope_draft.json"

PROMPT = """You are reading a bug bounty program policy. Your only job is to extract
facts from it into a JSON file. You do not test anything and you do not use the
network.

Read the file ./policy.txt (the full program page, pasted by the researcher).
Then write the file ./{draft_file} with exactly this structure:

{{
  "program_name": "string",
  "platform": "intigriti | bugcrowd | hackerone | yeswehack | external | unknown",
  "in_scope": [
    {{"asset": "exactly as written in the policy", "type": "wildcard | domain | url | ip | cidr | mobile | source_code | executable | other",
      "quote": "the exact sentence or table row from the policy", "notes": "anything that limits this asset, or empty"}}
  ],
  "out_of_scope": [ same shape as in_scope ],
  "excluded_vulnerabilities": ["vulnerability types the program says it does NOT accept"],
  "forbidden_actions": ["actions the program forbids, e.g. denial of service, social engineering, automated scanning, spam"],
  "automated_scanning": "allowed | limited | forbidden | not_mentioned",
  // If the policy states a requests-per-second or per-minute limit, automation is
  // allowed: use "allowed", not "limited".
  "rate_limit": {{"requests_per_second": number or null, "quote": "exact text or null"}},
  "required_headers": [{{"name": "header name", "value": "header value as written", "quote": "exact text"}}],
  "user_agent": "required User-Agent value, or null",
  "user_agent_mode": "append | exact | null",
  "ownership_scope": {{"owner": "organisation name",
                      "legal_names": ["every legal/registered company name the policy gives, e.g. 'AutoScout24 GmbH', 'Schweizerische Bundesbahnen SBB'"],
                      "seed_domains": ["any domain the policy names that is known to belong to the owner, e.g. 'autoscout24.de' - these seed the ownership search"],
                      "include_subsidiaries": true/false (true only if the policy explicitly says subsidiaries/acquisitions are in scope),
                      "quote": "exact text"}} or null,
  "scope_patterns": [
    {{"asset": "the pattern exactly as written, e.g. '*.autoscout24.*' or 'autoscout24.*'",
      "brand": "the brand label with no TLD, e.g. 'autoscout24'",
      "subdomains": true/false (true if the pattern starts with '*.' or '.', meaning subdomains are included),
      "quote": "exact text"}}
  ],
  "account_rules": {{"self_registration": "allowed | forbidden | not_mentioned",
                    "email_requirement": "for example: use your @intigriti.me address, or null",
                    "quote": "exact text or null"}},
  "ambiguities": [{{"item": "the unclear asset or rule", "why": "why it is unclear"}}],
  "other_rules": ["any other testing rule worth knowing, one short sentence each"]
}}

Rules for reading:
1. Copy every asset exactly as the policy writes it. Never invent, widen or
   guess an asset. If the policy says "*.example.com", write "*.example.com".
   Do not add "example.com" unless the policy names it.
2. "type": wildcard for *.domain; domain for a single host; url when a path or
   port is given; ip / cidr for addresses; mobile for app store ids or package
   names; source_code for repositories; executable for desktop software.
   Classify by the ASSET STRING itself, never by a "Type" column the platform
   shows: "*.example.com" is a wildcard even if a table labels its type "Other",
   "Domain", or leaves it blank.
3. If the policy names a domain and says "and all subdomains", output two
   entries: the domain itself (type domain) and "*.domain" (type wildcard).
4. Put an asset in out_of_scope if the policy says it is out of scope, not
   eligible, not part of the program, third party, or "do not test".
5. Scope is often split across several in-scope tables ("Tier 1", "Tier 2",
   "In scope", "Eligible", ...): EVERY asset in any of them is in_scope, and a
   bounty tier, "reduced bounty", or "max severity" note NEVER changes that. A
   separate "Excluded Assets" / "Out of scope" / "Ineligible" table is
   out_of_scope. Use "ambiguities" ONLY for an asset that truly cannot be read
   or is genuinely self-contradictory (a malformed name; the same asset listed
   as both in and out with no resolution). Do NOT mark an asset unclear just
   because its type column is odd, its bounty tier varies, a note says to
   cross-reference tables, or some specific subdomains under a wildcard are
   separately excluded. Put a clearly-listed eligible wildcard like
   "*.example.com" in in_scope and its excluded subdomains in out_of_scope - the
   out-of-scope entries win automatically, so nothing is lost by including it.
6. rate_limit.requests_per_second: convert to requests per second
   (for example 300 per minute = 5). Use the strictest limit if several are
   given. null if the policy gives no number.
7. required_headers: only headers the policy requires on every request
   (for example X-Bug-Bounty: <username>). Keep placeholders like <username>
   exactly as written.
8. user_agent_mode: "append" if the policy asks to add, append or include a
   tag in the User-Agent; "exact" only if it says the User-Agent must be
   exactly that value; null if no User-Agent rule.
9. ownership_scope: only when the policy defines scope by ownership instead
   of (or besides) a list, for example "any asset owned by ACME is in scope",
   "all assets belonging to X", "domains and IP ranges owned by X". Fill
   legal_names with every company name the policy gives and seed_domains with
   any domain it names that belongs to the owner - these two seed the
   ownership search in a later phase. Still do NOT turn the sentence into
   wildcards or guess domains/IPs yourself: put only assets the policy names in
   in_scope. include_subsidiaries is true ONLY if the policy explicitly says
   subsidiaries or acquired companies are in scope.
9b. scope_patterns: a 'brand on any TLD' form such as "*.autoscout24.*" or
   "autoscout24.*", meaning the brand across every country TLD it operates on.
   Record it here (brand = the label with no TLD). Do NOT also put it in
   in_scope or ambiguities - it is a pattern for a later phase to expand into
   real, proven country domains, not a testable asset by itself. A normal
   single wildcard like "*.autoscout24.de" is NOT a pattern; it goes in
   in_scope as usual.
10. Every "quote" must be copied word for word from policy.txt.
11. Write valid JSON only (double quotes, no comments, no trailing commas).

When the file is written, read it back once to check it is valid JSON, then
reply with the single word DONE.
"""

REPAIR_PROMPT = """The file ./{draft_file} you wrote has these problems:
{problems}

Read ./policy.txt and ./{draft_file} again and write a corrected ./{draft_file}
with the same structure. Fix only the listed problems, keep everything else.
Reply with the single word DONE when the corrected file is written.
"""


def validate_draft(data) -> list[str]:
    """Structural check of the agent's JSON. Returns a list of problems."""
    problems: list[str] = []
    if not isinstance(data, dict):
        return ["the top level must be a JSON object"]
    for key in ("in_scope", "out_of_scope"):
        items = data.get(key)
        if not isinstance(items, list):
            problems.append(f"'{key}' must be a list")
            continue
        for index, item in enumerate(items):
            if not isinstance(item, dict) or not isinstance(item.get("asset"), str) or not item["asset"].strip():
                problems.append(f"{key}[{index}] needs a non-empty 'asset' string")
            elif item.get("type") not in sc.ALL_KINDS:
                problems.append(f"{key}[{index}] ('{item.get('asset')}') has type '{item.get('type')}', "
                                f"which must be one of {', '.join(sc.ALL_KINDS)}")
    if data.get("platform") not in PLATFORMS:
        problems.append(f"'platform' must be one of {', '.join(PLATFORMS)}")
    if data.get("automated_scanning") not in SCANNING:
        problems.append(f"'automated_scanning' must be one of {', '.join(SCANNING)}")
    rate = data.get("rate_limit")
    if rate is not None:
        if not isinstance(rate, dict):
            problems.append("'rate_limit' must be an object")
        else:
            rps = rate.get("requests_per_second")
            if rps is not None and (not isinstance(rps, (int, float)) or isinstance(rps, bool) or rps <= 0):
                problems.append("'rate_limit.requests_per_second' must be a positive number or null")
    headers = data.get("required_headers")
    if headers is not None:
        if not isinstance(headers, list):
            problems.append("'required_headers' must be a list")
        else:
            for index, header in enumerate(headers):
                if not isinstance(header, dict) or not isinstance(header.get("name"), str) \
                        or not isinstance(header.get("value"), str):
                    problems.append(f"required_headers[{index}] needs 'name' and 'value' strings")
    for key in ("excluded_vulnerabilities", "forbidden_actions", "other_rules"):
        if key in data and not isinstance(data[key], list):
            problems.append(f"'{key}' must be a list of strings")
    accounts = data.get("account_rules")
    if accounts is not None and (not isinstance(accounts, dict)
                                 or accounts.get("self_registration") not in REGISTRATION):
        problems.append(f"'account_rules.self_registration' must be one of {', '.join(REGISTRATION)}")
    owned = data.get("ownership_scope")
    has_owner = isinstance(owned, dict) and str(owned.get("owner") or "").strip()
    if not data.get("in_scope") and not has_owner and not data.get("ambiguities"):
        problems.append("'in_scope' is empty. If the policy really lists no assets, add an ambiguity explaining "
                        "that, or fill ownership_scope if the scope is 'assets owned by ...'")
    return problems


@dataclass
class BuildResult:
    scope: sc.Scope
    review: list[str] = field(default_factory=list)       # human notes for scope_review.md
    problems: list[str] = field(default_factory=list)     # things the operator must look at


def _strs(values) -> list[str]:
    return [str(v).strip() for v in (values or []) if str(v).strip()]


def build_scope(draft: dict, policy_text: str, overrides_text: str, settings: dict) -> BuildResult:
    result = BuildResult(scope=sc.Scope())
    scope = result.scope
    seen: set[tuple[str, str, str, int | None]] = set()

    def add(target: list, asset: sc.Asset) -> None:
        key = (asset.kind, asset.host or asset.raw, asset.path, asset.port)
        if key not in seen or target is scope.out_of_scope:
            target.append(asset)
            seen.add(key)

    # 1. Out of scope first: anything that can be read is excluded. Unreadable
    #    exclusions are kept as raw text so the operator sees them.
    for item in draft.get("out_of_scope") or []:
        raw, kind = str(item.get("asset", "")).strip(), item.get("type")
        try:
            scope.out_of_scope.append(sc.parse_asset(raw, kind))
        except sc.AssetError as exc:
            scope.ambiguities.append({"item": raw, "why": f"out-of-scope entry could not be read ({exc}); "
                                      "anything that looks like it will not be tested"})
            # Keep a best-effort host exclusion so traffic to it is blocked anyway.
            for token in sc.mentioned_hosts(raw):
                try:
                    scope.out_of_scope.append(sc.parse_asset(token))
                except sc.AssetError:
                    pass

    # Brand-on-any-TLD patterns the discovery phase will expand. Collected from
    # the dedicated scope_patterns field AND rescued from any in_scope/ambiguity
    # entry that is actually such a pattern, keyed by brand to dedupe.
    patterns: dict[str, dict] = {}

    def add_pattern(raw: str) -> bool:
        pat = sc.parse_pattern(raw)
        if not pat:
            return False
        patterns.setdefault(pat["brand"], {"brand": pat["brand"], "subdomains": False, "raw": pat["raw"]})
        if pat["subdomains"]:
            patterns[pat["brand"]]["subdomains"] = True
        return True

    for item in draft.get("scope_patterns") or []:
        if isinstance(item, dict) and item.get("asset"):
            add_pattern(str(item["asset"]))

    # 2. In scope: must parse, must be named in the policy text.
    for item in draft.get("in_scope") or []:
        raw, kind = str(item.get("asset", "")).strip(), item.get("type")
        try:
            asset = sc.parse_asset(raw, kind)
        except sc.AssetError as exc:
            if add_pattern(raw):
                continue  # it is a brand pattern, not a failed asset
            scope.ambiguities.append({"item": raw, "why": f"could not be read ({exc}), so it is not tested"})
            continue
        if not sc.appears_in_policy(asset, policy_text):
            scope.ambiguities.append({"item": raw, "why": "the AI listed it, but policy.txt does not name it "
                                      "this way, so it is not tested"})
            continue
        if item.get("quote") and not sc.quote_in_policy(str(item["quote"]), policy_text):
            result.review.append(f"Note: the quote given for '{raw}' was not found word for word in policy.txt.")
        add(scope.in_scope, asset)

    for amb in draft.get("ambiguities") or []:
        if isinstance(amb, dict) and amb.get("item"):
            entry = {"item": str(amb["item"]), "why": str(amb.get("why", ""))}
            if add_pattern(entry["item"]):
                continue  # a brand pattern the AI mislabelled as unclear
            if looks_like_asset(entry["item"]):
                scope.ambiguities.append(entry)
            else:
                scope.questions.append(entry)

    # 3. Operator overrides win over everything the AI read.
    ins, outs, override_problems = sc.parse_overrides(overrides_text)
    result.problems += [f"scope-overrides.txt {p}" for p in override_problems]
    for raw in outs:
        try:
            scope.out_of_scope.append(sc.parse_asset(raw))
            result.review.append(f"Override: '{raw}' set OUT of scope by you.")
        except sc.AssetError as exc:
            result.problems.append(f"scope-overrides.txt: 'out {raw}' cannot be read ({exc})")
    for raw in ins:
        try:
            asset = sc.parse_asset(raw)
        except sc.AssetError as exc:
            result.problems.append(f"scope-overrides.txt: 'in {raw}' cannot be read ({exc})")
            continue
        add(scope.in_scope, asset)
        scope.ambiguities = [a for a in scope.ambiguities if a["item"].strip().lower() != raw.strip().lower()]
        result.review.append(f"Override: '{raw}' set IN scope by you.")

    # 4. In-scope entries that an exclusion fully covers are dropped from the
    #    list so the review is honest about what will be tested.
    kept = []
    for asset in scope.in_scope:
        if asset.kind in ("domain",) and any(sc.asset_matches(o, asset.host) for o in scope.out_of_scope
                                             if o.kind != "url"):
            result.review.append(f"'{asset.raw}' is listed in scope but also excluded, so it is not tested.")
            continue
        kept.append(asset)
    scope.in_scope = kept

    # 5. Hosts the policy mentions that ended up in neither list.
    classified = {a.host for a in scope.in_scope + scope.out_of_scope if a.host}
    wild = {a.host for a in scope.in_scope + scope.out_of_scope if a.kind == "wildcard"}
    unclassified = []
    for token in sorted(sc.mentioned_hosts(policy_text)):
        host = token[2:] if token.startswith("*.") else token
        if host in classified or host in sc.PLATFORM_DOMAINS or any(host.endswith("." + p) for p in sc.PLATFORM_DOMAINS):
            continue
        if any(host.endswith("." + w) for w in wild):
            continue
        unclassified.append(token)
    scope.unclassified_hosts = unclassified

    # 6. Rules.
    platform = draft.get("platform") if draft.get("platform") in PLATFORMS else "unknown"
    scope.program = {"name": str(draft.get("program_name") or "").strip(), "platform": platform}
    scan = draft.get("automated_scanning") if draft.get("automated_scanning") in SCANNING else "not_mentioned"
    rate = draft.get("rate_limit") or {}
    policy_rps = rate.get("requests_per_second") if isinstance(rate, dict) else None
    if not isinstance(policy_rps, (int, float)) or isinstance(policy_rps, bool) or policy_rps <= 0:
        policy_rps = None
    cfg = settings.get("scope", {})
    default_rps = float(cfg.get("default_rps", 5))
    # A hardware ceiling: the most this VPS should push through one proxy,
    # whatever the program allows. It protects the run quality, not the
    # program. Set it with: hunt rate-cap <n>.
    max_rps = float(cfg.get("max_rps", 200))

    if policy_rps:
        # The program stated an explicit number: honour it, capped only by
        # the hardware ceiling. A stated numeric rate means automation is
        # allowed, so "limited" does not drag it down to the slow floor.
        effective = min(float(policy_rps), max_rps)
        rate_source = "policy"
        if float(policy_rps) > max_rps:
            result.review.append(
                f"The program allows {policy_rps:g}/s; capped to {max_rps:g}/s for this VPS. "
                f"Raise it with: hunt rate-cap <n>.")
    elif scan == "forbidden":
        effective = 1.0
        rate_source = "automation forbidden"
    elif scan == "limited":
        effective = float(cfg.get("limited_scanning_rps", 2))
        rate_source = "limited automation, no number stated"
    else:
        effective = default_rps
        rate_source = "no rate stated, default used"

    handle = str(settings.get("researcher", {}).get("handle") or "").strip()
    headers: dict[str, str] = {}
    unresolved: list[str] = []
    for header in draft.get("required_headers") or []:
        if not isinstance(header, dict):
            continue
        name, value = str(header.get("name", "")).strip(), str(header.get("value", "")).strip()
        if not name or any(ch in name for ch in " :\r\n"):
            continue
        filled = _fill_placeholders(value, handle)
        if filled is None:
            unresolved.append(f"{name}: {value}")
            continue
        headers[name] = filled
    user_agent = draft.get("user_agent")
    if isinstance(user_agent, str) and user_agent.strip():
        filled = _fill_placeholders(user_agent.strip(), handle)
        if filled is None:
            unresolved.append(f"User-Agent: {user_agent}")
        else:
            headers["User-Agent"] = filled

    for name, value in sc.parse_override_headers(overrides_text).items():
        headers[name] = value
        unresolved = [u for u in unresolved if u.split(":", 1)[0].strip().lower() != name.lower()]
        result.review.append(f"Override: header '{name}' set by you.")

    accounts = draft.get("account_rules") if isinstance(draft.get("account_rules"), dict) else {}
    email_domain = PLATFORM_EMAIL_DOMAIN.get(platform)
    # Apply an operator rate override (scope-overrides.txt: "rate 120"),
    # still capped by the hardware ceiling.
    override_rps = sc.parse_override_rate(overrides_text)
    if override_rps is not None:
        effective = min(override_rps, max_rps)
        rate_source = "your override"
        result.review.append(f"Override: request rate set to {effective:g}/s by you.")

    scope.rules = {
        "automated_scanning": scan,
        # Automation is only genuinely limited when the program forbids it or
        # caps it AND gave no workable number. A stated numeric rate means
        # automation is allowed.
        "low_automation": scan == "forbidden" or (scan == "limited" and not policy_rps),
        "policy_rps": policy_rps,
        "effective_rps": effective,
        "rate_source": rate_source,
        "required_headers": headers,
        # Default append: it satisfies "append/include" wording and keeps a
        # browser-like agent; "exact" only when the policy demands the value.
        "user_agent_mode": "exact" if draft.get("user_agent_mode") == "exact" else "append",
        "ownership_scope": _ownership(draft, policy_text),
        "scope_patterns": list(patterns.values()),
        "unresolved_headers": unresolved,
        "self_registration": accounts.get("self_registration") if accounts.get("self_registration") in REGISTRATION
        else "not_mentioned",
        "email_requirement": accounts.get("email_requirement"),
        "researcher_email": f"{handle}@{email_domain}" if handle and email_domain else None,
    }
    scope.excluded_vulnerabilities = _strs(draft.get("excluded_vulnerabilities"))
    scope.forbidden_actions = _strs(draft.get("forbidden_actions"))
    scope.other_rules = _strs(draft.get("other_rules"))

    if unresolved:
        result.problems.append(
            "These required headers contain a placeholder that could not be filled: "
            + "; ".join(unresolved) + ". Set your username with: hunt handle <your-username>")
    if not scope.network_assets():
        result.problems.append("No testable web asset was found in the policy.")
    return result


def looks_like_asset(text: str) -> bool:
    """True if an 'unclear' item names a host, URL or IP (it then means an
    asset is held back); False for questions about rewards, reporting etc."""
    try:
        sc.parse_asset(text)
        return True
    except sc.AssetError:
        return bool(sc.mentioned_hosts(text)) and len(text.split()) <= 6


def _fill_placeholders(value: str, handle: str) -> str | None:
    """Replace <username>-style placeholders with the researcher handle.
    Returns None if a placeholder remains and no handle is known."""
    import re
    pattern = re.compile(r"<[^<>]{1,40}>|\{[^{}]{1,40}\}|\[[^\[\]]{1,40}\]")
    if not pattern.search(value):
        return value
    if not handle:
        return None
    return pattern.sub(handle, value)


def render_review(scope: sc.Scope, build: BuildResult, target_name: str) -> str:
    rules = scope.rules
    lines = [f"# Scope review: {target_name}", "",
             "Generated from policy.txt. Unclear items are NOT tested. To change anything, add lines",
             "to scope-overrides.txt in the target folder (for example: `in *.foo.com` or",
             "`out admin.foo.com`). The run picks the change up automatically.", "",
             f"- Program: {scope.program.get('name') or '(not named)'} ({scope.program.get('platform')})",
             f"- Automated scanning: {rules.get('automated_scanning')}",
             f"- Request rate used: {rules.get('effective_rps')} per second "
             f"(policy: {rules.get('policy_rps') or 'not stated'}; source: {rules.get('rate_source', '-')})",
             f"- Required headers: {_headers_text(rules)}",
             *([f"- Ownership scope: assets owned by {rules['ownership_scope']['owner']}"
                + (f" (legal names: {', '.join(rules['ownership_scope'].get('legal_names') or [])})"
                   if rules['ownership_scope'].get('legal_names') else "")
                + " - the discovery phase searches for owned assets and proves ownership before testing"]
               if rules.get("ownership_scope") else []),
             f"- Self-registration: {rules.get('self_registration')}",
             f"- Researcher email: {rules.get('researcher_email') or rules.get('email_requirement') or 'not required'}",
             "", "## In scope (will be tested)", ""]
    lines += [f"- `{a.raw}` ({a.kind})" for a in scope.in_scope] or ["- none"]
    lines += ["", "## Out of scope (blocked)", ""]
    lines += [f"- `{a.raw}` ({a.kind})" for a in scope.out_of_scope] or ["- none"]
    patterns = rules.get("scope_patterns") or []
    if patterns:
        lines += ["", "## Brand patterns to expand (discovery phase finds the real TLDs)", ""]
        for p in patterns:
            sub = "subdomains included" if p.get("subdomains") else "apex per TLD"
            lines += [f"- `{p.get('raw', p['brand'] + '.*')}` -> brand **{p['brand']}** on any TLD ({sub}); "
                      f"the run discovers which country domains exist and proves ownership before testing."]
    lines += ["", "## Unclear assets (not tested until you decide)", ""]
    lines += [f"- `{a['item']}`: {a['why']}" for a in scope.ambiguities] or ["- none"]
    if scope.questions:
        lines += ["", "## Notes about the rules (for your information, nothing is held back)", ""]
        lines += [f"- {a['item']}: {a['why']}" for a in scope.questions]
    lines += ["", "## Mentioned in the policy but not classified (not tested)", ""]
    lines += [f"- `{h}`" for h in scope.unclassified_hosts] or ["- none"]
    lines += ["", "## Not accepted vulnerability types", ""]
    lines += [f"- {v}" for v in scope.excluded_vulnerabilities] or ["- none listed"]
    lines += ["", "## Forbidden actions", ""]
    lines += [f"- {v}" for v in scope.forbidden_actions] or ["- none listed"]
    if scope.other_rules:
        lines += ["", "## Other rules", ""] + [f"- {v}" for v in scope.other_rules]
    if build.review or build.problems:
        lines += ["", "## Notes", ""] + [f"- {v}" for v in build.problems + build.review]
    return "\n".join(lines) + "\n"


def _ownership(draft: dict, policy_text: str) -> dict | None:
    """'All assets owned by X' scopes. Recorded with the owner's legal names and
    any seed domains the policy gives, so the discovery phase can search for
    owned assets by proof. The discovery phase - not this reader - decides what
    is actually in scope."""
    value = draft.get("ownership_scope")
    if not isinstance(value, dict) or not str(value.get("owner") or "").strip():
        return None
    quote = str(value.get("quote") or "").strip()
    legal = [str(n).strip()[:120] for n in (value.get("legal_names") or []) if str(n).strip()][:10]
    seeds = []
    for d in value.get("seed_domains") or []:
        try:
            seeds.append(sc.parse_asset(str(d)).host)
        except sc.AssetError:
            continue
    return {"owner": str(value["owner"]).strip()[:120],
            "legal_names": legal,
            "seed_domains": sorted(set(s for s in seeds if s))[:20],
            "include_subsidiaries": bool(value.get("include_subsidiaries")),
            "quote": quote[:400],
            "quote_found": bool(quote) and sc.quote_in_policy(quote, policy_text)}


def _headers_text(rules: dict) -> str:
    parts = []
    for name, value in (rules.get("required_headers") or {}).items():
        if name.lower() == "user-agent" and rules.get("user_agent_mode", "append") != "exact":
            parts.append(f"User-Agent: <browser agent> {value} (appended)")
        else:
            parts.append(f"{name}: {value}")
    return ", ".join(parts) or "none"
