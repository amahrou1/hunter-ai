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
  "rate_limit": {{"requests_per_second": number or null, "quote": "exact text or null"}},
  "required_headers": [{{"name": "header name", "value": "header value as written", "quote": "exact text"}}],
  "user_agent": "required User-Agent value, or null",
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
3. If the policy names a domain and says "and all subdomains", output two
   entries: the domain itself (type domain) and "*.domain" (type wildcard).
4. Put an asset in out_of_scope if the policy says it is out of scope, not
   eligible, not part of the program, third party, or "do not test".
5. If anything about an asset or a rule is unclear or contradictory, add it
   to ambiguities. Do NOT put an unclear asset in in_scope.
6. rate_limit.requests_per_second: convert to requests per second
   (for example 300 per minute = 5). Use the strictest limit if several are
   given. null if the policy gives no number.
7. required_headers: only headers the policy requires on every request
   (for example X-Bug-Bounty: <username>). Keep placeholders like <username>
   exactly as written.
8. Every "quote" must be copied word for word from policy.txt.
9. Write valid JSON only (double quotes, no comments, no trailing commas).

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
    if not data.get("in_scope"):
        problems.append("'in_scope' is empty. If the policy really lists no assets, add an ambiguity explaining that")
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

    # 2. In scope: must parse, must be named in the policy text.
    for item in draft.get("in_scope") or []:
        raw, kind = str(item.get("asset", "")).strip(), item.get("type")
        try:
            asset = sc.parse_asset(raw, kind)
        except sc.AssetError as exc:
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
    max_rps = float(cfg.get("max_rps", 20))
    effective = min(float(policy_rps) if policy_rps else default_rps, max_rps)
    if scan == "limited":
        effective = min(effective, float(cfg.get("limited_scanning_rps", 2)))
    if scan == "forbidden":
        effective = min(effective, 1.0)

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
    scope.rules = {
        "automated_scanning": scan,
        "low_automation": scan in ("limited", "forbidden"),
        "policy_rps": policy_rps,
        "effective_rps": effective,
        "required_headers": headers,
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
             f"(policy: {rules.get('policy_rps') or 'not stated'})",
             f"- Required headers: {', '.join(f'{k}: {v}' for k, v in rules.get('required_headers', {}).items()) or 'none'}",
             f"- Self-registration: {rules.get('self_registration')}",
             f"- Researcher email: {rules.get('researcher_email') or rules.get('email_requirement') or 'not required'}",
             "", "## In scope (will be tested)", ""]
    lines += [f"- `{a.raw}` ({a.kind})" for a in scope.in_scope] or ["- none"]
    lines += ["", "## Out of scope (blocked)", ""]
    lines += [f"- `{a.raw}` ({a.kind})" for a in scope.out_of_scope] or ["- none"]
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
