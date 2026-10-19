# hunter-ai

Autonomous, policy-bound bug bounty runner for one program at a time.
A Python orchestrator owns the order, state, scope and completion of a run;
AI agents (Claude Code in headless mode, pointed at GLM, DeepSeek or Claude)
are called only for judgment work inside a phase. The system never submits
anything: it produces verified report drafts for manual review.

Design documents live in the Google Drive folder "hunter-ai" (spec 00, setup guide 01).

## Install on the VPS (user `hunter`)

The setup guide in Drive has the one-time deploy-key step. After that:

```bash
git clone git@github-hunter-ai:amahrou1/hunter-ai.git ~/hunter-ai && bash ~/hunter-ai/install.sh
```

Then:

```bash
exec bash -l
hunt setup
hunt doctor
```

## Daily use

```bash
hunt new acme                      # creates ~/targets/acme with template files
nano ~/targets/acme/policy.txt     # paste the program page
hunt start acme                    # runs the whole pipeline in the background (tmux)
hunt start acme --until 03-probe   # run only up to a phase (test phase by phase)
hunt watch acme                    # live view; leave with Ctrl+b then d
hunt status acme                   # phases, live progress with % and time left, blockers
hunt stop acme                     # stop; `hunt start acme` resumes
hunt tell acme "focus api.acme.com"   # steer the run, also while it runs
hunt tell acme                     # list your messages and what they changed
hunt chat acme                     # talk to an AI about what the run found
hunt reset acme 02-recon           # clear a stuck phase so it runs again
hunt findings acme                 # findings so far (by severity) and report drafts
hunt leads acme                    # leads found so far (worth a closer look), by kind
hunt oob                           # your OOB server, blind-XSS collector, temp-mail use
hunt egress http://u:p@host:port   # route target traffic via a residential proxy (off = direct)
hunt scope acme                    # what was read as in scope / out / unclear
hunt scope acme check <url>        # would this URL be allowed?
hunt handle amahrou1               # your platform username (headers, emails)
hunt models use deepseek           # switch provider (glm | deepseek | claude)
hunt update                        # pull and reinstall
```

## Scope guard

Phase 00 has an AI read `policy.txt` into `scope_draft.json`; code then
validates it, rejects any in-scope entry that the policy text does not
actually name (no invented apex domains, no widened wildcards), lets
out-of-scope entries win, applies `scope-overrides.txt`, and writes
`hunt-output/scope.json` plus a readable `scope_review.md`.

Every request to a target goes through a local mitmproxy (`hunter/proxy_addon.py`):
out-of-scope HTTPS is refused at CONNECT (no TLS handshake), out-of-scope HTTP
is answered locally with 403, allowed requests get the policy's required headers
and a global rate limit, and everything is logged to `hunt-output/logs/traffic.jsonl`.
Model APIs and the mailbox API bypass the guard (they are not targets).
The guard proves itself at the end of intake and in `hunt doctor`.

`scope-overrides.txt` lines: `in *.foo.com`, `out admin.foo.com`,
`header X-Bug-Bounty: name`. Saving it during a run restarts the run with the
new scope.

## Steering a run (`hunt tell`, `hunt chat`)

`hunt tell <target> "<message>"` works at any time, from any terminal, also
while the run is going. Always put the message in double quotes. Clear
actions are applied by code and the interpretation is printed back (and sent
to Discord):

| Say | Effect |
|---|---|
| `focus api.acme.com` / `*.acme.com` | tested first in every later phase |
| `add 10.1.2.3` | added to the inventory (scope-checked; out of scope is refused) and probed |
| `avoid admin.acme.com` | never touched; the scope guard blocks it immediately (`avoid.json`) |
| `skip javascript` / `skip phase 6` | that phase does not run (intake, validation, disproof and report cannot be skipped) |
| `unfocus` / `unavoid` / `unskip` | undo |
| `forget 3` | message #3 is no longer shown to the AI |

Plain English works too ("api.acme.com looks juicy, test it harder", "please
add this IP 10.1.2.3", "don't touch admin.acme.com"). Every message, as
written, is also added to the system prompt of every later AI session, so
soft hints reach the testing agents. Nothing can widen the scope.

`hunt chat <target>` opens an interactive Claude session (on the active model)
in the target folder. It reads the run's results and passes your decisions on
with `hunt tell`; it never sends requests to the target itself.

## The pipeline (AI-driven)

`hunt start` runs these phases in order, on its own. Phase 00 (intake) is code:
it has an AI read `policy.txt`, then validates the scope and proves the guard.
Every other phase is an AI agent that decides what to run, reads the results,
adapts, follows leads, and records what it finds.

| Phase | Does | Model tier |
|---|---|---|
| 00-intake | read policy, build scope, prove the guard | (policy reader) |
| 01-intel | past and disclosed reports -> what to focus on | strong |
| 01b-dork-github | GitHub dorking for leaked secrets, classified by who leaked them, validated against the vendor | strong |
| 02-recon | subdomains, DNS, takeover candidates | flash |
| 03-probe | live services, fingerprints, baselines, IP-range port scan | flash |
| 04-map | crawl, endpoints, parameters, JavaScript | flash |
| 05-discover | hidden files and paths, content-checked leads | flash |
| 06-js | endpoints and secrets from JavaScript | flash |
| 06b-depconf | dependency confusion: internal package names vs public registries | strong |
| 07-accounts | supplied or self-registered accounts (owner + low-priv) | strong |
| 08-authz-logic | access control, IDOR/BOLA, logic, GraphQL authz | strong |
| 09-injection | XSS/SQLi/SSRF/SSTI/redirect, AI-feature tests (detect-only) | strong |
| 10-misconfig | CORS, headers, cache, disclosure, exposed services | flash |
| 10b-skills | optional pass over your skill playbooks | strong |
| 10c-hunt | free, goal-driven deep hunt: chains leads into impact | strong |
| 11-validate | re-prove with controls, set severity and CVSS | strong (max) |
| 12-disprove | adversarial second pass -> confirmed or dropped | strong (max) |
| 13-report | house-style drafts; you verify and submit | strong (max) |

Every finding-producing phase (including the optional skills pass and
dependency confusion) runs **before** validate/disprove/report, so anything
they find is validated, disproved and reported - nothing is stranded after the
report.

Change any phase's model with `hunt models role <role> <profile:tier>` (roles:
scanner, prober, mapper, discoverer, jsanalyst, misconfig, intel, accounts,
authz, injection, hunter, validator, disprover, writer).

## Free hunt (the creative capstone)

The structured phases guarantee coverage; they do not improvise. Phase `10c-hunt`
runs after all of them, with the whole picture in hand, and turns the agent
loose: it reads the full inventory, every phase's handoff (including their
"what the next phase should do" to-do lists), your own past `reports.txt`, and
other researchers' `resolved-reports.txt` (the program's bug patterns), decides
where the bugs are, and hunts - with the full toolset (headless browser, OOB,
mail, accounts) and the same scope/rate guards. The goal is to **chain** smaller
issues into real impact, which is where most high bounties actually live.

The known failure of agents like this is laziness - a few minutes of poking then
"no bugs found". Two things fight it:

- **Framing (true, not a quota):** active programs on Intigriti/Bugcrowd take
  valid criticals and highs every day, so the surface almost certainly holds
  findable bugs; a shallow "nothing" is a weak hunter. But the challenge is to
  *effort and creativity*, never a number - a fabricated finding is thrown out
  by the validate/disprove phases and is worse than none.
- **An enforced floor:** the agent logs every hypothesis it tests to
  `hypotheses-tested.md`; `check()` requires a minimum, so a thin log is PARTIAL
  and the hunt simply continues on the next run. Shallow effort does not pass.

Anything it finds flows into `11-validate -> 12-disprove -> 13-report` like any
other finding, so creativity never bypasses proof.

Each phase works through `hk`, the toolkit the agent uses: it reads and writes
the shared inventory (hosts, services, endpoints, leads, findings), imports
tool output, runs the safe built-in checks (port scan, baselines, content
checks, takeover), and reports progress. Every `hk` write is scope-checked.

## Fuzzing (tech-aware)

Content discovery (phase 05) is tuned per asset, not one list for everything.
From each live service's fingerprint, `hk fuzzplan <service-id>` picks the
wordlist(s) and the extensions for that stack (ASP.NET -> aspx/asmx/ashx/svc/
config..., PHP -> php/phtml/inc..., Java -> jsp/do/action..., API -> json), using
your own lists first. Point it at your lists with the `wordlists.dirs` setting
(defaults to `~/myLists` then `~/SecLists`). The agent then follows interesting
hits recursively but with judgement - reading each one for exposed dashboards,
leaks, or WAFs rather than brute-forcing blindly - tries 403 bypasses (including
ASP.NET cookieless tokens), and runs parameter discovery (arjun, or a params
wordlist) on dynamic endpoints, recording the parameters as leads for the
injection and access-control phases. The full method is in
`hunter/data/fuzzing_playbook.md` (the agent reads it via `hk playbook`).

## GitHub dorking (OSINT)

A standalone phase searches GitHub for secrets tied to the target - its org and
its domain - using a dork set (`hunter/data/github_dorks.md`), with your
`GITHUB_TOKEN`. It filters the usual junk (localhost / example / test), then
**classifies each real secret by who leaked it**, because that (not whether the
key is live) decides whether it is reportable:

- leaked from the company's **own org repo** -> finding;
- leaked by a **company employee** and it is an **internal** asset -> finding;
- leaked by a **customer / seller / integrator** (or an employee's own tenant
  key, or anyone whose link to the company is unproven) -> out-of-scope lead.

Only finding-track secrets are **validated** with one minimal read-only call to
their vendor (AWS STS, OpenAI, Anthropic, Stripe, Slack, GitHub, ...); the secret
value is masked, never stored. A third-party/customer credential is recorded as
a masked lead and never validated (that would be touching someone else's
account). Vendors it may call are the `osint.validate_hosts` allowlist. Built as
its own phase so Google/Bing/other dorking can be added later.

## Dependency confusion (supply chain)

A standalone phase (`06b-depconf`) hunts dependency confusion - a high-impact,
widely overlooked bug. It collects the target's internal package names from its
own JavaScript (harvested in `06-js`) and, with a `GITHUB_TOKEN`, from the org's
repo manifests (`package.json`/`.npmrc`, `requirements.txt`/`setup.py`/
`pyproject.toml`, `Gemfile`), then cross-references each name against the public
registry (npm / PyPI / RubyGems). A name the target depends on that is
**unclaimed** publicly - or whose public scope is unclaimed - is a candidate: if
a build resolves the public registry, an attacker-published package of that name
(higher version) runs on the build/dev host (RCE). High-confidence candidates
are recorded as `dependency-confusion` findings with the operator's two-stage
publish+callback PoC (callback -> your OOB host) baked into the steps; weaker
ones become leads. The method is in `hunter/data/depconf_playbook.md` (read via
`hk depconf`).

The system does only the safe half - discover, cross-reference, prove the name
is unclaimed, record, notify. **It never publishes a package:** that is the
exploit step, with a real side effect on the public registry and the target's
builds, so the command checker blocks `npm publish` / `twine upload` /
`gem push` / `npm adduser` / `cargo publish`. You publish the placeholder and
the callback payload by hand, attribute the callback IP (ARIN/RDAP: ignore
cloud/scanner ranges, trust the target's ASN/ISP), and release the name
afterward.

## How safety is enforced (not left to the model)

1. **Scope proxy.** Every request to a target goes through it; out-of-scope
   traffic is blocked at the network layer. Passive data sources and the model
   API bypass it (they are not targets).
2. **Command checker** (a PreToolUse hook): reads each command before it runs
   and blocks out-of-scope hosts, anything that disables the proxy, port
   scanners (use `hk portscan`), brute forcing, publishing a package to a public
   registry (the dependency-confusion exploit step - operator-only), and the
   run's own controls.
3. **Orchestrator:** owns phase order, the rate limit, state, resume and
   completion. Findings only become report drafts after the validate and
   disprove phases both pass them.

## Your testing infrastructure

The agents are given your own out-of-band tools, used only where the program
rules allow:

- **Temporary mailboxes (mail.tm):** for sign-up, password-reset and OTP flows
  and for making attacker/victim accounts. Used only when the program accepts
  any email; when it requires a platform address (@intigriti.me /
  @bugcrowdninja.com), that is used instead.
- **Out-of-band / SSRF listener:** your own server (`hunt oob` shows the
  address). The agent starts a listener on the VPS and points SSRF/XXE/blind
  payloads at it, then confirms the callback from the listener log.
- **Blind XSS:** beacons pointing at your collector, sprayed into input fields,
  parameters and headers (including User-Agent) wherever the agent submits
  input. A callback to your collector is the proof; you watch the collector.
- **Headless browser (`hbrowse`):** a real Chromium that runs *through the scope
  proxy* (so every request it makes is scope-checked, rate-limited, logged and
  uses the residential egress if one is set), for what curl cannot show - DOM /
  client-side XSS, open redirects that land, postMessage and window.name PoCs,
  and authenticated or stored-XSS flows (pass a session cookie). It prints JSON
  (final URL, status, fired JS dialogs = XSS proof, console, OOB callbacks) and
  refuses to run un-proxied. Toggle with the `browser.enabled` setting; installed
  by `install.sh` and reported by `hunt doctor`.

These hosts are not targets: the command checker and proxy allow them while
still blocking everything out of scope. Configure with `hunt oob`.

### Residential egress

Some targets block datacenter IPs at the edge (Akamai 403) or by IP-class rules,
so the whole surface looks closed from the VPS. `hunt egress <url>` routes
**target traffic** out through a residential/upstream HTTP proxy (a provider
endpoint, or your home connection via an SSH tunnel) so the target sees a
residential IP. Only target egress changes - the scope guard, rate limit and
logging still apply, and OOB / model / passive-source hosts always go direct.
`hunt egress off` returns to direct egress.

## Target types

The scope model and the phases work for any program shape:

| Scope | How it is handled |
|---|---|
| `*.example.com` | subdomains discovered (passive), resolved, scope-checked; the apex only if named |
| `example.com` / `all.example.com` | that host only, never expanded |
| URL with path or port | only that path / port is allowed by the guard |
| IP address / CIDR range | built-in TCP connect scan (no root, no libpcap), paced by the program rate; large ranges get fewer ports (reported) |
| "all assets owned by X" | recorded with its quote, never expanded by guessing; the run tests what the policy names plus what you confirm with `in ...` lines, and asks you on Discord |
| mobile apps, source code | listed, not tested yet (reported as gaps) |

## Target folder

| File | Required | Purpose |
|---|---|---|
| policy.txt | yes | Program page: scope, out of scope, rules |
| test-credentials.txt | no | Accounts you created (free text) |
| reports.txt | no | Your past reports (resolved / open) |
| resolved-reports.txt | no | Disclosed reports from other researchers |
| scope-overrides.txt | no | Your corrections: `in x`, `out y`, `header N: v` |
| subdomains.txt, ips.txt | no | Seeds (never scope) |
| an "AI automation" folder | no | A previous run's output (any of: `ai automation`, `ai-automation`, `old-system`, `prior`, ...). Mined for hosts/endpoints/leads/past findings as **reference only** - every agent is told to re-verify it from scratch and never trust its testing. |

Output goes to `<target>/hunt-output/`: `state.db` (source of truth),
`logs/`, `inputs/`, `run_summary.md`.

## Behaviour guarantees

- No approval prompts. Agents run with `claude -p --dangerously-skip-permissions`.
- A blocked item (for example missing accounts) is announced on Discord, the run
  continues, and at the end it waits a limited time for the input before
  listing the item as a gap.
- Resume after crash, reboot or stop. Finished phases are skipped; a phase whose
  code version changed after `hunt update` runs again; a changed policy.txt
  restarts every phase.
- Invalid key or model: the run stops at once with a clear message instead of
  retrying for hours.
- Secrets are stored only in `~/.config/hunter-ai/secrets.env` (mode 600) and
  are redacted from every notification.

## Development

```bash
pytest -q          # uses a fake Claude CLI and a fake Discord server
shellcheck install.sh bin/hunt
```
