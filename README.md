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
| 01b-dork-github | GitHub dorking for leaked secrets, validated against the vendor | strong |
| 02-recon | subdomains, DNS, takeover candidates | flash |
| 03-probe | live services, fingerprints, baselines, IP-range port scan | flash |
| 04-map | crawl, endpoints, parameters, JavaScript | flash |
| 05-discover | hidden files and paths, content-checked leads | flash |
| 06-js | endpoints and secrets from JavaScript | flash |
| 07-accounts | supplied or self-registered accounts (owner + low-priv) | strong |
| 08-authz-logic | access control, IDOR/BOLA, logic, GraphQL authz | strong |
| 09-injection | XSS/SQLi/SSRF/SSTI/redirect, AI-feature tests (detect-only) | strong |
| 10-misconfig | CORS, headers, cache, disclosure, exposed services | flash |
| 11-validate | re-prove with controls, set severity and CVSS | strong (max) |
| 12-disprove | adversarial second pass -> confirmed or dropped | strong (max) |
| 13-report | house-style drafts; you verify and submit | strong (max) |
| 14-skills | optional pass over your skill playbooks | strong |

Change any phase's model with `hunt models role <role> <profile:tier>` (roles:
scanner, prober, mapper, discoverer, jsanalyst, misconfig, intel, accounts,
authz, injection, validator, disprover, writer).

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
`GITHUB_TOKEN`. It filters the usual junk (localhost / example / test) and
**validates** a real secret with one minimal read-only call to its vendor (AWS
STS, OpenAI, Anthropic, Stripe, Slack, GitHub, ...) before recording it as a
finding; the secret value is masked, never stored. Vendors it may call are the
`osint.validate_hosts` allowlist (extend it in settings); a secret for a vendor
not on the list is recorded unvalidated for you to check. Built as its own phase
so Google/Bing/other dorking can be added later.

## How safety is enforced (not left to the model)

1. **Scope proxy.** Every request to a target goes through it; out-of-scope
   traffic is blocked at the network layer. Passive data sources and the model
   API bypass it (they are not targets).
2. **Command checker** (a PreToolUse hook): reads each command before it runs
   and blocks out-of-scope hosts, anything that disables the proxy, port
   scanners (use `hk portscan`), brute forcing, and the run's own controls.
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

These hosts are not targets: the command checker and proxy allow them while
still blocking everything out of scope. Configure with `hunt oob`.

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
