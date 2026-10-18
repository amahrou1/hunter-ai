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
hunt start acme                    # runs in the background (tmux)
hunt watch acme                    # live view; leave with Ctrl+b then d
hunt status acme                   # phases, live progress with % and time left, blockers
hunt stop acme                     # stop; `hunt start acme` resumes
hunt tell acme "focus api.acme.com"   # steer the run, also while it runs
hunt tell acme                     # list your messages and what they changed
hunt chat acme                     # talk to an AI about what the run found
hunt reset acme 02-recon           # clear a stuck phase so it runs again
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

## Recon and probing

`hunt tools install` downloads subfinder, dnsx, httpx, naabu, katana and ffuf
as released binaries (checksum-verified) into `~/.local/share/hunter-ai/tools`
(no compiler, no sudo). The installer calls it; rerun any time.

Phase 02 (recon) finds subdomains of in-scope wildcards (subfinder, passive),
resolves them (dnsx), scope-checks every result, and classifies each host as
in scope, out of scope, or likely third-party (a CNAME to a SaaS/CDN that pays
nothing, deprioritised). Dangling CNAMEs are flagged as subdomain-takeover
candidates. Phase 03 (probe) finds live HTTP(S) services with httpx, records
status/title/server/tech, and builds a per-host "soft 404" baseline so later
fuzzing can tell real pages from catch-all responses. Probing is incremental:
a resumed run, or a host added with `hunt tell`, only probes hosts not probed yet. All target traffic goes
through the scope proxy. Output: `hosts_in_scope.txt`, `recon.json`,
`services.txt`, `services.json`.

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

## Mapping and discovery

Phase 04 crawls every live in-scope site with katana through the guard (same
host only, robots/sitemap, JavaScript parsing). Forms are recorded, never
submitted. Output: `endpoints.txt`, `params.txt` (interesting names marked),
`js_files.txt`.

Phase 05 searches each site for unlinked paths with ffuf and a curated
built-in list (`hunter/data/discover.txt`; your own via settings
`discover.wordlist`). Catch-all pages are dropped using ffuf calibration plus
the phase-03 baselines. Sensitive hits (`.git`, `.env`, API docs, actuator,
backups, ...) are checked by content before they become a lead; secret values
are never copied into notifications or logs. Output: `discovered.txt`,
`leads.txt`.

Both phases go highest priority first (your `focus` hosts first), save
progress per site, skip dead upstreams, uniform gates and duplicate schemes,
and have a time budget (settings `crawl` / `discover`: `minutes_per_site`,
`max_hours`); what is left is reported and picked up on the next start.

Takeover candidates from recon get a second look in phase 03: kept only if the
CNAME target no longer resolves or the provider shows its "nothing here"
page; hosts serving a live page (including a password page) are cleared.

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
