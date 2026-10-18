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
hunt status acme                   # phases, blockers, AI usage
hunt stop acme                     # stop; `hunt start acme` resumes
hunt models use deepseek           # switch provider (glm | deepseek | claude)
hunt update                        # pull and reinstall
```

## Target folder

| File | Required | Purpose |
|---|---|---|
| policy.txt | yes | Program page: scope, out of scope, rules |
| test-credentials.txt | no | Accounts you created (free text) |
| reports.txt | no | Your past reports (resolved / open) |
| resolved-reports.txt | no | Disclosed reports from other researchers |
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
