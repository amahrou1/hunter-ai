# hunter-ai methodology build — file-by-file design

Scope after Abdallah's exclusions: **no focus/5-host mode** (manual), **no IDOR/BAC/privesc
phase** (separate authenticated system), **no shopping logic** (separate system). Everything
below is in scope.

Every new phase/playbook uses the **Jhaddix run-contract format** (proven on the depconf
retrofit): a MANDATORY RUN CONTRACT checklist in the first screen, each MUST step ending in a
named artifact, a "read the whole file, it's non-optional once invoked" line, helper scripts
named in the header table, and a completion gate the phase verifies in code (artifact must exist,
like we already do for handoff.md).

---

## 0. Run-contract standard (cross-cutting) — DONE as template on depconf

- `depconf_playbook.md` retrofitted: M1–M6 checklist + artifacts + "read the whole file" + gate.
- Apply the same header to every new playbook below.
- **Code side:** add a tiny `hunter/runcontract.py` helper `artifacts_present(workdir, names)` so a
  phase's `check()` can verify the MUST-step artifacts exist (not just handoff.md). Phases return
  PARTIAL naming the missing artifact. This makes the checklist enforceable, not just advisory.

## 1. `hk unlock` — 403/401 bypass tool (deterministic, code)

- **New:** `hunter/unlock.py` + `hk unlock <url>` subcommand in `kit.py`.
- Tries the jhaddix path-permutation set + header overrides through the **scope proxy** (so it's
  scope-checked and rate-limited like everything else): `//`, `/./`, `/%2e/`, `..;/`, trailing `/`,
  `/%20 /%09 /%00`, `;foo`, `/;/`, case flips (`/ADMIN`), `.json/.xml/.config` suffix; headers
  `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`, `X-Forwarded-Host`.
- Baselines the original status first; reports only permutations that flip 403/401→2xx **and**
  return a materially different body length (avoids soft-404 noise). Output: a table + optional
  `--json`. Records nothing itself; the calling phase decides to `hk add lead`/`finding`.
- **Reused by:** 10-misconfig and the GraphQL/jsintel phases. Respects program rules (read-only GETs).
- **Tests:** permutation set applied; only genuine flips reported; proxy env honored; soft-404 filtered.

## 2. 06c-jsintel — semantic JS analysis phase (agent, run-contract)

- **New:** `hunter/phases/ai_jsintel.py` + `hunter/data/jsintel_playbook.md`, id `06c-jsintel`,
  requires `04-map` (uses 06-js output when present, like depconf). role `intel`.
- **Run contract (artifacts):** `endpoints.txt` (REST, grouped), `graphql-ops.txt` (queries/
  mutations, incl. `grep -Eo '(query|mutation) \w+\('`), `auth.md` (auth/authz mechanisms, token
  builders — the Basic-auth-presence pattern), `hidden.txt` (debug/admin/legacy endpoints),
  `roles.txt` (role strings like ROLE_ADMIN for the authed system to use), `secrets.txt` (via the
  curated detector set, masked), `sinks.txt` (innerHTML/document.write/location/postMessage),
  `uploads.txt`. Each feeds the inventory via `hk add endpoint/lead`.
- Prompt adapted from the page's own "js analysis workflow", wrapped in the run-contract header.
- **Value:** this is the lead-generator for everything else; the $3k Basic-auth bug class lives here.
- **Tests:** phase wiring, version, playbook ships + has run-contract, artifacts enforced in check().

## 3. 07b-authflows — account-logic phase (agent, run-contract)

- **New:** `hunter/phases/ai_authflows.py` + `hunter/data/authflows_playbook.md`, id `07b-authflows`,
  requires `00-intake` + `07-accounts` (needs the temp-mail infra we already wire). role `scanner`.
  Scope note: this is **account/auth logic** (registration, reset, 2FA, OAuth, invite), **not** IDOR/
  object-authz — that's deliberately your separate system.
- **Run contract (MUST steps → leads/findings):**
  - Registration: email-parser abuse (case, `+tag`, `%00/%09/%20`/trailing space,
    `a@x.com@y.com`, `\n`-appended second email), register-over-unverified ATO, FB/Google-login
    no-email linking ATO, UUID→numeric on `/register/<uuid>`.
  - Reset: multi-email (`\n`/array/comma/space/`;`/CC/BCC HPP), token==session-id, host-header
    poisoning of the reset link.
  - 2FA: POST→DELETE on `/mfa/resend`, reset-skips-2FA, expired-code-accepted, sequential recovery
    codes, response-manip (false→true / 403→200) flagged as *client-side-only, verify server-side*.
  - OAuth: `Edit Access`→uncheck-email confusing flow (noted; needs manual FB step → lead only).
- All non-destructive, own accounts, in-scope, rate-limited. Respects program exclusions (if the
  policy excludes a class, skip + note).
- **Tests:** wiring, playbook run-contract, exclusions respected, artifacts enforced.

## 4. 09b-graphql — GraphQL testing phase (agent, run-contract)

- **New:** `hunter/phases/ai_graphql.py` + `hunter/data/graphql_playbook.md`, id `09b-graphql`,
  requires `04-map` (+ uses 06c-jsintel's `graphql-ops.txt`). role `intel`.
- **Run contract:** detect GraphQL endpoints (nuclei graphql-detect or path probe) →
  `gql-endpoints.txt`; introspection probe → `schema.json` if enabled, else pull ops from JS;
  GET-based CSRF test (url-encode query) → lead if it works; field-suggestion/`__typename` probing;
  note (never run) DoS/alias-abuse — **TikTok and many programs exclude DoS**, so it's recorded as a
  caveated lead only. BOLA/authz against mutations is explicitly **deferred to your authed system**.
- **Tests:** wiring, run-contract, DoS-noted-not-executed, exclusion handling.

## 5. `hk cache` — cache poisoning/deception probe (tool + tiny usage in 10-misconfig)

- **New:** `hunter/cachecheck.py` + `hk cache <url>`. Unkeyed-header poisoning probe (X-Forwarded-
  Host/Scheme/Proto, custom headers) checking reflection + `X-Cache: HIT`/`Age`; host-header `:1`/
  `\:1`/`?:1` → cacheable-error (DoS) **detected and reported, never amplified**; deception via
  static-ext suffix on an authed URL (`/account.css`, `/account/;.png?cb=1`) checking whether a
  private response gets cached. Read-only, proxy-routed, cache-buster per request so we never
  actually poison a shared cache beyond a single probed key.
- 10-misconfig prompt gains one header line pointing at `hk cache` for cache-looking responses.
- **Tests:** HIT/Age detection, deception suffixes, DoS-detect-not-amplify, proxy honored.

## 6. VHOST enumeration — into recon (code step + recon prompt line)

- **New:** `hk vhost <ip-or-host>` (or extend recon toolchain): Host-header fuzz a subdomain
  wordlist against discovered IPs, diff response signatures to surface virtual hosts not in DNS.
  Routed through the proxy, rate-limited, capped. Results → `hk add host` (marked vhost-found).
- Recon playbook/prompt gains a MUST step: "after resolving, vhost-enumerate the distinct IPs."
  (You flagged this from the talks notes; it already paid off in the bol free-hunt run.)
- **Tests:** vhost diff logic, scope-check on discovered names, rate cap.

## 7. Secret-scanning upgrade — curated detectors (code, used by dork + jsintel)

- **New:** `hunter/data/secret_detectors.txt` (the page's prefix list + regexes: `ghp_ gho_ glpat-
  sk-proj sk-admin- shpat_ AIza eyJhbGci PMAK- nvapi npm_ 0.0.1-security` …) + a `hk secrets <path>`
  wrapper that runs the curated set (and trufflehog/semgrep if installed) and masks hits to last 4.
- 01b-dork and 06c-jsintel call `hk secrets` instead of ad-hoc regex. Pairs with the provenance
  classifier already shipped.
- **Tests:** detector hits, masking, graceful fallback when trufflehog/semgrep absent.

## 8. Tech-fingerprint → test-pack hints (lightweight, prompt + nuclei sets)

- When probe/fingerprint sees a known tech, surface a targeted hint to the relevant phase:
  Salesforce Lightning (`poc_salesforce_lightning` object-misconfig), Ruby (`.json` authz bypass —
  *noted for your authed system*, not auto-run here), IIS (short-name/debug paths), Swagger (try
  every documented call for a 401-bypass), Grafana/JIRA (CVE template sets). Implemented as a small
  `tech → hint` map injected into the misconfig/jsintel prompt header (one line each), plus curated
  nuclei template dirs. No big prompt growth.
- **Tests:** map lookup, hint injection, no-tech → no hint.

---

## Build order (each = its own commit, tests, version bump)

1. `runcontract.py` helper + depconf gate wired (standard proven).  ← depconf header already done
2. `hk unlock` (tool).
3. `hk secrets` + detectors (tool).
4. `hk vhost` + recon step (tool+recon).
5. `hk cache` (tool) + 10-misconfig line.
6. 06c-jsintel (phase) — depends on nothing new but uses hk secrets.
7. 07b-authflows (phase).
8. 09b-graphql (phase) — uses jsintel output.
9. tech-hint map (prompt polish).

Tools first (2–5) because the phases (6–8) call them. Each lands green with tests; nothing touches
the running TikTok process (all effective next `hunt start`).

## Safety invariants (unchanged, reconfirmed for all the above)

- Everything routes through the scope proxy; `hk unlock/cache/vhost` are read-only GET probes.
- Nothing publishes or runs DoS/smuggling exploits — those stay operator-manual or noted-only.
- Program exclusions honored per phase (DoS, specific vuln classes) from the parsed policy.
- No new network egress hosts needed beyond the #9 allowlist already shipped.
