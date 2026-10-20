# JavaScript intelligence — deep semantic analysis (read this first)

<!-- ===================== MANDATORY RUN CONTRACT ===================== -->
<!-- If this phase is running you MUST read this whole file and do every MUST
     step. 06-js already collected the files and pulled obvious endpoints; THIS
     phase reads the JS for MEANING - the things a grep misses that turn into
     real bugs: auth mechanisms, roles, hidden/admin endpoints, GraphQL ops,
     secrets, dangerous sinks. Each MUST step ends in an artifact; a summary
     instead of the artifact is a FAILURE. -->

## RUN CONTRACT — complete every MUST (artifacts in ./ of your work dir)

- [ ] **M1 Endpoints**: every REST endpoint referenced in the JS, grouped by
      function (auth, admin, user, payment, upload, internal). Add in-scope ones
      with `hk add endpoint`. → artifact: `endpoints.txt`
- [ ] **M2 GraphQL ops**: query/mutation/subscription names and shapes
      (`grep -Eo '(query|mutation|subscription) \w+\('` plus operation strings).
      → artifact: `graphql-ops.txt`
- [ ] **M3 Auth mechanism**: how the app authenticates - token builders
      (e.g. an `Authorization: Basic btoa(user+':'+pass)` constructor, a bearer
      from storage), where tokens live, any "presence-only" check. → `auth.md`
- [ ] **M4 Hidden/admin/debug/legacy endpoints**: routes gated client-side,
      feature flags, `/debug`, `/internal`, admin-only calls, old API versions.
      Record as leads. → artifact: `hidden.txt`
- [ ] **M5 Roles**: role/permission strings (ROLE_ADMIN, isAdmin, scopes) for
      the authenticated-testing phase to use later. → artifact: `roles.txt`
- [ ] **M6 Secrets**: run `hk secrets <jsdir>` over the downloaded bundles;
      record real ones as `hk add lead secret-in-js <js-url> --evidence "<kind>"`
      (KIND ONLY, never the value). → artifact: `secrets.txt` (kinds + file, masked)
- [ ] **M7 Sinks**: dangerous client-side sinks and their sources - innerHTML,
      document.write, `location`/`location.hash`, `postMessage` handlers,
      `window.name`, `eval`, `setTimeout(string)` - as DOM-XSS leads for the
      injection phase. → artifact: `sinks.txt`
- [ ] **M8 Completion gate**: write ./handoff.md grouping what you found and
      naming the 10 highest-value threads for the testing phases. Only after
      M1–M7. If you run low on turns, stop WITHOUT handoff.md (you resume).
<!-- =================== END MANDATORY RUN CONTRACT =================== -->

## How to work

Reuse what 06-js already downloaded (see `hk handoff` for 06-js and its work
dir); fetch a missing bundle with curl through the proxy. Do NOT re-crawl.

Reading minified JS: beautify first where it helps (`npx prettier` or a simple
reformat), then read for MEANING, not just patterns. The high-value things:

- **Adjacent/staging/api domains** left in strings → add in-scope ones as hosts.
- **Paths** (`"/api/..."`, route tables) — note required prefixes.
- **HTTP methods + JSON body shapes** near a call — they reveal parameters and
  optional fields the UI never sends (mass-assignment / hidden-param leads).
- **Auth logic** — trace how the `Authorization` header is built. A header built
  from "presence" rather than a validated credential is the classic bug
  (sending just `Authorization: Basic` can bypass a backend that only checks the
  header exists). Record exactly how it is constructed in `auth.md`.
- **Roles** — any `admin`/`premium`/`ROLE_*`/scope string. Client-side role
  gates often hide server-side-unenforced functionality.
- **Sinks** — a user-controllable source (`location.hash`, `postMessage.data`,
  `window.name`, a query param) flowing into a sink is a DOM-XSS lead.
- **GraphQL** — operation names and variable shapes, especially when
  introspection is off; these feed the GraphQL phase.

## Recording

- In-scope endpoints → `hk add endpoint <METHOD> <url>`.
- Everything else of value → `hk add lead <kind> <url> --evidence "..."` with a
  precise kind: `hidden-endpoint`, `auth-mechanism`, `dom-sink`, `graphql-op`,
  `role-string`, `secret-in-js`, `adjacent-host`.
- Secrets: `hk secrets` first, then record by KIND only — never a value.

Everything you record is scope-checked and feeds the testing phases. This phase
does NOT exploit anything; it produces the map that makes the testing phases
sharp.
