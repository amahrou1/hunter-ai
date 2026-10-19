# GitHub dorking for leaked secrets (org + domain)

Find the target's GitHub presence, search for leaked credentials and secrets,
then VALIDATE the real ones before reporting. Most hits are junk (test/example/
localhost) - filter those out and only report what you can prove is live.

## 1. Find the org and identifiers
- The target domain(s) from `hk scope` (e.g. example.com) and the program name.
- Find the GitHub org: GET https://api.github.com/search/users?q=<company>+type:org
  and check the org's blog/website matches the domain. Note the org login (e.g.
  "exampleinc"). Also search by the bare domain. Use both org: and the domain.

## 2. Search (GitHub code search REST API)
Authenticated: add  -H "Authorization: Bearer $GITHUB_TOKEN"  -H "Accept: application/vnd.github+json"
  curl -s -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" \
    "https://api.github.com/search/code?q=<URL-ENCODED-QUERY>&per_page=50"
Code search is rate-limited (~10/min) - pace yourself, read the handoff, and
page results. Pull the file, then fetch its raw content to inspect the secret in
context.

Run these dork queries, substituting {org} and {domain}:
- org:{org} "password"          org:{org} "DB_USERNAME"        org:{org} "DATABASE_URL"
- org:{org} "eyJ"              (JWT)    org:{org} "ssh-rsa AAA"     org:{org} "-----BEGIN"
- org:{org} "AWS_ACCESS_KEY_ID"   org:{org} "aws_secret_access_key"   org:{org} "AKIA"
- org:{org} "CLIENT_SECRET"       org:{org} "api_key"      org:{org} "token" "secret" "password"
- org:{org} path:.env            org:{org} path:*.yml "password"      org:{org} path:*.yaml "_key"
- org:{org} path:.pem private     org:{org} path:.ppk private    org:{org} path:/credentials
- org:{org} path:/settings.py     org:{org} path:/database.yml  org:{org} "mongolab.com"
- "{domain}" "password"          "{domain}" "Authorization: Bearer"   "{domain}" "AWS_ACCESS_KEY_ID"
- "{domain}" "eyJ"               "@{domain}" "password"
- Subdomain mining (bonus): /.+\.{domain}/  to pull new hostnames from code; feed them to recon with hk.
Use the operator's extra dorks in this file too, and vary language: and path: filters.

## 3. Filter the junk (most hits are NOT valid)
Discard a hit when the surrounding code or repo says it is not real:
- host/URL is localhost, 127.0.0.1, example.com, test, sample, demo, changeme,
  "your-...-here", placeholder, dummy, xxxx, <...>.
- credentials like admin/admin, user/password, foo/bar in an example/test file,
  a README, a tutorial, fixtures, or a repo described as a demo/test project.
- clearly a public/sample key (Stripe's pk_test_, documented example tokens).
Keep hits that look real and tied to the target (its org, its domain, its infra).

## 3b. Classify by WHO leaked it (this decides scope, not whether it is live)
A live secret is reportable only when the TARGET is responsible for the leak.
Establish the repo owner with read-only OSINT (profile company/bio/email, org
membership, commit-author domain):
- company-org   : repo is under the target's official GitHub org(s)        -> FINDING
- company-person: owner is provably a target employee/affiliate, AND the
                  secret is an INTERNAL asset (infra/CI/service account/db/
                  cloud/signing/admin, or cross-tenant access)             -> FINDING
- company-person + the person's OWN customer/tenant key (e.g. a retailer/
                  affiliate OAuth client_id+secret scoped to one account)  -> LEAD (out of scope)
- third-party   : a customer / seller / affiliate / integrator, or anyone
                  whose link to the company you cannot prove               -> LEAD (out of scope)
Default to third-party whenever affiliation is unproven - never guess someone
into company-person. Out-of-scope leaks are recorded masked with
`hk add lead leaked-secret-thirdparty <url> --evidence "..."` and are NOT
validated or used; a courtesy heads-up to the company to revoke may be noted.

## 4. Validate before reporting (minimal, read-only)
Validate ONLY finding-track secrets (company-org, or company-person internal).
Only validate a secret whose vendor host is in the allowed validation list
(HUNTER_VALIDATE_HOSTS; a not-allowed vendor -> record the secret UNVALIDATED for
manual check, do not hit an arbitrary host). Make ONE minimal, read-only call that
only proves the key is live - never read or change data beyond that:
- AWS key: curl to https://sts.amazonaws.com/?Action=GetCallerIdentity (SigV4) or
  note it for manual aws sts get-caller-identity. A 200 identity = live.
- OpenAI/Anthropic/SendGrid/Stripe/Slack/etc.: the vendor's "who am I" / list
  endpoint with the key, e.g. GET https://api.openai.com/v1/models,
  GET https://api.anthropic.com/v1/models, GET https://slack.com/api/auth.test,
  GET https://api.stripe.com/v1/account, GET https://api.github.com/user.
- GitHub token: GET https://api.github.com/user (shows scopes).
A live, non-expired secret on the FINDING track (per 3b) is a finding. Record it with
`hk finding add --kind leaked-secret --severity <high/critical by impact>
--url <github file url> --summary "<secret type> for <service> leaked in <repo>"
--steps "where it was found + the one validation call and its result (mask the
secret value)" --impact "<what it grants>"`. NEVER paste the secret value - mask
it (last 4 chars only). A valid DB credential: confirm it authenticates with a
single connect, nothing more; do not read tables.

## 5. Scale later
This phase is GitHub only for now; Google/Bing/GitLab dorking can be added as
more steps here without changing the rest of the pipeline.

## Operator's dork set (use these too, {org}/{domain} substituted)
- /ssh:\/\/.*:.*@.*{domain}/        /ftp:\/\/.*:.*@.*{domain}/
- /.+\.{domain}/ NOT *.{domain} NOT {domain}     (subdomains)
- "base64" AND ("==" OR "END" OR "begin")        "base64" AND ("token" OR "secret")
- "eyJhbGciOiJ" language:json       path:.env ("=" AND "eyJ")
- language:yml "_key"   language:yml "admin"   language:yml "root"   language:yml "host"
- {domain} "AWS_ACCESS_KEY_ID:"    {domain} language:js password    {domain} "Authorization: Bearer"
- org:{org} password DB_USERNAME    org:{org} "eyJ"    org:{org} "ssh-rsa AAA"
- org:{org} path:*.* "mysql_password" AND "mysql_username"     org:{org} "azuread_login_username"
- org:{org} "DATABASE_URL"   org:{org} "HF_TOKEN"   org:{org} path:*.* "credentials"
- org:{org} path:*.* "password": "admin" AND "user": "admin"   (then VALIDATE - usually junk)
- path:/database.yml host NOT test NOT sample NOT localhost NOT example NOT 127.0.0.1
- path:.pem private   path:.ppk private   path:.sql mysql dump password
- path:.ica [WFClient] Password=   path:.json googleusercontent client_secret
- shodan_api_key language:python   path:.json mongolab.com
