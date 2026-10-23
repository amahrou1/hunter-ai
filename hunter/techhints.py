"""Tech-fingerprint -> test-pack hints (`hk techhints`).

When probing fingerprints a known technology, there are a few high-yield,
tech-specific checks worth surfacing to the testing phases - one line each, so
the prompt does not grow. This maps a fingerprint keyword (matched against a
service's `server`/`tech`/`title`) to a short hint. The phases call
`hk techhints`, which prints only the hints for technologies actually present
in this target's inventory.

Hints POINT at a check; they do not run anything and never auto-exploit. Where a
hint names an external PoC tool, it is the operator's manual step.
"""

from __future__ import annotations

# keyword (lowercase, matched as a substring of server/tech/title) -> hint.
HINTS: list[tuple[str, str]] = [
    ("salesforce", "Salesforce Sites: check for object misconfig (aura/Lightning) - unauthenticated "
                   "record access is common and high-value. Operator PoC: poc_salesforce_lightning."),
    ("lightning", "Salesforce Lightning/Aura: probe /aura endpoints for exposed objects via getItems/"
                  "RecordUi; result counts >0 often leak data."),
    ("iis", "IIS: try short-name (~) enumeration, /trace.axd, cookieless (S(x)) paths for 403/WAF bypass, "
            "and ViewState if __VIEWSTATE is present."),
    ("asp.net", "ASP.NET: __VIEWSTATE handling (MAC off?), .ashx/.asmx endpoints, trace.axd, and the "
                ".json/.config suffix 403 bypass."),
    ("ruby", "Ruby on Rails: a 401/403 path may open with a `.json` suffix; check for /rails/info and "
             "verbose errors."),
    ("rails", "Rails: `.json` suffix authz bypass, mass-assignment on create/update params, /rails/info."),
    ("wordpress", "WordPress: enumerate plugins (wp-content/plugins), check versions against known CVEs, "
                  "/wp-json/ user enumeration, xmlrpc.php."),
    ("joomla", "Joomla: check com_ components and their versions for known CVEs; /administrator/ exposure."),
    ("grafana", "Grafana: CVE-2021-43798 path traversal on old versions; /public/plugins/<id>/ ; default "
                "admin creds; anonymous org access."),
    ("jira", "Jira: unauthenticated /secure/ endpoints, user/project enumeration, known CVEs by version "
             "(e.g. SSRF/RCE in older builds)."),
    ("swagger", "Swagger/OpenAPI exposed: enumerate EVERY documented call and try each for a 401->200 "
                "bypass; the doc is a free endpoint+param list for the testing phases."),
    ("openapi", "OpenAPI doc exposed: feed every path+param into the testing phases; try undocumented "
                "verbs and the 401-bypass tricks on each."),
    ("citrix", "Citrix: check for known gateway CVEs by version (e.g. path traversal/RCE); /vpn/ paths."),
    ("actuator", "Spring Boot actuator: /actuator/env, /heapdump, /mappings - often leak secrets/config."),
    ("spring", "Spring: check /actuator/*, error-page stack traces, and known Spring4Shell-class CVEs by "
               "version."),
    ("nginx", "nginx: off-by-slash alias traversal (/assets../), merge_slashes, and misrouted internal "
              "locations (X-Accel-Redirect)."),
    ("apache", "Apache: path normalisation/traversal (CVE-2021-41773 class on old 2.4), mod_proxy SSRF, "
               ".htaccess/.htpasswd exposure."),
    ("tomcat", "Tomcat: /manager and /host-manager default creds, examples app, and the AJP ghostcat "
               "class on old versions."),
    ("jenkins", "Jenkins: /script console if reachable, /asynchPeople, user enumeration, old-version RCE "
                "CVEs by build."),
    ("gitlab", "GitLab: version-specific CVEs, open registration, exposed /explore and project "
               "enumeration."),
    ("kibana", "Kibana/Elastic: unauthenticated access to indices, old-version prototype-pollution RCE, "
               "/api/console."),
    ("jwt", "JWT in use: try alg=none, key confusion (RS256->HS256 with the public key), and a weak/"
            "guessable HMAC secret on the token."),
    ("graphql", "GraphQL detected: the 09b-graphql phase covers it - ensure introspection, batching/alias "
                "abuse, field suggestions and GET-CSRF were tested."),
    ("next.js", "Next.js: /_next/ data routes, the image-optimisation SSRF (_next/image?url=), and "
                "exposed getServerSideProps data."),
]


def hints_for(fingerprints: list[str]) -> list[tuple[str, str]]:
    """Given the distinct fingerprint strings present (server/tech/title), return
    (keyword, hint) for each technology detected, de-duplicated."""
    blob = " ".join(fingerprints).lower()
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for keyword, hint in HINTS:
        if keyword in blob and keyword not in seen:
            seen.add(keyword)
            out.append((keyword, hint))
    return out
