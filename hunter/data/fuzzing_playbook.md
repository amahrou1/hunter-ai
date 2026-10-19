# Fuzzing playbook (how a hunter fuzzes, applied per asset)

Fuzzing is where many bugs are found, but only with the right wordlist and the
right extensions for THAT asset, and by following and judging what you find -
not blind brute force.

## 1. Pick list + extensions per asset (do this per service)
Run `hk fuzzplan <service-id>` - it reads the service's server/tech and returns
the right wordlist(s), the extensions to use, and the params wordlist. It draws
on the operator's lists (~/myLists) first, then SecLists, then a built-in list.
You can also ask directly: `hk wordlist --kind aspnet|php|java|api|general|big`,
`hk wordlist --extensions aspnet`, `hk wordlist --list`.

Guidance by stack (fuzzplan encodes this; use it when choosing manually):
- ASP.NET / IIS: lists asp.txt, iis.txt, IIS.fuzz.txt, directory-list-lowercase-2.3-medium.
  extensions: aspx,asmx,ashx,asp,svc,dll,config,xml,txt,zip,7z,bak,old,json,htm,html,js
  Fuzz these dirs too: WebServices/ , xml/ , obj/ , OBJ/Debug , bin/ .
  Juicy to try by name: appsettings.json, Web.config, WebConfig.txt, web.dll,
  api.zip, wwwroot.zip, bin.7z, Service1.svc, *.asmx, *.ashx, Config.xml, Export.zip.
- PHP: php.txt, Common-PHP-Filenames.txt. extensions: php,phtml,php3,php5,inc,bak,old,txt,zip,sql,json,env
- Java/Tomcat/Spring: jsp.txt, spring-boot.txt, tomcat.txt. extensions: jsp,jspx,do,action,xml,properties,war,txt,zip
  Spring: also /actuator, /actuator/env, /actuator/heapdump. Tomcat: /manager/html, /host-manager/html.
- WordPress/Drupal/AEM: wordpress.txt / drupal.txt / aem.txt with their extensions.
- API / JSON host: api.txt, common-api-endpoints, swagger.txt; extension json; look for
  /swagger.json, /openapi.json, /v2/api-docs, /graphql, /.well-known/.
- Unknown: general list + extensions txt,bak,old,zip,config,json,xml,sql,env,yml.
Always run a general pass in addition to the stack-specific one. On a high-value
host, do a second deeper pass with `hk wordlist --kind big` (large list).

## 2. Recurse, but EVALUATE every interesting hit (do not brute blindly)
When you find a directory or endpoint that looks interesting (admin, dashboard,
internal, api, backup, upload, config, a 401/403 gate, an unusual 200), do NOT
just keep fuzzing deeper mechanically. For each one:
- Fetch it through the proxy and read the response and the HTML/JS source.
- Judge it: is it an internal dashboard or admin panel reachable WITHOUT auth?
  does it leak sensitive data, tokens, internal hostnames, or a stack trace?
  is it a login/gate worth auth testing later? is it a WAF/block page? or is it
  useless (marketing, redirect, empty)? Record a finding or lead accordingly;
  skip the useless ones.
- Then, only if it is worth it, fuzz one level deeper (e.g. /admin -> /admin/FUZZ)
  with the same stack list+extensions. Go at most 2-3 levels, and stop a branch
  that turns into noise or a WAF wall.
- If a path 403s, it may still be reachable. For ASP.NET/IIS try cookieless
  tokens to bypass path rules: /admin/(S(x))/main.aspx , /(S(x))/admin/main.aspx ,
  /admin/foo/(S(x))/../(S(x))/main.aspx . For others, try case changes, a
  trailing slash or %2e, and path-normalisation tricks. Note bypasses as findings.

## 3. Parameters on dynamic endpoints (feeds the injection phase)
When a hit is a dynamic endpoint (ends in .php/.aspx/.ashx/.jsp/.do or is an API
route), look for hidden parameters:
- Use `arjun -u <url>` if arjun is installed; otherwise fuzz param names with the
  params wordlist from fuzzplan: `ffuf -u '<url>?FUZZ=1' -w <params> -ac` and watch
  for response-size/status changes.
- Record each endpoint+params as a lead (`hk add lead parameters <url> --evidence
  "params: id, authenticated, debug, role"`) so the injection and authz phases
  test them.
- Flag obviously dangerous params yourself: a boolean like authenticated=,
  isAdmin=, debug=, test= - try flipping false->true / 0->1 and see if access or
  behaviour changes (that is a BAC/logic candidate -> `hk finding add`). A param
  that looks like a file path, url, id, or query is an injection candidate (LFI,
  SSRF, IDOR, SQLi) for phase 09 - record it as a lead, do not exploit destructively.

## 4. Stay safe
Everything goes through the scope proxy at the program's rate. Use the baselines
and `hk filter` to drop catch-all noise. Minimal, non-destructive proof only.
