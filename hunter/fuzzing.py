"""Tech-aware fuzzing: pick the right wordlist and extensions for each asset.

Not every wordlist or extension suits every target. From a service's
fingerprint (server / technology / host), this chooses the wordlists and
extensions a hunter would use for that stack, drawing on the operator's own
lists first (~/myLists), then SecLists, then the small built-in fallback.
"""

from __future__ import annotations

from pathlib import Path

# Where to look for wordlists, in order. Overridable via settings wordlists.dirs.
DEFAULT_DIRS = ["~/myLists", "~/SecLists/Discovery/Web-Content", "~/SecLists/Discovery/Web-Content/api"]

BUILTIN = Path(__file__).resolve().parent / "data" / "discover.txt"

# kind -> candidate filenames, best first; searched across the dirs above.
WORDLISTS: dict[str, list[str]] = {
    "general": ["onelistforallshort.txt", "common-dir-and-pathes.txt", "directory-list-lowercase-2.3-medium.txt",
                "dirsearch.txt", "raft-medium-directories.txt", "common.txt"],
    "big": ["myList.txt", "all.txt", "directory-list-2.3-big.txt", "directory-list-lowercase-2.3-big.txt",
            "raft-large-directories.txt"],
    "aspnet": ["asp.txt", "iis.txt", "IIS.fuzz.txt", "iis-systemweb.txt", "directory-list-lowercase-2.3-medium.txt"],
    "php": ["php.txt", "Common-PHP-Filenames.txt", "PHP.fuzz.txt", "dirsearch.txt"],
    "java": ["jsp.txt", "do.txt", "spring-boot.txt", "tomcat.txt", "ApacheTomcat.fuzz.txt",
             "JavaServlets-Common.fuzz.txt"],
    "wordpress": ["wordpress.txt", "CMS/wordpress.fuzz.txt"],
    "drupal": ["drupal.txt", "CMS/drupal.txt"],
    "aem": ["aem.txt", "AdobeCQ-AEM.txt", "aem2.txt"],
    "api": ["api.txt", "common-api-endpoints-mazen160.txt", "api/api-endpoints.txt", "swagger.txt",
            "oauth-oidc-scopes.txt"],
    "graphql": ["graphql.txt"],
    "coldfusion": ["coldfusion.txt"],
    "params": ["params.txt", "burp-parameter-names.txt", "BurpSuite-ParamMiner/lowercase-headers"],
    "config": ["config.txt"],
}

# kind -> extensions for ffuf -e (no leading dot). "" = directories only.
EXTENSIONS: dict[str, str] = {
    "aspnet": "aspx,asmx,ashx,asp,svc,dll,config,xml,txt,zip,7z,bak,old,json,htm,html,js",
    "php": "php,phtml,php3,php5,phps,inc,bak,old,txt,zip,sql,json,env",
    "java": "jsp,jspx,do,action,java,class,xml,properties,txt,zip,war,yml,yaml",
    "wordpress": "php,txt,bak,old,zip,sql,json",
    "drupal": "php,txt,bak,old,zip,inc,module",
    "aem": "json,xml,html,txt,zip,jsp",
    "coldfusion": "cfm,cfc,cfml,txt,bak,old,zip,xml",
    "api": "json,xml,txt",
    "graphql": "json",
    "general": "txt,bak,old,zip,tar.gz,config,conf,json,xml,sql,log,env,yml,yaml,ini,dll,7z",
}

# Tokens in a service's server/tech/host -> profile. First match wins.
SIGNS: list[tuple[tuple[str, ...], str]] = [
    (("asp.net", "aspnet", "microsoft-iis", "iis", ".net", "kestrel", "x-aspnet"), "aspnet"),
    (("php",), "php"),
    (("tomcat", "java", "servlet", "jboss", "jetty", "spring", "glassfish", "weblogic", "wildfly"), "java"),
    (("coldfusion", "lucee"), "coldfusion"),
    (("wordpress", "wp-"), "wordpress"),
    (("drupal",), "drupal"),
    (("adobe experience", "adobecq", "aem", "/content/dam"), "aem"),
    (("graphql",), "graphql"),
]


def dirs_from(settings: dict) -> list[Path]:
    cfg = (settings.get("wordlists", {}) or {}).get("dirs") or DEFAULT_DIRS
    return [Path(d).expanduser() for d in cfg]


def resolve(kind: str, settings: dict) -> Path | None:
    """First existing wordlist file for a kind, across the configured dirs."""
    dirs = dirs_from(settings)
    for name in WORDLISTS.get(kind, []):
        for base in dirs:
            candidate = base / name
            if candidate.is_file():
                return candidate
    return None


def general(settings: dict) -> Path:
    return resolve("general", settings) or BUILTIN


def detect(server: str = "", tech: str = "", host: str = "", content_type: str = "") -> str:
    """Pick a profile key from a service fingerprint."""
    blob = " ".join((server, tech, content_type)).lower()
    for tokens, key in SIGNS:
        if any(t in blob for t in tokens):
            return key
    if host.lower().split(".")[0] in ("api", "apis", "rest", "graphql") or "json" in content_type.lower():
        return "api"
    return "general"


def plan(settings: dict, server: str = "", tech: str = "", host: str = "",
         content_type: str = "") -> dict:
    """What to fuzz this service with: profile, wordlist path(s), extensions."""
    key = detect(server, tech, host, content_type)
    primary = resolve(key, settings) or general(settings)
    lists = [str(primary)]
    gen = general(settings)
    if str(gen) not in lists:
        lists.append(str(gen))                 # always also run a general pass
    return {"profile": key, "wordlists": lists, "extensions": EXTENSIONS.get(key, EXTENSIONS["general"]),
            "params_wordlist": str(resolve("params", settings) or ""),
            "big_wordlist": str(resolve("big", settings) or "")}
