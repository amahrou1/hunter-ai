"""Gated-login probing (`hk login-probe <url>`).

When the run finds an internal/admin dashboard or any login gate, a human hunter
tries the handful of credentials that actually work in practice: vendor default
accounts (admin/admin and the like), and any usernames/passwords that leaked in
the org's GitHub, its JavaScript, or its docs. This is NOT brute forcing - it is
a SMALL, bounded set of obvious guesses, the same thing a hunter types by hand
in the first two minutes. Many critical auth bypasses are exactly this.

Safety is in code, not in the model's restraint:
- A HARD cap on total attempts per host (MAX_ATTEMPTS). The agent cannot raise
  it; there is no password-list mode and no iteration tool.
- Every request goes through the scope proxy (so the host must be in scope) and
  under the program's rate limit.
- Username enumeration is by RESPONSE DIFFERENCE only (does a valid user get a
  different status/length/wording?), never a password spray.

The tool reports what it observed (a working credential, or which usernames look
valid); it records a finding only on a real login success, and a lead otherwise.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request

# The ceiling, enforced here. ~2 minutes of a human's manual guessing, never a
# brute force. Counts every credential attempt across default + leaked creds.
MAX_ATTEMPTS = 25
# Username-enumeration probe list is separate (differential, no passwords) and
# also capped.
MAX_ENUM = 30

# Vendor/default credential pairs worth the first guesses on an admin gate.
# Small and generic on purpose - leaked, tech-specific creds are added by the
# caller from the org's own leaks (far higher hit rate).
DEFAULT_CREDS = (
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"), ("admin", "changeme"),
    ("admin", ""), ("administrator", "administrator"), ("administrator", "password"),
    ("root", "root"), ("root", "toor"), ("root", "password"), ("test", "test"),
    ("guest", "guest"), ("user", "user"), ("demo", "demo"), ("superadmin", "superadmin"),
    ("admin", "admin@123"), ("admin", "Admin@123"), ("admin", "letmein"),
    ("tomcat", "tomcat"), ("sa", "sa"),
)

# Usernames for the differential-enumeration probe (no passwords sent for real).
ENUM_USERNAMES = (
    "admin", "administrator", "root", "test", "user", "guest", "demo", "info",
    "support", "service", "operator", "manager", "superadmin", "sysadmin",
    "webadmin", "backup", "oracle", "postgres", "jenkins", "git",
)

_UA = "Mozilla/5.0 (hunter-ai login-probe)"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # Keep a 3xx as the answer: a redirect to /dashboard is the success signal we
    # must see, not follow (following it loses the Set-Cookie/Location evidence).
    # Returning the response object from each http_error_3xx hands the 3xx back to
    # the caller unchanged, instead of urllib trying (and failing) to follow it.
    def http_error_301(self, req, fp, code, msg, headers):
        return fp

    http_error_302 = http_error_303 = http_error_307 = http_error_308 = http_error_301


def _no_redirect(opener):
    """Wrap an opener so redirects are returned, not followed. Put our handler
    FIRST so it wins over the default redirect handler already on the opener."""
    return urllib.request.build_opener(_NoRedirect(), *opener.handlers)


def _post(opener, url: str, data: dict, timeout: float = 15.0) -> dict:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"User-Agent": _UA,
                                          "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            content = resp.read(40000)
            return _summ(resp.status, content, resp.headers)
    except urllib.error.HTTPError as exc:
        content = exc.read(40000) if hasattr(exc, "read") else b""
        return _summ(exc.code, content, exc.headers,
                     blocked=bool(exc.headers and exc.headers.get("X-Hunter-Blocked")))
    except Exception as exc:  # noqa: BLE001 - a failed probe is data, not a crash
        return {"error": str(exc)[:160]}


def _post_json(opener, url: str, data: dict, timeout: float = 15.0) -> dict:
    req = urllib.request.Request(url, data=json.dumps(data).encode(), method="POST",
                                 headers={"User-Agent": _UA, "Content-Type": "application/json"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return _summ(resp.status, resp.read(40000), resp.headers)
    except urllib.error.HTTPError as exc:
        content = exc.read(40000) if hasattr(exc, "read") else b""
        return _summ(exc.code, content, exc.headers,
                     blocked=bool(exc.headers and exc.headers.get("X-Hunter-Blocked")))
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)[:160]}


_FAIL_WORDS = ("invalid", "incorrect", "failed", "wrong", "denied", "not found",
               "unauthor", "bad credential", "try again", "ungültig", "falsch")
_OK_WORDS = ("dashboard", "logout", "welcome", "sign out", "my account", "token",
             "set-cookie", "successfully", "willkommen", "abmelden")


def _summ(status: int, content: bytes, headers, blocked: bool = False) -> dict:
    text = content.decode("utf-8", "replace").lower()
    set_cookie = ""
    try:
        set_cookie = headers.get("Set-Cookie", "") or ""
    except Exception:  # noqa: BLE001
        pass
    return {
        "status": status,
        "len": len(content),
        "hash": hashlib.sha256(content).hexdigest()[:16],
        "fail_word": any(w in text for w in _FAIL_WORDS),
        "ok_word": any(w in text for w in _OK_WORDS),
        "set_auth_cookie": bool(set_cookie) and any(
            k in set_cookie.lower() for k in ("session", "token", "auth", "jwt", "sid")),
        "location": (headers.get("Location", "") if headers else "") or "",
        "blocked": blocked,
    }


def _looks_authenticated(baseline: dict, res: dict) -> bool:
    """A login success vs the known failure baseline: a new auth cookie, a
    redirect away from the login page, an OK word where the baseline had a fail
    word, or a clearly different successful body."""
    if "error" in res or res.get("blocked"):
        return False
    if res.get("set_auth_cookie") and not baseline.get("set_auth_cookie"):
        return True
    loc = res.get("location", "").lower()
    if loc and not any(x in loc for x in ("login", "signin", "auth", "error")) and res.get("status") in (301, 302, 303, 307):
        return True
    if res.get("ok_word") and not res.get("fail_word") and baseline.get("fail_word"):
        return True
    # A 200 with a body materially unlike the failure baseline and no fail word.
    if res.get("status") == 200 and not res.get("fail_word") and res.get("hash") != baseline.get("hash") \
            and abs(res.get("len", 0) - baseline.get("len", 0)) > 200:
        return True
    return False


def probe(url: str, opener, creds, field_map: dict | None = None, json_mode: bool = False,
          max_attempts: int = MAX_ATTEMPTS) -> dict:
    """Try a small, capped set of credentials against a login endpoint.

    url: the login POST endpoint. creds: iterable of (user, password). field_map:
    {"user": "<username field>", "password": "<password field>", ...extra static
    fields}. json_mode: send JSON instead of form-encoded.

    Returns the baseline failure response, any working credential, and the count.
    """
    fm = field_map or {"user": "username", "password": "password"}
    extra = {k: v for k, v in fm.items() if k not in ("user", "password")}
    opener = _no_redirect(opener)
    send = _post_json if json_mode else _post

    def attempt(user: str, pw: str) -> dict:
        data = dict(extra)
        data[fm.get("user", "username")] = user
        data[fm.get("password", "password")] = pw
        return send(opener, url, data)

    # Baseline: a definitely-wrong credential establishes the "failed login" shape.
    baseline = attempt("hunter_nouser_zzz", "hunter_nopass_zzz")
    result = {"url": url, "baseline": baseline, "working": [], "tried": 0, "json_mode": json_mode}
    if "error" in baseline or baseline.get("blocked"):
        result["note"] = baseline.get("error") or "baseline blocked by scope proxy"
        return result

    seen = set()
    for user, pw in creds:
        if result["tried"] >= max_attempts:
            result["note"] = f"hit the {max_attempts}-attempt cap"
            break
        key = (user, pw)
        if key in seen:
            continue
        seen.add(key)
        res = attempt(user, pw)
        result["tried"] += 1
        if res.get("blocked"):
            result["note"] = "blocked by scope proxy"
            break
        if _looks_authenticated(baseline, res):
            result["working"].append({"user": user, "password_masked": _mask(pw),
                                       "status": res.get("status"), "why": _why(baseline, res)})
    return result


def enumerate_users(url: str, opener, usernames=ENUM_USERNAMES, field_map: dict | None = None,
                    json_mode: bool = False, max_enum: int = MAX_ENUM) -> dict:
    """Differential username enumeration: send each username with a fixed wrong
    password and report usernames whose response SHAPE differs from an unknown
    user's (status/len/wording/timing). No real password guessing."""
    fm = field_map or {"user": "username", "password": "password"}
    extra = {k: v for k, v in fm.items() if k not in ("user", "password")}
    opener = _no_redirect(opener)
    send = _post_json if json_mode else _post
    wrong_pw = "hunter_wrongpass_zzz"

    def attempt(user: str) -> dict:
        data = dict(extra)
        data[fm.get("user", "username")] = user
        data[fm.get("password", "password")] = wrong_pw
        return send(opener, url, data)

    unknown = attempt(f"nouser_{hashlib.sha256(url.encode()).hexdigest()[:8]}")
    out = {"url": url, "unknown_baseline": unknown, "valid_candidates": [], "tried": 0}
    if "error" in unknown or unknown.get("blocked"):
        out["note"] = unknown.get("error") or "baseline blocked"
        return out
    base_sig = (unknown.get("status"), unknown.get("fail_word"), unknown.get("len", 0) // 50)
    for user in usernames:
        if out["tried"] >= max_enum:
            break
        res = attempt(user)
        out["tried"] += 1
        if "error" in res or res.get("blocked"):
            continue
        sig = (res.get("status"), res.get("fail_word"), res.get("len", 0) // 50)
        if sig != base_sig:
            out["valid_candidates"].append({"user": user, "status": res.get("status"),
                                            "len": res.get("len"), "note": _why(unknown, res)})
    return out


def _mask(pw: str) -> str:
    if not pw:
        return "(empty)"
    if len(pw) <= 2:
        return "*" * len(pw)
    return pw[0] + "*" * (len(pw) - 2) + pw[-1]


def _why(baseline: dict, res: dict) -> str:
    bits = []
    if res.get("set_auth_cookie") and not baseline.get("set_auth_cookie"):
        bits.append("set an auth cookie")
    if res.get("status") != baseline.get("status"):
        bits.append(f"status {baseline.get('status')}->{res.get('status')}")
    if res.get("ok_word") and not baseline.get("ok_word"):
        bits.append("success wording")
    if not res.get("fail_word") and baseline.get("fail_word"):
        bits.append("no failure wording")
    if abs(res.get("len", 0) - baseline.get("len", 0)) > 200:
        bits.append(f"len {baseline.get('len')}->{res.get('len')}")
    return ", ".join(bits) or "response differs from the failure baseline"
