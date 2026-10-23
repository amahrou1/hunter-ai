"""Extract every ID-bearing endpoint/parameter from the inventory, so the
access-control phase can test each one systematically instead of free-form
(the operator's own IDOR methodology, encoded).

Pure and offline: endpoint rows in, a checklist of (endpoint, id-location) out.
The EXTRACTION is code (deterministic, complete coverage); the TESTING judgment
- is this really cross-user data? - stays with the agent.

An "ID location" is where an object reference sits and could be swapped to reach
another user's / tenant's object:
- a path segment that is a number, UUID, hash, or base64-looking token
  (/users/123, /api/v2/orders/9f3b.../, /doc/aGVsbG8=)
- a query or body parameter named like an id (id, uid, user_id, orderId,
  accountId, ref, key, token, guid, no) or whose value looks like an id
- a GraphQL variable named like an id
"""

from __future__ import annotations

import json
import re
import urllib.parse

# Parameter NAMES that commonly carry an object reference.
_ID_NAME_RE = re.compile(
    r"(?:^|_|\b)(id|uid|guid|uuid|ref|key|no|num|pid|sid|tid|oid|fid|gid)$"
    r"|(?:_id|_uid|_ref|_key|_no|_num|id)$"
    r"|^(user|account|order|invoice|doc|file|object|item|customer|org|tenant|"
    r"group|team|project|message|ticket|card|payment|booking|report|node)(_?id)?$",
    re.I)

# Parameter VALUES that look like an object reference.
_NUMERIC_RE = re.compile(r"^\d{1,19}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX_RE = re.compile(r"^[0-9a-f]{16,64}$", re.I)
_B64_RE = re.compile(r"^[A-Za-z0-9+/_-]{8,}={0,2}$")
_MONGO_RE = re.compile(r"^[0-9a-f]{24}$", re.I)


def _value_is_id(value: str, *, numeric_floor: int = 1000) -> str | None:
    """Return the id-type label if the value looks like an object reference.

    A bare number only counts when it is large enough to be a real id
    (numeric_floor), so a page number or a quantity (page=2, amount=10) is not
    mistaken for an object id. A number named like an id is handled by the
    by-name path, which does not use this floor."""
    v = (value or "").strip()
    if not v or len(v) > 256:
        return None
    if _NUMERIC_RE.match(v):
        return "numeric" if int(v) >= numeric_floor else None
    if _UUID_RE.match(v):
        return "uuid"
    if _MONGO_RE.match(v):
        return "objectid"
    if _HEX_RE.match(v):
        return "hex"
    if _B64_RE.match(v) and len(v) >= 12 and not v.isalpha():
        return "token"
    return None


def _name_is_id(name: str) -> bool:
    return bool(name) and bool(_ID_NAME_RE.search(name))


def path_id_segments(url: str) -> list[dict]:
    """Path segments that look like an object id (/users/123 -> segment '123')."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return []
    out = []
    segs = [s for s in (parts.path or "").split("/") if s]
    for i, seg in enumerate(segs):
        seg_dec = urllib.parse.unquote(seg)
        # In a path, a number right after a resource label (/users/5) is an id
        # even when small - position gives the context a bare query value lacks.
        kind = _value_is_id(seg_dec, numeric_floor=1)
        if kind:
            prev = segs[i - 1] if i > 0 else ""
            out.append({"where": "path", "segment_index": i, "after": prev,
                        "value": seg_dec, "id_type": kind})
    return out


def _params_from_row(row) -> list[str]:
    try:
        return list(json.loads(row["params"])) if row["params"] else []
    except (json.JSONDecodeError, TypeError, KeyError):
        return []


def endpoint_id_targets(row) -> list[dict]:
    """All ID locations in one endpoint row (path segments + query/body params)."""
    url = row["url"] if "url" in row.keys() else row.get("url", "")
    targets = path_id_segments(url)
    # query params from the URL
    try:
        q = urllib.parse.urlsplit(url).query
        for name, value in urllib.parse.parse_qsl(q, keep_blank_values=True):
            if _name_is_id(name) or _value_is_id(value):
                targets.append({"where": "query", "param": name, "value": value,
                                "id_type": _value_is_id(value) or "by-name"})
    except ValueError:
        pass
    # recorded param names (from crawl/js) without values
    for name in _params_from_row(row):
        if _name_is_id(name) and not any(t.get("param") == name for t in targets):
            targets.append({"where": "param", "param": name, "value": "", "id_type": "by-name"})
    # body ids
    body = row["body"] if "body" in row.keys() else row.get("body")
    if body:
        for name, kind in _body_ids(body):
            targets.append({"where": "body", "param": name, "value": "", "id_type": kind})
    return targets


def _body_ids(body: str) -> list[tuple[str, str]]:
    out = []
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            for k, v in data.items():
                if _name_is_id(k) or (isinstance(v, (str, int)) and _value_is_id(str(v))):
                    out.append((k, _value_is_id(str(v)) or "by-name"))
    except (json.JSONDecodeError, TypeError):
        # form-encoded body
        for name, value in urllib.parse.parse_qsl(body, keep_blank_values=True):
            if _name_is_id(name) or _value_is_id(value):
                out.append((name, _value_is_id(value) or "by-name"))
    return out


def build_checklist(rows) -> list[dict]:
    """One checklist entry per (endpoint, id-location). Deduplicated by template
    so /users/1 and /users/2 collapse to one row to test."""
    seen = set()
    checklist = []
    for row in rows:
        method = row["method"] if "method" in row.keys() else row.get("method", "GET")
        url = row["url"] if "url" in row.keys() else row.get("url", "")
        for t in endpoint_id_targets(row):
            key = (method, _template(url), t.get("where"), t.get("param") or t.get("segment_index"))
            if key in seen:
                continue
            seen.add(key)
            checklist.append({"method": method, "url": url, **t})
    return checklist


def _template(url: str) -> str:
    """Collapse id values in the path so siblings dedupe (/users/1 -> /users/{id})."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    segs = []
    for s in (parts.path or "").split("/"):
        segs.append("{id}" if s and _value_is_id(urllib.parse.unquote(s), numeric_floor=1) else s)
    return f"{parts.scheme}://{parts.netloc}{'/'.join(segs)}"
