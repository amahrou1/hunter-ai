"""The IDOR/BOLA extractor: find every ID-bearing endpoint/param in the
inventory so the authz phase tests each systematically. Extraction is code;
testing is the agent."""

from __future__ import annotations

from hunter import idor


def _row(method, url, params=None, body=None):
    import json
    return {"method": method, "url": url, "params": json.dumps(params or []), "body": body}


def test_numeric_path_id():
    t = idor.path_id_segments("https://api.acme.test/users/123/orders")
    assert any(x["value"] == "123" and x["id_type"] == "numeric" and x["after"] == "users" for x in t)


def test_uuid_and_mongo_and_hex_path_ids():
    assert idor.path_id_segments("https://x.test/doc/550e8400-e29b-41d4-a716-446655440000")[0]["id_type"] == "uuid"
    assert idor.path_id_segments("https://x.test/o/5f1a2b3c4d5e6f7a8b9c0d1e")[0]["id_type"] == "objectid"


def test_query_id_by_name_and_value():
    t = idor.endpoint_id_targets(_row("GET", "https://x.test/view?user_id=5&page=2&ref=abc123def456"))
    params = {x.get("param") for x in t if x["where"] == "query"}
    assert "user_id" in params           # by name
    assert "ref" in params               # by value (looks like a token/hex)
    assert "page" not in params          # a page number named 'page' is not an id target


def test_body_json_ids():
    t = idor.endpoint_id_targets(_row("POST", "https://x.test/transfer", body='{"accountId": 99, "amount": 10}'))
    body_ids = {x["param"] for x in t if x["where"] == "body"}
    assert "accountId" in body_ids
    assert "amount" not in body_ids


def test_form_body_ids():
    t = idor.endpoint_id_targets(_row("POST", "https://x.test/do", body="order_id=7&qty=1"))
    assert any(x["param"] == "order_id" for x in t if x["where"] == "body")


def test_recorded_param_names():
    t = idor.endpoint_id_targets(_row("GET", "https://x.test/api", params=["invoiceId", "q"]))
    names = {x.get("param") for x in t}
    assert "invoiceId" in names and "q" not in names


def test_checklist_dedupes_sibling_ids():
    rows = [_row("GET", "https://x.test/users/1"), _row("GET", "https://x.test/users/2"),
            _row("GET", "https://x.test/users/3/profile")]
    cl = idor.build_checklist(rows)
    # /users/1 and /users/2 collapse to one target; /users/3/profile is a second
    user_targets = [c for c in cl if "/users/" in c["url"] and c["where"] == "path"]
    assert len(user_targets) == 2


def test_no_false_positive_on_plain_paths():
    assert idor.path_id_segments("https://x.test/about/contact/support") == []
    t = idor.endpoint_id_targets(_row("GET", "https://x.test/search?q=hello&sort=asc"))
    assert t == []


def test_graphql_style_variable_name():
    # a recorded param named like a node id is picked up
    t = idor.endpoint_id_targets(_row("POST", "https://x.test/graphql", params=["nodeId"]))
    assert any(x.get("param") == "nodeId" for x in t)
