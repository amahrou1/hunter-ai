"""07c-map-auth: logs in and maps the authenticated surface, feeding 08-authz.
A no-op (instant DONE) when there are no accounts."""

from __future__ import annotations

from types import SimpleNamespace

from hunter import assets as A
from hunter import state as st
from hunter.phases import PhaseResult
from hunter.phases.ai_map_auth import AIMapAuthPhase


def _ctx(tmp_path, creds_text=""):
    out = tmp_path / "out"; out.mkdir(parents=True, exist_ok=True)
    store = A.Assets(st.State(out / "state.db").db)
    target = SimpleNamespace(
        output=out, scope_file=out / "scope.json",
        input_text=lambda name: creds_text if name == "test-credentials.txt" else "",
    )
    return SimpleNamespace(target=target, assets=lambda: store, _store=store)


def test_no_accounts_is_instant_done(tmp_path):
    ctx = _ctx(tmp_path, creds_text="")
    phase = AIMapAuthPhase()
    assert phase._has_accounts(ctx) is False
    res = phase.run(ctx)
    assert res.status == st.DONE and "no accounts" in res.summary


def test_comment_only_credentials_is_no_op(tmp_path):
    ctx = _ctx(tmp_path, creds_text="# label | email | password | notes\n# fill me in\n")
    assert AIMapAuthPhase()._has_accounts(ctx) is False


def test_real_account_is_detected(tmp_path):
    ctx = _ctx(tmp_path, creds_text="admin | admin@acme.test | Pw123! | owner\n")
    assert AIMapAuthPhase()._has_accounts(ctx) is True


def test_check_no_op_without_accounts(tmp_path):
    ctx = _ctx(tmp_path, creds_text="")
    res = AIMapAuthPhase().check(ctx, ctx._store)
    assert res.status == st.DONE


def test_endpoint_count_source_filter(tmp_path):
    store = A.Assets(st.State(tmp_path / "s.db").db)
    store.add_endpoint("GET", "https://x.acme.test/a", source="crawl")
    store.add_endpoint("GET", "https://x.acme.test/admin", source="crawl-auth")
    store.db.commit()
    assert store.endpoint_count() == 2
    assert store.endpoint_count(source="crawl-auth") == 1
