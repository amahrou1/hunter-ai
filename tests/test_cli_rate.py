"""`hunt rate <target> <n>`: apply a program's updated rate mid-run by writing
effective_rps into scope.json (the running proxy re-reads it live)."""

from __future__ import annotations

import argparse

from hunter import cli, config, scope as sc


def _scope_file(target):
    target.output.mkdir(parents=True, exist_ok=True)
    s = sc.Scope(in_scope=[sc.parse_asset("*.acme.com")], out_of_scope=[],
                 rules={"effective_rps": 2.0, "rate_source": "limited, no number"})
    sc.save(s, target.scope_file)
    return s


def _args(target_name, value=None):
    ns = argparse.Namespace()
    ns.target = target_name
    ns.value = value
    return ns


def test_rate_updates_effective_rps(env, make_target):
    config.save_settings(config.DEFAULT_SETTINGS.copy())
    t = make_target("acme")
    _scope_file(t)
    assert sc.load(t.scope_file).rate_limit_rps == 2.0

    rc = cli.cmd_rate(_args("acme", "100"))
    assert rc == 0
    assert sc.load(t.scope_file).rate_limit_rps == 100.0


def test_rate_is_capped_by_vps_ceiling(env, make_target):
    s = config.DEFAULT_SETTINGS.copy()
    s["scope"] = dict(s["scope"])
    s["scope"]["max_rps"] = 50
    config.save_settings(s)
    t = make_target("acme")
    _scope_file(t)

    cli.cmd_rate(_args("acme", "100"))
    # requested 100 but VPS ceiling is 50 -> enforced 50
    assert sc.load(t.scope_file).rate_limit_rps == 50.0


def test_rate_rejects_bad_value(env, make_target):
    config.save_settings(config.DEFAULT_SETTINGS.copy())
    t = make_target("acme")
    _scope_file(t)
    assert cli.cmd_rate(_args("acme", "-5")) == 1
    assert sc.load(t.scope_file).rate_limit_rps == 2.0   # unchanged


def test_rate_show_without_value(env, make_target, capsys):
    config.save_settings(config.DEFAULT_SETTINGS.copy())
    t = make_target("acme")
    _scope_file(t)
    assert cli.cmd_rate(_args("acme", None)) == 0
    assert "2" in capsys.readouterr().out
