"""Per-host adaptive backoff: a host that returns 429/503 is slowed before the
next request to it, decays back to full speed when it recovers, and never
affects other hosts or speeds anything up."""

from __future__ import annotations

import asyncio

import pytest

from hunter.proxy_addon import HostGovernor, ScopeGuard


class _Resp:
    def __init__(self, status, headers=None):
        self.status_code = status
        self.headers = headers or {}


class _Flow:
    def __init__(self, status=None, headers=None):
        self.response = _Resp(status, headers) if status is not None else None


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_healthy_host_is_not_delayed():
    g = HostGovernor(base_delay=2.0)
    assert _run(g.wait("example.com")) == 0.0


def test_throttle_schedules_backoff_for_that_host_only():
    g = HostGovernor(base_delay=5.0, max_delay=60.0)
    g.record("sore.com", 429, throttled=True)
    # The sore host must now wait; an untouched host must not.
    assert _run(g.wait("other.com")) == 0.0
    waited = _run(g.wait("sore.com"))
    assert waited > 0


def test_backoff_grows_with_consecutive_signals():
    g = HostGovernor(base_delay=1.0, max_delay=100.0, trip_after=1)
    g.record("h", 429, throttled=True)   # strike 1 -> ~1s
    d1 = g._state["h"][1] - g._state["h"][2]  # scheduled gap after signal
    g.record("h", 429, throttled=True)   # strike 2 -> ~2s
    g.record("h", 429, throttled=True)   # strike 3 -> ~4s
    # delay_for reflects the doubling curve
    assert g._delay_for(1) == 1.0
    assert g._delay_for(2) == 2.0
    assert g._delay_for(3) == 4.0
    assert d1 >= 1.0


def test_delay_is_capped():
    g = HostGovernor(base_delay=2.0, max_delay=10.0)
    assert g._delay_for(50) == 10.0   # never exceeds the ceiling


def test_host_decays_back_to_full_speed_after_cooldown():
    # cooldown is clamped to >= 1s; drive decay by backdating the last signal.
    g = HostGovernor(base_delay=2.0, cooldown=1.0)
    g.record("h", 429, throttled=True)
    assert g._state["h"][0] >= 1
    # Pretend a cooldown window has passed with no new signals, and the gate
    # has already elapsed, so wait() decays the strike count.
    import time as _t
    g._state["h"][2] = _t.monotonic() - 5.0   # last signal well in the past
    g._state["h"][1] = _t.monotonic() - 5.0   # gate already open
    _run(g.wait("h"))
    assert g._state["h"][0] == 0              # recovered to full speed


def test_is_throttle_detects_rate_limit_signals():
    assert ScopeGuard._is_throttle(_Flow(429)) is True
    assert ScopeGuard._is_throttle(_Flow(503)) is True
    assert ScopeGuard._is_throttle(_Flow(200)) is False
    assert ScopeGuard._is_throttle(_Flow(404)) is False
    # Plain 403 is ordinary authz, not throttling ...
    assert ScopeGuard._is_throttle(_Flow(403)) is False
    # ... unless it carries a rate-limit signal.
    assert ScopeGuard._is_throttle(_Flow(403, {"Retry-After": "30"})) is True
    assert ScopeGuard._is_throttle(_Flow(403, {"X-RateLimit-Remaining": "0"})) is True


def test_governor_only_adds_delay_never_negative():
    g = HostGovernor(base_delay=3.0)
    g.record("h", 429, throttled=True)
    # After waiting once, waiting again when the gate has passed returns >= 0.
    _run(g.wait("h"))
    assert _run(g.wait("h")) >= 0.0
