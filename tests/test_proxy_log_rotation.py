"""The scope proxy addon rotates traffic.jsonl by size so a long run cannot
let the live proxy log grow without bound."""

from __future__ import annotations

from hunter.proxy_addon import ScopeGuard


def _guard(path, max_bytes, keep=3):
    g = ScopeGuard()
    g.log_path = path
    g.log_handle = path.open("a", encoding="utf-8", buffering=1)
    g.log_bytes = 0
    g.log_max_bytes = max_bytes
    g.log_keep = keep
    return g


def test_rotation_rolls_and_keeps_bounded(tmp_path):
    traffic = tmp_path / "traffic.jsonl"
    g = _guard(traffic, max_bytes=200, keep=2)

    # Write enough lines to force several rotations.
    for i in range(200):
        line = f'{{"i":{i},"pad":"{"x" * 50}"}}\n'
        g.log_handle.write(line)
        g.log_bytes += len(line.encode())
        if g.log_max_bytes and g.log_bytes >= g.log_max_bytes:
            g._rotate_log()
    g.log_handle.close()

    # The live file exists and is small (freshly rolled), and at most `keep`
    # rolled files survive - never an unbounded pile.
    assert traffic.exists()
    rolls = sorted(tmp_path.glob("traffic.*.jsonl"))
    assert 0 < len(rolls) <= 2
    assert {p.name for p in rolls} <= {"traffic.1.jsonl", "traffic.2.jsonl"}


def test_no_rotation_when_disabled(tmp_path):
    traffic = tmp_path / "traffic.jsonl"
    g = _guard(traffic, max_bytes=0)  # 0 = never rotate
    for i in range(50):
        line = f'{{"i":{i}}}\n'
        g.log_handle.write(line)
        g.log_bytes += len(line.encode())
        if g.log_max_bytes and g.log_bytes >= g.log_max_bytes:
            g._rotate_log()
    g.log_handle.close()
    assert traffic.exists()
    assert list(tmp_path.glob("traffic.*.jsonl")) == []  # nothing rolled


def test_rotation_preserves_lines_across_live_and_rolls(tmp_path):
    traffic = tmp_path / "traffic.jsonl"
    g = _guard(traffic, max_bytes=120, keep=5)
    written = []
    for i in range(60):
        line = f'{{"i":{i},"pad":"{"y" * 30}"}}\n'
        written.append(line)
        g.log_handle.write(line)
        g.log_bytes += len(line.encode())
        if g.log_max_bytes and g.log_bytes >= g.log_max_bytes:
            g._rotate_log()
    g.log_handle.close()

    # Reassemble everything still on disk; recent lines must all be present
    # (older ones may have aged out past `keep`, which is acceptable).
    seen = traffic.read_text()
    for p in tmp_path.glob("traffic.*.jsonl"):
        seen += p.read_text()
    assert written[-1] in seen
