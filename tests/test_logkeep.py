"""Log hygiene: compress finished-phase transcripts, prune past the budget,
and never touch a live file or the current phase's output."""

from __future__ import annotations

import gzip
import os

from hunter import logkeep


def _write(path, size_bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size_bytes)


def test_compress_old_transcripts_gzips_big_finished_files(tmp_path):
    logs = tmp_path / "logs"
    big = logs / "agents" / "02-recon" / "20250101-000000-recon-triage.try1.jsonl"
    _write(big, 6_000_000)  # above the 5 MB default threshold
    settings = {"logs": {"compress_after_mb": 5}}

    n = logkeep.compress_old_transcripts(logs, settings)

    assert n == 1
    assert not big.exists()
    gz = big.with_suffix(big.suffix + ".gz")
    assert gz.exists()
    with gzip.open(gz, "rb") as fh:
        assert fh.read() == b"x" * 6_000_000


def test_small_files_are_left_uncompressed(tmp_path):
    logs = tmp_path / "logs"
    small = logs / "agents" / "02-recon" / "a.try1.jsonl"
    _write(small, 1000)
    n = logkeep.compress_old_transcripts(logs, {"logs": {"compress_after_mb": 5}})
    assert n == 0
    assert small.exists()


def test_current_phase_and_live_files_are_never_touched(tmp_path):
    logs = tmp_path / "logs"
    # Live top-level files that must survive even when large.
    for name in ("run.log", "proxy.log", "traffic.jsonl"):
        _write(logs / name, 9_000_000)
    # The phase currently running: its big transcript must be left alone.
    current = logs / "agents" / "05-discover" / "live.try1.jsonl"
    _write(current, 9_000_000)
    # A finished phase's big transcript: this one should be compressed.
    old = logs / "agents" / "02-recon" / "done.try1.jsonl"
    _write(old, 9_000_000)

    logkeep.compress_old_transcripts(logs, {"logs": {"compress_after_mb": 5}},
                                     exclude_phase="05-discover")

    assert (logs / "run.log").exists()
    assert (logs / "proxy.log").exists()
    assert (logs / "traffic.jsonl").exists()
    assert current.exists()                       # current phase untouched
    assert not old.exists()                       # finished phase compressed
    assert old.with_suffix(old.suffix + ".gz").exists()


def test_enforce_budget_deletes_only_oldest_compressed(tmp_path):
    logs = tmp_path / "logs"
    # Three compressed rolls, oldest first; plus a live uncompressed file.
    paths = []
    for i, name in enumerate(("old.jsonl.gz", "mid.jsonl.gz", "new.jsonl.gz")):
        p = logs / "agents" / "p" / name
        _write(p, 1_000_000)
        os.utime(p, (1000 + i, 1000 + i))  # ascending mtime
        paths.append(p)
    live = logs / "traffic.jsonl"
    _write(live, 1_000_000)

    # Budget 2 MB: total is 4 MB, so ~2 MB of the oldest .gz must go.
    freed = logkeep.enforce_budget(logs, {"logs": {"budget_mb": 2}})

    assert freed >= 1_000_000
    assert not paths[0].exists()          # oldest .gz deleted
    assert paths[2].exists()              # newest .gz kept
    assert live.exists()                  # live file never deleted


def test_enforce_budget_never_deletes_uncompressed_even_over_budget(tmp_path):
    logs = tmp_path / "logs"
    big = logs / "agents" / "p" / "huge.try1.jsonl"   # not .gz
    _write(big, 5_000_000)
    freed = logkeep.enforce_budget(logs, {"logs": {"budget_mb": 1}})
    assert freed == 0
    assert big.exists()


def test_tidy_swallows_errors(tmp_path):
    # Pointing at a path that is a file, not a dir, must not raise.
    not_a_dir = tmp_path / "file"
    not_a_dir.write_text("x")
    logkeep.tidy(not_a_dir, {})  # should silently no-op


def test_dir_size_mb(tmp_path):
    logs = tmp_path / "logs"
    _write(logs / "a.jsonl", 2_000_000)
    _write(logs / "b.jsonl", 3_000_000)
    assert abs(logkeep.dir_size_mb(logs) - 5.0) < 0.01
