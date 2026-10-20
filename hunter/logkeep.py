"""Log hygiene: keep a run's on-disk logs from filling the VPS disk.

A long run writes a lot under <target>/output/logs/: one JSONL transcript per
AI session (the bulk - every turn and tool result inline), their .stderr.log /
.prompt.md / .system.md siblings, recon tool output under tools/, and the live
proxy traffic.jsonl. None of it was pruned, so a single big program could reach
hundreds of MB and a multi-program sweep could fill the disk - at which point
every phase fails silently (writes error, reads succeed).

Two things keep that bounded, both best-effort (a failure here never stops a
run) and both reading their limits from settings["logs"]:

- compress_old_transcripts(): after a phase finishes, gzip the session
  transcripts and tool output of already-finished phases. They are never read
  live again; gzip shrinks JSONL ~10x.
- enforce_budget(): delete the oldest compressed logs once the logs tree passes
  a total-size budget, newest kept. Live, uncompressed files are never touched,
  so an in-flight phase is safe.

The live proxy traffic.jsonl is capped separately, by size rotation inside the
proxy addon (see proxy_addon.py); this module only comprests/prunes it once it
has rolled.
"""

from __future__ import annotations

import gzip
import os
import shutil
from pathlib import Path

# Defaults (MB). Overridable via settings["logs"].
DEFAULT_BUDGET_MB = 2000          # whole logs tree per target; prune oldest past this
DEFAULT_COMPRESS_AFTER_MB = 5     # gzip a finished-phase file once it is at least this big

# Files that are safe to compress/prune once their phase is finished. The live
# run.log, proxy.log and the current traffic.jsonl are left alone.
_COMPRESSIBLE_SUFFIXES = (".jsonl", ".stderr.log", ".prompt.md", ".system.md", ".txt")
_NEVER_TOUCH = {"run.log", "proxy.log", "traffic.jsonl"}


def _cfg(settings: dict, key: str, default: int) -> int:
    try:
        return int((settings.get("logs") or {}).get(key, default))
    except (TypeError, ValueError):
        return default


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if path.is_file():
            yield path


def dir_size_mb(root: Path) -> float:
    if not root.is_dir():
        return 0.0
    total = 0
    for path in _iter_files(root):
        try:
            total += path.stat().st_size
        except OSError:
            continue
    return total / 1e6


def _gzip_file(path: Path) -> bool:
    """Replace path with path.gz (atomic-ish). Returns True on success."""
    target = path.with_suffix(path.suffix + ".gz")
    tmp = target.with_suffix(target.suffix + ".tmp")
    try:
        with path.open("rb") as src, gzip.open(tmp, "wb", compresslevel=6) as dst:
            shutil.copyfileobj(src, dst, length=1 << 20)
        os.replace(tmp, target)
        path.unlink()
        return True
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        return False


def compress_old_transcripts(logs_dir: Path, settings: dict, exclude_phase: str | None = None) -> int:
    """Gzip session transcripts / tool output belonging to finished phases.

    exclude_phase: the phase just run (or currently running); its own agents/
    and tools/ subfolders are skipped so a file still being written is never
    touched. Returns the number of files compressed.
    """
    if not logs_dir.is_dir():
        return 0
    threshold = _cfg(settings, "compress_after_mb", DEFAULT_COMPRESS_AFTER_MB) * 1_000_000
    skip_dirs = set()
    if exclude_phase:
        skip_dirs = {logs_dir / "agents" / exclude_phase, logs_dir / "tools" / exclude_phase}
    done = 0
    for path in _iter_files(logs_dir):
        if path.suffix == ".gz" or path.name in _NEVER_TOUCH:
            continue
        if not path.name.endswith(_COMPRESSIBLE_SUFFIXES):
            continue
        if any(skip == path.parent or skip in path.parents for skip in skip_dirs):
            continue
        try:
            if path.stat().st_size < threshold:
                continue
        except OSError:
            continue
        if _gzip_file(path):
            done += 1
    return done


def enforce_budget(logs_dir: Path, settings: dict) -> int:
    """Delete the oldest compressed logs until the tree is under the budget.

    Only *.gz files are ever deleted - live, uncompressed logs (including the
    current phase's output and the active traffic.jsonl) are never removed, so a
    running phase cannot lose data it still needs. Returns bytes freed.
    """
    if not logs_dir.is_dir():
        return 0
    budget = _cfg(settings, "budget_mb", DEFAULT_BUDGET_MB) * 1_000_000
    total = sum(p.stat().st_size for p in _iter_files(logs_dir) if _safe_size(p))
    if total <= budget:
        return 0
    gz = sorted((p for p in _iter_files(logs_dir) if p.suffix == ".gz"),
                key=lambda p: _safe_mtime(p))
    freed = 0
    for path in gz:
        if total - freed <= budget:
            break
        try:
            size = path.stat().st_size
            path.unlink()
            freed += size
        except OSError:
            continue
    return freed


def _safe_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _safe_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def tidy(logs_dir: Path, settings: dict, exclude_phase: str | None = None) -> None:
    """Run both steps, best-effort. Called after each phase finishes."""
    try:
        compress_old_transcripts(logs_dir, settings, exclude_phase=exclude_phase)
        enforce_budget(logs_dir, settings)
    except Exception:
        # Log hygiene must never break a run.
        pass
