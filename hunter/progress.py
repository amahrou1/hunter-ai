"""Human-readable progress for `hunt status`: step, done/total, percent,
estimated time left (from the pace of the current step) and time running."""

from __future__ import annotations

import datetime as _dt
import time


def duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return "less than a minute"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours} h {minutes} min" if minutes else f"{hours} h"
    return f"{hours // 24} days {hours % 24} h"


def _since(iso: str | None, now: float) -> float | None:
    if not iso:
        return None
    try:
        started = _dt.datetime.fromisoformat(iso)
    except ValueError:
        return None
    if started.tzinfo is None:
        started = started.replace(tzinfo=_dt.timezone.utc)
    return now - started.timestamp()


def describe(progress: dict | None, started_at: str | None, now: float | None = None) -> str:
    """One line for a running phase."""
    now = time.time() if now is None else now
    running = _since(started_at, now)
    tail = f"running {duration(running)}" if running is not None else ""
    if not progress:
        return f"starting ({tail})" if tail else "starting"
    step = progress.get("step") or "working"
    done, total, unit = progress.get("done"), progress.get("total"), progress.get("unit") or "items"
    if done is None:
        size = f" ({total} {unit})" if total else ""
        return f"{step}{size}: working, no estimate for this step" + (f" - {tail}" if tail else "")
    total = total or 0
    percent = int(100 * done / total) if total else 0
    text = f"{step}: {done} of {total} {unit} ({percent}%)"
    elapsed = now - float(progress.get("step_started") or now)
    if 0 < done < total and elapsed > 0:
        left = elapsed / done * (total - done)
        text += f", about {duration(left)} left"
    elif done == 0 and total:
        text += ", estimate after the first ones finish"
    return text + (f" - {tail}" if tail else "")
