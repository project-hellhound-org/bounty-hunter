"""
hellhound/core/background_tasks.py — fire-and-collect background tool execution.

The `parallel` tool runs several tools at once but BLOCKS the turn until they all
finish. This is the other half, inspired by how Claude Code's harness runs a long
job detached and notifies on completion: spawn a slow tool (a full spider, a
nuclei sweep, an authenticated content-discovery) in a daemon thread, get a
task_id back IMMEDIATELY, keep testing other things, and collect the result on a
later turn via `check_tasks`. Pure, thread-safe registry — the agent (which has
the scope gate / rate limiter on execute_tool_call) supplies the actual work
function; this module only tracks it.
"""

from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Callable, Dict, List

_REGISTRY: Dict[str, "_BgTask"] = {}
_LOCK = threading.Lock()
MAX_ACTIVE = 4  # cap concurrent background tasks so a loop can't spawn hundreds


class _BgTask:
    __slots__ = ("id", "label", "status", "result", "error", "started", "finished", "collected")

    def __init__(self, task_id: str, label: str):
        self.id = task_id
        self.label = label
        self.status = "running"   # running | done | error
        self.result: Any = None
        self.error: str | None = None
        self.started = time.time()
        self.finished: float | None = None
        self.collected = False


def active_count() -> int:
    with _LOCK:
        return sum(1 for t in _REGISTRY.values() if t.status == "running")


def spawn(label: str, fn: Callable[[], Any]) -> Dict[str, Any]:
    """Run fn() in a daemon thread. Returns {task_id,...} immediately, or an
    error dict if too many are already active."""
    if active_count() >= MAX_ACTIVE:
        return {"error": f"too many background tasks already running (max {MAX_ACTIVE}) — "
                         f"wait for some to finish (check_tasks) before spawning more."}
    task_id = "bg_" + uuid.uuid4().hex[:8]
    task = _BgTask(task_id, label)
    with _LOCK:
        _REGISTRY[task_id] = task

    def _runner():
        try:
            task.result = fn()
            task.status = "done"
        except Exception as e:  # never let a background crash take down the process
            task.error = f"{type(e).__name__}: {e}"
            task.status = "error"
        finally:
            task.finished = time.time()

    threading.Thread(target=_runner, name=task_id, daemon=True).start()
    return {"task_id": task_id, "label": label, "status": "running"}


def _elapsed(t: "_BgTask") -> float:
    return round((t.finished or time.time()) - t.started, 1)


def status_all() -> List[Dict[str, Any]]:
    with _LOCK:
        return [{"task_id": t.id, "label": t.label, "status": t.status, "elapsed_s": _elapsed(t)}
                for t in _REGISTRY.values()]


def collect_finished(mark: bool = True) -> List[Dict[str, Any]]:
    """Return results of finished-but-not-yet-collected tasks; mark them collected
    so the same result isn't surfaced to the agent twice."""
    out = []
    with _LOCK:
        for t in _REGISTRY.values():
            if t.status in ("done", "error") and not t.collected:
                out.append({"task_id": t.id, "label": t.label, "status": t.status,
                            "elapsed_s": _elapsed(t), "result": t.result, "error": t.error})
                if mark:
                    t.collected = True
    return out


def reset() -> None:
    """Clear the registry — for tests / a fresh engagement."""
    with _LOCK:
        _REGISTRY.clear()
