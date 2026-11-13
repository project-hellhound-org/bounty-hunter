"""
hellhound/core/tui_status.py — live "it's working" indicator for the TUI.

This is the Claude Code-style animated status line: a braille spinner plus a
rotating, slightly-playful phrase ("On the hunt…", "Cooking…", "Wrapping
up…") and an elapsed-seconds counter, so you always know a turn is actually
running (the old prompt_toolkit UI had a spinner thread; the Textual UI gets
this instead). Kept in its own module so the phrase set / animation is easy
to tweak without touching the app wiring.

The widget animates on a Textual interval timer (UI thread). start()/stop()
toggle visibility; set_label() pins a specific phrase (e.g. the running tool)
until cleared. All mutations are plain method calls — the app marshals them
from its worker thread via App.call_from_thread.
"""

from __future__ import annotations

import time
from typing import Optional

from textual.widgets import Static


# Braille spinner frames — same family Claude Code / rich use.
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

# Rotating phrases. Deliberately in loose "just starting -> deep in it ->
# finishing" order; the indicator walks them by elapsed time so a long turn
# visibly moves through them instead of sitting on one word.
_PHRASES = [
    "Picking up the scent",
    "On the hunt",
    "Sniffing around",
    "Digging in",
    "Working on it",
    "Poking the target",
    "Cooking",
    "Chasing it down",
    "Correlating",
    "Still at it",
    "Wrapping up",
]

_FRAME_INTERVAL = 0.2     # seconds per spinner frame (5 fps — halved from 10 fps so the
                          # animation repaint can't eat the UI thread's frame budget and
                          # starve key/click handling during a long-running tool)
_PHRASE_EVERY = 4         # seconds each rotating phrase stays up


class WorkingIndicator(Static):
    """Animated spinner + rotating status phrase + elapsed timer.

    Hidden (display=False) while idle; the app calls start() at the top of a
    turn and stop() when it finishes.
    """

    def __init__(self, id: Optional[str] = None) -> None:  # noqa: A002 - Textual uses `id`
        super().__init__("", id=id, markup=True)
        self._frame = 0
        self._t0 = time.monotonic()
        self._pinned: str = ""      # a specific phrase (e.g. "Running curl") or ""
        self._running = False

    def on_mount(self) -> None:
        self.display = False
        self.set_interval(_FRAME_INTERVAL, self._tick)

    # -- control (called from the app; safe on the UI thread) --
    def start(self, label: str = "") -> None:
        self._t0 = time.monotonic()
        self._pinned = label or ""
        self._running = True
        self.display = True
        self._repaint()

    def set_label(self, label: str) -> None:
        self._pinned = label or ""

    def stop(self) -> None:
        self._running = False
        self.display = False

    # -- animation --
    def _tick(self) -> None:
        if not self._running:
            return
        self._frame = (self._frame + 1) % len(_SPINNER)
        self._repaint()

    def _repaint(self) -> None:  # NB: not _render — that's Textual's internal hook
        elapsed = int(time.monotonic() - self._t0)
        phrase = self._pinned or _PHRASES[(elapsed // _PHRASE_EVERY) % len(_PHRASES)]
        spin = _SPINNER[self._frame]
        self.update(
            f"[bold red]{spin}[/bold red] [italic]{phrase}…[/italic] "
            f"[dim]({elapsed}s · esc to cancel)[/dim]"
        )
