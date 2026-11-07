"""
hellhound/core/tui_banners.py — the banner pool for the TUI.

msfconsole-style: a small pool of ASCII banners, one picked at random each
launch. The original hound is always in the pool; new banners just get added
to _BANNERS (name, markup) — nothing else to wire.

Markup is Textual/Rich console markup (red figure, highlighted eyes). Keep
each banner roughly the same height (~7–9 lines) so it sits cleanly beside
the info pane.
"""

from __future__ import annotations

import random
from typing import List, Tuple


# The original front-facing hound (solid red, white eyes).
_HOUND = r"""[bold red]    ▲                 ▲
   /█\   .───────.   /█\
  /███\_/  ▄   ▄  \_/███\
 < ◥███   [bold white](●) (●)[/bold white]   ███◤ >
  \ ◥██    \___/    ██◤ /
   \__ \_  ▲ ▲ ▲  _/ __/
      \__\ ▼ ▼ ▼ /__/[/bold red]"""


# (name, markup). Add new banners here — that's the whole integration.
# The pool is kept (msfconsole-style random picker) so good banners can be
# dropped in later; right now the hound is the only one.
_BANNERS: List[Tuple[str, str]] = [
    ("hound", _HOUND),
]


def random_banner() -> str:
    """Return a random banner's markup for this launch."""
    return random.choice(_BANNERS)[1]


def banner_names() -> List[str]:
    return [name for name, _ in _BANNERS]
