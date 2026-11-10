"""
hellhound/core/tool_shared.py - cross-cutting helpers shared by the tool executors.

Split slice 10 (the foundation). These six helpers were referenced by dozens of
executors scattered across agent.py; keeping them there blocked moving the big
tool clusters (recon shell-out, curl-based testing, reporting) into tools/
modules without lazy-import gymnastics. They are leaf helpers (no agent.py
internals), so they lift out cleanly and both agent.py and every tools/ module can
now import them from one place. agent.py re-imports all six, so its ~100 existing
call sites resolve unchanged.
"""
import os
import re
import json
import time
import subprocess
import threading
import concurrent.futures
from typing import Any, Callable, Dict, List, Optional

import requests

from hellhound.core.toolcheck import get_binary_path
from hellhound.core.http_utils import merge_global_context, normalize_headers, normalize_cookies
from hellhound.core.tasks import Target
from hellhound.core.ai_utils import ThinkingIndicator

# Module-level state these helpers own (moved with them from agent.py).
_LAST_TOOL_OUTPUT_CAP = 200_000  # chars kept per stream — in-memory only, bounds worst case without a file on disk
_BOUNDED_REQUEST_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="hh-http")


def _html_escape(s: Any) -> str:
    import html as _html_mod
    return _html_mod.escape(str(s if s is not None else ""), quote=True)


def _find_binary(name: str) -> Optional[str]:
    """Find binary in system PATH as well as standard user Go binary directories."""
    return get_binary_path(name)


def _run_cmd_with_heartbeat(cmd, timeout: int, emit: Any, label: str,
                              heartbeat_interval: int = 5, shell: bool = False,
                              env: Optional[Dict[str, str]] = None,
                              live_parser: Optional[Callable[[str], Optional[str]]] = None,
                              max_live_lines: int = 40,
                              target: Any = None) -> "subprocess.CompletedProcess":
    """
    Runs a subprocess without blocking silently for the full timeout window.
    Long recon calls (passive OSINT lookups, DNS brute-force) previously used
    a single `subprocess.run(..., timeout=N)` — the terminal showed nothing
    between "tool started" and "tool finished," which for an unindexed
    domain (nothing found until timeout) looked exactly like a hang.
    Polls in `heartbeat_interval`-second slices and emits a progress line
    each time so the CLI stays visibly alive, then hard-kills at `timeout`.

    `cmd` is a List[str] argv by default (shell=False); pass a single command
    STRING with shell=True for callers that need real shell features (pipes,
    heredocs, redirects, `&&` chains) — e.g. run_terminal_command's ad-hoc
    multi-stage pipelines, which can't be expressed as a plain argv list.

    `env`, when given, REPLACES the subprocess's environment entirely (same
    as subprocess.Popen's own env= semantics) — callers that want to add
    variables on top of the normal environment must pass os.environ.copy()
    plus their additions, not a bare dict of just the new vars, or the
    child process loses PATH and everything else it needs to run at all.

    `live_parser`, when given, is called with EVERY new stdout line as the
    subprocess produces it — not just at the end. A fuzzer/brute-forcer
    (ffuf, feroxbuster) run through this used to show NOTHING but a static
    "still running (Ns)..." placeholder the whole time, with zero
    visibility into what it was actually finding, unlike spider's live
    crawl feed. Return a short string from live_parser to surface it
    immediately via emit.info() (a real new scrollback line, same as
    spider), or None to ignore that line. Capped at max_live_lines
    surfaced hits per call — a huge wordlist run finding hundreds of hits
    still returns ALL of them in the final parsed result, just not all
    individually echoed to a scrolling terminal.

    `target`, when given, stashes this run's FULL captured stdout/stderr
    (not just the capped live-surfaced lines) into
    target.state["_last_tool_output"] after a successful run, in memory
    only — no file written. That's what the /output command reads back,
    so a researcher who only saw a handful of live-streamed hits can still
    pull the complete output of the run that just finished. Capped at
    _LAST_TOOL_OUTPUT_CAP chars per stream so one huge unfiltered run can't
    grow memory unboundedly; this never touches disk and is overwritten by
    the next call that passes a target, so it only ever holds the LAST run.

    Implementation note: this reads stdout/stderr via background threads
    instead of the simpler `proc.communicate(timeout=...)` loop the
    original version used, because communicate() owns the pipes outright —
    nothing else can read from them while it's blocked inside one call, so
    there was no way to inspect output AS it arrived, only after the next
    communicate() call returned (at most once per heartbeat_interval, and
    even then only the output accumulated in that slice, already consumed
    silently). The reader threads drain the pipes continuously (also
    avoiding the classic deadlock where a full stdout buffer blocks the
    child while nothing is reading it) and `live_parser` runs inline as
    each line arrives.
    """
    start = time.monotonic()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=shell, env=env, bufsize=1)

    stdout_lines: List[str] = []
    stderr_lines: List[str] = []
    _lock = threading.Lock()
    _live_shown = [0]  # single-element list so the nested reader can mutate it without `nonlocal` gymnastics across two readers

    def _reader(stream, sink: List[str], is_stdout: bool):
        try:
            for line in iter(stream.readline, ''):
                if line == '':
                    break
                with _lock:
                    sink.append(line)
                if is_stdout and live_parser is not None:
                    try:
                        surfaced = live_parser(line.rstrip('\n'))
                    except Exception:
                        surfaced = None
                    if surfaced:
                        do_emit = False
                        with _lock:
                            if _live_shown[0] < max_live_lines:
                                _live_shown[0] += 1
                                do_emit = True
                        if do_emit and emit and hasattr(emit, "info"):
                            try:
                                emit.info(surfaced)
                            except Exception:
                                pass
        except Exception:
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    t_out = threading.Thread(target=_reader, args=(proc.stdout, stdout_lines, True), daemon=True)
    t_err = threading.Thread(target=_reader, args=(proc.stderr, stderr_lines, False), daemon=True)
    t_out.start()
    t_err.start()

    try:
        while True:
            elapsed = time.monotonic() - start
            remaining = timeout - elapsed
            if remaining <= 0:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                # CAUGHT IN THE WILD (sqlmap on result.gujaratuniversity.ac.in):
                # a long-running tool that confirms injectability and
                # enumerates DB names BEFORE hitting the wall clock still had
                # all of that sitting in stdout_lines/stderr_lines at the
                # moment of kill -- but a bare TimeoutExpired(cmd, timeout)
                # carries no output, so every caller's `except
                # subprocess.TimeoutExpired:` handler had nothing to parse
                # and had to report "timed out" with zero signal, discarding
                # real confirmed findings and forcing a full noisy re-run
                # from scratch. Give the reader threads a moment to drain
                # what's already buffered and attach it to the exception so
                # callers (see _execute_sqlmap_scan) can salvage partial
                # results instead of throwing them away.
                t_out.join(timeout=2)
                t_err.join(timeout=2)
                with _lock:
                    partial_stdout = ''.join(stdout_lines)
                    partial_stderr = ''.join(stderr_lines)
                raise subprocess.TimeoutExpired(cmd, timeout, output=partial_stdout, stderr=partial_stderr)
            try:
                proc.wait(timeout=min(heartbeat_interval, remaining))
                # Process finished — give the reader threads a brief moment
                # to drain any last buffered bytes/EOF, then assemble the
                # same (stdout, stderr) string shape communicate() used to
                # return, so every existing caller's parsing code keeps
                # working unchanged.
                t_out.join(timeout=2)
                t_err.join(timeout=2)
                with _lock:
                    stdout = ''.join(stdout_lines)
                    stderr = ''.join(stderr_lines)
                if target is not None and hasattr(target, "state") and isinstance(target.state, dict):
                    try:
                        target.state["_last_tool_output"] = {
                            "label": label,
                            "cmd": cmd if isinstance(cmd, str) else " ".join(str(c) for c in cmd),
                            "returncode": proc.returncode,
                            "stdout": stdout[-_LAST_TOOL_OUTPUT_CAP:],
                            "stdout_truncated": len(stdout) > _LAST_TOOL_OUTPUT_CAP,
                            "stderr": stderr[-_LAST_TOOL_OUTPUT_CAP:],
                            "stderr_truncated": len(stderr) > _LAST_TOOL_OUTPUT_CAP,
                            "ts": time.time(),
                        }
                    except Exception:
                        pass
                return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
            except subprocess.TimeoutExpired:
                # Was emit.info(...) — ThinkingIndicator.info()/print_step()
                # prints a brand-new permanent scrollback line on every call,
                # so a long-running command produced a wall of near-identical
                # "still running (5s)... still running (10s)..." lines
                # instead of one line updating in place. set_label() instead
                # relabels the ALREADY-RUNNING spinner (which already shows
                # its own live elapsed-time counter), so this now reads as a
                # single line that updates in place, not N accumulating
                # ones. Falls back to info() only for a backend with no
                # spinner to update (e.g. plain headless/API emit), where a
                # one-line-per-tick log is the correct behavior anyway.
                elapsed_s = int(time.monotonic() - start)
                # PlainEmit/ConsoleEmit both define set_label() as a no-op
                # (nothing to relabel without a live spinner) — checking
                # hasattr() alone would silently swallow this heartbeat for
                # every non-interactive backend. The ORIGINAL version of
                # this check only looked for a `.indicator` attribute,
                # assuming `emit` would always be chat_ui.py's
                # InteractiveAgentEmit WRAPPER (which stores its
                # ThinkingIndicator as self.indicator). CAUGHT IN THE WILD:
                # the actual interactive console's main REPL loop
                # (chat_ui.py, start_chat_session) passes the raw
                # ThinkingIndicator itself as `emit` — it has no
                # `.indicator` attribute (it IS the indicator), so that
                # check was always False on the real deployed path and
                # this silently kept falling through to the info()
                # branch — printing a brand-new "still running (Ns)..."
                # scrollback line every heartbeat tick, i.e. the exact
                # flooding this was supposed to have already fixed.
                # Detect BOTH shapes: the wrapper (has .indicator) and a
                # bare ThinkingIndicator passed directly as emit.
                _live_indicator = isinstance(emit, ThinkingIndicator) or getattr(emit, "indicator", None) is not None
                if emit and _live_indicator and hasattr(emit, "set_label"):
                    emit.set_label(f"{label} still running ({elapsed_s}s)")
                elif emit and hasattr(emit, "info"):
                    # No leading "[*] " here — every emit backend's own
                    # info() already prefixes its own icon (ThinkingIndicator's
                    # print_step() renders its "*" icon, PlainEmit/ConsoleEmit
                    # render a "[*]" of their own via rich markup), so a
                    # literal "[*]" baked into the message text here doubled
                    # up into a visible "* [*] ..." / "[*] [*] ..." on every
                    # single line.
                    emit.info(f"{label} still running ({elapsed_s}s)...")
                continue
    finally:
        if proc.poll() is None:
            proc.kill()


def _bounded_request(fn: Callable[[], Any], hard_timeout: float = 20.0):
    """
    Runs a blocking network call (a requests.get/post/request(...) lambda)
    with a REAL wall-clock ceiling, regardless of what it's actually stuck
    on inside.

    Why this exists: every direct `requests.*` call in this file already
    passes timeout=N, but requests'/urllib3's timeout only covers the
    connect and read phases of an established socket — it does NOT cover
    DNS resolution (socket.getaddrinfo()), which happens first and has no
    timeout of its own. On a network where a name silently doesn't resolve
    (firewalled, sinkholed, a slow/overloaded resolver), getaddrinfo() can
    block for the OS resolver's own retry/timeout budget — tens of seconds
    to a few minutes, far past the "timeout=10" the code asked for. Because
    that's a blocking C-level call, it's also NOT interruptible by the
    console's cooperative SIGINT-based soft-cancel (_InterruptGuard in
    chat_ui.py) on the first Ctrl-C, which is exactly the "stuck for
    minutes, Ctrl-C does nothing" behavior this fixes.

    Running the call on a worker thread and bounding it with .result(
    timeout=hard_timeout) guarantees the CALLING thread (the orchestrator
    loop) gets control back within hard_timeout seconds no matter what —
    the worker thread may still be blocked and leak until the OS-level hang
    finally resolves on its own, but it's a daemon-pool thread, so it never
    keeps the process alive and never blocks the researcher's session
    again. Raises TimeoutError, which callers turn into a clean error dict
    instead of hanging.
    """
    future = _BOUNDED_REQUEST_POOL.submit(fn)
    try:
        return future.result(timeout=hard_timeout)
    except concurrent.futures.TimeoutError:
        raise TimeoutError(
            f"Network call did not complete within {hard_timeout}s (DNS resolution and/or connection appear "
            f"to be hanging rather than cleanly timing out/refusing — this is usually a firewalled, "
            f"sinkholed, or unresponsive host, not a slow-but-working one)."
        )


def _with_identity_bearer_header(headers: Dict[str, Any], target: Target) -> Dict[str, Any]:
    """
    Returns `headers` with an `Authorization: Bearer <token>` entry added
    from the target's active identity (`target.state["auth_token"]` /
    `["forged_token"]`, set by capture_identity/swap_session/jwt_forge) —
    but ONLY when `headers` doesn't already carry its own explicit
    Authorization value, same "don't double up on two different
    credentials" rule curl's own auto-attach uses. A no-op when there's
    no bearer token captured yet (returns `headers` unchanged). Used by
    every direct-binary tool (ffuf/feroxbuster executors underneath
    fuzz_hunter/content_discovery/vhost_fuzz, sqlmap_scan) that builds its
    own headers list instead of going through apply_session_config.
    """
    headers = dict(headers or {})
    if any(k.lower() == "authorization" for k in headers.keys()):
        return headers
    state = target.state if (target and hasattr(target, "state") and isinstance(target.state, dict)) else {}
    bearer_token = state.get("auth_token") or state.get("forged_token")
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    return headers


def _target_auth_options(target: Target) -> Dict[str, Any]:
    """
    Pulls this target's already-captured authenticated session (from a
    login flow, cookie_inspector, swap_session, or an imported Burp/Caido
    history) into the `options` shape http_utils.apply_session_config()
    reads — auth_cookies / auth_headers. Shared by every rule-based recon
    module wrapper below (wafbuster, surface_auditor, cors_checker,
    graphql_probe, transport_auditor, hydra, fuzz_hunter's internal
    fallback) so each of them tests WITH the live session instead of a
    bare unauthenticated requests.Session(), same auth source of truth
    every other request-sending tool (curl, httpx, run_terminal_command,
    sqlmap_scan) already reads from. Returns {} (nothing to add) when no
    session has been captured yet — harmless no-op for a pre-auth target.

    Also folds in a bearer auth_token/forged_token (set by capture_identity/
    swap_session or jwt_forge) as an Authorization header when the state
    doesn't already carry its own explicit Authorization header — curl has
    always done this bearer-token auto-attach on its own; this is the same
    behavior extended to every tool that goes through this shared helper,
    so an identity captured via a Bearer token (not just a cookie) actually
    reaches them instead of silently only working for curl/spider.
    """
    state = target.state if (target and isinstance(target.state, dict)) else {}
    out: Dict[str, Any] = {}
    cookies = state.get("cookies")
    session_cookie = state.get("session_cookie")
    if isinstance(cookies, dict) and cookies:
        out["auth_cookies"] = dict(cookies)
    elif session_cookie:
        out["auth_cookies"] = normalize_cookies(session_cookie)
    headers = state.get("headers")
    auth_headers = _with_identity_bearer_header(headers if isinstance(headers, dict) else {}, target)
    if auth_headers:
        out["auth_headers"] = auth_headers
    return out
