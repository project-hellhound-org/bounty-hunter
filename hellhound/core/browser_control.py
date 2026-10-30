# hellhound/core/browser_control.py
"""
Generic interactive browser-control tool.

Why this exists: the existing Playwright usage in hellhound/modules/recon/spider.py
is all one-shot -- it launches a browser, crawls, and tears everything down inside a
single module.run() call. That's fine for recon, but it can't do a multi-step
interactive flow (log in, solve a client-side redirect, click through an MFA
prompt, then poke at an authenticated page) across SEPARATE tool calls, because
there's no persistent page between calls.

This module gives the agent a persistent, per-target browser session: goto/click/
fill/eval_js/get_storage/get_cookies/get_network_log/screenshot, where the browser
and page stay alive across tool calls until explicitly closed (or the process exits).

Playwright's async API objects are bound to the event loop they were created on,
so you can't just asyncio.run() a fresh loop per call and keep the page alive --
the page would belong to a loop that no longer exists by the next call. Instead a
single background thread owns one long-lived event loop, Playwright/browser/page
objects are created and used only on that loop, and each synchronous tool call
schedules a coroutine onto it with asyncio.run_coroutine_threadsafe(...).result().
"""

import asyncio
import threading
import time
import base64
from typing import Any, Dict, List, Optional

PLAYWRIGHT_AVAILABLE = False
PLAYWRIGHT_ERROR = None
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError as e:
    PLAYWRIGHT_ERROR = str(e)
except Exception as e:
    PLAYWRIGHT_ERROR = f"{type(e).__name__}: {e}"


# ──────────────────────────────────────────────────────────────────────────
# Background event loop thread -- one per process, started lazily.
# ──────────────────────────────────────────────────────────────────────────

class _LoopThread:
    _instance: Optional["_LoopThread"] = None
    _lock = threading.Lock()

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True, name="hellhound-browser-loop")
        self._thread.start()

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    @classmethod
    def get(cls) -> "_LoopThread":
        with cls._lock:
            if cls._instance is None:
                cls._instance = _LoopThread()
            return cls._instance

    def run_coro(self, coro, timeout: float = 45.0):
        fut = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return fut.result(timeout=timeout)


# ──────────────────────────────────────────────────────────────────────────
# Per-target session state -- lives on the background loop's thread only.
# ──────────────────────────────────────────────────────────────────────────

class _BrowserSession:
    def __init__(self):
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self.network_log: List[Dict[str, Any]] = []
        self.last_used = time.time()

    async def ensure_started(self):
        if self.page is not None:
            # CAUGHT IN THE WILD (2026-10): this used to just trust a
            # non-None page reference and return immediately -- if the
            # underlying Chromium process had died (crash, OOM kill, a
            # sandboxing issue in the container), self.page/self.browser
            # stayed non-None forever, so every single action on this
            # session failed with the identical "Connection closed while
            # reading from the driver" error for the rest of the
            # engagement, with nothing ever relaunching a fresh browser.
            # Checking is_connected() here catches that proactively,
            # before wasting a call on a browser that's already dead.
            try:
                still_alive = self.browser is not None and self.browser.is_connected()
            except Exception:
                still_alive = False
            if still_alive:
                return
            await self.close()
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        self.context = await self.browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 HellhoundBountyHunter/1.0"
            ),
        )
        self.page = await self.context.new_page()

        def _on_request(req):
            try:
                self.network_log.append({
                    "type": "request",
                    "method": req.method,
                    "url": req.url,
                    "resource_type": req.resource_type,
                    "ts": time.time(),
                })
            except Exception:
                pass

        def _on_response(resp):
            try:
                self.network_log.append({
                    "type": "response",
                    "status": resp.status,
                    "url": resp.url,
                    "ts": time.time(),
                })
            except Exception:
                pass

        self.page.on("request", _on_request)
        self.page.on("response", _on_response)
        # Rolling cap -- a long interactive session shouldn't grow this file
        # or the tool-result payload unboundedly.
        self._cap_log()

    def _cap_log(self):
        if len(self.network_log) > 500:
            del self.network_log[: len(self.network_log) - 500]

    async def close(self):
        try:
            if self.context:
                await self.context.close()
        except Exception:
            pass
        try:
            if self.browser:
                await self.browser.close()
        except Exception:
            pass
        try:
            if self.playwright:
                await self.playwright.stop()
        except Exception:
            pass
        self.playwright = self.browser = self.context = self.page = None
        self.network_log = []


class _SessionRegistry:
    """Keyed by "<target>::<session_id>" (session_id defaults to "default").
    Only ever touched from the background loop thread's coroutines (via
    run_coro), so no extra lock is needed around the dict itself -- asyncio
    on a single loop is cooperative, not preemptive.

    Multiple session_ids under the same target give independent browser
    CONTEXTS (own cookie jar, own storage, own page) -- what cross-user
    IDOR/BAC testing actually needs: a "victim" session logged in as one
    account and an "attacker" session logged in as another, open and
    interactive at the same time, instead of one shared context where
    logging in as the second user destroys the first user's session.
    """

    def __init__(self):
        self.sessions: Dict[str, _BrowserSession] = {}

    def get_or_create(self, key: str) -> _BrowserSession:
        sess = self.sessions.get(key)
        if sess is None:
            sess = _BrowserSession()
            self.sessions[key] = sess
        return sess

    def keys_for_target(self, target_prefix: str) -> List[str]:
        prefix = f"{target_prefix}::"
        return [k for k in self.sessions.keys() if k.startswith(prefix)]


_registry = _SessionRegistry()


async def _list_sessions_coro(target_prefix: str) -> Dict[str, Any]:
    keys = _registry.keys_for_target(target_prefix)
    sessions = []
    for k in keys:
        sess = _registry.sessions.get(k)
        if sess is None:
            continue
        session_id = k.split("::", 1)[1] if "::" in k else k
        sessions.append({
            "session_id": session_id,
            "active": sess.page is not None,
            "url": sess.page.url if sess.page is not None else None,
            "last_used": sess.last_used,
        })
    return {"status": "success", "action": "list_sessions", "sessions": sessions, "count": len(sessions)}


async def _close_all_coro(target_prefix: str) -> Dict[str, Any]:
    keys = _registry.keys_for_target(target_prefix)
    closed = []
    for k in keys:
        sess = _registry.sessions.get(k)
        if sess is not None:
            await sess.close()
        _registry.sessions.pop(k, None)
        closed.append(k.split("::", 1)[1] if "::" in k else k)
    return {"status": "success", "action": "close", "closed_sessions": closed, "count": len(closed)}


# ──────────────────────────────────────────────────────────────────────────
# Async action implementations
# ──────────────────────────────────────────────────────────────────────────

# Substrings of the Playwright exceptions a genuinely-dead browser
# process raises -- as opposed to an ordinary action failure (a selector
# that doesn't exist, a navigation timeout), which should surface as-is,
# not trigger a relaunch.
_DEAD_BROWSER_MARKERS = (
    "connection closed",
    "target closed",
    "target page, context or browser has been closed",
    "browser has been closed",
    "has been closed",
)


def _looks_like_dead_browser(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(marker in msg for marker in _DEAD_BROWSER_MARKERS)


async def _do_action(key: str, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
    sess = _registry.get_or_create(key)

    if action == "close":
        had_session = sess.page is not None
        await sess.close()
        _registry.sessions.pop(key, None)
        return {"status": "success", "action": "close", "closed": had_session}

    await sess.ensure_started()
    sess.last_used = time.time()
    timeout_ms = int(float(params.get("timeout", 15)) * 1000)

    try:
        return await _run_page_action(sess, action, params, timeout_ms)
    except Exception as e:
        if not _looks_like_dead_browser(e):
            raise
        # CAUGHT IN THE WILD (2026-10): a browser that died mid-action
        # (not just between calls -- ensure_started()'s health check
        # above only catches the between-calls case) used to just bubble
        # up as a bare "Connection closed" error with the stale session
        # left in place, so the NEXT call failed identically, and the
        # one after that, for the rest of the engagement -- a researcher
        # watching this saw browser_control as simply broken, with no
        # indication a relaunch would have fixed it. Tear the dead
        # session down, start a completely fresh one, and retry the SAME
        # action exactly once before giving up -- this is a recovery
        # from infrastructure flakiness, not a loop (one retry, then a
        # real error if it's still broken).
        try:
            await sess.close()
        except Exception:
            pass
        _registry.sessions.pop(key, None)
        sess = _registry.get_or_create(key)
        await sess.ensure_started()
        sess.last_used = time.time()
        try:
            result = await _run_page_action(sess, action, params, timeout_ms)
            result["auto_recovered_from_crashed_browser"] = True
            return result
        except Exception as e2:
            return {
                "status": "error",
                "error": (
                    f"Browser action '{action}' failed: {type(e2).__name__}: {e2} "
                    f"(the browser session had crashed and was automatically relaunched, "
                    f"but the retry failed too -- this looks like a persistent environment "
                    f"issue, e.g. the sandbox can't keep Chromium alive at all, not a one-off crash)."
                ),
            }


async def _run_page_action(sess: "_BrowserSession", action: str, params: Dict[str, Any], timeout_ms: int) -> Dict[str, Any]:
    page = sess.page

    if action == "goto":
        url = params.get("url")
        if not url:
            return {"status": "error", "error": "goto requires a 'url' parameter"}
        wait_until = params.get("wait_for") or "load"
        if wait_until not in ("load", "domcontentloaded", "networkidle", "commit"):
            wait_until = "load"
        resp = await page.goto(url, wait_until=wait_until, timeout=timeout_ms)
        return {
            "status": "success",
            "action": "goto",
            "url": page.url,
            "http_status": resp.status if resp else None,
            "title": await page.title(),
        }

    if action == "click":
        selector = params.get("selector")
        if not selector:
            return {"status": "error", "error": "click requires a 'selector' parameter"}
        await page.click(selector, timeout=timeout_ms)
        return {"status": "success", "action": "click", "selector": selector, "url": page.url}

    if action == "fill":
        selector = params.get("selector")
        value = params.get("value")
        if not selector or value is None:
            return {"status": "error", "error": "fill requires 'selector' and 'value' parameters"}
        await page.fill(selector, str(value), timeout=timeout_ms)
        return {"status": "success", "action": "fill", "selector": selector}

    if action == "eval_js":
        script = params.get("script")
        if not script:
            return {"status": "error", "error": "eval_js requires a 'script' parameter"}
        try:
            result = await page.evaluate(script)
        except Exception as e:
            return {"status": "error", "error": f"JS evaluation failed: {e}"}
        return {"status": "success", "action": "eval_js", "result": result}

    if action == "get_storage":
        local_storage = await page.evaluate(
            "() => { const o = {}; for (let i = 0; i < localStorage.length; i++) { "
            "const k = localStorage.key(i); o[k] = localStorage.getItem(k); } return o; }"
        )
        session_storage = await page.evaluate(
            "() => { const o = {}; for (let i = 0; i < sessionStorage.length; i++) { "
            "const k = sessionStorage.key(i); o[k] = sessionStorage.getItem(k); } return o; }"
        )
        return {
            "status": "success",
            "action": "get_storage",
            "local_storage": local_storage,
            "session_storage": session_storage,
        }

    if action == "get_cookies":
        cookies = await sess.context.cookies()
        return {"status": "success", "action": "get_cookies", "cookies": cookies}

    if action == "get_network_log":
        sess._cap_log()
        return {
            "status": "success",
            "action": "get_network_log",
            "count": len(sess.network_log),
            "entries": sess.network_log[-200:],
        }

    if action == "screenshot":
        png_bytes = await page.screenshot(full_page=bool(params.get("full_page", False)))
        return {
            "status": "success",
            "action": "screenshot",
            "url": page.url,
            "image_base64": base64.b64encode(png_bytes).decode("ascii"),
        }

    return {"status": "error", "error": f"Unknown browser action '{action}'"}


# ──────────────────────────────────────────────────────────────────────────
# Synchronous entry point -- what agent.py's executor calls.
# ──────────────────────────────────────────────────────────────────────────

def run_browser_action(key: str, action: str, params: Optional[Dict[str, Any]] = None, timeout: float = 45.0) -> Dict[str, Any]:
    if not PLAYWRIGHT_AVAILABLE:
        return {
            "status": "error",
            "error": f"Playwright is not available in this environment ({PLAYWRIGHT_ERROR}). "
                     f"Interactive browser control requires it; recon-only flows can still use curl/spider.",
        }
    params = params or {}
    loop_thread = _LoopThread.get()
    try:
        return loop_thread.run_coro(_do_action(key, action, params), timeout=timeout)
    except asyncio.TimeoutError:
        return {"status": "error", "error": f"Browser action '{action}' timed out after {timeout}s"}
    except Exception as e:
        return {"status": "error", "error": f"Browser action '{action}' failed: {type(e).__name__}: {e}"}


async def _seed_cookies_coro(key: str, cookies: List[Dict[str, Any]]) -> Dict[str, Any]:
    sess = _registry.get_or_create(key)
    await sess.ensure_started()
    sess.last_used = time.time()
    added = 0
    errors = []
    for c in cookies:
        try:
            await sess.context.add_cookies([c])
            added += 1
        except Exception as e:
            errors.append(f"{c.get('name', '?')}: {e}")
    return {"status": "success", "action": "seed_cookies", "added": added, "attempted": len(cookies), "errors": errors or None}


def seed_session_cookies(key: str, cookies: List[Dict[str, Any]], timeout: float = 15.0) -> Dict[str, Any]:
    """
    CAUGHT IN THE WILD (2026-10): cookie sync only ever flowed browser ->
    curl (see agent.py's _execute_browser_control, which folds whatever
    cookies the browser is holding into target.state after goto/click/
    fill/get_cookies) -- the reverse never happened. A researcher who
    logged in via curl (or any other tool that captures a session into
    target.state) and THEN opened browser_control got a brand-new,
    logged-out browser context with no idea the curl session existed,
    forcing a manual cookie copy-paste to actually use the browser
    authenticated. This is the other half: seed a FRESH (or already-
    running) browser session's cookie jar from cookies captured elsewhere,
    so "I already have a session, go drive the browser with it" just
    works. Each cookie dict needs Playwright's expected shape -- at least
    name/value and either 'url' or both 'domain'+'path'; build these with
    agent.py's _cookies_for_browser_seed() rather than hand-rolling them
    here, which also decides whether seeding is worth doing at all (empty
    cookie jar, no domain to attach them to, etc).
    """
    if not PLAYWRIGHT_AVAILABLE:
        return {"status": "success", "action": "seed_cookies", "added": 0, "attempted": len(cookies), "note": "Playwright not available"}
    if not cookies:
        return {"status": "success", "action": "seed_cookies", "added": 0, "attempted": 0}
    loop_thread = _LoopThread.get()
    try:
        return loop_thread.run_coro(_seed_cookies_coro(key, cookies), timeout=timeout)
    except Exception as e:
        return {"status": "error", "error": f"seed_session_cookies failed: {type(e).__name__}: {e}"}


def list_sessions(target_prefix: str, timeout: float = 15.0) -> Dict[str, Any]:
    """Lists every open session_id for this target (across every browser
    context, not just 'default') -- what's actually open right now, each
    with its own cookie jar/storage, for multi-context cross-user testing."""
    if not PLAYWRIGHT_AVAILABLE:
        return {"status": "success", "action": "list_sessions", "sessions": [], "count": 0}
    loop_thread = _LoopThread.get()
    try:
        return loop_thread.run_coro(_list_sessions_coro(target_prefix), timeout=timeout)
    except Exception as e:
        return {"status": "error", "error": f"list_sessions failed: {type(e).__name__}: {e}"}


def close_all_sessions(target_prefix: str, timeout: float = 30.0) -> Dict[str, Any]:
    """Tears down EVERY open session_id for this target at once (vs. a
    plain 'close', which only ever closes the single session_id it was
    called with)."""
    if not PLAYWRIGHT_AVAILABLE:
        return {"status": "success", "action": "close", "closed_sessions": [], "count": 0}
    loop_thread = _LoopThread.get()
    try:
        return loop_thread.run_coro(_close_all_coro(target_prefix), timeout=timeout)
    except Exception as e:
        return {"status": "error", "error": f"close_all_sessions failed: {type(e).__name__}: {e}"}
