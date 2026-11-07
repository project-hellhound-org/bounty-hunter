"""
hellhound/core/stealth.py — stealth / evasion profile (roadmap #5).

For AUTHORIZED testing only (same scope policy as the rest of the tool). On a
live bug-bounty program a WAF/CDN routinely false-blocks a researcher's own
legitimate test traffic — a bare `python-requests` User-Agent, no browser
headers, is flagged before the actual payload is even evaluated. This module
produces a coherent, rotated, browser-realistic header set, tuned by whichever
WAF the target profile has already fingerprinted, so a legitimate request
isn't dropped for looking non-human. It does NOT defeat authentication, hide
activity from the program owner, or do anything outside the authorized surface
— it just makes authorized requests look like a normal browser and surfaces
WAF-specific tactics the researcher can apply.

Pure functions over a UA pool + a WAF→tactics table; the `stealth` tool reads
the target's persisted `waf_detected` and returns a ready-to-use header set.
"""

from __future__ import annotations

import itertools
import random
from typing import Any, Dict, List, Optional


# Realistic, current desktop/mobile User-Agents (rotated per call).
USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
]

_UA_CYCLE = itertools.cycle(USER_AGENTS)


def pick_user_agent(rotate: bool = True) -> str:
    """Return a User-Agent. Rotates deterministically through the pool by
    default (so consecutive requests vary); random pick when rotate=False."""
    return next(_UA_CYCLE) if rotate else random.choice(USER_AGENTS)


def _ua_family(ua: str) -> str:
    u = ua.lower()
    if "firefox" in u:
        return "firefox"
    if "chrome" in u or "crios" in u:
        return "chrome"
    if "safari" in u:
        return "safari"
    return "chrome"


def browser_headers(ua: str) -> Dict[str, str]:
    """A coherent header set that matches the given UA — the headers a real
    browser sends alongside it, so the request fingerprint is consistent (a
    Chrome UA with Firefox-only headers is itself a bot tell)."""
    fam = _ua_family(ua)
    h: Dict[str, str] = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Connection": "keep-alive",
    }
    if fam == "chrome":
        is_mobile = "Mobile" in ua or "Android" in ua or "iPhone" in ua
        h["sec-ch-ua"] = '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"'
        h["sec-ch-ua-mobile"] = "?1" if is_mobile else "?0"
        h["sec-ch-ua-platform"] = '"Android"' if ("Android" in ua) else ('"macOS"' if "Mac" in ua else '"Windows"')
    return h


# WAF/CDN → authorized-testing tactics. Advisory notes the researcher applies,
# plus a few concrete header nudges. Matched by substring against the detected
# WAF names the target profile already stores.
WAF_PROFILES: Dict[str, Dict[str, Any]] = {
    "cloudflare": {
        "prefer_ua": "desktop_chrome",
        "headers": {"CF-IPCountry": "", "Accept-Language": "en-US,en;q=0.9"},
        "notes": [
            "Cloudflare rate-limits aggressively — pace requests (it's why the target profile tracks 429s).",
            "A bare non-browser UA is flagged before the payload matters; send a full browser header set.",
            "For a blocked payload, prefer encoding/case mutation (use waf_evasion_probe) over raw retries.",
        ],
    },
    "akamai": {
        "prefer_ua": "desktop_chrome",
        "headers": {},
        "notes": [
            "Akamai inspects header ORDER and consistency — keep the browser header set coherent with the UA.",
            "Abrupt param/encoding changes trip it; mutate one thing at a time (waf_evasion_probe).",
        ],
    },
    "aws": {
        "prefer_ua": "desktop_chrome",
        "headers": {},
        "notes": ["AWS WAF is often rule-set based — try alternate encodings/casing on a blocked payload (waf_evasion_probe)."],
    },
    "imperva": {
        "prefer_ua": "desktop_chrome",
        "headers": {},
        "notes": ["Imperva/Incapsula sets its own cookies and challenges non-browser clients — a full browser header set matters most here."],
    },
    "incapsula": {"alias": "imperva"},
    "modsecurity": {
        "prefer_ua": "desktop_chrome",
        "headers": {},
        "notes": ["ModSecurity/OWASP CRS is signature-based — comment-injection, case, and double-encoding bypasses are the usual levers (waf_evasion_probe)."],
    },
    "f5": {
        "prefer_ua": "desktop_chrome",
        "headers": {},
        "notes": ["F5 BIG-IP ASM fingerprints clients — keep the header set consistent and pace requests."],
    },
}


def waf_evasion_profile(waf_names: Optional[List[str]]) -> Dict[str, Any]:
    """Merge the tactics for every WAF currently fingerprinted on the target."""
    matched: List[str] = []
    headers: Dict[str, str] = {}
    notes: List[str] = []
    for raw in (waf_names or []):
        name = str(raw).strip().lower()
        for key, prof in WAF_PROFILES.items():
            if key in name:
                if "alias" in prof:
                    prof = WAF_PROFILES.get(prof["alias"], {})
                matched.append(key)
                headers.update({k: v for k, v in (prof.get("headers") or {}).items() if v})
                for n in prof.get("notes", []):
                    if n not in notes:
                        notes.append(n)
    return {"matched_wafs": matched, "headers": headers, "notes": notes}


def build_stealth_headers(target: Any = None, ua: Optional[str] = None,
                          rotate: bool = True, extra: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Assemble a WAF-aware, browser-realistic header set for the active target.
    Reads the target's persisted `waf_detected` so the header set is tuned to
    whatever protection was already fingerprinted. Returns the headers plus the
    evasion profile (matched WAFs + advisory notes)."""
    chosen_ua = ua or pick_user_agent(rotate=rotate)
    headers = browser_headers(chosen_ua)

    waf_names = []
    try:
        if target is not None and hasattr(target, "state") and isinstance(target.state, dict):
            waf_names = list(target.state.get("waf_detected") or [])
    except Exception:
        waf_names = []
    prof = waf_evasion_profile(waf_names)
    headers.update(prof["headers"])
    if extra and isinstance(extra, dict):
        headers.update(extra)

    return {
        "user_agent": chosen_ua,
        "headers": headers,
        "waf_profile": prof,
        "note": ("Pass these as the `headers` for your curl/request calls. For AUTHORIZED testing only — "
                 "this makes legitimate requests look like a normal browser so a WAF doesn't false-block "
                 "them; it is not a way around auth or scope."),
    }
