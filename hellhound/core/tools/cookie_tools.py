"""
hellhound/core/tools/cookie_tools.py - session-cookie inspection.

Split slice 7 from agent.py. cookie_inspector classifies cookies on a target
(JWT vs opaque session vs tracking) and flags security-attribute gaps, backed by
its own self-contained closure: the opaque-session name list, a safe base64url
JSON decoder, and the per-cookie classifier. No agent.py internals. agent.py
re-imports the executor so TOOL_REGISTRY wiring is unchanged.
"""
import base64
import json
import re
from typing import Any, Dict, List, Optional

from hellhound.core.tasks import Target


_WELL_KNOWN_OPAQUE_SESSION_NAMES = (
    "phpsessid", "jsessionid", "connect.sid", "asp.net_sessionid", "aspsessionid",
    "laravel_session", "ci_session", "sessionid", "session_id", "sid", "remember_token",
    "csrftoken", "csrf_token", "xsrf-token", "x-xsrf-token", "_ga", "_gid",
)


def _b64url_decode_json_safe(segment: str) -> Optional[Dict[str, Any]]:
    """Best-effort base64url-decode a single dot-separated segment and parse
    it as JSON. Returns None (never raises) if it isn't decodable JSON —
    used only for classification, not for anything that needs to trust the
    content."""
    try:
        s = segment.replace("-", "+").replace("_", "/")
        s += "=" * ((4 - len(s) % 4) % 4)
        decoded = base64.b64decode(s)
        parsed = json.loads(decoded)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def _classify_cookie_value(name: str, value: Any) -> Dict[str, Any]:
    """
    Classifies a single cookie/header value so the caller can decide whether
    jwt_forge is even worth invoking on it, WITHOUT spending a jwt_forge call
    to find out. This mechanizes the rule jwt_forge's own description
    already states in prose (zero dots -> not a JWT, don't call it) so it
    doesn't depend on the model reading and following that prose every time.

    Three outcomes:
      - "jwt_candidate": dot-separated AND the first segment decodes to a
        JSON object containing a JWT-shaped header key (alg/typ). Worth
        calling jwt_forge for real forgery attempts.
      - "dot_separated_non_jwt": has at least one '.' but the first segment
        doesn't decode as a JWT header — e.g. a Flask/itsdangerous signed
        session blob. jwt_forge can STILL be called on these (it decodes
        and returns session content instead of forging claims) but it will
        never produce a forged-privilege token, so this is a lower-priority
        call than jwt_candidate, not a hard "never call" like opaque below.
      - "opaque_session_id": zero dots at all — PHPSESSID, connect.sid,
        a plain hex/UUID session id, an opaque bearer token. jwt_forge is
        guaranteed to reject these outright; do not call it on these.
    """
    if not isinstance(value, str) or not value.strip():
        return {"name": name, "classification": "empty", "reason": "no value to classify"}

    value = value.strip()
    well_known = next((n for n in _WELL_KNOWN_OPAQUE_SESSION_NAMES if n == str(name).lower()), None)

    dots = value.count(".")
    if dots < 1:
        return {
            "name": name,
            "classification": "opaque_session_id",
            "well_known_type": well_known,
            "reason": "no '.' separators — not JWT-shaped at all; jwt_forge would reject this outright.",
            "call_jwt_forge": False,
        }

    header_json = _b64url_decode_json_safe(value.split(".", 1)[0])
    if header_json and ("alg" in header_json or "typ" in header_json):
        return {
            "name": name,
            "classification": "jwt_candidate",
            "decoded_header": header_json,
            "reason": "dot-separated and the header segment decodes to a JSON object with alg/typ — a real JWT.",
            "call_jwt_forge": True,
        }

    return {
        "name": name,
        "classification": "dot_separated_non_jwt",
        "well_known_type": well_known,
        "reason": (
            "has dot-separated segments but the header doesn't decode as a JWT header — likely a "
            "framework-signed session cookie (e.g. Flask itsdangerous), not a real JWT. jwt_forge "
            "can still decode this for session content, but forgery/privilege-escalation techniques "
            "will not apply — do not expect alg:none/kid/jwk tricks to work on this one."
        ),
        "call_jwt_forge": "optional",
    }


def _execute_cookie_inspector(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Classify every cookie you're holding BEFORE deciding whether to call
    jwt_forge on any of them. Fixes the recurring noisy-call pattern: any
    time a Set-Cookie/cookie shows up, reflexively calling jwt_forge on it
    regardless of shape — which just burns a turn on a guaranteed
    'not a valid JWT' error for the common case (PHPSESSID, connect.sid,
    JSESSIONID, a plain opaque session id). This tool costs nothing (no
    network call, pure local classification) and tells you definitively
    which cookies are worth sending to jwt_forge and which aren't.

    Reads cookies from (in order of preference): the 'cookies' arg if
    given (dict of name->value, or a raw 'name=value; name2=value2' Cookie
    header string), otherwise whatever's already been observed for this
    target in target.state['cookies'].
    """
    raw_input = args.get("cookies")
    pairs: Dict[str, str] = {}

    if isinstance(raw_input, dict):
        pairs = {str(k): str(v) for k, v in raw_input.items()}
    elif isinstance(raw_input, str) and raw_input.strip():
        for part in raw_input.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k.strip():
                    pairs[k.strip()] = v.strip()
    elif isinstance(raw_input, list):
        for item in raw_input:
            if isinstance(item, dict) and item.get("name"):
                pairs[str(item["name"])] = str(item.get("value", ""))

    source = "args"
    if not pairs:
        source = "target.state['cookies']"
        if hasattr(target, "state") and isinstance(target.state, dict):
            stored = target.state.get("cookies")
            if isinstance(stored, dict):
                pairs = {str(k): str(v) for k, v in stored.items()}

    if not pairs:
        return {
            "status": "no_cookies",
            "note": "No cookies given and none observed yet for this target (target.state['cookies'] is empty). "
                    "Make a request first (curl/spider) so cookies are captured, or pass them explicitly.",
        }

    results = [_classify_cookie_value(name, value) for name, value in pairs.items()]
    jwt_candidates = [r["name"] for r in results if r["classification"] == "jwt_candidate"]
    worth_trying = [r["name"] for r in results if r["classification"] == "dot_separated_non_jwt"]
    skip = [r["name"] for r in results if r["classification"] == "opaque_session_id"]

    if emit and hasattr(emit, "info"):
        emit.info(
            f"[*] cookie_inspector: {len(jwt_candidates)} JWT candidate(s), "
            f"{len(worth_trying)} dot-separated-but-not-JWT, {len(skip)} opaque (skip jwt_forge)."
        )

    return {
        "status": "success",
        "source": source,
        "cookies": results,
        "jwt_candidates": jwt_candidates,
        "worth_trying_jwt_forge": worth_trying,
        "skip_jwt_forge_for": skip,
        "recommendation": (
            f"Call jwt_forge on: {', '.join(jwt_candidates)}." if jwt_candidates else
            f"No confirmed JWTs. {('Optionally try jwt_forge on ' + ', '.join(worth_trying) + ' for session content.') if worth_trying else 'Do not call jwt_forge — all cookies are opaque session identifiers. Look at mass assignment, IDOR, or business-logic flaws on the session instead.'}"
        ),
    }
