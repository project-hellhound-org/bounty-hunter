"""
hellhound/core/surface_map.py — request/response correlation (roadmap #3).

Turns raw spider/recon output into a *prioritized, typed* attack surface:

  1. infer_param_type() — classify each discovered parameter by its DATA TYPE
     (numeric_id, uuid, email, file_path, url, token, search, json, boolean)
     from its name and any observed value, and map that type to the test
     family it actually warrants (numeric_id -> IDOR enumeration, file_path ->
     LFI/traversal, url -> SSRF/open-redirect, json -> mass-assignment, ...).
     This is distinct from the hypothesis engine's name->vuln-class guess:
     that answers "what bug class might this be", this answers "what SHAPE is
     this value, so the fuzzer sends type-appropriate payloads instead of a
     generic wordlist".

  2. group_endpoints() — bucket endpoints by FUNCTION (auth / payments / admin
     / user / api / upload) from path keywords, so a hunt works the
     high-value groups (auth, payments, admin) first instead of fuzzing
     everything flat.

  3. build_surface_map() — read the target's stored spider_intel / endpoints /
     parameters and assemble a ranked fuzz plan from the two above.

Pure functions over target.state; no network, no new deps. Feeds the fuzzer
and the model's prioritization — it does not itself send traffic or record
findings.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


# ── Param TYPE -> which payload/test family it warrants ──────────────────────
PARAM_TYPE_TESTS = {
    "numeric_id":  "IDOR/BOLA enumeration (increment/decrement, swap to another account's id), type juggling",
    "uuid":        "IDOR via leaked/guessable UUIDs; check if ids are predictable or exposed elsewhere",
    "email":       "user enumeration, account-takeover via email change, header/SMTP injection",
    "file_path":   "LFI / path traversal (../), upload-path abuse, null-byte / extension tricks",
    "url":         "SSRF (internal/metadata), open redirect, request smuggling via url parsing",
    "token":       "auth bypass, JWT forging/alg confusion, session fixation — classify with cookie_inspector/jwt_forge first",
    "search":      "SQLi (error/boolean/time), reflected XSS, NoSQL operators",
    "json":        "mass assignment (role/balance/is_admin), type confusion, NoSQLi operators",
    "boolean":     "privilege flip / mass assignment (flip to true/admin), parameter pollution",
    "unknown":     "generic fuzzing (reflection, error-based, special chars) to characterize behavior first",
}

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_INT_RE = re.compile(r"^-?\d{1,19}$")
_URL_RE = re.compile(r"^https?://", re.I)
_FILEY_RE = re.compile(r"(\.(php|aspx?|jsp|html?|json|xml|png|jpe?g|pdf|txt|csv|zip|conf|ya?ml)$|/)", re.I)

# name-token -> type (checked when the value is absent/ambiguous)
_NAME_TYPE_TOKENS = [
    ("numeric_id", ("id", "uid", "userid", "user_id", "account_id", "acct", "pid", "oid",
                    "num", "no", "order_id", "invoice_id", "object_id", "record")),
    ("email",      ("email", "mail", "e_mail", "to", "recipient")),
    ("file_path",  ("file", "path", "page", "template", "doc", "document", "include",
                    "filename", "filepath", "load", "dir", "folder", "attachment")),
    ("url",        ("url", "uri", "redirect", "return", "returnurl", "return_url", "next",
                    "callback", "link", "dest", "destination", "continue", "image_url", "webhook")),
    ("token",      ("token", "key", "secret", "auth", "session", "sid", "jwt", "access_token",
                    "api_key", "apikey", "csrf", "nonce", "signature")),
    ("search",     ("search", "q", "query", "filter", "sort", "order", "keyword", "term",
                    "category", "tag", "ref", "s")),
    ("json",       ("json", "data", "payload", "body", "params", "attributes", "properties")),
    ("boolean",    ("is_", "has_", "enable", "enabled", "disable", "active", "flag",
                    "admin", "is_admin", "debug", "verified", "approved")),
]


def infer_param_type(name: str, value: Any = None) -> str:
    """Classify a parameter by data type. Observed value wins over the name
    (a value is ground truth); falls back to name tokens, then 'unknown'."""
    v = "" if value is None else str(value).strip()
    if v and v.lower() not in ("none", "null", "undefined"):
        if _INT_RE.match(v):
            return "numeric_id"
        if _UUID_RE.match(v):
            return "uuid"
        if _EMAIL_RE.match(v):
            return "email"
        if v[:1] in ("{", "["):
            return "json"
        if v.lower() in ("true", "false", "0", "1", "yes", "no"):
            return "boolean"
        if _URL_RE.match(v):
            return "url"
        if _FILEY_RE.search(v):
            return "file_path"

    n = (name or "").strip().lower()
    if n:
        # exact-ish first: bare "id" or "*_id"
        if n == "id" or n.endswith("_id") or n.endswith("id") and len(n) <= 6:
            return "numeric_id"
        words = re.split(r"[_\-.]+", n)
        for ptype, tokens in _NAME_TYPE_TOKENS:
            for tok in tokens:
                if tok.endswith("_"):           # prefix token (is_, has_)
                    if n.startswith(tok):
                        return ptype
                elif tok == n or tok in words:  # exact name or whole underscore/dash word
                    return ptype
        # Substring match only for distinctive (>=5 char) tokens, so short
        # tokens like "no"/"id"/"q" can't match inside unrelated words
        # ("unknown" contains "no", "profile" contains "file").
        for ptype, tokens in _NAME_TYPE_TOKENS:
            if any(len(tok) >= 5 and tok in n for tok in tokens):
                return ptype
    return "unknown"


# ── Endpoint FUNCTION grouping ───────────────────────────────────────────────
_ENDPOINT_GROUPS = [
    ("auth",     ("login", "logout", "signin", "sign-in", "signup", "sign-up", "register",
                  "auth", "oauth", "sso", "password", "passwd", "reset", "forgot", "token",
                  "session", "mfa", "2fa", "otp", "verify", "activate", "credential")),
    ("payments", ("pay", "payment", "checkout", "billing", "invoice", "card", "charge",
                  "subscription", "subscribe", "wallet", "transfer", "transaction", "balance",
                  "refund", "payout", "order", "cart", "coupon", "price")),
    ("admin",    ("admin", "manage", "management", "dashboard", "console", "backend",
                  "internal", "superuser", "root", "config", "settings", "setup", "staff",
                  "moderator", "sysadmin", "control")),
    ("upload",   ("upload", "import", "attachment", "media", "avatar", "file", "image",
                  "document", "export", "download")),
    ("user",     ("user", "account", "profile", "me", "member", "customer", "contact",
                  "address", "preference")),
    ("api",      ("api", "graphql", "rest", "/v1", "/v2", "/v3", ".json", "rpc", "webhook",
                  "endpoint", "swagger", "openapi")),
]


def _endpoint_str(ep: Any) -> str:
    if isinstance(ep, dict):
        return str(ep.get("url") or ep.get("endpoint") or ep.get("path") or "")
    return str(ep or "")


def group_endpoints(endpoints: List[Any]) -> Dict[str, List[str]]:
    """Bucket endpoints by function. An endpoint can land in several groups
    (e.g. /api/admin/users -> api + admin + user). 'other' collects anything
    unmatched so nothing is silently dropped."""
    groups: Dict[str, List[str]] = {g: [] for g, _ in _ENDPOINT_GROUPS}
    groups["other"] = []
    seen_any = set()
    for ep in endpoints or []:
        url = _endpoint_str(ep)
        if not url:
            continue
        low = url.lower()
        matched = False
        for gname, tokens in _ENDPOINT_GROUPS:
            if any(tok in low for tok in tokens):
                if url not in groups[gname]:
                    groups[gname].append(url)
                matched = True
                seen_any.add(url)
        if not matched and url not in groups["other"]:
            groups["other"].append(url)
    # Drop empty buckets for a clean result.
    return {g: v for g, v in groups.items() if v}


# Which functional groups are worth hitting first.
_GROUP_PRIORITY = {"admin": 0, "payments": 1, "auth": 2, "upload": 3, "user": 4, "api": 5, "other": 9}


def _collect_params(target) -> List[Dict[str, Any]]:
    """Gather discovered parameters (with any observed value + the url they
    were seen on) from the places recon writes them."""
    st = target.state if hasattr(target, "state") and isinstance(target.state, dict) else {}
    out: List[Dict[str, Any]] = []
    seen = set()

    def add(name, value=None, url=""):
        key = (str(name).strip().lower(), str(url))
        if not name or key in seen:
            return
        seen.add(key)
        out.append({"param": str(name), "value": value, "url": url})

    # plain parameter names
    for p in st.get("parameters", []) or []:
        if isinstance(p, dict):
            add(p.get("name") or p.get("param"), p.get("value"), p.get("url", ""))
        else:
            add(p)
    # spider_intel parameters
    intel = st.get("spider_intel") or {}
    for p in (intel.get("parameters") or []):
        add(p if not isinstance(p, dict) else (p.get("name") or p.get("param")),
            (p.get("value") if isinstance(p, dict) else None),
            (p.get("url", "") if isinstance(p, dict) else ""))
    # hydra param_signals carry url+parameter
    for sig in st.get("param_signals", []) or []:
        if isinstance(sig, dict):
            add(sig.get("parameter") or sig.get("param"), None, sig.get("url", ""))
    return out


def build_surface_map(target) -> Dict[str, Any]:
    """Assemble the typed, prioritized attack surface for this target from its
    stored recon. Returns param-type table + endpoint groups + a ranked fuzz
    plan (high-value functional groups first)."""
    st = target.state if hasattr(target, "state") and isinstance(target.state, dict) else {}
    endpoints = list(st.get("endpoints", []) or [])
    intel = st.get("spider_intel") or {}
    endpoints += list(intel.get("endpoints", []) or [])

    params = _collect_params(target)
    typed_params = []
    for p in params:
        ptype = infer_param_type(p["param"], p.get("value"))
        typed_params.append({
            "param": p["param"],
            "type": ptype,
            "seen_on": p.get("url", ""),
            "test_family": PARAM_TYPE_TESTS.get(ptype, PARAM_TYPE_TESTS["unknown"]),
        })

    endpoint_groups = group_endpoints(endpoints)

    # Ranked fuzz plan: one entry per functional group, ordered by priority,
    # each annotated with the typed params worth throwing at it.
    plan = []
    for gname in sorted(endpoint_groups, key=lambda g: _GROUP_PRIORITY.get(g, 9)):
        plan.append({
            "group": gname,
            "priority": _GROUP_PRIORITY.get(gname, 9),
            "endpoint_count": len(endpoint_groups[gname]),
            "sample_endpoints": endpoint_groups[gname][:5],
        })

    # Count param types for a quick summary.
    type_counts: Dict[str, int] = {}
    for tp in typed_params:
        type_counts[tp["type"]] = type_counts.get(tp["type"], 0) + 1

    return {
        "param_types": typed_params,
        "param_type_counts": type_counts,
        "endpoint_groups": endpoint_groups,
        "fuzz_plan": plan,
        "summary": _summarize(typed_params, endpoint_groups, type_counts),
    }


def _summarize(typed_params, endpoint_groups, type_counts) -> str:
    if not typed_params and not endpoint_groups:
        return ("No parameters or endpoints mapped yet — run spider/katana/content_discovery "
                "first, then call map_surface again.")
    parts = []
    if endpoint_groups:
        hi = [g for g in ("admin", "payments", "auth") if g in endpoint_groups]
        if hi:
            parts.append("high-value endpoint groups present: " + ", ".join(
                f"{g} ({len(endpoint_groups[g])})" for g in hi))
    if type_counts:
        top = sorted(type_counts.items(), key=lambda kv: -kv[1])[:4]
        parts.append("param types: " + ", ".join(f"{t}×{c}" for t, c in top))
    return ("Attack surface mapped — " + "; ".join(parts) + ". Work the high-priority groups first, "
            "and fuzz each param with its type-appropriate family (see test_family).") if parts else \
           "Surface mapped, but nothing high-signal stood out yet."
