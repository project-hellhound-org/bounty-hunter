"""
hellhound/core/js_intel.py — bundled sensitive-data / PII extraction from JS & HTML.

js_miner finds API endpoints; js_static_analysis/BlobUnpacker does sourcemaps.
Neither looks for the thing that's often the actual bug: a SPA baking sensitive
data straight into the page — framework state blobs (`__NEXT_DATA__`,
`window.__NUXT__`, `__INITIAL_STATE__`, `__APOLLO_STATE__`, `window.__INIT_PROFILE__`,
inline application/json) that carry a user's own record, OTHER users' records,
roles, hashes, tokens, or hardcoded API keys/JWTs/emails in the bundle. That's a
sensitive-data-exposure finding on its own, and often reveals IDs/roles that
turn into IDOR.

`scan_bundled_data(text, source_url)` is a pure function over one blob of
HTML/JS; it returns structured hits (type, severity, redacted sample, why).
Advisory only — the agent still has to confirm + record via the normal path.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

# Client-side state blobs that routinely embed real records.
_STATE_MARKERS = [
    ("__NEXT_DATA__", re.compile(r"__NEXT_DATA__")),
    ("window.__NUXT__", re.compile(r"window\.__NUXT__")),
    ("__INITIAL_STATE__", re.compile(r"__(?:INITIAL|PRELOADED)_STATE__")),
    ("__APOLLO_STATE__", re.compile(r"__APOLLO_STATE__")),
    ("INIT_PROFILE", re.compile(r"__?INIT_PROFILE__?")),
    ("inline application/json", re.compile(r'<script[^>]*type=["\']application/json["\']', re.I)),
]

# Keys that, when present in a bundled blob, mean real sensitive data is exposed.
_SENSITIVE_KEY_RE = re.compile(
    r'["\'](email|e-mail|password|passwd|pwd|password_?hash|ssn|social_?security|'
    r'api_?key|secret|access_?token|refresh_?token|auth_?token|credit_?card|card_?number|'
    r'cvv|phone|mobile|address|dob|date_?of_?birth|salary|balance|wallet|private_?key|'
    r'session_?id|is_?admin|role|user_?id)["\']\s*:',
    re.I,
)

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b")
_APIKEY_RE = re.compile(
    r"\b(?:sk_live_[A-Za-z0-9]{16,}|sk_test_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_\-]{20,}|ghp_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_\-]{18,}|"
    r"xox[baprs]-[A-Za-z0-9\-]{10,})\b"
)
# Emails that are almost never real user PII (placeholders, vendor noise).
_EMAIL_NOISE = (
    "example.com", "example.org", "example.net", "sentry.io", "@sentry", "yourdomain",
    "domain.com", "email.com", "test@test", "user@example", "name@", "you@", "your@",
    "no-reply@", "noreply@", "support@sentry", "placeholder", "@2x", "@3x", "w3.org",
    "schema.org", "googleapis", "gstatic",
)


def _redact(s: str) -> str:
    s = str(s)
    if len(s) <= 10:
        return s[:3] + "…"
    return s[:8] + "…" + s[-4:]


def _real_emails(blob: str) -> List[str]:
    out = []
    for e in _EMAIL_RE.findall(blob):
        el = e.lower()
        if any(n in el for n in _EMAIL_NOISE):
            continue
        if e not in out:
            out.append(e)
    return out


def scan_bundled_data(text: str, source_url: str = "") -> List[Dict[str, Any]]:
    """Scan one HTML/JS blob for bundled sensitive data / PII. Returns hits."""
    hits: List[Dict[str, Any]] = []
    if not text or not isinstance(text, str):
        return hits

    # 1. Framework state blobs — scan a window after each marker for sensitive keys/emails.
    _seen_state = set()  # dedup overlapping markers over the same blob (e.g. __NEXT_DATA__ IS inline json)
    for name, rx in _STATE_MARKERS:
        m = rx.search(text)
        if not m:
            continue
        window = text[m.end(): m.end() + 20000]
        keys = sorted({k.lower().replace("-", "_").replace(" ", "") for k in _SENSITIVE_KEY_RE.findall(window)})
        emails = _real_emails(window)
        _sig = (tuple(keys), len(emails))
        if (keys or emails) and _sig in _seen_state:
            continue
        if keys or emails:
            _seen_state.add(_sig)
            # Treat it as high only if it carries actually-identifying/secret keys
            # or more than one real email (a list of users), else medium.
            strong = bool(emails) or any(k in keys for k in (
                "email", "password", "password_hash", "ssn", "api_key", "secret",
                "access_token", "auth_token", "credit_card", "card_number", "private_key", "wallet"))
            hits.append({
                "type": "bundled_state",
                "blob": name,
                "severity": "high" if strong else "medium",
                "sensitive_keys": keys[:14],
                "emails_found": len(emails),
                "email_sample": emails[:8],
                "source": source_url,
                "why": (f"{name} is baked into the page and carries sensitive fields "
                        f"({', '.join(keys[:6]) or 'user records'}" + (f", {len(emails)} email(s)" if emails else "") + "). "
                        "Client-side state that embeds a user's own or OTHER users' records is a sensitive-data-exposure "
                        "finding, and the IDs/roles in it frequently enable IDOR. Pull the blob and confirm it contains "
                        "data the current user shouldn't see."),
            })

    # 2. Hardcoded JWTs.
    for tok in dict.fromkeys(_JWT_RE.findall(text)):
        hits.append({"type": "jwt", "severity": "high", "sample": _redact(tok), "source": source_url,
                     "why": "A JWT embedded in client-side code — decode it (cookie_inspector/jwt_forge); may be a live session or a signing-key/claims leak."})

    # 3. Hardcoded API keys / provider tokens.
    for key in dict.fromkeys(_APIKEY_RE.findall(text)):
        hits.append({"type": "api_key", "severity": "high", "sample": _redact(key), "source": source_url,
                     "why": "A live-looking API key/provider token hardcoded in client-side code — test and report as a secret exposure."})

    # 4. Loose emails outside a state blob (user/employee enumeration).
    emails = _real_emails(text)
    if emails and not any(h["type"] == "bundled_state" for h in hits):
        hits.append({"type": "emails", "severity": "medium", "count": len(emails),
                     "email_sample": emails[:10], "source": source_url,
                     "why": "Real email addresses embedded in client-side code — fuel user/employee enumeration and phishing, and often flag bundled user data worth a closer look."})

    return hits


def summarize_bundled_hits(hits: List[Dict[str, Any]]) -> str:
    if not hits:
        return ""
    highs = [h for h in hits if h.get("severity") == "high"]
    kinds: Dict[str, int] = {}
    for h in hits:
        kinds[h["type"]] = kinds.get(h["type"], 0) + 1
    parts = ", ".join(f"{n}× {t}" for t, n in kinds.items())
    lead = f"{len(highs)} high-severity" if highs else "potential"
    return (f"Bundled-data scan: {lead} client-side exposure(s) — {parts}. "
            "Treat state blobs with other users' records / secrets as sensitive-data-exposure; "
            "confirm the data is cross-user or non-public, then verify_finding + record_finding.")
