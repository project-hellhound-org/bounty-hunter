"""
hellhound/core/verify_engine.py — independent, code-level signal checking
for findings, to sit alongside (never replace) the existing VERIFICATION
GATE in agent.py's `_execute_record_finding`.

Why this exists: simply replaying a captured request and reporting the
HTTP status code proves a request was SENT, not that the vulnerability
actually fired (that was all the retired ReproEngine ever did). The
VERIFICATION GATE
added earlier (`_VERIFICATION_REQUIRED_CLASSES` in agent.py) requires the
model to explicitly set `verified=true` with a substantive
`verification_note` before sqli/xss/ssrf/idor/access-control findings can
be recorded at critical/high severity — but that's still the model
self-attesting from its own reading of a response, with nothing
code-level actually checking the claim.

This module adds the thing a careful human researcher does before filing:
a POSITIVE assertion (does the response actually show the vulnerability's
real signal — a SQL error string, a reflected-unescaped payload, a cloud
metadata credential, an evaluated template expression, a CORS header
combination that's actually exploitable) and, when a negative control
response is supplied, a DIFFERENTIAL check (does that signal disappear
when the vulnerable input is removed — ruling out "this is just a normal
error page" false positives).

IMPORTANT — this does NOT weaken or replace the VERIFICATION GATE:
- It has no write access to target.findings and cannot record anything.
- A `no_verifier_for_class` or `inconclusive` result is not a pass — the
  gate's own verified=true + substantive verification_note requirement
  is untouched either way, per AGENTS.md rule 2 ("you may strengthen
  [these checks]... never remove them, add a bypass flag, or loosen what
  counts as substantive").
- idor/access-control-category findings now have a real verifier
  (`verify_idor`, below) now that the two-account primitive
  (`capture_identity`/`swap_session` in agent.py) exists to produce a
  genuine attacker-vs-victim pair of responses. Like every other
  verifier here, it is still just a signal check on response dicts the
  CALLER captured — it issues no network traffic itself, and a
  `verified` result from it still does not set `verified=true` on the
  finding by itself; `verify_finding`/`_execute_record_finding` decide
  that, exactly as for every other class.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
import re


@dataclass
class VerifyResult:
    verified: bool
    status: str  # "verified" | "refuted" | "inconclusive" | "no_verifier_for_class"
    reason: str
    positive_evidence: Optional[str] = None
    negative_evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verified": self.verified,
            "status": self.status,
            "reason": self.reason,
            "positive_evidence": self.positive_evidence,
            "negative_evidence": self.negative_evidence,
        }


def _body_of(resp: Optional[Dict[str, Any]]) -> str:
    if not isinstance(resp, dict):
        return ""
    return str(resp.get("body_preview") or resp.get("body") or "")


def _headers_of(resp: Optional[Dict[str, Any]]) -> Dict[str, str]:
    if not isinstance(resp, dict):
        return {}
    h = resp.get("headers") or {}
    return {str(k).lower(): str(v) for k, v in h.items()} if isinstance(h, dict) else {}


# ── SQLi ─────────────────────────────────────────────────────────────────
_SQLI_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "unclosed quotation mark",
    "quoted string not properly terminated", "ora-01756", "ora-00933",
    "sqlite3.operationalerror", "pg_query(): query failed", "psql:",
    "odbc sql server driver", "microsoft ole db provider for sql server",
    "warning: mysqli", "syntax error at or near", "unterminated quoted string",
    "supplied argument is not a valid mysql", "sqlstate[",
    "you have an error in your sql syntax",
]


def verify_sqli(positive: Dict[str, Any], negative: Optional[Dict[str, Any]], args: Dict[str, Any]) -> VerifyResult:
    pos_body = _body_of(positive).lower()
    hit = next((s for s in _SQLI_ERROR_SIGNATURES if s in pos_body), None)
    if hit:
        if negative is not None:
            if hit in _body_of(negative).lower():
                return VerifyResult(False, "refuted",
                    f"error signature '{hit}' is present in BOTH the payload response and the control "
                    f"response — not injection-specific (looks like a generic error page), not confirmed.",
                    positive_evidence=hit)
            return VerifyResult(True, "verified",
                f"SQL error signature '{hit}' present in the payload response and absent from the control.",
                positive_evidence=hit, negative_evidence="absent in control")
        return VerifyResult(True, "verified",
            f"SQL error signature '{hit}' present in the response (no control supplied — can't fully rule "
            f"out a generic error page; a control replay would make this stronger).",
            positive_evidence=hit)

    expected_marker = args.get("expected_marker")
    if expected_marker:
        pos_has = expected_marker in _body_of(positive)
        if pos_has:
            if negative is not None and expected_marker in _body_of(negative):
                return VerifyResult(False, "refuted",
                    "expected boolean-true marker is present in BOTH payload and control responses — not "
                    "conditional on the injection.", positive_evidence=expected_marker)
            return VerifyResult(True, "verified",
                f"expected boolean-true marker '{expected_marker}' present in the payload response"
                + (" and absent from the control." if negative is not None else " (no control supplied)."),
                positive_evidence=expected_marker)

    return VerifyResult(False, "inconclusive",
        "no known SQL error signature in the response body, and no expected_marker match. For boolean/"
        "blind SQLi pass expected_marker (a string that should appear only on the TRUE-condition payload); "
        "for time-based SQLi this verifier can't assert timing — check elapsed_ms yourself.")


# ── SSRF ─────────────────────────────────────────────────────────────────
_SSRF_METADATA_MARKERS = [
    "ami-id", "instance-id", "iam/security-credentials", "accesskeyid",
    "computemetadata", "akia", "metadata-flavor", "secretaccesskey",
    "x-aws-ec2-metadata-token",
]


def verify_ssrf(positive: Dict[str, Any], negative: Optional[Dict[str, Any]], args: Dict[str, Any]) -> VerifyResult:
    body = _body_of(positive).lower()
    hit = next((m for m in _SSRF_METADATA_MARKERS if m in body), None)
    if hit:
        return VerifyResult(True, "verified",
            f"cloud metadata/credential marker '{hit}' present in the response body — the server-side "
            f"request reached an internal metadata service and returned its contents.",
            positive_evidence=hit)
    expected_marker = args.get("expected_marker")
    if expected_marker and expected_marker.lower() in body:
        return VerifyResult(True, "verified",
            f"expected out-of-band/internal-only marker '{expected_marker}' present in the response.",
            positive_evidence=expected_marker)
    return VerifyResult(False, "inconclusive",
        "no cloud-metadata/credential marker found in the response body. If this SSRF targets something "
        "other than a cloud metadata service, pass expected_marker (e.g. a token your OOB listener logged), "
        "or confirm the out-of-band hit directly instead of relying on this verifier.")


# ── XSS ──────────────────────────────────────────────────────────────────
def verify_xss(positive: Dict[str, Any], negative: Optional[Dict[str, Any]], args: Dict[str, Any]) -> VerifyResult:
    # STRONGEST signal: real script execution confirmed in an actual
    # browser (hellhound/core/browser_control.py's 'confirm_script_execution'
    # action — a JS dialog genuinely fired, or the page's own running JS set
    # a marker), not just a text match against the response body. This is
    # additive/strengthening per AGENTS.md rule 2: the text-reflection check
    # below is untouched and still applies exactly as before whenever the
    # caller hasn't (or can't) run the browser-based check.
    if bool(args.get("execution_confirmed")):
        evidence = args.get("execution_evidence") or "execution_confirmed=true (see browser_control's confirm_script_execution result)"
        return VerifyResult(True, "verified",
            f"REAL script execution was confirmed in a headless browser — {evidence}. This is a stronger "
            f"signal than text reflection: the injected script actually ran (a JS dialog fired, or the "
            f"page's own code set a marker), not just that the payload text appears unescaped in the HTML.",
            positive_evidence=str(evidence))

    payload = args.get("payload") or args.get("xss_payload")
    if not payload:
        return VerifyResult(False, "inconclusive",
            "no 'payload' argument supplied — pass the exact injected string so reflection can be checked. "
            "For a stronger check than text reflection, drive the same request through browser_control and "
            "call action='confirm_script_execution' with a unique marker, then pass execution_confirmed=true "
            "(and execution_evidence=<its evidence string>) here instead.")
    body = _body_of(positive)
    if payload in body:
        return VerifyResult(True, "verified",
            "the exact payload reflects verbatim (unescaped) in the response body. This confirms the HTML "
            "sink is unescaped — it does NOT by itself confirm a script actually ran (escaped-but-present "
            "text, a dead context, or CSP could still block real execution). For a stronger result: goto the "
            "same URL via browser_control, call action='confirm_script_execution' with a unique marker the "
            "payload executes (e.g. alert('<marker>') or window.__hh_xss_proof='<marker>'), then re-call "
            "this with execution_confirmed=true.",
            positive_evidence=payload)
    escaped_variants = [
        payload.replace("<", "&lt;").replace(">", "&gt;"),
        payload.replace('"', "&quot;").replace("'", "&#39;"),
    ]
    if any(v in body for v in escaped_variants if v and v != payload):
        return VerifyResult(False, "refuted",
            "the payload text is present but HTML-entity-encoded in the response — looks escaped, not "
            "exploitable as reflected XSS as sent.")
    return VerifyResult(False, "inconclusive",
        "payload not found anywhere in the captured response body — check that the right response "
        "(the one actually containing the reflection, e.g. after a redirect) was captured.")


# ── SSTI ─────────────────────────────────────────────────────────────────
_SSTI_CANARIES = {
    "{{7*7}}": "49", "${7*7}": "49", "#{7*7}": "49", "<%= 7*7 %>": "49",
    "{{4*7}}": "28", "${4*7}": "28",
}


def verify_ssti(positive: Dict[str, Any], negative: Optional[Dict[str, Any]], args: Dict[str, Any]) -> VerifyResult:
    body = _body_of(positive)
    payload = str(args.get("payload") or "")
    expected = args.get("expected_result") or _SSTI_CANARIES.get(payload)
    if not expected:
        return VerifyResult(False, "inconclusive",
            "couldn't determine the expected evaluated result — pass expected_result explicitly, or use a "
            "known math canary payload like '{{7*7}}'.")
    if re.search(rf"(?<!\d){re.escape(str(expected))}(?!\d)", body):
        return VerifyResult(True, "verified",
            f"the template expression evaluated to '{expected}' in the response body — server-side template "
            f"evaluation confirmed, not just payload reflection.",
            positive_evidence=str(expected))
    if payload and payload in body:
        return VerifyResult(False, "refuted",
            "the raw payload is reflected verbatim but did NOT evaluate to the expected result — looks like "
            "plain reflection/XSS, not server-side template injection.")
    return VerifyResult(False, "inconclusive",
        f"neither the evaluated result ('{expected}') nor the raw payload appear in the response body.")


# ── CORS misconfiguration ───────────────────────────────────────────────
def verify_cors(positive: Dict[str, Any], negative: Optional[Dict[str, Any]], args: Dict[str, Any]) -> VerifyResult:
    headers = _headers_of(positive)
    acao = headers.get("access-control-allow-origin")
    acac = (headers.get("access-control-allow-credentials") or "").strip().lower()
    origin_sent = str(args.get("origin_sent") or "").strip()

    if not acao:
        return VerifyResult(False, "inconclusive",
            "no Access-Control-Allow-Origin header in the response — nothing to evaluate.")
    if acao == "*" and acac == "true":
        # Invalid per the Fetch spec, but some stacks honor it anyway — a real misconfig when they do.
        return VerifyResult(True, "verified",
            "ACAO: * combined with ACAC: true — spec-invalid but some stacks still honor both headers "
            "together, which is a real credentialed cross-origin read bug when they do.",
            positive_evidence=f"ACAO={acao}, ACAC={acac}")
    if origin_sent and acao.strip() == origin_sent and acac == "true":
        return VerifyResult(True, "verified",
            f"the server reflected the attacker-supplied Origin ('{origin_sent}') back in ACAO with "
            f"ACAC: true — any origin can read credentialed responses.",
            positive_evidence=f"ACAO={acao}, ACAC={acac}")
    return VerifyResult(False, "refuted",
        f"ACAO is present ('{acao}') but not reflecting an arbitrary attacker-supplied origin with "
        f"credentials allowed — not exploitable as a credentialed cross-origin read as tested.",
        positive_evidence=f"ACAO={acao}, ACAC={acac or 'unset'}")


# ── IDOR / Broken Access Control ────────────────────────────────────────
def verify_idor(positive: Dict[str, Any], negative: Optional[Dict[str, Any]], args: Dict[str, Any]) -> VerifyResult:
    """
    `positive` is the response from requesting a victim's resource WHILE
    ACTING AS THE ATTACKER (i.e. captured after swap_session("attacker")
    or similar — the request itself must carry the attacker's own
    session, with the victim's resource id/path in the URL). `negative`
    is optional: the SAME request repeated with no session at all
    (anonymous) or with a session that should never be granted access —
    used to tell "this endpoint just doesn't require auth at all" apart
    from "the attacker's own authorization was bypassed."

    `args["victim_marker"]` is required: a string that should appear ONLY
    in a response that actually belongs to the victim (e.g. the victim's
    email, a unique order/invoice number, a field value the attacker's
    own account could never legitimately produce). Without a marker this
    verifier has no way to distinguish "got 200 with someone else's data"
    from "got 200 with a generic/empty/error page" — status code alone
    proves nothing for IDOR.
    """
    victim_marker = args.get("victim_marker")
    if not victim_marker:
        return VerifyResult(False, "inconclusive",
            "no 'victim_marker' argument supplied — pass a string unique to the victim's own data (their "
            "email, an order ID, an account name) so this verifier can confirm the response actually "
            "contains someone else's data rather than just returning HTTP 200.")

    pos_status = positive.get("status_code")
    pos_body = _body_of(positive)
    if pos_status and int(pos_status) >= 400:
        return VerifyResult(False, "refuted",
            f"the attacker-session request for the victim's resource returned HTTP {pos_status} — access "
            f"was NOT granted, so there's nothing to verify as an IDOR here.")
    if victim_marker not in pos_body:
        return VerifyResult(False, "inconclusive",
            f"victim_marker '{victim_marker}' was not found in the attacker-session response body. Either "
            f"access was properly denied (check the actual status/body), or the marker doesn't match what "
            f"this endpoint actually returns — double-check it against a response you know belongs to the "
            f"victim.")

    if negative is not None:
        neg_status = negative.get("status_code")
        neg_body = _body_of(negative)
        if victim_marker in neg_body and (not neg_status or int(neg_status) < 400):
            return VerifyResult(False, "refuted",
                f"victim_marker '{victim_marker}' is present even in the control response (e.g. anonymous "
                f"or no-auth) — this endpoint isn't authorization-gated at all for anyone, which may still "
                f"be a real finding (broken access control / missing auth), but it is NOT a cross-account "
                f"IDOR specifically — the attacker's own identity made no difference.",
                positive_evidence=victim_marker, negative_evidence="victim_marker also present in control")
        return VerifyResult(True, "verified",
            f"victim_marker '{victim_marker}' is present in the response fetched using the ATTACKER's own "
            f"session, and absent/denied in the control — the attacker's authorization was bypassed to "
            f"read another account's data. Confirm the attacker and victim are genuinely different accounts "
            f"(not two sessions of the same user) before filing.",
            positive_evidence=victim_marker, negative_evidence="absent/denied in control")

    return VerifyResult(True, "verified",
        f"victim_marker '{victim_marker}' is present in the response fetched using the attacker's own "
        f"session (no control supplied — a control replay as anonymous or as the attacker's own resource "
        f"would make this stronger). Confirm the attacker and victim are genuinely different accounts "
        f"before filing.",
        positive_evidence=victim_marker)


VERIFIERS: Dict[str, Callable[[Dict[str, Any], Optional[Dict[str, Any]], Dict[str, Any]], VerifyResult]] = {
    "sqli": verify_sqli,
    "sql_injection": verify_sqli,
    "ssrf": verify_ssrf,
    "xss": verify_xss,
    "reflected_xss": verify_xss,
    "stored_xss": verify_xss,
    "dom_xss": verify_xss,
    "ssti": verify_ssti,
    "cors": verify_cors,
    "cors_misconfig": verify_cors,
    "cors_misconfiguration": verify_cors,
    "idor": verify_idor,
    "access_control": verify_idor,
    "broken_access_control": verify_idor,
    "bac": verify_idor,
}


def supported_classes() -> List[str]:
    return sorted(set(VERIFIERS.keys()))


def verify(kind: str, positive: Dict[str, Any], negative: Optional[Dict[str, Any]] = None,
           args: Optional[Dict[str, Any]] = None) -> VerifyResult:
    """
    Dispatch to the class-specific verifier for `kind`. `positive` and
    `negative` are response dicts shaped like _execute_curl's return value
    (status_code / headers / body_preview at minimum — anything with that
    shape works, this module never issues its own network requests).

    A `no_verifier_for_class` result is informational, not a failure —
    callers (agent.py's verify_finding tool) should say plainly that this
    vuln class has no automated check yet and fall back to the existing
    verified=true + verification_note path.
    """
    args = args or {}
    fn = VERIFIERS.get((kind or "").strip().lower())
    if not fn:
        return VerifyResult(False, "no_verifier_for_class",
            f"no automated verifier registered for kind={kind!r}. Supported: {supported_classes()}.")
    try:
        return fn(positive, negative, args)
    except Exception as e:
        return VerifyResult(False, "inconclusive",
            f"verifier raised an exception (treated as inconclusive, not a false pass): {e}")