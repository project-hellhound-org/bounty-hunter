"""
hellhound/core/hypothesis_engine.py — tech-stack-driven hypothesis
generation, so the agent can reason "this target is PHP + this CMS, so it
probably has THESE vuln classes, test THEM first" the way a human
researcher (or a tool like XBOW/Horizon3) does, instead of defaulting to
"enumerate the tool arsenal in order and see what sticks."

This is deliberately a SIGNAL ENGINE, not an execution engine: it never
sends network traffic, never records a finding, and a hypothesis it
generates is a LEAD to go test, not a claim of anything confirmed. Nothing
here touches the VERIFICATION GATE or the EVIDENCE GUARDRAIL in
`_execute_record_finding` — a hypothesis becomes a finding only the normal
way, by the model actually testing it and then calling record_finding
(gated exactly as before). See AGENTS.md rule 2 — this module adds a new
kind of lead, it does not add a new way to skip verification.

Design, deliberately kept simple for a first slice:
- A flat table of RULES, each keyed on a cheap, explainable signal (a
  tech-stack token, an endpoint-path pattern, a response header) and
  producing one or more Hypothesis objects with a plain-English rationale
  and a concrete test sketch — something a researcher (or the model) can
  act on immediately, not just a vuln-class name.
- `generate()` runs every rule against whatever's actually known about the
  target (tech_stack list + endpoints + headers + a few flags), dedupes to
  the HIGHEST-confidence hypothesis per vuln_class, and returns them
  ranked confidence-desc. No ML, no LLM call, no network — pure pattern
  matching over strings already sitting in target.state, so it's instant
  and fully deterministic (same inputs -> same ranked list every time,
  which also makes it trivially testable).
- This intentionally overlaps in spirit with pattern_db.py (cross-target
  "this technique worked before") but is a different axis: pattern_db
  answers "what has actually WORKED on a stack like this, from real
  confirmed findings," while this module answers "what SHOULD be tried
  on a stack like this, from general knowledge of the technology," even
  on the very first target of that stack ever seen. agent.py's
  generate_hypotheses tool merges both: static rules here, plus a
  pattern_db.match() lookup folded in as extra-high-confidence leads when
  a prior confirmed technique matches this target's stack too.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
import re


CONFIDENCE_ORDER = {"high": 3, "medium": 2, "low": 1}


@dataclass
class Hypothesis:
    vuln_class: str
    confidence: str  # "high" | "medium" | "low"
    rationale: str
    test_sketch: str
    signal: str  # what specifically triggered this (for transparency/debugging)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_class": self.vuln_class,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "test_sketch": self.test_sketch,
            "signal": self.signal,
        }


def _norm_tokens(items: Optional[List[Any]]) -> Set[str]:
    out = set()
    for it in (items or []):
        s = str(it).strip().lower()
        if s:
            out.add(s)
    return out


def _any_token_contains(tokens: Set[str], *substrings: str) -> Optional[str]:
    """Returns the first matching token (for the 'signal' field) or None."""
    for tok in tokens:
        for sub in substrings:
            if sub in tok:
                return tok
    return None


def _endpoints_matching(endpoints: List[str], *patterns: str) -> List[str]:
    hits = []
    for ep in endpoints or []:
        low = str(ep).lower()
        if any(p in low for p in patterns):
            hits.append(ep)
    return hits


_NUMERIC_ID_PATH_RE = re.compile(r"/(?:[a-z_]+/)?\d+(?:/|$|\?)")


def _endpoints_with_numeric_ids(endpoints: List[str]) -> List[str]:
    return [ep for ep in (endpoints or []) if _NUMERIC_ID_PATH_RE.search(str(ep).lower())]


# ──────────────────────────────────────────────────────────────────────────
# Rule table. Each rule is a function (tech, endpoints, headers, ctx) ->
# list[Hypothesis] | None. Kept as plain functions (not a declarative data
# table) so each rule can use whatever matching logic actually makes sense
# for it, while staying independently testable and easy to read top-to-
# bottom as "if you see X, consider Y."
# ──────────────────────────────────────────────────────────────────────────

def _rule_wordpress(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    hit = _any_token_contains(tech, "wordpress", "wp-")
    if not hit and not _endpoints_matching(endpoints, "/wp-content/", "/wp-json/", "/wp-admin/"):
        return []
    sig = hit or "wp-* path discovered"
    return [
        Hypothesis("xss", "medium",
            "WordPress sites accumulate XSS in plugins/themes far more than core — comment fields, "
            "search, and plugin-added shortcode parameters are the usual spots.",
            "Enumerate installed plugins/themes (wpscan_scan) and check their changelogs/CVE history "
            "for known XSS first; if none hit, probe comment/search fields with a standard XSS payload set.",
            sig),
        Hypothesis("auth_bypass", "low",
            "WordPress user enumeration via /wp-json/wp/v2/users or ?author=N, often followed by weak "
            "password/credential-stuffing attempts against wp-login.php or XML-RPC.",
            "wpscan_scan for user enumeration, then hydra against wp-login.php only with researcher-"
            "provided or confirmed-leaked credentials — never blind credential stuffing.",
            sig),
        Hypothesis("sqli", "low",
            "Older or poorly-audited WordPress plugins are a common source of unauthenticated SQLi in "
            "custom AJAX actions (admin-ajax.php?action=...).",
            "wpscan_scan for a plugin vulnerability match; if a plugin with a known SQLi CVE is present, "
            "verify_finding(kind='sqli') against its specific vulnerable parameter.",
            sig),
    ]


def _rule_laravel(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    hit = _any_token_contains(tech, "laravel")
    if not hit:
        return []
    return [
        Hypothesis("info_disclosure", "high",
            "Laravel apps left in APP_DEBUG=true dump the full stack trace, .env values, and APP_KEY on "
            "any unhandled exception — a single malformed request away from a secrets leak.",
            "curl an endpoint likely to throw (bad param type, missing required field) and check the "
            "response for a Whoops/Ignition debug page; also try GET /.env directly.",
            hit),
        Hypothesis("rce", "low",
            "A leaked Laravel APP_KEY (from the debug page above) enables PHP object deserialization "
            "RCE via a crafted signed cookie (the well-known Laravel APP_KEY RCE chain).",
            "Only pursue this AFTER confirming an APP_KEY leak via the info_disclosure hypothesis above — "
            "it's a chained finding, not a standalone test.",
            hit),
    ]


def _rule_rails(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    hit = _any_token_contains(tech, "rails", "ruby on rails", "ruby")
    if not hit:
        return []
    return [
        Hypothesis("mass_assignment", "medium",
            "Rails apps that skip or misconfigure strong parameters (permit!/attr_accessible-style "
            "gaps) let a client set model attributes that were never meant to be client-writable "
            "(role, admin flag, account_id) via an extra, unexpected form/JSON field.",
            "On a create/update endpoint, add an unexpected field matching a likely sensitive column "
            "name (admin, role, is_admin, account_id) to the request body and check whether it actually "
            "took effect on the created/updated record.",
            hit),
        Hypothesis("insecure_deserialization", "low",
            "Older Rails apps (or anything still calling YAML.load / Marshal.load on user-controlled "
            "data, a recurring historical Rails CVE pattern) can hit remote code execution via a "
            "crafted serialized payload.",
            "Look for any endpoint that accepts a serialized blob (a 'state', 'data', or cookie-backed "
            "value) and check the Rails/gem versions in use against known YAML/Marshal deserialization "
            "CVEs before attempting a payload.",
            hit),
    ]


def _rule_drupal(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    hit = _any_token_contains(tech, "drupal")
    if not hit:
        return []
    return [
        Hypothesis("rce", "low",
            "Drupal has a recurring history of unauthenticated RCE via its render/form API and REST/"
            "JSON:API modules (the 'Drupalgeddon'-class issues) — version-dependent, but worth checking "
            "before anything else on a fingerprinted Drupal target.",
            "Identify the exact Drupal core/module versions (meta generator tag, CHANGELOG.txt, "
            "/core/CHANGELOG.txt) and check them against known Drupal core/contrib RCE advisories before "
            "attempting any payload.",
            hit),
        Hypothesis("broken_access_control", "low",
            "Drupal's node access system is permission-matrix-driven and easy to misconfigure per "
            "content type/view — a common source of content or user data reachable without the "
            "intended role.",
            "Enumerate node/entity IDs as an unauthenticated or low-privilege session and check whether "
            "restricted content (unpublished nodes, admin-only views) is still reachable directly.",
            hit),
    ]


def _rule_django(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    hit = _any_token_contains(tech, "django")
    if not hit:
        return []
    return [
        Hypothesis("info_disclosure", "high",
            "Django's DEBUG=True error page discloses the full request/settings dump including "
            "SECRET_KEY and installed apps on any 500 error.",
            "Trigger a 500 (malformed input, wrong content-type on a JSON endpoint) and check for the "
            "yellow Django debug page.",
            hit),
        Hypothesis("auth_bypass", "low",
            "The default /admin/ path is often left reachable; combined with a weak or default "
            "superuser credential this is a fast path to full control.",
            "Check whether /admin/ is reachable and whether it's rate-limited before any credential "
            "attempt — never brute-force without researcher-confirmed scope for that.",
            hit),
    ]


def _rule_flask(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    hit = _any_token_contains(tech, "flask", "jinja2", "werkzeug")
    if not hit:
        return []
    return [
        Hypothesis("ssti", "medium",
            "Flask/Jinja2 templates that interpolate user input directly (rather than via a safe "
            "context variable) are a classic SSTI source — '{{7*7}}' evaluating to 49 is the canary.",
            "Try the math canary payload '{{7*7}}' in any field that gets reflected back in rendered "
            "HTML, then verify_finding(kind='ssti', payload='{{7*7}}').",
            hit),
        Hypothesis("rce", "low",
            "Werkzeug's debugger, if left enabled, exposes an interactive Python console with a PIN "
            "that's sometimes derivable or defaults to being unset in misconfigured deployments.",
            "Trigger an unhandled exception and check whether the Werkzeug interactive debugger page "
            "(not just a generic 500) is served.",
            hit),
    ]


def _rule_node_nosql(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    hit = _any_token_contains(tech, "express", "node.js", "nodejs", "mongodb", "mongoose")
    if not hit:
        return []
    out = [
        Hypothesis("nosqli", "medium",
            "Express/Node APIs backed by MongoDB are routinely vulnerable to operator-injection NoSQLi "
            "when request bodies are parsed as JSON and passed straight into a query ($ne, $gt, $regex).",
            "On a login or filter endpoint, try a JSON body like {\"username\":\"admin\",\"password\":"
            "{\"$ne\":null}} instead of a string password and watch for an auth bypass.",
            hit),
    ]
    if _any_token_contains(tech, "express", "node.js", "nodejs"):
        out.append(Hypothesis("rce", "low",
            "Node.js apps using lodash/merge-style deep-merge on user input (common in config/settings "
            "endpoints) are a classic prototype-pollution-to-RCE source.",
            "Probe any JSON-accepting PATCH/PUT endpoint with a '__proto__' key in the body and check "
            "for behavior changes elsewhere in the app afterward.",
            hit))
    return out


def _rule_spring_java(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    hit = _any_token_contains(tech, "spring", "springboot", "spring-boot", "java")
    if not hit and not _endpoints_matching(endpoints, "/actuator/"):
        return []
    sig = hit or "/actuator/ path discovered"
    return [
        Hypothesis("info_disclosure", "high",
            "Spring Boot Actuator endpoints (/actuator/env, /actuator/heapdump, /actuator/mappings), if "
            "left exposed, leak config, environment variables, and sometimes credentials directly.",
            "curl /actuator, /actuator/env, and /actuator/heapdump directly and check for JSON config "
            "or a downloadable heap dump.",
            sig),
        Hypothesis("rce", "low",
            "Older Spring versions are a frequent source of deserialization/expression-language RCE "
            "(SpEL injection, Spring4Shell-class issues) depending on exact version.",
            "Fingerprint the exact Spring Boot version (via /actuator/info or response headers) and "
            "check it against known CVEs before attempting anything.",
            sig),
    ]


def _rule_aspnet(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    hit = _any_token_contains(tech, "asp.net", "aspnet", "iis")
    if not hit:
        return []
    return [
        Hypothesis("rce", "low",
            "Unencrypted/weak-keyed ASP.NET ViewState can be tampered with to achieve deserialization "
            "RCE if the machine key is known, default, or leaked.",
            "Check whether __VIEWSTATE is present and whether __VIEWSTATEMAC validation is enforced; "
            "this is a specialist test (ysoserial.net-class tooling), not a quick curl check.",
            hit),
        Hypothesis("info_disclosure", "low",
            "IIS short-filename (8.3) disclosure can enumerate hidden file/directory names via "
            "crafted tilde (~) requests.",
            "Try a request like GET /somepa~1.aspx and compare 404 behavior against a known-nonexistent "
            "short name to confirm the technique works here.",
            hit),
    ]


def _rule_graphql(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    hit = _any_token_contains(tech, "graphql") or _endpoints_matching(endpoints, "/graphql")
    if not hit:
        return []
    sig = hit if isinstance(hit, str) else "graphql endpoint discovered"
    return [
        Hypothesis("info_disclosure", "high",
            "GraphQL introspection, if left enabled in production, hands over the entire schema — "
            "every type, field, and mutation — massively shortcutting recon for every other hypothesis.",
            "graphql_probe for introspection; if it succeeds, mine the schema for mutations that look "
            "under-authorized (admin-sounding names, bulk operations) before anything else.",
            sig),
        Hypothesis("idor", "medium",
            "GraphQL node-based APIs often resolve objects by a raw/guessable ID in a query variable "
            "with the same per-field authorization gaps as REST IDOR, just less visible without the "
            "schema from introspection.",
            "Once the schema is known, try querying an object type by a different numeric/UUID id than "
            "your own account's, under your own session, and check whether it resolves.",
            sig),
    ]


def _rule_jwt(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    hit = _any_token_contains(tech, "jwt") or bool(ctx.get("has_jwt"))
    if not hit:
        return []
    sig = hit if isinstance(hit, str) else "JWT-shaped token observed"
    return [
        Hypothesis("auth_bypass", "medium",
            "JWTs accepted with alg=none, or signed with a guessable/weak HMAC secret, let an attacker "
            "forge arbitrary claims (role=admin, user_id=<victim>) without knowing any real secret.",
            "jwt_forge to try alg=none and a common-secret-list HMAC brute force against a captured "
            "token; if either works, re-sign a token claiming elevated privilege and verify the server "
            "actually honors it.",
            sig),
    ]


def _rule_numeric_id_paths(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    hits = _endpoints_with_numeric_ids(endpoints)
    if not hits:
        return []
    return [
        Hypothesis("idor", "medium",
            f"{len(hits)} discovered endpoint(s) take a raw numeric id in the path (e.g. {hits[0]}) — "
            f"sequential/guessable IDs with per-object data are the single most common real-world IDOR "
            f"shape.",
            "capture_identity on two separate accounts, swap_session to the attacker, request a "
            "resource id that belongs to the other account, then verify_finding(kind='idor', "
            "victim_marker=<something unique to that account's data>).",
            hits[0]),
    ]


def _rule_file_upload(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    hits = _endpoints_matching(endpoints, "upload", "/media/", "/attachments/", "/files/")
    if not hits:
        return []
    return [
        Hypothesis("file_upload_rce", "low",
            f"An upload-shaped endpoint was discovered ({hits[0]}) — unrestricted file upload (missing "
            f"extension/MIME allowlisting, or a client-side-only check) is a common path straight to RCE "
            f"via a webshell.",
            "Try uploading a file with a server-executable extension (matching the stack's language) "
            "disguised with a double extension or a manipulated Content-Type, then check if it's "
            "reachable and executes at its stored URL.",
            hits[0]),
    ]


def _rule_ssrf_prone_features(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    hits = _endpoints_matching(endpoints, "webhook", "url=", "fetch", "proxy", "preview", "pdf", "screenshot", "import")
    if not hits:
        return []
    return [
        Hypothesis("ssrf", "medium",
            f"A feature that fetches a researcher-influenced URL server-side was discovered "
            f"({hits[0]}) — webhooks, URL previews, PDF/screenshot generation, and import-by-URL "
            f"features are the classic SSRF entry points.",
            "Point the URL parameter at an internal/metadata address (cloud metadata IP, localhost, an "
            "internal hostname) or an out-of-band listener, then verify_finding(kind='ssrf').",
            hits[0]),
    ]


def _rule_cors(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    acao = (headers or {}).get("access-control-allow-origin")
    if not acao:
        return []
    return [
        Hypothesis("cors", "low",
            f"An Access-Control-Allow-Origin header is already present on at least one response "
            f"('{acao}') — worth checking whether it reflects an arbitrary attacker Origin alongside "
            f"Access-Control-Allow-Credentials: true.",
            "cors_checker with an attacker-controlled Origin header against a credentialed endpoint, "
            "then verify_finding(kind='cors', origin_sent=<that origin>).",
            f"ACAO={acao}"),
    ]


_PARAM_SIGNAL_GROUPS = {
    "open_redirect": (("redirect", "url", "return", "returnurl", "return_url", "next", "callback",
                        "continue", "dest", "destination", "redir", "target", "to"),
        "A parameter named like a redirect/callback target ('{param}') was discovered — unvalidated "
        "open-redirect parameters are also the #1 enabler of OAuth/SSO account-takeover chains "
        "(see the oauth_sso hypothesis if one fires too).",
        "Set the parameter to an attacker-controlled external URL (https://attacker-controlled.example) "
        "and check whether the response actually redirects there instead of staying on-site or rejecting it."),
    "lfi": (("file", "path", "page", "template", "doc", "document", "include", "filename", "filepath", "load"),
        "A parameter named like a filesystem path/filename ('{param}') was discovered — a classic local "
        "file inclusion / path traversal entry point when the value is used to build a server-side file path.",
        "Try a path-traversal payload (../../../../etc/passwd or the Windows equivalent) and a null-byte/"
        "double-encoding variant if the first attempt is filtered, and check the response for file content "
        "instead of an error."),
    "sqli": (("search", "filter", "sort", "order", "query", "q", "keyword", "category", "ref"),
        "A parameter named like a search/filter/sort field ('{param}') was discovered — these commonly "
        "build a SQL WHERE/ORDER BY clause directly from the parameter value, a frequent unauthenticated "
        "SQLi entry point distinct from the login-form case.",
        "Try a single quote and a boolean-true/false pair (' OR '1'='1 vs ' OR '1'='2) and compare "
        "response differences, then verify_finding(kind='sqli') on whatever signature shows up."),
    "command_injection": (("cmd", "command", "exec", "execute", "ping", "host", "ip", "run", "shell"),
        "A parameter named like a system-command argument ('{param}') was discovered — a strong signal "
        "the backend shells out with this value (common in network-diagnostic-style features: ping, "
        "traceroute, DNS lookup tools).",
        "Try a command-separator payload (e.g. ; id or | id, adjusted to the likely OS/shell) and check "
        "for command output appearing in the response, or use an out-of-band ping/DNS callback to confirm "
        "blind execution."),
}


def _rule_param_name_signals(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    params = ctx.get("parameters") or []
    param_tokens = {str(p).strip().lower() for p in params if p}
    if not param_tokens:
        return []
    out = []
    for vuln_class, (name_tokens, rationale_tpl, test_sketch) in _PARAM_SIGNAL_GROUPS.items():
        hit = next((p for p in param_tokens if any(p == nt or p.endswith(f"_{nt}") or p.endswith(nt) for nt in name_tokens)), None)
        if hit:
            out.append(Hypothesis(vuln_class, "low",
                rationale_tpl.format(param=hit),
                test_sketch,
                f"parameter name: {hit}"))
    return out


# Role -> (vuln_class, confidence, rationale template, test sketch template).
# These roles come from hydra's actual per-parameter entropy/role analysis
# (hellhound/modules/analysis/Hydra.py's Cerberus engine) — a real signal
# about what a SPECIFIC discovered parameter looks like it does (admin
# flag, path reference, auth-sensitive, GraphQL-introspectable, an OAuth
# callback sink), not just a name-token guess the way _PARAM_SIGNAL_GROUPS
# above works. {param}/{url}/{impact} are filled in per finding.
_HYDRA_ROLE_VULN_MAP: Dict[str, tuple] = {
    "ADMIN_FLAG": ("broken_access_control", "medium",
        "hydra's parameter analysis flagged '{param}' on {url} as an admin/privilege-flag-shaped "
        "parameter (impact {impact}/10) — if the backend trusts this value from the client instead of "
        "the authenticated session's own role, flipping it is a direct privilege-escalation path.",
        "Replay the request with '{param}' changed to an admin/true/1-shaped value under a LOW-privilege "
        "session and check whether the response reflects elevated access instead of being rejected."),
    "AUTH_PARAM": ("broken_access_control", "medium",
        "hydra's parameter analysis flagged '{param}' on {url} as an auth-sensitive parameter (impact "
        "{impact}/10) — commonly a role/permission/account-scope value that the server should be deriving "
        "from the session, not trusting from the request.",
        "Use capture_identity/swap_session to hold two accounts, then replay the request as the lower-"
        "privileged one with '{param}' set to the higher-privileged value and check what comes back."),
    "PATH_REFERENCE": ("lfi", "medium",
        "hydra's parameter analysis flagged '{param}' on {url} as a filesystem-path-shaped parameter "
        "(impact {impact}/10) — a real occurrence in a discovered request, not just a name guess.",
        "Try a path-traversal payload (../../../../etc/passwd or the Windows equivalent) against this "
        "exact parameter/URL and check the response for file content instead of an error."),
    "GRAPHQL_INTROSPECTABLE": ("info_disclosure", "medium",
        "hydra's parameter analysis flagged {url} as GraphQL-introspectable (impact {impact}/10) — an "
        "open introspection query can disclose the full schema, including fields/mutations never meant "
        "to be publicly documented.",
        "Run graphql_probe against this endpoint and check whether a full introspection query succeeds "
        "unauthenticated."),
    "OAUTH_CALLBACK_SINK": ("open_redirect", "medium",
        "hydra's parameter analysis flagged '{param}' on {url} as an OAuth/SSO callback sink (impact "
        "{impact}/10) — the classic open-redirect-to-account-takeover chain if the callback/redirect "
        "target isn't strictly allowlisted.",
        "Check whether '{param}' accepts a value outside the registered redirect_uri allowlist, and "
        "whether the resulting auth code/token is actually usable once redirected off-site."),
}


def _rule_hydra_param_roles(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    """
    Consumes hydra's per-parameter role/impact findings (persisted by
    agent.py's _execute_hydra into target.state["param_signals"], passed
    in here as ctx["param_signals"]) — richer than _rule_param_name_signals
    above, which only ever sees bare discovered parameter NAMES. This rule
    sees what hydra actually determined about a parameter's likely role
    from where/how it showed up (admin flags, auth-sensitive values, path
    references, GraphQL introspectability, OAuth callback sinks), each
    anchored to the real url+parameter it was seen on, not a guess from
    the name alone.
    """
    signals = ctx.get("param_signals") or []
    if not isinstance(signals, list) or not signals:
        return []
    # Keep only the highest-impact finding per role so a target with many
    # similarly-flagged parameters doesn't flood the board with near-
    # duplicate hypotheses of the same class.
    best_by_role: Dict[str, Dict[str, Any]] = {}
    for sig in signals:
        if not isinstance(sig, dict):
            continue
        roles = sig.get("roles") or []
        impact = sig.get("impact_score", 0) or 0
        for role in roles:
            if role not in _HYDRA_ROLE_VULN_MAP:
                continue
            current = best_by_role.get(role)
            if current is None or impact > (current.get("impact_score", 0) or 0):
                best_by_role[role] = sig
    out = []
    for role, sig in best_by_role.items():
        vuln_class, confidence, rationale_tpl, test_sketch_tpl = _HYDRA_ROLE_VULN_MAP[role]
        param = sig.get("parameter", "?")
        url = sig.get("url", "?")
        impact = sig.get("impact_score", "?")
        out.append(Hypothesis(
            vuln_class, confidence,
            rationale_tpl.format(param=param, url=url, impact=impact),
            test_sketch_tpl.format(param=param, url=url, impact=impact),
            f"hydra role {role} on {param}@{url}",
        ))
    return out


def _rule_waf_detected(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    waf_names = ctx.get("waf_detected") or []
    if not waf_names:
        return []
    names = ", ".join(str(w) for w in waf_names[:3])
    return [
        Hypothesis("waf_evasion", "low",
            f"A WAF/protection layer ({names}) was fingerprinted in front of this target — any payload-"
            f"based hypothesis above (sqli/xss/ssti/command_injection) may get silently blocked rather "
            f"than genuinely failing, which looks identical from a single response.",
            "Before concluding a payload-based hypothesis is a dead end, run waf_evasion_probe to check "
            "whether a baseline payload is actually being blocked, and if so, whether an encoding/casing/ "
            "fragmentation variant gets through.",
            names),
    ]


def _rule_leaked_vcs_and_env(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    git_hit = _endpoints_matching(endpoints, "/.git/")
    env_hit = _endpoints_matching(endpoints, "/.env")
    out = []
    if git_hit:
        out.append(Hypothesis("info_disclosure", "medium",
            "An exposed .git directory lets an attacker reconstruct the full source tree (including "
            "past commits that may contain removed secrets) with a standard git-dumper technique.",
            "GET /.git/config and /.git/HEAD directly; if either returns real git data instead of a "
            "404, that confirms an exposed repository worth extracting.",
            git_hit[0]))
    if env_hit:
        out.append(Hypothesis("info_disclosure", "high",
            f"A /.env path was already discovered ({env_hit[0]}) — if directly readable this is an "
            f"immediate secrets leak (DB credentials, API keys, signing secrets).",
            "GET the .env path directly and check whether it returns real KEY=VALUE content instead of "
            "a 404/redirect.",
            env_hit[0]))
    return out


def _rule_elastic_mongo_redis_exposed(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    hit = _any_token_contains(tech, "elasticsearch", "mongodb", "redis")
    if not hit:
        return []
    return [
        Hypothesis("unauthenticated_data_access", "medium",
            f"A {hit} service was fingerprinted directly on this host/port — these commonly ship with "
            f"no authentication by default and are a frequent source of fully unauthenticated data "
            f"exposure when internet-reachable.",
            f"Attempt a direct, read-only connection/query to the {hit} service on its default port and "
            f"see whether it responds without credentials; stop immediately if it does and report it "
            f"rather than exploring further.",
            hit),
    ]


def _rule_oauth_sso(tech: Set[str], endpoints: List[str], headers: Dict[str, str], ctx: Dict[str, Any]) -> List[Hypothesis]:
    hits = _endpoints_matching(endpoints, "oauth", "/sso/", "callback", "/saml")
    tech_hit = _any_token_contains(tech, "oauth", "saml")
    if not hits and not tech_hit:
        return []
    sig = (hits[0] if hits else tech_hit)
    return [
        Hypothesis("account_takeover", "low",
            "OAuth/SSO redirect_uri or SAML ACS endpoints that aren't strictly allowlisted are a classic "
            "open-redirect-to-account-takeover chain — steal the auth code/assertion by redirecting it "
            "to an attacker-controlled host.",
            "Check whether redirect_uri (or the SAML equivalent) accepts a value outside the registered "
            "allowlist (a subdomain trick, an open-redirect chain, or a loosely-matched wildcard), and "
            "whether the authorization code is actually usable once redirected there.",
            sig),
    ]


_RULES = [
    _rule_wordpress, _rule_laravel, _rule_django, _rule_flask, _rule_node_nosql,
    _rule_spring_java, _rule_aspnet, _rule_graphql, _rule_jwt, _rule_numeric_id_paths,
    _rule_file_upload, _rule_ssrf_prone_features, _rule_cors, _rule_leaked_vcs_and_env,
    _rule_elastic_mongo_redis_exposed, _rule_oauth_sso, _rule_param_name_signals,
    _rule_waf_detected, _rule_rails, _rule_drupal, _rule_hydra_param_roles,
]


def generate(tech_stack: Optional[List[str]] = None, endpoints: Optional[List[str]] = None,
             headers: Optional[Dict[str, str]] = None, context: Optional[Dict[str, Any]] = None) -> List[Hypothesis]:
    """
    Runs every rule and returns a ranked, deduped hypothesis list.

    `context` carries the signal sources that don't fit the tech_stack/
    endpoints/headers shape: `context["parameters"]` (discovered parameter
    NAMES, e.g. from spider/fuzz_hunter — used for name-pattern rules like
    "a 'redirect' param suggests open_redirect/account-takeover chaining,
    a 'cmd' param suggests command_injection"), `context["waf_detected"]`
    (WAF/protection names already fingerprinted, e.g. by wafbuster — used
    to flag that payload-based hypotheses may need waf_evasion_probe before
    being written off as dead ends), and `context["param_signals"]` (hydra's
    real per-parameter role/impact findings — admin flags, auth-sensitive
    params, path references, GraphQL introspectability, OAuth callback
    sinks — each anchored to the actual url+parameter it was seen on,
    richer than a bare name guess).

    Dedup keeps the HIGHEST-confidence hypothesis per vuln_class (a rule
    firing twice for the same class, e.g. idor from both numeric-id-paths
    and graphql, isn't double-counted — the stronger rationale wins).
    Ties keep whichever fired first (rule order above is itself a rough
    "how reliable is this signal" ordering, framework-specific debug leaks
    before generic path-shape guesses).
    """
    tech = _norm_tokens(tech_stack)
    eps = list(endpoints or [])
    hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    ctx = context or {}

    all_hyps: List[Hypothesis] = []
    for rule in _RULES:
        try:
            result = rule(tech, eps, hdrs, ctx)
        except Exception:
            continue
        if result:
            all_hyps.extend(result)

    best_by_class: Dict[str, Hypothesis] = {}
    for h in all_hyps:
        existing = best_by_class.get(h.vuln_class)
        if existing is None or CONFIDENCE_ORDER.get(h.confidence, 0) > CONFIDENCE_ORDER.get(existing.confidence, 0):
            best_by_class[h.vuln_class] = h

    ranked = sorted(best_by_class.values(), key=lambda h: -CONFIDENCE_ORDER.get(h.confidence, 0))
    return ranked


def supported_signal_count() -> int:
    """How many independent rule functions exist — for tests/sanity checks, not a feature."""
    return len(_RULES)