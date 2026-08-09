import asyncio
import aiohttp
import re
import json
import math
import time
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

NAME = "hydra"
CATEGORY = "analysis"
DESCRIPTION = "Universal Attack Surface & Parameter Logic Auditor — Impact-First (Geryon/Lailaps/Cerberus Engine v2)"

OPTIONS = [
    {"name": "concurrency",     "type": "int",  "default": 10,         "help": "Concurrent probing threads"},
    {"name": "timeout",         "type": "int",  "default": 10,         "help": "Probing timeout (seconds)"},
    {"name": "probe_intensity", "type": "str",  "default": "standard", "help": "light | standard | deep"},
    {"name": "enable_probing",  "type": "bool", "default": True,       "help": "Enable differential response analysis"},
]

# =============================================================================
# IMPACT SCORING — drives everything downstream
# =============================================================================
# Every finding gets an impact score. Downstream agents consume the highest
# scoring findings first. This is the core philosophy change from v1.

IMPACT_SCORES = {
    # Critical — account takeover / auth bypass territory
    "OPEN_REDIRECT_TO_ATO":      10,
    "JWT_EXPOSED":               10,
    "OAUTH_CALLBACK_SINK":       10,
    "AUTH_PARAM":                 9,
    "ADMIN_FLAG":                 9,
    "PRIVILEGE_CHAIN":            9,
    # High — direct data access / injection
    "BOLA_CHAIN":                 8,
    "OBJECT_IDENTIFIER":          8,
    "IDOR_SURFACE":               8,
    "LFI_SURFACE":                7,
    "SQLI_SURFACE":               7,
    "SSTI_SURFACE":               7,
    "CMDI_SURFACE":               7,
    "NOSQLI_SURFACE":             7,
    # Medium — information disclosure / indirect
    "SENSITIVE_DATA":             6,
    "BASE64_ENCODED":             5,
    "HEX_ENCODED":                5,
    "HIGH_ENTROPY":               5,
    "GRAPHQL_INTROSPECTABLE":     5,
    "PATH_REFERENCE":             4,
    "EXTERNAL_SINK":              4,
    "CROSS_CONTEXT_EXPOSURE":     4,
    # Low — recon value
    "API_KEY_PARAM":              3,
    "SPA_ROUTING_PARAM":          2,
    "DYNAMIC_VOLATILE":           2,
}

# =============================================================================
# ATTACK CHAIN DEFINITIONS — multi-angle perspective
# =============================================================================
# Each chain maps a role to: what it might lead to, and which auditor owns it.
# This is the "think like a hunter" logic — a redirect param isn't just
# a redirect, it's a potential OAuth token theft vector.

ATTACK_CHAINS = {
    "OBJECT_IDENTIFIER": {
        "chains": ["IDOR", "BOLA", "Mass Assignment", "Insecure Direct Reference"],
        "auditor": "idor_analysis",
        "impact_path": "Object enumeration → unauthorized data access → PII/account takeover",
        "questions": [
            "Is this ID predictable/sequential?",
            "Does unauthenticated access return data?",
            "Does changing ID return another user's data?",
        ]
    },
    "EXTERNAL_SINK": {
        "chains": ["Open Redirect", "SSRF", "OAuth Token Theft", "Phishing"],
        "auditor": "redirect_analysis",
        "impact_path": "Open redirect → OAuth flow hijack → account takeover",
        "questions": [
            "Is this in an OAuth callback flow?",
            "Does it accept arbitrary domains?",
            "Is there a whitelist bypassable with @, //, or \\?",
        ]
    },
    "PATH_REFERENCE": {
        "chains": ["LFI", "Path Traversal", "RFI", "Template Injection"],
        "auditor": "path_traversal_analysis",
        "impact_path": "Path traversal → /etc/passwd → SSH keys → RCE",
        "questions": [
            "Does the server reflect file content?",
            "Are null bytes or double encoding accepted?",
            "Is there a wrapper like php://filter?",
        ]
    },
    "ADMIN_FLAG": {
        "chains": ["Privilege Escalation", "RBAC Bypass", "Mass Assignment"],
        "auditor": "privilege_analysis",
        "impact_path": "Boolean flag flip → admin access → full account control",
        "questions": [
            "Is this sent in a POST body or header?",
            "Does the server trust client-supplied role?",
            "Is there a mass assignment path via JSON?",
        ]
    },
    "AUTH_PARAM": {
        "chains": ["Token Leakage", "Session Fixation", "JWT Attack", "Replay Attack"],
        "auditor": "auth_analysis",
        "impact_path": "Credential in URL/param → logged → replayed → account takeover",
        "questions": [
            "Is this value logged server-side in plaintext?",
            "Is the token in a GET param (Referer leakage risk)?",
            "Is JWT signature verified?",
        ]
    },
    "GRAPHQL_INTROSPECTABLE": {
        "chains": ["Schema Disclosure", "Batch Query Abuse", "IDOR via aliases", "Mutation Injection"],
        "auditor": "graphql_analysis",
        "impact_path": "Introspection → full schema → IDOR mutations → data exfiltration",
        "questions": [
            "Is introspection enabled in production?",
            "Are mutations rate-limited?",
            "Can aliases bypass rate limiting?",
        ]
    },
    "HIGH_ENTROPY": {
        "chains": ["Token Brute Force", "Hash Cracking", "Predictable Secret"],
        "auditor": "entropy_analysis",
        "impact_path": "Weak random → predictable token → account takeover without authentication",
        "questions": [
            "Is this a reset token or invite link?",
            "Was this generated with a weak PRNG?",
            "Is the token time-bounded?",
        ]
    },
}

# =============================================================================
# CERBERUS HEAD — Parameter & Value Pattern Intelligence
# =============================================================================

# Word-boundary safe matching — prevents "paid" matching "id"
def _wbmatch(pname, variants):
    pname = pname.lower()
    for v in variants:
        if re.search(rf'(?<![a-z0-9]){re.escape(v)}(?![a-z0-9])', pname):
            return True
    return False

_ID_VARIANTS       = ["id", "uid", "user", "account", "profile", "order", "invoice",
                       "doc", "ref", "uuid", "guid", "slug", "record", "entry",
                       "object", "resource", "entity", "item", "node"]

_PATH_VARIANTS     = ["file", "path", "page", "template", "load", "include",
                       "src", "source", "view", "layout", "module", "theme",
                       "dir", "folder", "root"]

_URL_VARIANTS      = ["url", "link", "redirect", "next", "to", "goto", "dest",
                       "destination", "site", "domain", "callback", "return",
                       "returnto", "continue", "forward", "target", "redir",
                       "location", "uri", "href", "action"]

_ADMIN_VARIANTS    = ["admin", "root", "role", "is_admin", "isadmin", "status",
                       "debug", "dev", "permission", "privilege", "superuser",
                       "access", "level", "tier", "group", "scope", "grant",
                       "flag", "override", "bypass", "internal"]

_SENSITIVE_VARIANTS = ["email", "token", "secret", "key", "auth", "session",
                        "pass", "password", "hash", "otp", "code", "nonce",
                        "sig", "signature", "hmac", "csrf", "bearer", "apikey",
                        "api_key", "client_secret", "private"]

_GRAPHQL_VARIANTS  = ["query", "mutation", "subscription", "variables",
                       "operationname", "extensions", "fragment"]

_SPA_VARIANTS      = ["tab", "step", "screen", "view", "modal", "section",
                       "panel", "route", "nav", "state", "mode", "theme",
                       "lang", "locale", "page", "sort", "filter", "q",
                       "search", "limit", "offset", "cursor", "after", "before"]

_JWT_RE    = re.compile(r'^eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+$')
_B64_RE    = re.compile(r'^[a-zA-Z0-9+/]{8,}={0,2}$')
_HEX_RE    = re.compile(r'^[a-fA-F0-9]{8,}$')
_UUID_RE   = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.I)
_NUMERIC_RE = re.compile(r'^\d{1,10}$')

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

def normalize_param(name: str) -> str:
    """Normalize camelCase, snake_case, kebab-case to flat lowercase for semantic comparison."""
    name = re.sub(r'([A-Z])', r'_\1', name)
    return re.sub(r'[_\-\s]', '', name).lower()

# =============================================================================
# LAILAPS HEAD — Probe Seeds by Role
# =============================================================================

PROBE_SEEDS_BY_ROLE = {
    "OBJECT_IDENTIFIER": [
        ("IDOR_ZERO",    "0"),
        ("IDOR_NEG",     "-1"),
        ("IDOR_LARGE",   "99999999"),
        ("IDOR_UUID",    "00000000-0000-0000-0000-000000000000"),
    ],
    "PATH_REFERENCE": [
        ("LFI_UNIX",     "../../../etc/passwd"),
        ("LFI_WIN",      "..\\..\\..\\windows\\win.ini"),
        ("LFI_DOUBLE",   "....//....//etc/passwd"),
        ("LFI_NULL",     "/etc/passwd\x00"),
        ("LFI_WRAPPER",  "php://filter/convert.base64-encode/resource=index.php"),
    ],
    "EXTERNAL_SINK": [
        ("REDIR_PROTO",  "//evil.com"),
        ("REDIR_SLASH",  "/\\evil.com"),
        ("REDIR_AT",     "https://legit.com@evil.com"),
        ("SSRF_LOCAL",   "http://127.0.0.1"),
        ("SSRF_169",     "http://169.254.169.254/latest/meta-data/"),
    ],
    "ADMIN_FLAG": [
        ("PRIV_TRUE",    "true"),
        ("PRIV_ONE",     "1"),
        ("PRIV_ADMIN",   "admin"),
        ("PRIV_ROOT",    "root"),
    ],
    "AUTH_PARAM": [
        ("TOKEN_EMPTY",  ""),
        ("TOKEN_NULL",   "null"),
        ("TOKEN_INVALID","aaaa.bbbb.cccc"),
    ],
    "GRAPHQL_INTROSPECTABLE": [
        ("GQL_INTRO",    '{"query":"{__schema{types{name}}}"}'),
        ("GQL_BATCH",    '[{"query":"{__typename}"},{"query":"{__typename}"}]'),
    ],
    "_DEFAULT": [
        ("SQLI_BASIC",   "'"),
        ("SQLI_OR",      "' OR '1'='1"),
        ("SSTI_JINJA",   "{{7*7}}"),
        ("SSTI_EL",      "${7*7}"),
        ("SSTI_ERB",     "<%= 7*7 %>"),
        ("CMDI_SEMI",    ";id"),
        ("CMDI_PIPE",    "|id"),
        ("XSS_TAG",      "<h1>x</h1>"),
        ("NOSQLI_GT",    '{"$gt":""}'),
        ("NOSQLI_WHERE", '{"$where":"1==1"}'),
    ],
}

# =============================================================================
# CONTENT-TYPE PROBE BUILDERS
# =============================================================================

def build_probe_request(url, method, pname, seed_value, content_type=None):
    """
    Returns (probed_url, kwargs_for_aiohttp) shaped correctly for the
    endpoint's content type. Handles JSON, form, GraphQL, and query params.
    """
    u = urlparse(url)
    existing_params = parse_qs(u.query)

    ct = (content_type or "").lower()

    if "graphql" in url.lower() or "graphql" in ct:
        # GraphQL — inject into the query variable
        body = {"query": f'{{ __typename }}', "variables": {pname: seed_value}}
        return url, {"json": body}

    elif "application/json" in ct or method.upper() in ("POST", "PUT", "PATCH") and not ct:
        # JSON body injection
        body = {pname: seed_value}
        return url, {"json": body}

    elif "multipart" in ct:
        form = aiohttp.FormData()
        form.add_field(pname, seed_value)
        return url, {"data": form}

    else:
        # Default: query parameter injection (GET and generic POST)
        existing_params[pname] = [seed_value]
        clean_url = u._replace(query="").geturl()
        return clean_url, {"params": existing_params}

# =============================================================================
# HYDRA ENGINE
# =============================================================================

class HydraEngine:
    def __init__(self, emit, session, options):
        self.emit   = emit
        self.session = session
        self.options = options
        self.seen    = set()

    # -------------------------------------------------------------------------
    # CERBERUS — Entropy & Role Analysis
    # -------------------------------------------------------------------------

    def analyze_entropy(self, pname, value, url="", content_type=None):
        """
        Returns: (roles: list, chains: list, impact_score: int, auditor: str|None)
        Analyzes both the parameter name AND its value (from URL path segments,
        observed values, or None).
        """
        pname_norm = pname.lower()
        value = str(value) if value else ""
        roles = []
        chains = []
        auditor = None
        impact = 0

        # ── Format Detection (value-level) ──────────────────────────────────
        if _JWT_RE.match(value):
            roles.append("AUTH_PARAM")
            chains.extend(ATTACK_CHAINS["AUTH_PARAM"]["chains"])
            auditor = ATTACK_CHAINS["AUTH_PARAM"]["auditor"]
            impact = max(impact, IMPACT_SCORES["JWT_EXPOSED"])

        elif _UUID_RE.match(value):
            roles.append("OBJECT_IDENTIFIER")
            # UUID-style IDs are often IDOR targets
            impact = max(impact, IMPACT_SCORES["IDOR_SURFACE"])

        elif _B64_RE.match(value) and len(value) > 12:
            roles.append("BASE64_ENCODED")
            impact = max(impact, IMPACT_SCORES["BASE64_ENCODED"])

        elif _HEX_RE.match(value) and len(value) > 12:
            roles.append("HEX_ENCODED")
            impact = max(impact, IMPACT_SCORES["HEX_ENCODED"])

        elif _NUMERIC_RE.match(value):
            # Short sequential numeric ID — classic IDOR surface
            if int(value) < 100000:
                roles.append("OBJECT_IDENTIFIER")
                impact = max(impact, IMPACT_SCORES["IDOR_SURFACE"])

        # Shannon entropy on value — high entropy = likely token/secret
        if value and len(value) > 8:
            ent = shannon_entropy(value)
            if ent > 4.5:
                roles.append("HIGH_ENTROPY")
                impact = max(impact, IMPACT_SCORES["HIGH_ENTROPY"])

        # ── Path segment value mining ────────────────────────────────────────
        # Even if the spider didn't pass a value, extract candidates from URL path
        if not value and url:
            path_parts = [p for p in urlparse(url).path.split("/") if p and len(p) > 4]
            for part in path_parts:
                if _JWT_RE.match(part):
                    roles.append("AUTH_PARAM")
                    impact = max(impact, IMPACT_SCORES["JWT_EXPOSED"])
                elif _UUID_RE.match(part):
                    roles.append("OBJECT_IDENTIFIER")
                    impact = max(impact, IMPACT_SCORES["IDOR_SURFACE"])
                elif shannon_entropy(part) > 4.5 and len(part) > 8:
                    roles.append("HIGH_ENTROPY")
                    impact = max(impact, IMPACT_SCORES["HIGH_ENTROPY"])

        # ── Name-based Role Detection (word-boundary safe) ──────────────────
        if _wbmatch(pname_norm, _ID_VARIANTS):
            roles.append("OBJECT_IDENTIFIER")
            c = ATTACK_CHAINS["OBJECT_IDENTIFIER"]
            chains.extend(c["chains"])
            auditor = auditor or c["auditor"]
            impact = max(impact, IMPACT_SCORES["OBJECT_IDENTIFIER"])

        if _wbmatch(pname_norm, _URL_VARIANTS):
            roles.append("EXTERNAL_SINK")
            c = ATTACK_CHAINS["EXTERNAL_SINK"]
            chains.extend(c["chains"])
            auditor = auditor or c["auditor"]
            impact = max(impact, IMPACT_SCORES["EXTERNAL_SINK"])
            # Extra: if this URL param appears near OAuth-related paths → ATO risk
            if url and any(x in url.lower() for x in ["oauth", "login", "auth", "sso", "callback"]):
                roles.append("OAUTH_CALLBACK_SINK")
                impact = max(impact, IMPACT_SCORES["OAUTH_CALLBACK_SINK"])

        if _wbmatch(pname_norm, _PATH_VARIANTS):
            roles.append("PATH_REFERENCE")
            c = ATTACK_CHAINS["PATH_REFERENCE"]
            chains.extend(c["chains"])
            auditor = auditor or c["auditor"]
            impact = max(impact, IMPACT_SCORES["LFI_SURFACE"])

        if _wbmatch(pname_norm, _ADMIN_VARIANTS):
            roles.append("ADMIN_FLAG")
            c = ATTACK_CHAINS["ADMIN_FLAG"]
            chains.extend(c["chains"])
            auditor = auditor or c["auditor"]
            impact = max(impact, IMPACT_SCORES["ADMIN_FLAG"])

        if _wbmatch(pname_norm, _SENSITIVE_VARIANTS):
            roles.append("AUTH_PARAM")
            c = ATTACK_CHAINS["AUTH_PARAM"]
            chains.extend(c["chains"])
            auditor = auditor or c["auditor"]
            impact = max(impact, IMPACT_SCORES["SENSITIVE_DATA"])

        if _wbmatch(pname_norm, _GRAPHQL_VARIANTS):
            roles.append("GRAPHQL_INTROSPECTABLE")
            c = ATTACK_CHAINS["GRAPHQL_INTROSPECTABLE"]
            chains.extend(c["chains"])
            auditor = auditor or c["auditor"]
            impact = max(impact, IMPACT_SCORES["GRAPHQL_INTROSPECTABLE"])

        if _wbmatch(pname_norm, _SPA_VARIANTS) and not roles:
            roles.append("SPA_ROUTING_PARAM")
            impact = max(impact, IMPACT_SCORES["SPA_ROUTING_PARAM"])

        # Deduplicate chains
        chains = list(dict.fromkeys(chains))
        return roles, chains, impact, auditor

    # -------------------------------------------------------------------------
    # LAILAPS — Three-Shot Differential Probing
    # -------------------------------------------------------------------------

    async def _fire(self, method, url, **kwargs):
        """Single HTTP fire — returns (status, body_len, elapsed) or None on error."""
        try:
            t0 = time.monotonic()
            timeout = aiohttp.ClientTimeout(total=self.options.get("timeout", 10))
            async with self.session.request(method, url, timeout=timeout, **kwargs) as r:
                body = await r.read()
                return r.status, len(body), time.monotonic() - t0, await r.text(errors="replace")
        except Exception:
            return None

    async def probe_differential(self, url, method, pname, original_value,
                                  roles=None, content_type=None):
        """
        Three-shot stability model:
          Shot A — benign value "hydra_a"  → baseline
          Shot B — benign value "hydra_b"  → confirm baseline stability
          Shot C — taint seed              → measure real delta vs A

        Seeds are chosen by role (Cerberus output) for semantic targeting.
        Delta threshold is percentage-based, not absolute.
        """
        if not self.options.get("enable_probing"):
            return []

        # ── Shot A — Baseline ────────────────────────────────────────────────
        probed_url_a, kwargs_a = build_probe_request(url, method, pname, "hydra_a", content_type)
        shot_a = await self._fire(method, probed_url_a, **kwargs_a)
        if not shot_a:
            return []
        status_a, len_a, time_a, _ = shot_a

        # ── Shot B — Stability Check ─────────────────────────────────────────
        probed_url_b, kwargs_b = build_probe_request(url, method, pname, "hydra_b", content_type)
        shot_b = await self._fire(method, probed_url_b, **kwargs_b)
        if not shot_b:
            return []
        status_b, len_b, time_b, _ = shot_b

        # If A ≠ B, page is naturally volatile — skip, don't report
        len_ab_delta = abs(len_a - len_b)
        if status_a != status_b or (len_a > 0 and len_ab_delta / len_a > 0.05):
            return [{"delta_type": "UNSTABLE_BASELINE", "confidence": "Skip — volatile page"}]

        # ── Shot C — Taint Probes by Role ────────────────────────────────────
        seed_set = []
        if roles:
            for role in roles:
                if role in PROBE_SEEDS_BY_ROLE:
                    seed_set.extend(PROBE_SEEDS_BY_ROLE[role])
        if not seed_set:
            seed_set = PROBE_SEEDS_BY_ROLE["_DEFAULT"]

        # Respect probe_intensity
        intensity = self.options.get("probe_intensity", "standard")
        if intensity == "light":
            seed_set = seed_set[:1]
        elif intensity == "standard":
            seed_set = seed_set[:3]
        # deep = all seeds

        deltas = []
        for seed_name, seed_val in seed_set:
            probed_url_c, kwargs_c = build_probe_request(url, method, pname,
                                                          original_value + seed_val if original_value else seed_val,
                                                          content_type)
            shot_c = await self._fire(method, probed_url_c, **kwargs_c)
            if not shot_c:
                continue
            status_c, len_c, time_c, body_c = shot_c

            status_shift = status_c != status_a
            len_delta    = abs(len_c - len_a)
            pct_delta    = (len_delta / len_a) if len_a > 0 else 0
            time_delta   = time_c - time_a

            # Signal criteria:
            # - Status shift (3xx → 200, 200 → 500, etc.)
            # - >5% body length shift on a stable baseline
            # - >3s timing anomaly (blind injection indicator)
            # - Error keywords in response body
            error_hit = any(kw in body_c.lower() for kw in [
                "syntax error", "sql", "odbc", "mysql", "ora-", "pg::",
                "fatal error", "warning:", "traceback", "exception",
                "undefined variable", "permission denied",
            ])

            significant = status_shift or pct_delta > 0.05 or time_delta > 3.0 or error_hit

            if significant:
                deltas.append({
                    "seed":         seed_name,
                    "seed_value":   seed_val,
                    "delta_type":   "DYNAMISM_DETECTED",
                    "status_shift": status_shift,
                    "status_from":  status_a,
                    "status_to":    status_c,
                    "length_pct":   round(pct_delta * 100, 1),
                    "timing_delta": round(time_delta, 2),
                    "error_hit":    error_hit,
                    "confidence":   "High (Three-Shot Differential)",
                })

        return deltas

    # -------------------------------------------------------------------------
    # GERYON — Multi-Angle Logic Chain Correlation
    # -------------------------------------------------------------------------

    def map_logic_chains(self, endpoints):
        """
        Correlates parameters across endpoints with semantic normalization.
        Detects: BOLA chains, redirect chains, privilege chains, mass assignment
        surfaces, and parameter shadowing opportunities.
        """
        # Build: normalized_name → list of (original_name, url, method, roles)
        param_map = {}
        for ep in endpoints:
            url    = ep.get("url", "")
            method = ep.get("method", "GET")
            roles  = ep.get("_hydra_roles", {})  # populated during Cerberus pass
            params = ep.get("params", {})

            flat_names = []
            if isinstance(params, dict):
                for bucket in params.values():
                    if isinstance(bucket, list):
                        flat_names.extend(bucket)
            elif isinstance(params, list):
                flat_names.extend(params)

            for name in flat_names:
                if not name:
                    continue
                norm = normalize_param(name)
                param_map.setdefault(norm, []).append({
                    "original": name,
                    "url":      url,
                    "method":   method,
                    "roles":    roles.get(name, []),
                })

        logic_findings = []

        for norm_name, occurrences in param_map.items():
            if len(occurrences) < 2:
                continue

            urls   = [o["url"] for o in occurrences]
            all_roles = [r for o in occurrences for r in o["roles"]]
            unique_roles = list(set(all_roles))

            # ── BOLA Chain — ID param across auth + non-auth endpoints ───────
            if any(r in ("OBJECT_IDENTIFIER",) for r in unique_roles):
                auth_eps    = [o for o in occurrences if any(x in o["url"].lower() for x in ["api", "user", "account", "profile", "order"])]
                unauth_eps  = [o for o in occurrences if not any(x in o["url"].lower() for x in ["api", "user", "account", "profile", "order"])]
                if auth_eps and unauth_eps:
                    logic_findings.append({
                        "type":        "BOLA_CHAIN",
                        "parameter":   norm_name,
                        "urls":        urls,
                        "impact":      IMPACT_SCORES["BOLA_CHAIN"],
                        "description": f"ID param '{norm_name}' straddles authenticated and unauthenticated endpoints — classic BOLA surface.",
                        "auditor":     "idor_analysis",
                    })

            # ── Redirect Chain — URL param near auth/OAuth ───────────────────
            if any(r in ("EXTERNAL_SINK", "OAUTH_CALLBACK_SINK") for r in unique_roles):
                oauth_eps = [o for o in occurrences if any(x in o["url"].lower() for x in ["oauth", "login", "auth", "sso", "callback", "logout"])]
                if oauth_eps:
                    logic_findings.append({
                        "type":        "REDIRECT_CHAIN",
                        "parameter":   norm_name,
                        "urls":        urls,
                        "impact":      IMPACT_SCORES["OAUTH_CALLBACK_SINK"],
                        "description": f"Redirect param '{norm_name}' appears in auth/OAuth flow — open redirect → token theft → ATO.",
                        "auditor":     "redirect_analysis",
                    })
                else:
                    logic_findings.append({
                        "type":        "CROSS_CONTEXT_REDIRECT",
                        "parameter":   norm_name,
                        "urls":        urls,
                        "impact":      IMPACT_SCORES["EXTERNAL_SINK"],
                        "description": f"Redirect param '{norm_name}' appears across {len(urls)} endpoints — test for open redirect and SSRF.",
                        "auditor":     "redirect_analysis",
                    })

            # ── Privilege Chain — admin/role param on user-facing endpoint ───
            if any(r in ("ADMIN_FLAG",) for r in unique_roles):
                logic_findings.append({
                    "type":        "PRIVILEGE_CHAIN",
                    "parameter":   norm_name,
                    "urls":        urls,
                    "impact":      IMPACT_SCORES["PRIVILEGE_CHAIN"],
                    "description": f"Admin/role param '{norm_name}' visible on {len(urls)} endpoints — test for mass assignment and privilege escalation.",
                    "auditor":     "privilege_analysis",
                })

            # ── Generic Cross-Context for remaining high-impact roles ─────────
            if any(r in ("AUTH_PARAM", "SENSITIVE_DATA") for r in unique_roles) and len(occurrences) > 1:
                logic_findings.append({
                    "type":        "CREDENTIAL_REUSE_SURFACE",
                    "parameter":   norm_name,
                    "urls":        urls,
                    "impact":      IMPACT_SCORES["SENSITIVE_DATA"],
                    "description": f"Sensitive param '{norm_name}' appears across {len(urls)} endpoints — check for token reuse and session fixation.",
                    "auditor":     "auth_analysis",
                })

        # Sort logic findings by impact descending
        logic_findings.sort(key=lambda x: x["impact"], reverse=True)
        return logic_findings


# =============================================================================
# ASYNC RUNNER
# =============================================================================

async def _run_async(target, emit, options=None):
    emit.info("[*] HYDRA v2: Impact-First Universal Parameter & Logic Analysis starting...")

    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints    = spider_intel.get("endpoints", [])

    if not endpoints:
        emit.warn("[!] No endpoints in Intel. Did Spider run?")
        return {"raw": "No endpoints", "intel": {}, "signals": ["NO_ENDPOINTS"]}

    engine      = HydraEngine(emit, None, options or {})
    all_findings = []
    sem         = asyncio.Semaphore(options.get("concurrency", 10))

    async def process_endpoint(ep):
        url         = ep.get("url", "")
        method      = ep.get("method", "GET")
        params      = ep.get("params", {})
        content_type = ep.get("content_type") or ep.get("observed_content_type") or ""

        flat_names = []
        if isinstance(params, dict):
            for bucket in params.values():
                if isinstance(bucket, list):
                    flat_names.extend(bucket)
        elif isinstance(params, list):
            flat_names.extend(params)

        # Also mine path segments for implicit parameters
        path_parts = [p for p in urlparse(url).path.split("/") if p]
        for part in path_parts:
            if _UUID_RE.match(part) or _NUMERIC_RE.match(part) or (_HEX_RE.match(part) and len(part) > 8):
                flat_names.append(f"__path__{part}")

        ep_role_map = {}
        ep_findings = []

        for pname in flat_names:
            if not pname:
                continue

            is_path_param = pname.startswith("__path__")
            real_value    = pname.replace("__path__", "") if is_path_param else ""
            real_name     = "id" if is_path_param else pname

            async with sem:
                # Cerberus
                roles, chains, impact, auditor = engine.analyze_entropy(
                    real_name, real_value, url=url, content_type=content_type
                )
                ep_role_map[pname] = roles

                # Lailaps
                deltas = []
                if options.get("enable_probing") and impact >= 4:  # Only probe meaningful params
                    deltas = await engine.probe_differential(
                        url, method, real_name, real_value, roles=roles, content_type=content_type
                    )

                if not roles and not deltas:
                    continue

                # Build impact path from highest-impact chain
                impact_path = None
                hunter_questions = []
                for role in roles:
                    if role in ATTACK_CHAINS:
                        impact_path      = ATTACK_CHAINS[role]["impact_path"]
                        hunter_questions = ATTACK_CHAINS[role]["questions"]
                        break

                finding = {
                    "parameter":         pname,
                    "url":               url,
                    "method":            method,
                    "roles":             roles,
                    "attack_chains":     chains,
                    "impact_score":      impact,
                    "impact_path":       impact_path,
                    "hunter_questions":  hunter_questions,
                    "recommended_auditor": auditor,
                    "differential":      deltas,
                    "content_type":      content_type,
                }
                ep_findings.append(finding)

                # Emit by severity
                if impact >= 8:
                    emit.success(f"  [CRITICAL] {pname} @ {method} {url}")
                elif impact >= 6:
                    emit.warn(f"  [HIGH]     {pname} @ {method} {url}")
                else:
                    emit.info(f"  [MED/LOW]  {pname} @ {method} {url}")

                if roles:
                    emit.info(f"             Roles: {', '.join(roles)}")
                if chains:
                    emit.info(f"             Attack Chains: {', '.join(chains[:3])}")
                if impact_path:
                    emit.info(f"             Impact Path: {impact_path}")
                if deltas:
                    real_deltas = [d for d in deltas if d.get("delta_type") == "DYNAMISM_DETECTED"]
                    if real_deltas:
                        emit.success(f"             Differential: {len(real_deltas)} seed(s) triggered response shift")
                if auditor:
                    emit.info(f"             → Route to: {auditor}")

        # Attach role map to ep for Geryon
        ep["_hydra_roles"] = ep_role_map
        return ep_findings

    # Fire all endpoints concurrently
    async with aiohttp.ClientSession() as session:
        engine.session = session
        tasks   = [process_endpoint(ep) for ep in endpoints]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, list):
            all_findings.extend(r)

    # Sort all findings by impact descending — highest impact surfaces first
    all_findings.sort(key=lambda x: x.get("impact_score", 0), reverse=True)

    # Geryon — Logic Chain Correlation
    logic_findings = engine.map_logic_chains(endpoints)
    if logic_findings:
        emit.success(f"[+] Geryon: {len(logic_findings)} logic chains identified.")
        for lf in logic_findings[:3]:  # Preview top 3
            emit.warn(f"    [{lf['type']}] {lf['parameter']} → {lf['description'][:80]}")

    emit.success(f"[+] HYDRA v2 complete. {len(all_findings)} surfaces | {len(logic_findings)} chains.")

    # Build signals list cleanly (no None pollution)
    signals = ["SURFACE_MAPPED"]
    auditor_signals = {
        "idor_analysis":            "IDOR_SURFACE_FOUND",
        "path_traversal_analysis":   "LFI_SURFACE_FOUND",
        "redirect_analysis":        "OPEN_REDIRECT_SURFACE_FOUND",
        "privilege_analysis":       "PRIVILEGE_SURFACE_FOUND",
        "auth_analysis":            "AUTH_SURFACE_FOUND",
        "graphql_analysis":         "GRAPHQL_SURFACE_FOUND",
        "entropy_analysis":         "HIGH_ENTROPY_SURFACE_FOUND",
    }
    seen_auditors = set(f.get("recommended_auditor") for f in all_findings if f.get("recommended_auditor"))
    for auditor_name, signal in auditor_signals.items():
        if auditor_name in seen_auditors:
            signals.append(signal)

    if any(lf["type"] == "BOLA_CHAIN" for lf in logic_findings):
        signals.append("BOLA_CHAIN_DETECTED")
    if any(lf["type"] in ("REDIRECT_CHAIN", "OAUTH_CALLBACK_SINK") for lf in logic_findings):
        signals.append("ATO_CHAIN_DETECTED")

    return {
        "raw": f"HYDRA v2 analyzed {len(endpoints)} endpoints. {len(all_findings)} surfaces, {len(logic_findings)} logic chains.",
        "intel": {
            "surfaces":     all_findings,
            "logic_chains": logic_findings,
            "vulnerabilities": [f for f in all_findings if f.get("impact_score", 0) >= 7],
        },
        "signals": signals,
    }


# =============================================================================
# SYNC ENTRY POINT
# =============================================================================

def run(target, emit_obj, options: dict = None):
    """Hellhound synchronous entry point."""
    try:
        return asyncio.run(_run_async(target, emit_obj, options))
    except RuntimeError:
        # Already inside a running event loop (e.g., framework async context)
        try:
            import nest_asyncio
            nest_asyncio.apply()
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(_run_async(target, emit_obj, options))
        except ImportError:
            emit_obj.warn("HYDRA: nest_asyncio not installed. Run: pip install nest_asyncio")
        except Exception as e:
            emit_obj.warn(f"HYDRA fallback execution error: {e}")
    except Exception as e:
        emit_obj.warn(f"HYDRA execution error: {e}")
        return {"raw": str(e), "intel": {}, "signals": ["HYDRA_CRASH"]}