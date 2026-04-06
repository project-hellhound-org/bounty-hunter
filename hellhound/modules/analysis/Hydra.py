import asyncio
import aiohttp
import re
import json
import base64
import time
from urllib.parse import urlparse, parse_qs
from hellhound.core import http_utils

NAME = "hydra"
CATEGORY = "analysis"
DESCRIPTION = "Universal Attack Surface & Parameter Logic Auditor (Geryon/Lailaps/Cerberus Engine)"

OPTIONS = [
    {"name": "concurrency", "type": int, "default": 10, "help": "Concurrent probing threads"},
    {"name": "timeout", "type": int, "default": 10, "help": "Probing timeout (seconds)"},
    {"name": "probe_intensity", "type": str, "default": "standard", "help": "light | standard | deep"},
    {"name": "enable_probing", "type": bool, "default": True, "help": "Enable differential response analysis"},
]

# ─────────────────────────────────────────────────────────────────────────────
# ENTROPY & DATA INSIGHT PATTERNS (Cerberus Head)
# ─────────────────────────────────────────────────────────────────────────────

_ID_VARIANTS = ["id", "uid", "user", "account", "profile", "order", "invoice", "doc", "ref", "uuid", "guid", "slug"]
_PATH_VARIANTS = ["file", "path", "page", "template", "load", "include", "src", "source"]
_URL_VARIANTS = ["url", "link", "redirect", "next", "to", "goto", "dest", "destination", "site", "domain", "callback", "return"]
_ADMIN_VARIANTS = ["admin", "root", "role", "is_admin", "status", "debug", "dev", "permission", "privilege", "superuser"]
_SENSITIVE_VARIANTS = ["email", "token", "secret", "key", "auth", "session", "pass", "password", "hash"]

_B64_RE = re.compile(r'^[a-zA-Z0-9+/]+={0,2}$')
_JWT_RE = re.compile(r'^eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+$')
_HEX_RE = re.compile(r'^[a-fA-F0-9]+$')

# ─────────────────────────────────────────────────────────────────────────────
# DIFFERENTIAL PROBE SEEDS (Lailaps Head)
# ─────────────────────────────────────────────────────────────────────────────

PROBE_SEEDS = {
    "SQLI": "'",
    "CMDI": ";",
    "SSTI": "{{7*7}}",
    "LFI": "/etc/passwd\x00",
    "XSS": "<h1",
}

# ─────────────────────────────────────────────────────────────────────────────
# HYDRA ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class HydraEngine:
    def __init__(self, emit, session, options):
        self.emit = emit
        self.session = session
        self.options = options
        self.findings = []
        self.targets = []
        self.seen = set()

    def analyze_entropy(self, pname, value):
        """Analyzes parameter format and role (Cerberus Logic)."""
        pname = pname.lower()
        value = str(value) if value else ""
        
        roles = []
        confidence = "Passive"
        recom = None

        # Format detection
        if _JWT_RE.match(value):
            roles.append("JWT_TOKEN")
            recom = "jwt_analyzer"
        elif _B64_RE.match(value) and len(value) > 8:
            roles.append("BASE64_ENCODED")
        elif _HEX_RE.match(value) and len(value) > 8:
            roles.append("HEX_ENCODED")

        # Role detection
        if any(x in pname for x in _ID_VARIANTS):
            roles.append("OBJECT_IDENTIFIER")
            recom = "idordetector"
        elif any(x in pname for x in _PATH_VARIANTS):
            roles.append("PATH_REFERENCE")
            recom = "pathtraveller"
        elif any(x in pname for x in _URL_VARIANTS):
            roles.append("EXTERNAL_SINK")
        elif any(x in pname for x in _ADMIN_VARIANTS):
            roles.append("DECISION_LOGIC")
            recom = "rbac"
        elif any(x in pname for x in _SENSITIVE_VARIANTS):
            roles.append("SENSITIVE_DATA")

        return roles, recom

    async def probe_differential(self, url, method, pname, original_value):
        """Measures response deltas to identify injection surfaces (Lailaps Logic)."""
        if not self.options.get("enable_probing"):
            return None

        # Base request for baseline
        try:
            async with self.session.request(method, url, timeout=self.options.get("timeout")) as r:
                baseline_len = len(await r.read())
                baseline_status = r.status
                baseline_time = time.time()
        except:
            return None

        # Send a generic "Taint" probe (SQLi single quote is best for general DB error/length shifts)
        taint = original_value + "'" if original_value else "'"
        
        # Build multipart if needed? For now just handle query/form
        u = urlparse(url)
        params = parse_qs(u.query)
        params[pname] = [taint]
        # simplified for prototype
        probed_url = u._replace(query="").geturl()

        try:
            t0 = time.time()
            async with self.session.request(method, probed_url, params=params, timeout=self.options.get("timeout")) as r:
                probed_len = len(await r.read())
                probed_status = r.status
                probed_time = time.time() - t0
                
                # Analyze Delta
                len_delta = abs(probed_len - baseline_len)
                status_delta = probed_status != baseline_status
                
                if status_delta or (len_delta > 100): # Significant shift
                    return {
                        "delta_type": "DYNAMISM_DETECTED",
                        "status_shift": status_delta,
                        "length_shift": len_delta,
                        "confidence": "High (Differential)"
                    }
        except:
            pass
        return None

    def map_logic_chains(self, endpoints):
        """Correlates parameters across endpoints (Geryon Logic)."""
        global_params = {}
        for ep in endpoints:
            params = ep.get("params", {})
            for bucket, names in params.items():
                for name in names:
                    global_params.setdefault(name, []).append(ep.get("url"))

        logic_findings = []
        for name, urls in global_params.items():
            if len(urls) > 1 and any(x in name.lower() for x in _ADMIN_VARIANTS + _ID_VARIANTS):
                logic_findings.append({
                    "parameter": name,
                    "urls": urls,
                    "type": "CROSS_CONTEXT_EXPOSURE",
                    "description": "Parameter exists across multiple endpoints — potential for session reuse or BOLA."
                })
        return logic_findings

async def _run_async(target, emit, options=None):
    emit.info("[*] HYDRA: Starting Universal Parameter & Logic Analysis...")
    
    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])

    if not endpoints:
        emit.warn("[!] No endpoints found in Intel. Did Spider run?")
        return {"raw": "No endpoints", "signals": ["NO_ENDPOINTS"]}

    engine = HydraEngine(emit, None, options or {})
    all_findings = []

    # Cerberus + Lailaps phases
    async with aiohttp.ClientSession() as session:
        engine.session = session
        
        for ep in endpoints:
            url = ep.get("url")
            method = ep.get("method", "GET")
            params = ep.get("params", {})
            
            # Extract flat names
            flat_names = []
            if isinstance(params, dict):
                for p_items in params.values():
                    flat_names.extend(p_items)
            
            for pname in flat_names:
                if not pname: continue
                
                # Cerberus: Entropy Analysis
                roles, recom = engine.analyze_entropy(pname, None) # Value extraction not fully supported in Spider 12.0 yet
                
                # Lailaps: Differential Probing (Optional)
                delta = None
                if options.get("enable_probing"):
                    delta = await engine.probe_differential(url, method, pname, "")
                
                if roles or delta:
                    finding = {
                        "parameter": pname,
                        "url": url,
                        "method": method,
                        "roles": roles,
                        "recommended_auditor": recom,
                        "differential": delta
                    }
                    all_findings.append(finding)
                    
                    emit.warn(f"    [!] HYDRA → {pname} ({method} {url})")
                    if roles: emit.info(f"        Role: {', '.join(roles)}")
                    if delta: emit.success(f"        Delta: Dynamism detected (Status: {delta['status_shift']}, Len: {delta['length_shift']})")
                    if recom: emit.info(f"        Targeting Auditor: {recom}")

    # Geryon: Logic Mapping
    logic_findings = engine.map_logic_chains(endpoints)
    if logic_findings:
        emit.success(f"[+] Geryon: Identified {len(logic_findings)} logic correlation chains.")

    emit.success(f"[+] HYDRA mapping complete. Found {len(all_findings)} attack surfaces.")

    return {
        "raw": f"HYDRA analyzed {len(endpoints)} endpoints. Found {len(all_findings)} surfaces.",
        "intel": {
            "surfaces": all_findings,
            "logic_chains": logic_findings,
            "vulnerabilities": all_findings
        },
        "signals": ["SURFACE_MAPPED", "IDOR_SURFACE_FOUND" if any("idordetector" == f.get("recommended_auditor") for f in all_findings) else None]
    }

def run(target, emit_obj, options: dict = None):
    """Hellhound synchronous entry point."""
    try:
        # Use asyncio.run() to create a new loop for the analysis.
        # This is the cleanest way to execute async logic from a sync context.
        return asyncio.run(_run_async(target, emit_obj, options))
    except RuntimeError as e:
        # Fallback if an event loop is already running in this thread
        if "running" in str(e).lower():
            try:
                loop = asyncio.get_event_loop()
                return loop.create_task(_run_async(target, emit_obj, options))
            except:
                pass
        emit_obj.warn(f"HYDRA execution error: {e}")
        return {"raw": str(e), "intel": {}, "signals": ["HYDRA_CRASH"]}
    except Exception as e:
        emit_obj.warn(f"HYDRA execution error: {e}")
        return {"raw": str(e), "intel": {}, "signals": ["HYDRA_CRASH"]}
