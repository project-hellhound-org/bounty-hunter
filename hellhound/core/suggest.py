"""
hellhound/core/suggest.py

Advanced rule-based suggestion engine (HOWL command).
Reads self.results from console and returns structured, prioritised next-steps.

Design principles:
  - Web targets only. No nmap / host / port / service logic.
  - Deterministic only. No AI, no guessing.
  - Cross-module correlation: chains findings across modules into attack paths.
  - Priority scoring: confirmed RCE outweighs param hints outweighs recon gaps.
  - Every suggestion carries: priority, confidence, reason, evidence, action.
  - Output is structured: CRITICAL PATH → CHAINS → OPTIONAL → SKIP LIST.
  - All intel key names must match actual module return shapes.
  - Module names in suggestions must exist in the modules/ tree.

Spider v12 intel shape:
  endpoints[], secrets[], cors_issues[], sourcemaps[], summary{}, tech_stack[]
  params per endpoint: {"query":[], "form":[], "js":[], ...}  (dict of buckets)

Exmap intel shape (new):
  cves[], exploits[], metasploit_modules[], components[], low_confidence[]
  each CVE: {id, summary, cvss, cvss_version, severity, cwes, weaponized,
             evidence_score, evidence_notes, component, component_version, nvd_url}
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────

KNOWN_MODULES = {
    "spider", "bacdetector", "cmdinj", "parax",
    "graphql_hunter", "jwt_analyzer", "wafbuster", "exmap",
    "idordetector",
}


P_CRITICAL = 0
P_HIGH     = 1
P_MEDIUM   = 2
P_LOW      = 3
P_SKIP     = 99

CONF_CONFIRMED = "confirmed"
CONF_STRONG    = "strong"
CONF_LIKELY    = "likely"
CONF_POSSIBLE  = "possible"

STATIC_ASSET_EXTENSIONS = {
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg",
    ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
    ".webp", ".mp4", ".mp3", ".pdf", ".zip",
}

PARAM_NOISE_BLOCKLIST = {
    "page", "limit", "offset", "size", "per_page", "cursor", "skip", "take",
    "format", "locale", "lang", "timezone", "currency",
    "v", "version", "cache", "ts", "t", "_", "cb", "bust",
    "tab", "view", "mode", "layout", "theme", "color",
    "type",
}

IDOR_PARAMS = {
    "id", "user_id", "uid", "account_id", "profile_id", "order_id",
    "invoice_id", "doc_id", "file_id", "record_id", "customer_id",
    "ticket_id", "item_id", "product_id", "post_id", "comment_id",
    "message_id", "thread_id", "conversation_id", "asset_id",
}
SQLI_PARAMS = {
    "search", "query", "q", "keyword", "filter", "sort", "order",
    "where", "username", "email", "login", "category",
    "tag", "status", "name",
}
CMDI_PARAMS = {
    "cmd", "exec", "command", "run", "ping", "host", "ip",
    "url", "to", "from", "file", "path", "dir", "shell",
    "input", "target", "dest", "source", "ref",
}
LFI_PARAMS = {
    "file", "path", "page", "template", "include", "load",
    "read", "doc", "document", "view", "lang",
    "module", "conf", "config",
}
REDIRECT_PARAMS = {
    "redirect", "return", "next", "url", "goto", "target",
    "continue", "redir", "returnUrl", "returnTo", "back",
}

PARAM_CLASS_WEIGHT = {
    "cmdi":     4,
    "sqli":     3,
    "lfi":      3,
    "idor":     2,
    "redirect": 1,
}


# ─────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────

@dataclass
class Suggestion:
    priority:   int
    confidence: str
    source:     str
    action:     str
    reason:     str
    evidence:   List[str]     = field(default_factory=list)
    chain:      Optional[str] = None
    skip:       bool          = False

    @property
    def priority_label(self):
        return {
            P_CRITICAL: "CRITICAL",
            P_HIGH:     "HIGH",
            P_MEDIUM:   "MEDIUM",
            P_LOW:      "LOW",
            P_SKIP:     "SKIP",
        }.get(self.priority, "?")

    @property
    def confidence_bar(self):
        return {
            CONF_CONFIRMED: "████",
            CONF_STRONG:    "███░",
            CONF_LIKELY:    "██░░",
            CONF_POSSIBLE:  "█░░░",
        }.get(self.confidence, "░░░░")


@dataclass
class SuggestReport:
    critical_path:  List[Suggestion] = field(default_factory=list)
    chains:         List[Suggestion] = field(default_factory=list)
    optional_intel: List[Suggestion] = field(default_factory=list)
    skip_list:      List[Suggestion] = field(default_factory=list)
    ran_modules:    List[str]        = field(default_factory=list)
    attack_chains:  List[str]        = field(default_factory=list)

    def all_active(self) -> List[Suggestion]:
        return self.critical_path + self.chains + self.optional_intel

    def as_strings(self) -> List[str]:
        lines = []
        if self.critical_path:
            lines.append("── CRITICAL PATH ─────────────────────────────────")
            for i, s in enumerate(self.critical_path, 1):
                lines.append(f"  [{i}] {s.action}")
                lines.append(f"      why:      {s.reason}")
                for ev in s.evidence:
                    lines.append(f"      evidence: {ev}")
                if s.chain:
                    lines.append(f"      chain:    {s.chain}")
        if self.chains:
            lines.append("── ATTACK CHAINS ─────────────────────────────────")
            for s in self.chains:
                lines.append(f"  ⛓  {s.action}")
                lines.append(f"      {s.reason}")
        if self.optional_intel:
            lines.append("── OPTIONAL INTEL ────────────────────────────────")
            for s in self.optional_intel:
                lines.append(f"  ○  {s.action}")
                lines.append(f"      {s.reason}")
        if self.skip_list:
            lines.append("── SKIP FOR NOW ──────────────────────────────────")
            for s in self.skip_list:
                lines.append(f"  ✗  {s.action}  ({s.reason})")
        if self.attack_chains:
            lines.append("── CONFIRMED CHAINS ──────────────────────────────")
            for c in self.attack_chains:
                lines.append(f"  ⚡ {c}")
        return lines


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def _is_static_asset(url: str) -> bool:
    try:
        path = urlparse(url).path.lower().split("?")[0]
        return any(path.endswith(ext) for ext in STATIC_ASSET_EXTENSIONS)
    except Exception:
        return False


def _flat_params(ep) -> set:
    raw = ep.get("params", {})
    if isinstance(raw, dict):
        names = set()
        for bucket in raw.values():
            if isinstance(bucket, list):
                names.update(bucket)
    elif isinstance(raw, list):
        names = {p["name"] for p in raw if isinstance(p, dict) and "name" in p}
    else:
        names = set()
    return names - PARAM_NOISE_BLOCKLIST


def _param_risk_score(params: set) -> dict:
    hits = {}
    if params & CMDI_PARAMS:     hits["cmdi"]     = sorted(params & CMDI_PARAMS)
    if params & SQLI_PARAMS:     hits["sqli"]     = sorted(params & SQLI_PARAMS)
    if params & LFI_PARAMS:      hits["lfi"]      = sorted(params & LFI_PARAMS)
    if params & IDOR_PARAMS:     hits["idor"]     = sorted(params & IDOR_PARAMS)
    if params & REDIRECT_PARAMS: hits["redirect"] = sorted(params & REDIRECT_PARAMS)

    score = sum(PARAM_CLASS_WEIGHT.get(cls, 0) for cls in hits)
    if   score >= 7: conf = CONF_STRONG
    elif score >= 4: conf = CONF_LIKELY
    else:            conf = CONF_POSSIBLE

    return {"classes": list(hits.keys()), "score": score, "hits": hits, "confidence": conf}


def _severity_rank(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        sev.lower().strip(), 5
    )


def _top_severity(findings: list) -> str:
    if not findings:
        return "none"
    ranked = sorted(findings, key=lambda f: _severity_rank(f.get("severity", "info")))
    return ranked[0].get("severity", "unknown").lower().strip()


def _sugg(priority, confidence, source, action, reason,
          evidence=None, chain=None, skip=False) -> Suggestion:
    return Suggestion(
        priority=priority, confidence=confidence, source=source,
        action=action, reason=reason,
        evidence=evidence or [], chain=chain, skip=skip,
    )


# ─────────────────────────────────────────────────────────────
# SHARED INTEL EXTRACTORS
# ─────────────────────────────────────────────────────────────

def _extract_bac_findings(results: dict) -> list:
    intel    = results.get("bacdetector", {}).get("intel", {})
    bac      = intel.get("bac", {})
    findings = bac.get("findings", []) if isinstance(bac, dict) else []
    vulns    = intel.get("vulnerabilities", [])
    all_f    = findings + vulns
    for f in all_f:
        if "severity" in f and isinstance(f["severity"], str):
            f["severity"] = f["severity"].lower().strip()
    return all_f


def _extract_idor_findings(results: dict) -> list:
    intel = results.get("idordetector", {}).get("intel", {})
    return [
        f for f in intel.get("findings", intel.get("vulnerabilities", []))
        if f.get("confirmed", True)
    ]


def _extract_cmdi_confirmed(results: dict) -> list:
    """Handles both 'confirmed' bool and 'detection' non-empty string."""
    vulns = results.get("cmdinj", {}).get("intel", {}).get("vulnerabilities", [])
    return [v for v in vulns if v.get("confirmed") or v.get("detection")]


def _spider_looks_incomplete(results: dict) -> tuple:
    intel           = results.get("spider", {}).get("intel", {})
    endpoints       = intel.get("endpoints", [])
    ep_count        = len(endpoints)
    auth_required   = sum(1 for e in endpoints if e.get("auth_required"))
    param_sensitive = sum(1 for e in endpoints if e.get("parameter_sensitive"))
    secrets         = len(intel.get("secrets", []))
    cors            = len(intel.get("cors_issues", []))

    if ep_count < 20 and auth_required == 0 and param_sensitive == 0 and secrets == 0 and cors == 0:
        return True, f"only {ep_count} endpoints with zero auth/sensitive/secrets/CORS signals — likely interrupted or shallow"
    if intel.get("summary", {}).get("interrupted") or intel.get("summary", {}).get("partial"):
        return True, "Spider scan was interrupted — partial results only"
    return False, ""


# ─────────────────────────────────────────────────────────────
# CROSS-MODULE CORRELATOR
# ─────────────────────────────────────────────────────────────

def _correlate(results: dict, ran: set) -> List[Suggestion]:
    chains = []

    spider_intel = results.get("spider",      {}).get("intel", {})
    parax_intel  = results.get("parax",       {}).get("intel", {})
    fp_intel     = results.get("fingerprint", {}).get("intel", {})

    endpoints     = spider_intel.get("endpoints", [])
    bac_findings  = _extract_bac_findings(results)
    idor_findings = _extract_idor_findings(results)
    confirmed_rce = _extract_cmdi_confirmed(results)
    parax_vulns   = parax_intel.get("vulnerabilities", [])

    dynamic_eps  = [e for e in endpoints if not _is_static_asset(e.get("url", ""))]
    bac_bypasses = [f for f in bac_findings if f.get("severity","") in ("critical","high")]

    # Chain 1: CMDi params + confirmed RCE
    cmdi_param_eps = [e for e in dynamic_eps if _flat_params(e) & CMDI_PARAMS]
    if cmdi_param_eps and confirmed_rce:
        chains.append(_sugg(
            P_CRITICAL, CONF_CONFIRMED, "correlator",
            action  = "RCE chain confirmed — document PoC + equip Exmap for CVE context",
            reason  = "Spider flagged CMDi-risk params and CMDinj confirmed exploitation on overlapping endpoints",
            evidence= [
                f"Spider: {len(cmdi_param_eps)} endpoint(s) with CMDi-risk params",
                f"CMDinj: {len(confirmed_rce)} confirmed RCE finding(s)",
            ],
            chain   = "Spider → CMDinj → Exmap",
        ))

    # Chain 2: BAC bypass + sensitive endpoints
    sensitive_eps = [e for e in endpoints if e.get("parameter_sensitive") or e.get("auth_required")]
    if bac_bypasses and sensitive_eps:
        chains.append(_sugg(
            P_CRITICAL, CONF_CONFIRMED, "correlator",
            action  = "Privilege escalation path — replay BAC bypass on sensitive endpoints",
            reason  = "BACdetector found auth bypass + Spider mapped sensitive endpoints; combine for horizontal/vertical escalation",
            evidence= [
                f"BAC: {len(bac_bypasses)} high/critical bypass finding(s)",
                f"Spider: {len(sensitive_eps)} sensitive/auth-walled endpoint(s)",
            ],
            chain   = "BACdetector → Spider sensitive EPs → IDORdetector",
        ))

    # Chain 3: BAC bypass + IDOR params, IDORdetector not run
    idor_param_eps = [e for e in dynamic_eps if _flat_params(e) & IDOR_PARAMS]
    if idor_param_eps and bac_bypasses and "idordetector" not in ran:
        chains.append(_sugg(
            P_HIGH, CONF_STRONG, "correlator",
            action  = "equip IDORdetector — BAC bypass + IDOR-risk params on same surface",
            reason  = "Auth bypass confirmed; IDOR params present — object-level access control likely broken",
            evidence= [
                f"Spider: {len(idor_param_eps)} endpoint(s) with IDOR-risk params",
                f"BAC: bypass confirmed at high/critical severity",
            ],
            chain   = "BACdetector → IDORdetector",
        ))

    # Chain 4: Confirmed IDOR + BAC = full object takeover
    if idor_findings and bac_bypasses:
        top_url = idor_findings[0].get("url", idor_findings[0].get("endpoint", "?"))
        chains.append(_sugg(
            P_CRITICAL, CONF_CONFIRMED, "correlator",
            action  = "Full object takeover path confirmed — extract, pivot, escalate",
            reason  = "IDORdetector confirmed unauthorised object access + BACdetector confirmed auth bypass; full escalation is proven",
            evidence= [
                f"IDOR: {len(idor_findings)} confirmed object access violation(s)",
                f"BAC: {len(bac_bypasses)} high/critical bypass finding(s)",
                f"Top IDOR: {top_url}",
            ],
            chain   = "BACdetector + IDORdetector → data exfiltration",
        ))

    # Chain 5: Confirmed IDOR endpoints + SQLi params
    if idor_findings and "parax" not in ran:
        idor_urls    = {f.get("url", f.get("endpoint","")) for f in idor_findings}
        sqli_overlap = [e for e in dynamic_eps if e.get("url","") in idor_urls and _flat_params(e) & SQLI_PARAMS]
        if sqli_overlap:
            chains.append(_sugg(
                P_HIGH, CONF_STRONG, "correlator",
                action  = "equip Parax — confirmed IDOR endpoints also carry SQLi-risk params",
                reason  = "Same endpoints with confirmed IDOR have query params matching SQLi patterns",
                evidence= [
                    f"IDOR-confirmed endpoints with SQLi params: {len(sqli_overlap)}",
                    f"Example: {sqli_overlap[0].get('url','')}",
                ],
                chain   = "IDORdetector → Parax",
            ))

    # Chain 6: Fingerprint versioned tech + Exmap not run
    detected_tech = fp_intel.get("detected", {}) or fp_intel.get("technologies", {})
    versioned_tech = {
        k: v for k, v in (detected_tech.items() if isinstance(detected_tech, dict) else {}.items())
        if v and str(v).strip()
    }
    if versioned_tech and "exmap" not in ran:
        top = list(versioned_tech.items())[:3]
        chains.append(_sugg(
            P_HIGH, CONF_STRONG, "correlator",
            action  = "equip Exmap — versioned tech fingerprinted, CVE lookup pending",
            reason  = "Fingerprint identified specific software versions; Exmap will map these to NVD CVEs with evidence scoring",
            evidence= [f"Fingerprint: {k} {v}" for k, v in top],
            chain   = "Fingerprint → Exmap",
        ))

    # Chain 7: Spider tech stack detected + Exmap not run
    tech_stack = spider_intel.get("tech_stack", [])
    if isinstance(tech_stack, set):
        tech_stack = list(tech_stack)
    if tech_stack and "exmap" not in ran and not versioned_tech:
        tech_names = [(t.get("name", t) if isinstance(t, dict) else str(t)) for t in tech_stack[:4]]
        chains.append(_sugg(
            P_HIGH, CONF_LIKELY, "correlator",
            action  = "equip Exmap — Spider detected web tech stack, CVE lookup not yet performed",
            reason  = "Exmap will extract versions from Spider intel and map each component to NVD CVEs",
            evidence= [f"Tech detected: {', '.join(str(t) for t in tech_names)}"],
            chain   = "Spider → Exmap",
        ))

    # Chain 8: Parax high-risk + CMDinj not run
    high_parax = [v for v in parax_vulns if v.get("risk","").lower() in ("critical","high")]
    if high_parax and "cmdinj" not in ran:
        chains.append(_sugg(
            P_HIGH, CONF_STRONG, "correlator",
            action  = "equip CMDinj — Parax confirmed high-risk params, injection not yet probed",
            reason  = "Parax classified params as high risk for injection; CMDinj will actively exploit these",
            evidence= [f"Parax: {len(high_parax)} high/critical-risk param(s)"],
            chain   = "Parax → CMDinj",
        ))

    # Chain 9: GraphQL endpoints found + hunter not run
    graphql_eps = spider_intel.get("graphql", [])
    if graphql_eps and "graphql_hunter" not in ran:
        chains.append(_sugg(
            P_HIGH, CONF_STRONG, "correlator",
            action  = "equip GraphQL — Spider found exposed GraphQL endpoints",
            reason  = "GraphQL endpoints are often misconfigured with introspection enabled; dedicated probe required",
            evidence= [f"Spider: {len(graphql_eps)} endpoint(s) detected"],
            chain   = "Spider → GraphQL",
        ))

    # Chain 10: Potential JWTs found + analyzer not run
    jwt_found = any("id_token" in str(e).lower() or "bearer" in str(e).lower() for e in spider_intel.get("endpoints", []))
    if jwt_found and "jwt_analyzer" not in ran:
        chains.append(_sugg(
            P_HIGH, CONF_LIKELY, "correlator",
            action  = "equip JWTanalyzer — Spider found potential tokens in endpoints",
            reason  = "Authorization headers or token-like strings detected; verify for algorithm confusion/none vulnerabilities",
            chain   = "Spider → JWTanalyzer",
        ))

    # Chain 10: Exmap found weaponized CVEs + no confirmed exploitation yet
    exmap_cves = results.get("exmap", {}).get("intel", {}).get("cves", [])
    weaponized  = [c for c in exmap_cves if c.get("weaponized")]
    if weaponized and not confirmed_rce:
        chains.append(_sugg(
            P_CRITICAL, CONF_CONFIRMED, "correlator",
            action  = "manual exploitation — Exmap found weaponized CVEs with public exploits",
            reason  = "Confirmed CVEs have weaponized exploits available; these are actionable attack paths",
            evidence= [
                f"Weaponized CVEs: {len(weaponized)}",
            ] + [
                f"{c.get('id','?')}  CVSS:{c.get('cvss','?')}  evidence:{c.get('evidence_score',0)}/100  → {c.get('component','?')}"
                for c in sorted(weaponized, key=lambda x: -(x.get("cvss") or 0))[:3]
            ],
            chain   = "Exmap → manual exploit / Metasploit",
        ))

    return chains


# ─────────────────────────────────────────────────────────────
# MODULE ANALYZERS
# ─────────────────────────────────────────────────────────────

def _analyze_spider(results, ran) -> List[Suggestion]:
    out   = []
    intel = results["spider"].get("intel", {})

    endpoints = intel.get("endpoints",   [])
    secrets   = intel.get("secrets",     [])
    cors      = intel.get("cors_issues", [])

    if not endpoints:
        out.append(_sugg(P_HIGH, CONF_POSSIBLE, "spider",
            action="re-run Spider with higher max_depth or authenticated cookie",
            reason="No endpoints discovered; likely hitting a login wall or shallow crawl",
        ))
        return out

    incomplete, incomplete_reason = _spider_looks_incomplete(results)
    if incomplete:
        out.append(_sugg(P_CRITICAL, CONF_CONFIRMED, "spider",
            action  = "re-run Spider — current intel is incomplete",
            reason  = f"Spider data insufficient for reliable downstream analysis: {incomplete_reason}",
            evidence= [
                f"Endpoints loaded: {len(endpoints)}",
                "Downstream results (IDOR, BAC, CMDi) are unreliable against a partial map",
                "Let Spider run to completion before striking other modules",
            ],
        ))
        return out

    dynamic_eps = [ep for ep in endpoints if not _is_static_asset(ep.get("url", ""))]
    auth_walled = [e for e in dynamic_eps if e.get("auth_required")]

    ep_risks = []
    for ep in dynamic_eps:
        params = _flat_params(ep)
        risk   = _param_risk_score(params)
        if risk["score"] > 0:
            ep_risks.append((ep.get("url",""), risk))
    ep_risks.sort(key=lambda x: x[1]["score"], reverse=True)

    cmdi_eps     = [(u,r) for u,r in ep_risks if "cmdi"     in r["classes"]]
    sqli_eps     = [(u,r) for u,r in ep_risks if "sqli"     in r["classes"]]
    lfi_eps      = [(u,r) for u,r in ep_risks if "lfi"      in r["classes"]]
    idor_eps     = [(u,r) for u,r in ep_risks if "idor"     in r["classes"]]
    redirect_eps = [(u,r) for u,r in ep_risks if "redirect" in r["classes"]]

    if cmdi_eps and "cmdinj" not in ran:
        top_url, top_risk = cmdi_eps[0]
        top3 = [f"  {u}  →  {', '.join(r['hits'].get('cmdi',[]))}" for u,r in cmdi_eps[:3]]
        out.append(_sugg(P_HIGH, top_risk["confidence"], "spider",
            action  = "equip CMDinj",
            reason  = f"{len(cmdi_eps)} endpoint(s) carry CMDi-risk params — highest risk: {top_url}",
            evidence= [f"Matched params: {', '.join(top_risk['hits'].get('cmdi',[]))}"] + top3,
        ))

    if sqli_eps and "parax" not in ran:
        top_url, top_risk = sqli_eps[0]
        top3 = [f"  {u}  →  {', '.join(r['hits'].get('sqli',[]))}" for u,r in sqli_eps[:3]]
        out.append(_sugg(P_HIGH, top_risk["confidence"], "spider",
            action  = "equip Parax",
            reason  = f"{len(sqli_eps)} dynamic endpoint(s) carry SQLi-risk params",
            evidence= [f"Matched params: {', '.join(top_risk['hits'].get('sqli',[]))}"] + top3,
        ))

    if lfi_eps and "parax" not in ran:
        top_url, top_risk = lfi_eps[0]
        top3 = [f"  {u}  →  {', '.join(r['hits'].get('lfi',[]))}" for u,r in lfi_eps[:3]]
        out.append(_sugg(P_HIGH, top_risk["confidence"], "spider",
            action  = "equip Parax (LFI-risk params detected)",
            reason  = f"{len(lfi_eps)} endpoint(s) carry LFI-risk params — file inclusion risk",
            evidence= [f"Matched params: {', '.join(top_risk['hits'].get('lfi',[]))}"] + top3,
        ))

    if auth_walled and "bacdetector" not in ran:
        out.append(_sugg(P_HIGH, CONF_STRONG, "spider",
            action  = "equip BACdetector",
            reason  = f"{len(auth_walled)} auth-walled endpoint(s) — access control not yet verified",
            evidence= [e.get("url","") for e in auth_walled[:3]],
        ))

    if idor_eps and "bacdetector" not in ran:
        top_url, top_risk = idor_eps[0]
        out.append(_sugg(P_HIGH, CONF_LIKELY, "spider",
            action  = "equip BACdetector (IDOR-risk params)",
            reason  = f"{len(idor_eps)} endpoint(s) with object-reference params — IDOR likely",
            evidence= [f"Matched params: {', '.join(top_risk['hits'].get('idor',[]))}"] + [u for u,_ in idor_eps[:3]],
        ))

    if secrets:
        by_type = {}
        for s in secrets:
            t = s.get("type","unknown")
            by_type[t] = by_type.get(t, 0) + 1
        types_str = ", ".join(f"{t} x{c}" for t, c in by_type.items())
        out.append(_sugg(P_CRITICAL, CONF_CONFIRMED, "spider",
            action  = "review loot immediately — secrets exposed",
            reason  = f"{len(secrets)} secret(s) found in source/JS ({types_str})",
            evidence= [f"Types: {types_str}"],
        ))

    high_cors = [c for c in cors if c.get("severity","").upper() in ("HIGH","CRITICAL")]
    if high_cors:
        out.append(_sugg(P_HIGH, CONF_CONFIRMED, "spider",
            action  = "manual CORS verification required",
            reason  = f"{len(high_cors)} high/critical CORS misconfiguration(s) — cross-origin request forgery risk",
            evidence= [c.get("url","") for c in high_cors[:3]],
        ))

    if redirect_eps and "parax" not in ran:
        out.append(_sugg(P_MEDIUM, CONF_LIKELY, "spider",
            action  = "equip Parax (open redirect params)",
            reason  = f"{len(redirect_eps)} endpoint(s) with redirect params — phishing pivot potential",
            evidence= [u for u,_ in redirect_eps[:2]],
        ))

    return out


def _analyze_fingerprint(results, ran) -> List[Suggestion]:
    out   = []
    intel = results["fingerprint"].get("intel", {})

    waf      = intel.get("waf",  None)
    cms      = intel.get("cms",  None)
    detected = intel.get("detected",{}) or intel.get("technologies",{})
    headers  = intel.get("headers",{})

    if waf:
        out.append(_sugg(P_HIGH, CONF_CONFIRMED, "fingerprint",
            action  = "equip WAFBuster — WAF detected",
            reason  = f"{waf} WAF identified; all direct exploitation attempts will be blocked without a bypass",
            evidence= [f"WAF: {waf}"],
        ))

    if cms:
        cms_name    = cms.get("name","") if isinstance(cms, dict) else str(cms)
        cms_version = cms.get("version","") if isinstance(cms, dict) else ""
        version_tag = f" v{cms_version}" if cms_version else ""

        if cms_version and "exmap" not in ran:
            out.append(_sugg(P_HIGH, CONF_STRONG, "fingerprint",
                action  = "equip Exmap",
                reason  = f"{cms_name}{version_tag} detected with version — map to CVE database",
                evidence= [f"CMS: {cms_name}{version_tag}"],
            ))
        elif not cms_version and "exmap" not in ran:
            out.append(_sugg(P_MEDIUM, CONF_LIKELY, "fingerprint",
                action  = "equip Exmap",
                reason  = f"{cms_name} detected (no version) — Exmap will attempt low-confidence CVE mapping",
                evidence= [f"CMS: {cms_name}  (version not detected — lower confidence)"],
            ))

    if isinstance(detected, dict):
        versioned = {k: v for k, v in detected.items() if v and str(v).strip()}
        if versioned and not cms and "exmap" not in ran:
            top = list(versioned.items())[:4]
            out.append(_sugg(P_HIGH, CONF_STRONG, "fingerprint",
                action  = "equip Exmap",
                reason  = "Specific software versions identified — CVE lookup not yet performed",
                evidence= [f"{k}: {v}" for k, v in top],
            ))

    missing = [
        h for h in ["X-Frame-Options","Content-Security-Policy","Strict-Transport-Security","X-Content-Type-Options"]
        if isinstance(headers, dict) and not headers.get(h)
    ]
    if missing:
        out.append(_sugg(P_MEDIUM, CONF_CONFIRMED, "fingerprint",
            action  = "document missing security headers",
            reason  = f"{len(missing)} security header(s) absent — increases attack surface",
            evidence= [f"Missing: {', '.join(missing)}"],
        ))

    return out


def _analyze_bacdetector(results, ran) -> List[Suggestion]:
    out          = []
    all_findings = _extract_bac_findings(results)

    if not all_findings:
        out.append(_sugg(P_LOW, CONF_POSSIBLE, "bacdetector",
            action="review BAC config — no findings; verify session handling manually",
            reason="Zero findings may mean robust access control, or insufficient coverage",
        ))
        return out

    high     = [f for f in all_findings if f.get("severity","") in ("critical","high")]
    top      = _top_severity(all_findings)
    top_urls = list({f.get("url",f.get("endpoint","")) for f in high if f.get("url") or f.get("endpoint")})[:3]

    out.append(_sugg(
        P_CRITICAL if top in ("critical","high") else P_HIGH,
        CONF_CONFIRMED, "bacdetector",
        action  = "review loot — BAC findings require manual verification + PoC",
        reason  = f"{len(all_findings)} access control issue(s), top severity: {top.upper()}",
        evidence= [f"Total: {len(all_findings)} | High/Critical: {len(high)}"] + top_urls,
    ))

    if high and "cmdinj" not in ran:
        out.append(_sugg(P_HIGH, CONF_STRONG, "bacdetector",
            action  = "equip CMDinj — confirmed auth bypass enables direct injection testing",
            reason  = "Access control bypass on auth-required endpoints creates direct path to CMDi",
            evidence= [f"BAC bypass at: {f.get('url',f.get('endpoint',''))}" for f in high[:2]],
        ))

    if high and "idordetector" not in ran:
        out.append(_sugg(P_HIGH, CONF_STRONG, "bacdetector",
            action  = "equip IDORdetector — auth bypass on object endpoints indicates IDOR surface",
            reason  = "High/critical BAC bypass found; object-level access control is the natural next test",
            evidence= [f"BAC: {len(high)} high/critical finding(s)"],
        ))

    return out


def _analyze_idordetector(results, ran) -> List[Suggestion]:
    out      = []
    findings = _extract_idor_findings(results)

    if not findings:
        out.append(_sugg(P_LOW, CONF_POSSIBLE, "idordetector",
            action="review IDORdetector config — no confirmed findings; verify ID pool coverage",
            reason="Zero confirmed IDORs; may need wider ID range or authenticated session for harvest pass",
        ))
        return out

    by_location: dict      = {}
    sensitive_findings: list = []
    for f in findings:
        loc = f.get("location", f.get("param_location","unknown"))
        by_location[loc] = by_location.get(loc, 0) + 1
        ev  = f.get("evidence",[])
        if isinstance(ev, list) and any("sensitive" in str(e).lower() for e in ev):
            sensitive_findings.append(f)
        elif isinstance(ev, str) and "sensitive" in ev.lower():
            sensitive_findings.append(f)

    loc_summary = ", ".join(f"{loc}: {cnt}" for loc, cnt in by_location.items())
    top_urls    = list({f.get("url",f.get("endpoint","")) for f in findings if f.get("url") or f.get("endpoint")})[:3]

    out.append(_sugg(
        P_CRITICAL, CONF_CONFIRMED, "idordetector",
        action  = "document IDOR PoC + assess data exposure scope",
        reason  = f"{len(findings)} confirmed IDOR finding(s) — unauthorised object access proven ({loc_summary})",
        evidence= [f"Confirmed: {len(findings)}  |  Locations: {loc_summary}"] + top_urls,
    ))

    if sensitive_findings:
        out.append(_sugg(
            P_CRITICAL, CONF_CONFIRMED, "idordetector",
            action  = "escalate — IDOR responses contain sensitive data fields",
            reason  = f"{len(sensitive_findings)} IDOR finding(s) leaked sensitive response fields (PII, tokens, credentials)",
            evidence= [
                f.get("url",f.get("endpoint","?")) + "  ->  " + str(f.get("evidence",""))[:80]
                for f in sensitive_findings[:3]
            ],
        ))

    if "parax" not in ran:
        out.append(_sugg(P_HIGH, CONF_LIKELY, "idordetector",
            action  = "equip Parax — test IDOR-confirmed endpoints for SQLi/LFi",
            reason  = "IDOR-confirmed endpoints are high-value injection targets; Parax will probe the same surface",
        ))

    return out


def _analyze_parax(results, ran) -> List[Suggestion]:
    out   = []
    intel = results["parax"].get("intel", {})
    vulns = intel.get("vulnerabilities", [])

    if not vulns:
        out.append(_sugg(P_LOW, CONF_POSSIBLE, "parax",
            action="review Parax config — no param risks found, verify coverage",
            reason="Zero findings; confirm Parax scanned all discovered endpoints",
        ))
        return out

    by_class = {}
    for v in vulns:
        cls = v.get("type", v.get("class","unknown"))
        by_class[cls] = by_class.get(cls, 0) + 1

    high = [v for v in vulns if v.get("risk","").lower() in ("critical","high")]

    out.append(_sugg(
        P_CRITICAL if high else P_HIGH,
        CONF_CONFIRMED, "parax",
        action  = "review loot — parameter risks classified, highest-confidence first",
        reason  = f"{len(vulns)} param risk(s) across {len(by_class)} class(es): {', '.join(by_class.keys())}",
        evidence= [f"{cls}: {cnt}" for cls, cnt in by_class.items()],
    ))

    if high and "cmdinj" not in ran:
        out.append(_sugg(P_HIGH, CONF_STRONG, "parax",
            action  = "equip CMDinj — Parax classified params as high injection risk",
            reason  = f"{len(high)} high/critical param risks; active exploitation not yet attempted",
        ))

    return out


def _analyze_cmdinj(results, ran) -> List[Suggestion]:
    out   = []
    intel = results["cmdinj"].get("intel", {})
    vulns = intel.get("vulnerabilities", [])

    if not vulns:
        out.append(_sugg(P_LOW, CONF_POSSIBLE, "cmdinj",
            action="no CMDi findings — consider manual payload crafting or WAF bypass",
            reason="Zero findings; WAF or input sanitisation may be filtering probes",
        ))
        return out

    confirmed   = [v for v in vulns if v.get("confirmed") or v.get("detection")]
    unconfirmed = [v for v in vulns if not (v.get("confirmed") or v.get("detection"))]

    if confirmed:
        top_urls = [v.get("url",v.get("endpoint","")) for v in confirmed[:3]]
        out.append(_sugg(P_CRITICAL, CONF_CONFIRMED, "cmdinj",
            action  = "document PoC + escalate — confirmed RCE",
            reason  = f"{len(confirmed)} confirmed command injection(s) with PoC; this is the critical finding",
            evidence= [f"Confirmed: {len(confirmed)} | Unconfirmed: {len(unconfirmed)}"] + top_urls,
        ))
        if "exmap" not in ran:
            out.append(_sugg(P_HIGH, CONF_STRONG, "cmdinj",
                action  = "equip Exmap — map confirmed RCE context to CVEs for report",
                reason  = "Exmap will correlate confirmed RCE with known CVEs and Metasploit modules",
            ))
    elif unconfirmed:
        out.append(_sugg(P_HIGH, CONF_LIKELY, "cmdinj",
            action  = "manual verification required — unconfirmed CMDi findings",
            reason  = f"{len(unconfirmed)} unconfirmed injection indicator(s); scanner saw evidence but could not verify blind",
            evidence= [v.get("url",v.get("endpoint","")) for v in unconfirmed[:3]],
        ))

    return out


def _analyze_graphql_hunter(results, ran) -> List[Suggestion]:
    out   = []
    intel = results.get("graphql_hunter", {}).get("intel", {})
    eps   = intel.get("graphql_endpoints", [])
    
    if eps:
        vuln_eps = [e for e in eps if e.get("introspection_enabled") or e.get("suggestions_enabled")]
        if vuln_eps:
             out.append(_sugg(P_CRITICAL, CONF_CONFIRMED, "graphql_hunter",
                action  = "exploit GraphQL — introspection/suggestions enabled",
                reason  = f"{len(vuln_eps)} GraphQL endpoint(s) allow schema extraction or field suggestions",
                evidence= [e.get("endpoint","") for e in vuln_eps[:3]],
            ))
        else:
            out.append(_sugg(P_MEDIUM, CONF_CONFIRMED, "graphql_hunter",
                action  = "review GraphQL loot — endpoints confirmed but locked down",
                reason  = f"{len(eps)} GraphQL endpoint(s) analyzed; no immediate leaks found",
            ))
    return out


def _analyze_jwt_analyzer(results, ran) -> List[Suggestion]:
    out   = []
    intel = results.get("jwt_analyzer", {}).get("intel", {})
    jwts  = intel.get("jwts", [])
    
    critical = [j for j in jwts if any("CRITICAL" in v for v in j.get("vulnerabilities", []))]
    if critical:
        out.append(_sugg(P_CRITICAL, CONF_CONFIRMED, "jwt_analyzer",
            action  = "escalate JWT — critical vulnerability (e.g. none algorithm) confirmed",
            reason  = f"{len(critical)} JWT(s) are exploitable via algorithm confusion or null signatures",
            evidence= [j.get("token","")[:30] + "..." for j in critical[:2]],
        ))
    elif jwts:
        out.append(_sugg(P_HIGH, CONF_CONFIRMED, "jwt_analyzer",
            action  = "review JWT loot — sensitive data exposure in claims",
            reason  = "Tokens analyzed; some contain high-value PII or session identifiers",
        ))
    return out


def _analyze_credleak(results, ran) -> List[Suggestion]:
    out   = []
    intel = results["credleak"].get("intel", {})

    emails = intel.get("emails",  [])
    keys   = intel.get("api_keys", intel.get("keys", []))
    pastes = intel.get("pastes",  [])
    s3     = intel.get("s3_buckets", [])

    if keys:
        ev = [f"Key types: {', '.join(set(k.get('type','?') for k in keys))}"] if keys and isinstance(keys[0], dict) else [f"{len(keys)} key(s)"]
        out.append(_sugg(P_CRITICAL, CONF_CONFIRMED, "credleak",
            action  = "revoke and rotate — API keys/secrets found in leak databases",
            reason  = f"{len(keys)} key(s) exposed; active keys are immediately exploitable",
            evidence= ev,
        ))
    if pastes:
        out.append(_sugg(P_HIGH, CONF_CONFIRMED, "credleak",
            action  = "review paste exposure — credentials or code found in public pastes",
            reason  = f"{len(pastes)} paste(s) containing target data",
        ))
    if s3:
        out.append(_sugg(P_HIGH, CONF_CONFIRMED, "credleak",
            action  = "verify S3 bucket permissions — public buckets detected",
            reason  = f"{len(s3)} S3 bucket(s) found; misconfigured buckets allow data exfiltration",
            evidence= s3[:3],
        ))
    if emails and not keys and not pastes:
        out.append(_sugg(P_MEDIUM, CONF_CONFIRMED, "credleak",
            action  = "harvest email list for phishing prep or password spray",
            reason  = f"{len(emails)} email address(es) found — no active leaks, but useful for next phase",
        ))

    return out


def _analyze_exmap(results, ran) -> List[Suggestion]:
    """
    Reads new Exmap intel shape:
      cves[]              — evidence-scored CVEs above threshold
      exploits[]          — ExploitDB entries
      metasploit_modules[]
      low_confidence[]    — suppressed CVEs below evidence threshold
    """
    out   = []
    intel = results["exmap"].get("intel", {})

    cves     = intel.get("cves",               [])
    exploits = intel.get("exploits",           [])
    msf      = intel.get("metasploit_modules", [])
    low_conf = intel.get("low_confidence",     [])

    if not cves and not exploits and not msf:
        if low_conf:
            out.append(_sugg(P_MEDIUM, CONF_POSSIBLE, "exmap",
                action  = "review Exmap low_confidence — CVEs found but evidence below threshold",
                reason  = f"{len(low_conf)} CVE(s) suppressed; consider 'set show_low_confidence true' or run Spider with version detection enabled",
                evidence= [f"Suppressed CVEs: {len(low_conf)} — use 'loot' to inspect"],
            ))
        return out

    critical_cves = [c for c in cves if (c.get("cvss") or 0) >= 9.0]
    weaponized    = [c for c in cves if c.get("weaponized")]

    if cves:
        priority = P_CRITICAL if (critical_cves or weaponized) else P_HIGH
        top_cves = sorted(cves, key=lambda c: (-(c.get("evidence_score") or 0), -(c.get("cvss") or 0)))[:3]
        evidence = [f"CVEs: {len(cves)} confirmed  |  {len(critical_cves)} critical  |  {len(weaponized)} weaponized"]
        for c in top_cves:
            wpn = " [WEAPONIZED]" if c.get("weaponized") else ""
            evidence.append(
                f"{c.get('id','?')}{wpn}  CVSS:{c.get('cvss','?')}  evidence:{c.get('evidence_score',0)}/100"
                f"  -> {c.get('component','?')}" + (f" {c.get('component_version','')}" if c.get("component_version") else "")
            )
        out.append(_sugg(priority, CONF_CONFIRMED, "exmap",
            action  = "review CVE findings — Exmap mapped web stack to confirmed CVEs",
            reason  = f"{len(cves)} CVE(s) above evidence threshold; {len(critical_cves)} critical, {len(weaponized)} weaponized",
            evidence= evidence,
        ))

    if weaponized:
        top_w = sorted(weaponized, key=lambda c: -(c.get("cvss") or 0))[:3]
        out.append(_sugg(P_CRITICAL, CONF_CONFIRMED, "exmap",
            action  = "exploit now — weaponized CVEs with public exploits confirmed on target stack",
            reason  = f"{len(weaponized)} CVE(s) have ExploitDB entries or Metasploit modules; these are immediately actionable",
            evidence= [
                f"{c.get('id','?')}  CVSS:{c.get('cvss','?')}  evidence:{c.get('evidence_score',0)}/100  -> {c.get('component','?')}"
                for c in top_w
            ],
        ))

    if msf:
        out.append(_sugg(P_HIGH, CONF_CONFIRMED, "exmap",
            action  = "load Metasploit modules for mapped CVEs",
            reason  = f"{len(msf)} Metasploit module(s) available",
            evidence= msf[:4],
        ))

    if low_conf:
        out.append(_sugg(P_LOW, CONF_POSSIBLE, "exmap",
            action  = "review Exmap low_confidence list — suppressed CVEs may be relevant",
            reason  = f"{len(low_conf)} CVE(s) below evidence threshold; run 'set show_low_confidence true' or improve version detection to promote them",
        ))

    return out


# ─────────────────────────────────────────────────────────────
# SKIP LIST BUILDER
# ─────────────────────────────────────────────────────────────

def _build_skip_list(results: dict, ran: set, active_actions: set) -> List[Suggestion]:
    skip         = []
    spider_intel = results.get("spider", {}).get("intel", {})
    endpoints    = spider_intel.get("endpoints", [])
    secrets      = spider_intel.get("secrets",   [])


    if "fuzzhunter" not in ran and "spider" in ran and len(endpoints) > 20:
        skip.append(_sugg(P_SKIP, CONF_LIKELY, "skip",
            action="FUZZhunter",
            reason=f"Spider already mapped {len(endpoints)} endpoints — fuzzing would duplicate coverage",
            skip=True,
        ))


    return skip


# ─────────────────────────────────────────────────────────────
# CONFIRMED ATTACK CHAIN LABELS
# ─────────────────────────────────────────────────────────────

def _detected_attack_chains(results: dict) -> List[str]:
    chains = []
    ran    = set(results.keys())

    confirmed_rce  = _extract_cmdi_confirmed(results)
    bac_bypasses   = [f for f in _extract_bac_findings(results) if f.get("severity","") in ("critical","high")]
    idor_confirmed = _extract_idor_findings(results)
    exmap_cves     = results.get("exmap", {}).get("intel", {}).get("cves", [])
    weaponized     = [c for c in exmap_cves if c.get("weaponized")]
    has_secrets    = bool(results.get("spider", {}).get("intel", {}).get("secrets", []))

    if confirmed_rce and "exmap" in ran:
        chains.append("RCE-to-CVE chain: CMDinj confirmed -> Exmap correlated -> full exploit documented")

    if bac_bypasses and confirmed_rce:
        chains.append("Privilege escalation chain: BAC bypass -> CMDinj on auth-protected endpoint -> full compromise")

    if idor_confirmed and bac_bypasses:
        chains.append(
            f"Full object takeover: BAC bypass ({len(bac_bypasses)} finding(s)) + "
            f"IDOR confirmed ({len(idor_confirmed)} object(s)) -> horizontal escalation proven"
        )

    if weaponized:
        cve_ids = ", ".join(c.get("id","?") for c in weaponized[:3])
        chains.append(
            f"Weaponized CVE chain: Exmap mapped {len(weaponized)} exploitable CVE(s) "
            f"on detected stack [{cve_ids}] -> immediate exploitation path"
        )


    return chains


# ─────────────────────────────────────────────────────────────
# MAIN ENTRY POINTS
# ─────────────────────────────────────────────────────────────

def suggest_actions(results: dict) -> List[str]:
    """Legacy-compatible flat string output."""
    return suggest_report(results).as_strings()


def suggest_report(results: dict) -> SuggestReport:
    report = SuggestReport()

    if not results:
        report.critical_path.append(_sugg(P_HIGH, CONF_POSSIBLE, "howl",
            action="equip Spider",
            reason="No intelligence gathered yet — Spider is the mandatory first step for web targets",
        ))
        return report

    ran = set(results.keys())
    report.ran_modules = sorted(ran)

    all_suggestions: List[Suggestion] = []

    analyzer_map = {
        "spider":       _analyze_spider,
        "fingerprint":  _analyze_fingerprint,
        "bacdetector":  _analyze_bacdetector,
        "idordetector": _analyze_idordetector,
        "parax":        _analyze_parax,
        "cmdinj":       _analyze_cmdinj,
        "graphql_hunter": _analyze_graphql_hunter,
        "jwt_analyzer":   _analyze_jwt_analyzer,
        "exmap":        _analyze_exmap,
    }

    for module, analyzer in analyzer_map.items():
        if module in results:
            try:
                all_suggestions.extend(analyzer(results, ran))
            except Exception:
                pass

    correlation_chains = _correlate(results, ran)

    if "spider" not in ran:
        all_suggestions.append(_sugg(P_HIGH, CONF_STRONG, "howl",
            action="equip Spider first",
            reason="Spider provides the foundational endpoint map that all other modules depend on",
        ))

    conf_order = {CONF_CONFIRMED: 0, CONF_STRONG: 1, CONF_LIKELY: 2, CONF_POSSIBLE: 3}
    all_suggestions.sort(key=lambda s: (s.priority, conf_order.get(s.confidence, 4)))
    correlation_chains.sort(key=lambda s: (s.priority, conf_order.get(s.confidence, 4)))

    seen_actions: set = set()
    deduped: List[Suggestion] = []
    for s in all_suggestions:
        key = s.action.lower().strip()
        if key not in seen_actions:
            seen_actions.add(key)
            deduped.append(s)

    for s in deduped:
        if s.priority <= P_HIGH:
            report.critical_path.append(s)
        else:
            report.optional_intel.append(s)

    report.chains        = correlation_chains
    report.skip_list     = _build_skip_list(results, ran, seen_actions)
    report.attack_chains = _detected_attack_chains(results)

    return report