"""
hellhound/core/suggest.py

Advanced rule-based suggestion engine (HOWL command).
Reads self.results from console and returns structured, prioritised next-steps.

Design principles:
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
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional


# ─────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────

KNOWN_MODULES = {
    "spider", "bacdetector", "cmdinj", "parax",
    "seige", "fuzzhunter", "fingerprint", "credleak",
    "stalk", "surfacemap", "wafbuster", "exmap",
    "idordetector", "emptracker", "phishprep",
}

SERVICE_MODULE_MAP = {
    "http":         ["spider", "fuzzhunter", "wafbuster"],
    "https":        ["spider", "fuzzhunter", "wafbuster"],
    "ftp":          [],
    "ssh":          [],
    "mysql":        [],
    "microsoft-ds": [],
}

# Priority tiers (lower = more urgent)
P_CRITICAL  = 0   # confirmed exploitable, act immediately
P_HIGH      = 1   # strong evidence, high-confidence recommendation
P_MEDIUM    = 2   # moderate evidence, worth pursuing
P_LOW       = 3   # informational, optional next step
P_SKIP      = 99  # intentionally not recommended right now

# Confidence labels
CONF_CONFIRMED  = "confirmed"   # module produced a verified finding
CONF_STRONG     = "strong"      # multiple corroborating signals
CONF_LIKELY     = "likely"      # single signal, high-risk param/pattern
CONF_POSSIBLE   = "possible"    # heuristic match, low specificity

# Version → CVE map (extend as needed)
VERSION_CVE_MAP = [
    {
        "match":   r"apache[/ ]*2\.4\.49",
        "cve":     "CVE-2021-41773",
        "title":   "Apache Path Traversal + RCE",
        "cvss":    9.8,
        "weaponized": True,
    },
    {
        "match":   r"apache[/ ]*2\.4\.50",
        "cve":     "CVE-2021-42013",
        "title":   "Apache Path Traversal (bypass of 41773 patch)",
        "cvss":    9.8,
        "weaponized": True,
    },
    {
        "match":   r"vsftpd[/ ]*2\.3\.4",
        "cve":     "CVE-2011-2523",
        "title":   "vsftpd Backdoor Command Execution",
        "cvss":    10.0,
        "weaponized": True,
    },
    {
        "match":   r"openssh[/ ]*[67]\.\d",
        "cve":     "CVE-2016-6210",
        "title":   "OpenSSH Username Enumeration",
        "cvss":    5.3,
        "weaponized": False,
    },
    {
        "match":   r"php[/ ]*[45]\.\d",
        "cve":     "CVE-2012-1823",
        "title":   "PHP CGI Argument Injection",
        "cvss":    7.5,
        "weaponized": True,
    },
    {
        "match":   r"wordpress[/ ]*([0-3]\.\d|4\.[0-8])",
        "cve":     "CVE-2019-8943",
        "title":   "WordPress Path Traversal (old core)",
        "cvss":    6.5,
        "weaponized": False,
    },
]

# Param name sets for vuln class heuristics
IDOR_PARAMS = {
    "id", "user_id", "uid", "account_id", "profile_id", "order_id",
    "invoice_id", "doc_id", "file_id", "record_id", "customer_id",
    "ticket_id", "item_id", "product_id", "post_id", "comment_id",
}
SQLI_PARAMS = {
    "search", "query", "q", "keyword", "filter", "sort", "order",
    "where", "name", "username", "email", "login", "category",
    "tag", "type", "status", "page", "limit", "offset",
}
CMDI_PARAMS = {
    "cmd", "exec", "command", "run", "ping", "host", "ip",
    "url", "to", "from", "file", "path", "dir", "shell",
    "input", "target", "dest", "source", "ref",
}
LFI_PARAMS = {
    "file", "path", "page", "template", "include", "load",
    "read", "doc", "document", "view", "lang", "locale",
    "module", "conf", "config",
}
REDIRECT_PARAMS = {
    "redirect", "return", "next", "url", "goto", "target",
    "continue", "redir", "returnUrl", "returnTo", "back",
}

# Cross-param overlap: if an endpoint has params in multiple classes
# it gets a higher combined risk score
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
    """A single actionable suggestion with full context."""
    priority:   int             # P_CRITICAL..P_SKIP
    confidence: str             # CONF_CONFIRMED..CONF_POSSIBLE
    source:     str             # which module/rule produced this
    action:     str             # what to do: "equip X" / "review loot" / "manual verify"
    reason:     str             # one-line human explanation
    evidence:   List[str] = field(default_factory=list)   # bullet points of raw data
    chain:      Optional[str] = None   # attack chain label if part of a multi-step path
    skip:       bool = False           # if True → goes into SKIP LIST not main output

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
        bars = {
            CONF_CONFIRMED: "████",
            CONF_STRONG:    "███░",
            CONF_LIKELY:    "██░░",
            CONF_POSSIBLE:  "█░░░",
        }
        return bars.get(self.confidence, "░░░░")


@dataclass
class SuggestReport:
    """Full structured output from the suggestion engine."""
    critical_path:  List[Suggestion] = field(default_factory=list)
    chains:         List[Suggestion] = field(default_factory=list)
    optional_intel: List[Suggestion] = field(default_factory=list)
    skip_list:      List[Suggestion] = field(default_factory=list)
    ran_modules:    List[str]        = field(default_factory=list)
    attack_chains:  List[str]        = field(default_factory=list)   # detected multi-step paths

    def all_active(self) -> List[Suggestion]:
        return self.critical_path + self.chains + self.optional_intel

    def as_strings(self) -> List[str]:
        """Legacy-compatible flat list for callers that expect List[str]."""
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
            lines.append("── DETECTED ATTACK CHAINS ────────────────────────")
            for c in self.attack_chains:
                lines.append(f"  ⚡ {c}")
        return lines


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def _flat_params(ep) -> set:
    """
    Spider v12: params stored as dict of buckets.
    {"query": ["id", "user"], "form": ["email"], "js": [], ...}
    Flatten to a set of param name strings.
    """
    raw = ep.get("params", {})
    if isinstance(raw, dict):
        names = set()
        for bucket in raw.values():
            if isinstance(bucket, list):
                names.update(bucket)
        return names
    if isinstance(raw, list):
        return {p["name"] for p in raw if isinstance(p, dict) and "name" in p}
    return set()


def _param_risk_score(params: set) -> dict:
    """
    Given a flat set of param names, return a dict of:
      {"classes": [...vuln classes...], "score": int, "hits": {class: [matched_params]}}
    Higher score = more diverse risk.
    """
    hits = {}
    if params & CMDI_PARAMS:
        hits["cmdi"]     = sorted(params & CMDI_PARAMS)
    if params & SQLI_PARAMS:
        hits["sqli"]     = sorted(params & SQLI_PARAMS)
    if params & LFI_PARAMS:
        hits["lfi"]      = sorted(params & LFI_PARAMS)
    if params & IDOR_PARAMS:
        hits["idor"]     = sorted(params & IDOR_PARAMS)
    if params & REDIRECT_PARAMS:
        hits["redirect"] = sorted(params & REDIRECT_PARAMS)

    score = sum(PARAM_CLASS_WEIGHT.get(cls, 0) for cls in hits)
    return {"classes": list(hits.keys()), "score": score, "hits": hits}


def _severity_rank(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        sev.lower(), 5
    )


def _top_severity(findings: list) -> str:
    if not findings:
        return "none"
    ranked = sorted(findings, key=lambda f: _severity_rank(f.get("severity", "info")))
    return ranked[0].get("severity", "unknown")


def _sugg(priority, confidence, source, action, reason,
          evidence=None, chain=None, skip=False) -> Suggestion:
    return Suggestion(
        priority=priority,
        confidence=confidence,
        source=source,
        action=action,
        reason=reason,
        evidence=evidence or [],
        chain=chain,
        skip=skip,
    )


# ─────────────────────────────────────────────────────────────
# CROSS-MODULE CORRELATOR
# ─────────────────────────────────────────────────────────────

def _correlate(results: dict, ran: set) -> List[Suggestion]:
    """
    Detects multi-module attack chains and produces high-value suggestions
    that no single module's section would emit alone.

    Examples of chains detected:
      Spider(cmdi_params) + CMDinj(confirmed) → "RCE chain complete, escalate"
      Spider(auth_endpoints) + BAC(bypass)    → "Auth bypass chain, pivot to IDOR"
      Fingerprint(cms_version) + Exmap        → "Version fingerprint → CVE lookup chain"
      BAC(bypass) + Spider(sensitive_ep)      → "Auth bypass on sensitive endpoint"
      Stalk(subdomains) + Spider(endpoints)   → "Multi-surface coverage chain"
    """
    chains = []

    spider_intel  = results.get("spider",      {}).get("intel", {})
    bac_intel     = results.get("bacdetector", {}).get("intel", {})
    cmdinj_intel  = results.get("cmdinj",      {}).get("intel", {})
    parax_intel   = results.get("parax",       {}).get("intel", {})
    fp_intel      = results.get("fingerprint", {}).get("intel", {})
    stalk_intel   = results.get("stalk",       {}).get("intel", {})

    endpoints     = spider_intel.get("endpoints",   [])
    bac_findings  = (bac_intel.get("bac",   {}).get("findings", []) if isinstance(bac_intel.get("bac"), dict) else []) + bac_intel.get("vulnerabilities", [])
    cmdi_vulns    = cmdinj_intel.get("vulnerabilities", [])
    parax_vulns   = parax_intel.get("vulnerabilities",  [])

    # ── Chain 1: CMDi params found by Spider + CMDinj confirmed RCE ──
    cmdi_param_eps = [e for e in endpoints if _flat_params(e) & CMDI_PARAMS]
    confirmed_rce  = [v for v in cmdi_vulns if v.get("confirmed")]
    if cmdi_param_eps and confirmed_rce:
        chains.append(_sugg(
            P_CRITICAL, CONF_CONFIRMED, "correlator",
            action  = "RCE chain confirmed — document PoC + escalate to Exmap for CVE context",
            reason  = "Spider flagged CMDi-risk params and CMDinj confirmed exploitation on overlapping endpoints",
            evidence= [
                f"Spider: {len(cmdi_param_eps)} endpoint(s) with CMDi-risk params",
                f"CMDinj: {len(confirmed_rce)} confirmed RCE finding(s)",
            ],
            chain   = "Spider → CMDinj → Exmap",
        ))

    # ── Chain 2: BAC bypass + sensitive endpoints = privilege escalation path ──
    bac_bypasses = [f for f in bac_findings if f.get("severity","").lower() in ("critical","high")]
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

    # ── Chain 3: IDOR params + BAC bypass = confirmed object access ──
    idor_param_eps = [e for e in endpoints if _flat_params(e) & IDOR_PARAMS]
    if idor_param_eps and bac_bypasses and "idordetector" not in ran:
        chains.append(_sugg(
            P_HIGH, CONF_STRONG, "correlator",
            action  = "equip IDORdetector — BAC bypass + IDOR-risk params on same surface",
            reason  = "Auth bypass is confirmed; IDOR params present; object-level access control likely broken",
            evidence= [
                f"Spider: {len(idor_param_eps)} endpoint(s) with IDOR-risk params",
                f"BAC: bypass confirmed at high/critical severity",
            ],
            chain   = "BACdetector → IDORdetector",
        ))

    # ── Chain 4: Fingerprint version + no Exmap run ──
    detected_tech  = fp_intel.get("detected", {}) or fp_intel.get("technologies", {})
    versioned_tech = {k: v for k, v in (detected_tech.items() if isinstance(detected_tech, dict) else {}.items()) if v and str(v).strip()}
    if versioned_tech and "exmap" not in ran:
        top = list(versioned_tech.items())[:3]
        chains.append(_sugg(
            P_HIGH, CONF_STRONG, "correlator",
            action  = "equip Exmap — versioned tech fingerprinted, CVE lookup pending",
            reason  = "Fingerprint identified specific software versions; Exmap will map these to known CVEs and weaponized exploits",
            evidence= [f"Fingerprint: {k} {v}" for k, v in top],
            chain   = "Fingerprint → Exmap",
        ))

    # ── Chain 5: Parax high-risk params + CMDinj not run ──
    high_parax = [v for v in parax_vulns if v.get("risk","").lower() in ("critical","high")]
    if high_parax and "cmdinj" not in ran:
        chains.append(_sugg(
            P_HIGH, CONF_STRONG, "correlator",
            action  = "equip CMDinj — Parax confirmed high-risk params, injection not yet probed",
            reason  = "Parax classified params as high risk for injection; CMDinj will actively exploit these",
            evidence= [f"Parax: {len(high_parax)} high/critical-risk param(s)"],
            chain   = "Parax → CMDinj",
        ))

    # ── Chain 6: Stalk subdomains + Spider not yet run on all surfaces ──
    subdomains = stalk_intel.get("infrastructure", {}).get("subdomains", [])
    if subdomains and "spider" in ran:
        chains.append(_sugg(
            P_MEDIUM, CONF_LIKELY, "correlator",
            action  = "re-equip Spider on discovered subdomains",
            reason  = "Stalk found subdomains not in current Spider scope; each is an independent attack surface",
            evidence= [f"Stalk: {len(subdomains)} subdomain(s): {', '.join(subdomains[:4])}{'...' if len(subdomains)>4 else ''}"],
            chain   = "Stalk → Spider (multi-surface)",
        ))

    # ── Chain 7: Secrets found + CredLeak not run ──
    secrets = spider_intel.get("secrets", [])
    if secrets and "credleak" not in ran:
        chains.append(_sugg(
            P_HIGH, CONF_LIKELY, "correlator",
            action  = "equip CredLeak — Spider found exposed secrets, check paste/leak databases",
            reason  = "Exposed API keys or emails in source may appear in breach databases; CredLeak will verify",
            evidence= [f"Spider: {len(secrets)} secret(s) exposed in source/JS"],
            chain   = "Spider secrets → CredLeak",
        ))

    return chains


# ─────────────────────────────────────────────────────────────
# MODULE ANALYZERS
# ─────────────────────────────────────────────────────────────

def _analyze_nmap(results, ran) -> List[Suggestion]:
    out = []
    intel    = results["nmap"].get("intel", {})
    services = intel.get("services", {})

    if not services:
        out.append(_sugg(P_MEDIUM, CONF_POSSIBLE, "nmap",
            action="re-run nmap with -p- flag",
            reason="No services parsed from current scan; default port range may have missed services",
        ))
        return out

    for port_proto, data in services.items():
        port    = port_proto.split("/")[0]
        service = data.get("service", "").lower()
        version = data.get("version", "")

        # Service → module suggestions
        for svc_key, modules in SERVICE_MODULE_MAP.items():
            if svc_key in service:
                for mod in modules:
                    if mod not in ran:
                        out.append(_sugg(P_HIGH, CONF_STRONG, "nmap",
                            action  = f"equip {mod}",
                            reason  = f"{service.upper()} on port {port} is a web surface — {mod} not yet run",
                            evidence= [f"Port {port}: {service} {version}".strip()],
                        ))

        # Version CVE matching
        for rule in VERSION_CVE_MAP:
            if version and re.search(rule["match"], version, re.IGNORECASE):
                weaponized_tag = " [WEAPONIZED EXPLOIT EXISTS]" if rule["weaponized"] else ""
                out.append(_sugg(P_CRITICAL, CONF_CONFIRMED, "nmap",
                    action  = f"equip Exmap + manual exploit — {rule['cve']}{weaponized_tag}",
                    reason  = f"{rule['title']} (CVSS {rule['cvss']}) detected on port {port}",
                    evidence= [
                        f"Detected version: {version} on port {port}",
                        f"CVE: {rule['cve']} | CVSS: {rule['cvss']}",
                        f"Weaponized: {'YES' if rule['weaponized'] else 'NO'}",
                    ],
                ))

    return out


def _analyze_spider(results, ran) -> List[Suggestion]:
    out = []
    intel     = results["spider"].get("intel", {})
    endpoints = intel.get("endpoints",   [])
    secrets   = intel.get("secrets",     [])
    cors      = intel.get("cors_issues", [])
    tech      = intel.get("tech_stack",  [])
    if isinstance(tech, set):
        tech = list(tech)

    if not endpoints:
        out.append(_sugg(P_HIGH, CONF_POSSIBLE, "spider",
            action="re-run Spider with higher max_depth or authenticated cookie",
            reason="No endpoints discovered; likely hitting a login wall or shallow crawl",
        ))
        return out

    # Surface summary (informational)
    auth_walled = [e for e in endpoints if e.get("auth_required")]
    sensitive   = [e for e in endpoints if e.get("parameter_sensitive")]

    # Param-level risk scoring across all endpoints
    ep_risks = []
    for ep in endpoints:
        params = _flat_params(ep)
        risk   = _param_risk_score(params)
        if risk["score"] > 0:
            ep_risks.append((ep.get("url", ""), risk))

    # Sort by score descending
    ep_risks.sort(key=lambda x: x[1]["score"], reverse=True)

    # Aggregate by vuln class
    cmdi_eps     = [(u, r) for u, r in ep_risks if "cmdi"     in r["classes"]]
    sqli_eps     = [(u, r) for u, r in ep_risks if "sqli"     in r["classes"]]
    lfi_eps      = [(u, r) for u, r in ep_risks if "lfi"      in r["classes"]]
    idor_eps     = [(u, r) for u, r in ep_risks if "idor"     in r["classes"]]
    redirect_eps = [(u, r) for u, r in ep_risks if "redirect" in r["classes"]]

    if cmdi_eps and "cmdinj" not in ran:
        top_url, top_risk = cmdi_eps[0]
        out.append(_sugg(P_HIGH, CONF_LIKELY, "spider",
            action  = "equip CMDinj",
            reason  = f"{len(cmdi_eps)} endpoint(s) carry CMDi-risk params — highest risk at {top_url}",
            evidence= [
                f"Matched params: {', '.join(top_risk['hits'].get('cmdi', []))}",
                f"Total CMDi-risk endpoints: {len(cmdi_eps)}",
            ],
        ))

    if sqli_eps and "parax" not in ran:
        top_url, top_risk = sqli_eps[0]
        out.append(_sugg(P_HIGH, CONF_LIKELY, "spider",
            action  = "equip Parax",
            reason  = f"{len(sqli_eps)} endpoint(s) carry SQLi-risk params",
            evidence= [
                f"Matched params: {', '.join(top_risk['hits'].get('sqli', []))}",
                f"Top endpoint: {top_url}",
            ],
        ))

    if lfi_eps and "parax" not in ran:
        top_url, top_risk = lfi_eps[0]
        out.append(_sugg(P_HIGH, CONF_LIKELY, "spider",
            action  = "equip Parax (LFI-risk params detected)",
            reason  = f"{len(lfi_eps)} endpoint(s) carry LFI-risk params — file inclusion risk",
            evidence= [
                f"Matched params: {', '.join(top_risk['hits'].get('lfi', []))}",
                f"Top endpoint: {top_url}",
            ],
        ))

    if auth_walled and "bacdetector" not in ran:
        out.append(_sugg(P_HIGH, CONF_STRONG, "spider",
            action  = "equip BACdetector",
            reason  = f"{len(auth_walled)} auth-walled endpoint(s) — access control not yet verified",
            evidence= [f"Auth-walled: {e.get('url','')} " for e in auth_walled[:3]],
        ))

    if idor_eps and "bacdetector" not in ran:
        top_url, top_risk = idor_eps[0]
        out.append(_sugg(P_HIGH, CONF_LIKELY, "spider",
            action  = "equip BACdetector (IDOR-risk params)",
            reason  = f"{len(idor_eps)} endpoint(s) with object-reference params — IDOR likely",
            evidence= [
                f"Matched params: {', '.join(top_risk['hits'].get('idor', []))}",
                f"Top endpoint: {top_url}",
            ],
        ))

    # Secrets
    if secrets:
        by_type = {}
        for s in secrets:
            t = s.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
        types_str = ", ".join(f"{t} ×{c}" for t, c in by_type.items())
        out.append(_sugg(P_CRITICAL, CONF_CONFIRMED, "spider",
            action  = "review loot immediately — secrets exposed",
            reason  = f"{len(secrets)} secret(s) found in source/JS ({types_str})",
            evidence= [f"Types: {types_str}"],
        ))

    # CORS
    high_cors = [c for c in cors if c.get("severity","").upper() in ("HIGH","CRITICAL")]
    if high_cors:
        out.append(_sugg(P_HIGH, CONF_CONFIRMED, "spider",
            action  = "manual CORS verification required",
            reason  = f"{len(high_cors)} high/critical CORS misconfiguration(s) — cross-origin request forgery risk",
            evidence= [c.get("url", "") for c in high_cors[:3]],
        ))

    # Open redirect
    if redirect_eps and "parax" not in ran:
        out.append(_sugg(P_MEDIUM, CONF_LIKELY, "spider",
            action  = "equip Parax (open redirect params)",
            reason  = f"{len(redirect_eps)} endpoint(s) with redirect params — phishing pivot potential",
            evidence= [u for u, _ in redirect_eps[:2]],
        ))

    return out


def _analyze_fingerprint(results, ran) -> List[Suggestion]:
    out = []
    intel = results["fingerprint"].get("intel", {})

    detected   = intel.get("detected",     {}) or intel.get("technologies", {})
    waf        = intel.get("waf",          None)
    cms        = intel.get("cms",          None)
    frameworks = intel.get("frameworks",   [])
    headers    = intel.get("headers",      {})

    if waf:
        out.append(_sugg(P_HIGH, CONF_CONFIRMED, "fingerprint",
            action  = "equip WAFBuster — WAF detected",
            reason  = f"{waf} WAF identified; direct exploitation attempts will be blocked without bypass",
            evidence= [f"WAF: {waf}"],
        ))

    if cms:
        cms_name    = cms.get("name", "") if isinstance(cms, dict) else str(cms)
        cms_version = cms.get("version", "") if isinstance(cms, dict) else ""
        version_tag = f" v{cms_version}" if cms_version else ""

        # Check version against CVE map
        matched_cves = []
        for rule in VERSION_CVE_MAP:
            if re.search(rule["match"], f"{cms_name}{version_tag}", re.IGNORECASE):
                matched_cves.append(rule)

        if matched_cves and "exmap" not in ran:
            for rule in matched_cves:
                out.append(_sugg(P_CRITICAL, CONF_CONFIRMED, "fingerprint",
                    action  = f"equip Exmap + manual exploit — {rule['cve']} [{rule['title']}]",
                    reason  = f"{cms_name}{version_tag} maps to known CVE (CVSS {rule['cvss']})",
                    evidence= [
                        f"CMS: {cms_name}{version_tag}",
                        f"CVE: {rule['cve']} | Weaponized: {'YES' if rule['weaponized'] else 'NO'}",
                    ],
                ))
        elif cms_version and "exmap" not in ran:
            out.append(_sugg(P_HIGH, CONF_STRONG, "fingerprint",
                action  = "equip Exmap",
                reason  = f"{cms_name}{version_tag} detected with specific version — map to CVE database",
                evidence= [f"CMS: {cms_name}{version_tag}"],
            ))

    # Generic versioned tech → Exmap
    if isinstance(detected, dict):
        versioned = {k: v for k, v in detected.items() if v and str(v).strip()}
        if versioned and not cms and "exmap" not in ran:
            top = list(versioned.items())[:4]
            out.append(_sugg(P_HIGH, CONF_STRONG, "fingerprint",
                action  = "equip Exmap",
                reason  = "Specific software versions identified — CVE lookup not yet performed",
                evidence= [f"{k}: {v}" for k, v in top],
            ))

    # Security header gaps
    missing_headers = []
    security_headers = [
        "X-Frame-Options", "Content-Security-Policy",
        "Strict-Transport-Security", "X-Content-Type-Options",
    ]
    if isinstance(headers, dict):
        for h in security_headers:
            if not headers.get(h):
                missing_headers.append(h)
    if missing_headers:
        out.append(_sugg(P_MEDIUM, CONF_CONFIRMED, "fingerprint",
            action  = "document missing security headers",
            reason  = f"{len(missing_headers)} security header(s) absent — increases attack surface",
            evidence= [f"Missing: {', '.join(missing_headers)}"],
        ))

    return out


def _analyze_bacdetector(results, ran) -> List[Suggestion]:
    out = []
    intel        = results["bacdetector"].get("intel", {})
    bac          = intel.get("bac", {})
    findings     = bac.get("findings", []) if isinstance(bac, dict) else []
    vulns        = intel.get("vulnerabilities", [])
    all_findings = findings + vulns

    if not all_findings:
        out.append(_sugg(P_LOW, CONF_POSSIBLE, "bacdetector",
            action="review BAC config — no findings, but verify session handling manually",
            reason="Zero findings may mean robust access control, or insufficient coverage",
        ))
        return out

    high = [f for f in all_findings if f.get("severity","").lower() in ("critical","high")]
    top  = _top_severity(all_findings)

    out.append(_sugg(
        P_CRITICAL if top in ("critical","high") else P_HIGH,
        CONF_CONFIRMED, "bacdetector",
        action  = "review loot — BAC findings require manual verification + PoC",
        reason  = f"{len(all_findings)} access control issue(s), top severity: {top.upper()}",
        evidence= [
            f"Total: {len(all_findings)} | High/Critical: {len(high)}",
        ] + [f.get("url","") for f in high[:2]],
    ))

    if high and "cmdinj" not in ran:
        out.append(_sugg(P_HIGH, CONF_STRONG, "bacdetector",
            action  = "equip CMDinj — confirmed auth bypass enables direct injection testing",
            reason  = "Access control bypass on auth-required endpoints creates direct path to CMDi",
            evidence= [f"BAC bypass at: {f.get('url','')} " for f in high[:2]],
        ))

    return out


def _analyze_parax(results, ran) -> List[Suggestion]:
    out = []
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
        cls = v.get("type", v.get("class", "unknown"))
        by_class[cls] = by_class.get(cls, 0) + 1

    high = [v for v in vulns if v.get("risk","").lower() in ("critical","high")]
    top  = _top_severity([{"severity": v.get("risk","info")} for v in vulns])

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
            reason  = f"{len(high)} high/critical param risks identified; active exploitation not yet attempted",
        ))

    return out


def _analyze_cmdinj(results, ran) -> List[Suggestion]:
    out = []
    intel = results["cmdinj"].get("intel", {})
    vulns = intel.get("vulnerabilities", [])

    if not vulns:
        out.append(_sugg(P_LOW, CONF_POSSIBLE, "cmdinj",
            action="no CMDi findings — consider manual payload crafting or WAF bypass",
            reason="Zero findings; WAF or input sanitisation may be filtering probes",
        ))
        return out

    confirmed = [v for v in vulns if v.get("confirmed")]
    unconfirmed = [v for v in vulns if not v.get("confirmed")]

    if confirmed:
        out.append(_sugg(P_CRITICAL, CONF_CONFIRMED, "cmdinj",
            action  = "document PoC + escalate — confirmed RCE",
            reason  = f"{len(confirmed)} confirmed command injection(s) with PoC; this is the critical finding",
            evidence= [
                f"Confirmed: {len(confirmed)} | Unconfirmed: {len(unconfirmed)}",
            ] + [v.get("url","") for v in confirmed[:2]],
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
            evidence= [v.get("url","") for v in unconfirmed[:3]],
        ))

    return out


def _analyze_seige(results, ran) -> List[Suggestion]:
    out = []
    intel = results["seige"].get("intel", {})
    vulns = intel.get("vulnerabilities", [])
    score = intel.get("risk_score", 0)

    if vulns:
        high = [v for v in vulns if v.get("severity","").lower() in ("critical","high")]
        out.append(_sugg(
            P_CRITICAL if high else P_HIGH,
            CONF_CONFIRMED, "seige",
            action  = "review Seige findings — Nikto/Nuclei flagged issues",
            reason  = f"{len(vulns)} vulnerability finding(s) (risk score: {score}); {len(high)} high/critical",
            evidence= [f"{v.get('title','')} [{v.get('severity','')}]" for v in high[:3]],
        ))

    return out


def _analyze_credleak(results, ran) -> List[Suggestion]:
    out = []
    intel  = results["credleak"].get("intel", {})
    emails = intel.get("emails",  [])
    keys   = intel.get("api_keys", intel.get("keys", []))
    pastes = intel.get("pastes",  [])
    s3     = intel.get("s3_buckets", [])

    if keys:
        out.append(_sugg(P_CRITICAL, CONF_CONFIRMED, "credleak",
            action  = "revoke and rotate — API keys/secrets found in leak databases",
            reason  = f"{len(keys)} key(s) exposed; active keys are immediately exploitable",
            evidence= [f"Key types: {', '.join(set(k.get('type','?') for k in keys))}"] if isinstance(keys[0], dict) else [f"{len(keys)} key(s)"],
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


def _analyze_stalk(results, ran) -> List[Suggestion]:
    out = []
    intel      = results["stalk"].get("intel", {})
    subdomains = intel.get("infrastructure", {}).get("subdomains", [])
    open_ports = intel.get("infrastructure", {}).get("open_ports",  [])
    emails     = intel.get("exposure",       {}).get("emails",      [])

    if subdomains and "surfacemap" not in ran:
        out.append(_sugg(P_HIGH, CONF_STRONG, "stalk",
            action  = "equip SurfaceMAP on discovered subdomains",
            reason  = f"{len(subdomains)} subdomain(s) found — service enumeration not yet performed",
            evidence= subdomains[:5],
        ))

    if emails and "credleak" not in ran:
        out.append(_sugg(P_MEDIUM, CONF_LIKELY, "stalk",
            action  = "equip CredLeak — emails harvested, check breach databases",
            reason  = f"{len(emails)} email(s) found in OSINT — check for credential exposure",
        ))

    return out


def _analyze_exmap(results, ran) -> List[Suggestion]:
    out = []
    intel    = results["exmap"].get("intel", {})
    cves     = intel.get("cves",     [])
    exploits = intel.get("exploits", [])
    msf      = intel.get("metasploit_modules", [])

    if cves:
        critical_cves = [c for c in cves if float(c.get("cvss", 0)) >= 9.0]
        out.append(_sugg(
            P_CRITICAL if critical_cves else P_HIGH,
            CONF_CONFIRMED, "exmap",
            action  = "manual exploitation — Exmap mapped CVEs with known exploits",
            reason  = f"{len(cves)} CVE(s) mapped; {len(critical_cves)} CVSS 9.0+",
            evidence= [f"{c.get('cve','?')} CVSS:{c.get('cvss','?')} — {c.get('title','')}" for c in critical_cves[:3]],
        ))
    if msf:
        out.append(_sugg(P_HIGH, CONF_CONFIRMED, "exmap",
            action  = "load Metasploit modules for mapped CVEs",
            reason  = f"{len(msf)} Metasploit module(s) available for detected service versions",
            evidence= msf[:3],
        ))

    return out


# ─────────────────────────────────────────────────────────────
# SKIP LIST BUILDER
# ─────────────────────────────────────────────────────────────

def _build_skip_list(results: dict, ran: set, active_actions: set) -> List[Suggestion]:
    """
    Build a reasoned skip list: modules not suggested, with WHY.
    Only skip modules that are installed and would normally be considered.
    """
    skip = []
    spider_intel = results.get("spider", {}).get("intel", {})
    endpoints    = spider_intel.get("endpoints", [])

    # Phishprep — skip if no employee data collected
    emp_ran   = "emptracker" in ran
    stalk_ran = "stalk" in ran
    if "phishprep" not in ran and not emp_ran:
        skip.append(_sugg(P_SKIP, CONF_POSSIBLE, "skip",
            action="Phishprep",
            reason="No employee data collected yet — run EMPtracker or Stalk first",
            skip=True,
        ))

    # FUZZhunter — skip if Spider already did surface mapping
    if "fuzzhunter" not in ran and "spider" in ran and len(endpoints) > 20:
        skip.append(_sugg(P_SKIP, CONF_LIKELY, "skip",
            action="FUZZhunter",
            reason=f"Spider already mapped {len(endpoints)} endpoints — fuzzing would duplicate coverage",
            skip=True,
        ))

    # CredLeak — skip if no emails and spider found no secrets
    secrets = spider_intel.get("secrets", [])
    stalk_intel = results.get("stalk", {}).get("intel", {})
    stalk_emails = stalk_intel.get("exposure", {}).get("emails", [])
    if "credleak" not in ran and not secrets and not stalk_emails:
        skip.append(_sugg(P_SKIP, CONF_POSSIBLE, "skip",
            action="CredLeak",
            reason="No emails or secrets found yet — insufficient data to query leak databases",
            skip=True,
        ))

    # Stalk — skip if recon already comprehensive
    if "stalk" in ran:
        skip.append(_sugg(P_SKIP, CONF_CONFIRMED, "skip",
            action="Stalk (re-run)",
            reason="OSINT recon already completed this session",
            skip=True,
        ))

    return skip


# ─────────────────────────────────────────────────────────────
# ATTACK CHAIN LABEL BUILDER
# ─────────────────────────────────────────────────────────────

def _detected_attack_chains(results: dict) -> List[str]:
    """
    Return human-readable labels for complete attack chains detected.
    These are shown as highlights in the report — "what story do the findings tell".
    """
    chains = []
    ran = set(results.keys())

    cmdi_confirmed  = any(
        v.get("confirmed")
        for v in results.get("cmdinj", {}).get("intel", {}).get("vulnerabilities", [])
    )
    bac_bypass      = any(
        f.get("severity","").lower() in ("critical","high")
        for f in (
            results.get("bacdetector",{}).get("intel",{}).get("bac",{}).get("findings",[])
            + results.get("bacdetacker",{}).get("intel",{}).get("vulnerabilities",[])
            if isinstance(results.get("bacdetector",{}).get("intel",{}).get("bac",{}), dict) else []
        )
    )
    has_cves        = bool(results.get("exmap", {}).get("intel", {}).get("cves", []))
    has_secrets     = bool(results.get("spider", {}).get("intel", {}).get("secrets", []))
    has_subdomains  = bool(results.get("stalk",  {}).get("intel", {}).get("infrastructure", {}).get("subdomains", []))

    if cmdi_confirmed and "exmap" in ran:
        chains.append("RCE-to-CVE chain: CMDinj confirmed → Exmap correlated → full exploit documented")

    if bac_bypass and cmdi_confirmed:
        chains.append("Privilege escalation chain: BAC bypass → CMDinj on auth-protected endpoint → full compromise")

    if has_secrets and "credleak" in ran:
        chains.append("Credential exposure chain: Spider exposed secrets → CredLeak verified breach → active key found")

    if has_subdomains and "surfacemap" in ran and "spider" in ran:
        chains.append("Multi-surface chain: Stalk subdomains → SurfaceMAP enumerated → Spider crawled all surfaces")

    return chains


# ─────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────

def suggest_actions(results: dict) -> List[str]:
    """
    Legacy-compatible entry point.
    Returns List[str] for callers expecting flat string output.
    """
    report = suggest_report(results)
    return report.as_strings()


def suggest_report(results: dict) -> SuggestReport:
    """
    Full structured entry point.
    Returns SuggestReport with priority-sorted suggestions, chains, skip list.
    """
    report = SuggestReport()

    if not results:
        report.critical_path.append(_sugg(P_HIGH, CONF_POSSIBLE, "howl",
            action="equip Spider",
            reason="No intelligence gathered yet — Spider is the mandatory first step for web targets",
        ))
        return report

    ran = set(results.keys())
    report.ran_modules = sorted(ran)

    # ── Run per-module analyzers ──────────────────────────────
    all_suggestions: List[Suggestion] = []

    analyzer_map = {
        "nmap":        _analyze_nmap,
        "spider":      _analyze_spider,
        "fingerprint": _analyze_fingerprint,
        "bacdetector": _analyze_bacdetector,
        "parax":       _analyze_parax,
        "cmdinj":      _analyze_cmdinj,
        "seige":       _analyze_seige,
        "credleak":    _analyze_credleak,
        "stalk":       _analyze_stalk,
        "exmap":       _analyze_exmap,
    }

    for module, analyzer in analyzer_map.items():
        if module in results:
            try:
                all_suggestions.extend(analyzer(results, ran))
            except Exception:
                pass  # never crash the suggest engine on bad intel shapes

    # ── Cross-module correlation ──────────────────────────────
    correlation_chains = _correlate(results, ran)

    # ── Baseline: if spider not run ──────────────────────────
    if "spider" not in ran:
        all_suggestions.append(_sugg(P_HIGH, CONF_STRONG, "howl",
            action="equip Spider first",
            reason="Spider provides the foundational endpoint map that all other modules depend on",
        ))

    # ── Sort all suggestions by priority then confidence ──────
    conf_order = {CONF_CONFIRMED: 0, CONF_STRONG: 1, CONF_LIKELY: 2, CONF_POSSIBLE: 3}
    all_suggestions.sort(key=lambda s: (s.priority, conf_order.get(s.confidence, 4)))
    correlation_chains.sort(key=lambda s: (s.priority, conf_order.get(s.confidence, 4)))

    # ── Deduplicate by action string ─────────────────────────
    seen_actions = set()
    deduped = []
    for s in all_suggestions:
        key = s.action.lower().strip()
        if key not in seen_actions:
            seen_actions.add(key)
            deduped.append(s)

    # ── Partition into output tiers ───────────────────────────
    for s in deduped:
        if s.priority <= P_HIGH:
            report.critical_path.append(s)
        else:
            report.optional_intel.append(s)

    report.chains    = correlation_chains
    report.skip_list = _build_skip_list(results, ran, seen_actions)

    # ── Detected complete attack chains ──────────────────────
    report.attack_chains = _detected_attack_chains(results)

    return report