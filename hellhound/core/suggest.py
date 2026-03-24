"""
hellhound/core/suggest.py

Rule-based suggestion engine (HOWL command).
Reads self.results from console and returns a list of next-step strings.

Rules:
  - Deterministic only. No AI, no guessing.
  - All intel key names must match actual module return shapes.
  - Module names in suggestions must exist in the modules/ tree.
  - Spider v12 intel shape: endpoints[], secrets[], cors_issues[],
    sourcemaps[], summary{}, tech_stack[]
    params per endpoint: {"query":[], "form":[], "js":[], ...}  (dict of buckets)
"""

import re


# =================================================
# KNOWN MODULES (must exist in modules/ tree)
# Only suggest modules that are actually installed.
# =================================================

KNOWN_MODULES = {
    "spider", "bacdetector", "cmdinj", "parax",
    "seige", "fuzzhunter", "fingerprint", "credleak",
    "stalk", "surfacemap", "wafbuster", "exmap",
}

# =================================================
# SERVICE → MODULE MAP (for nmap intel)
# =================================================

SERVICE_MODULE_MAP = {
    "http":         ["spider", "fuzzhunter", "wafbuster"],
    "https":        ["spider", "fuzzhunter", "wafbuster"],
    "ftp":          [],   # no ftp module yet
    "ssh":          [],   # no ssh module yet
    "mysql":        [],
    "microsoft-ds": [],
}

# =================================================
# VERSION HEURISTICS
# =================================================

VERSION_HINTS = [
    {
        "match": r"apache\s*2\.4\.49",
        "hint": "CRITICAL: Apache Path Traversal (CVE-2021-41773) — manual exploit recommended"
    },
    {
        "match": r"vsftpd\s*2\.3\.4",
        "hint": "CRITICAL: vsftpd 2.3.4 Backdoor (CVE-2011-2523) — manual exploit recommended"
    },
]

# =================================================
# PARAM NAMES → LIKELY VULN CLASS
# =================================================

IDOR_PARAMS   = {"id", "user_id", "uid", "account_id", "profile_id", "order_id",
                 "invoice_id", "doc_id", "file_id", "record_id"}
SQLI_PARAMS   = {"search", "query", "q", "keyword", "filter", "sort", "order",
                 "where", "name", "username", "email"}
CMDI_PARAMS   = {"cmd", "exec", "command", "run", "ping", "host", "ip",
                 "url", "to", "from", "file", "path"}


# =================================================
# HELPERS
# =================================================

def _flat_params(ep):
    """
    Spider v12 stores params as a dict of buckets:
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
        # Legacy flat list of dicts {"name": "id"}
        return {p["name"] for p in raw if isinstance(p, dict) and "name" in p}
    return set()


def _dedup(suggestions):
    return list(dict.fromkeys(suggestions))


# =================================================
# MAIN ANALYZER
# =================================================

def suggest_actions(results):
    """
    Accepts full self.results dict from console.
    Returns a list of actionable suggestion strings.
    """
    if not results:
        return ["[!] No intelligence gathered yet — run spider first"]

    suggestions = []
    ran = set(results.keys())

    # ─────────────────────────────────────────────
    # 1. NMAP INTEL
    # ─────────────────────────────────────────────
    if "nmap" in results:
        intel    = results["nmap"].get("intel", {})
        services = intel.get("services", {})

        for port_proto, data in services.items():
            port    = port_proto.split("/")[0]
            service = data.get("service", "").lower()
            version = data.get("version", "")

            for svc_key, modules in SERVICE_MODULE_MAP.items():
                if svc_key in service:
                    for mod in modules:
                        if mod not in ran:
                            suggestions.append(
                                f"[PORT {port}] {service.upper()} detected → equip {mod}"
                            )

            for rule in VERSION_HINTS:
                if re.search(rule["match"], version, re.IGNORECASE):
                    suggestions.append(f"[PORT {port}] {rule['hint']}")

        if not services:
            suggestions.append("[NMAP] No services parsed — try a full port scan (-p-)")

    # ─────────────────────────────────────────────
    # 2. SPIDER INTEL (v12 key shape)
    # ─────────────────────────────────────────────
    if "spider" in results:
        intel     = results["spider"].get("intel", {})
        endpoints = intel.get("endpoints", [])
        secrets   = intel.get("secrets", [])
        cors      = intel.get("cors_issues", [])
        summary   = intel.get("summary", {})
        tech      = intel.get("tech_stack", [])
        if isinstance(tech, set):
            tech = list(tech)

        if not endpoints:
            suggestions.append(
                "[SPIDER] No endpoints found — increase max_depth or set cookie for auth"
            )
        else:
            ep_count     = len(endpoints)
            auth_walled  = [e for e in endpoints if e.get("auth_required")]
            sensitive    = [e for e in endpoints if e.get("parameter_sensitive")]

            suggestions.append(
                f"[SPIDER] {ep_count} endpoints mapped — "
                f"{len(auth_walled)} auth-walled, {len(sensitive)} param-sensitive"
            )

            # Suggest BACdetector if auth walls found and not yet run
            if auth_walled and "bacdetector" not in ran:
                suggestions.append(
                    f"[SPIDER] {len(auth_walled)} auth-walled endpoints → equip BACdetector"
                )

            # Scan param names for vuln classes
            idor_hits, sqli_hits, cmdi_hits = [], [], []
            for ep in endpoints:
                params = _flat_params(ep)
                url    = ep.get("url", "")
                if params & IDOR_PARAMS:
                    idor_hits.append(url)
                if params & SQLI_PARAMS:
                    sqli_hits.append(url)
                if params & CMDI_PARAMS:
                    cmdi_hits.append(url)

            if idor_hits and "bacdetector" not in ran:
                suggestions.append(
                    f"[SPIDER] IDOR-risk params on {len(idor_hits)} endpoint(s) → equip BACdetector"
                )
            if sqli_hits and "parax" not in ran:
                suggestions.append(
                    f"[SPIDER] SQLi-risk params on {len(sqli_hits)} endpoint(s) → equip Parax"
                )
            if cmdi_hits and "cmdinj" not in ran:
                suggestions.append(
                    f"[SPIDER] CMDi-risk params on {len(cmdi_hits)} endpoint(s) → equip CMDinj"
                )

        # Secrets
        if secrets:
            by_type = {}
            for s in secrets:
                by_type[s.get("type","unknown")] = by_type.get(s.get("type","unknown"),0) + 1
            types_str = ", ".join(f"{t}×{c}" for t, c in by_type.items())
            suggestions.append(
                f"[SPIDER] {len(secrets)} secret(s) found ({types_str}) → review loot"
            )

        # CORS
        if cors:
            high_cors = [c for c in cors if c.get("severity","").upper() in ("HIGH","CRITICAL")]
            if high_cors:
                suggestions.append(
                    f"[SPIDER] {len(high_cors)} high-severity CORS misconfiguration(s) → manual verification"
                )

        # Tech stack
        if tech:
            tech_str = ", ".join(tech[:5])
            suggestions.append(f"[SPIDER] Tech stack: {tech_str}")

        # Suggest Parax if not run yet and endpoints exist
        if endpoints and "parax" not in ran:
            suggestions.append("[SPIDER] Parameter risk not yet classified → equip Parax")

        # Suggest CMDinj if not run yet
        if endpoints and "cmdinj" not in ran:
            suggestions.append("[SPIDER] Command injection not yet probed → equip CMDinj")

    # ─────────────────────────────────────────────
    # 3. BACDETECTOR INTEL
    # ─────────────────────────────────────────────
    if "bacdetector" in results:
        intel    = results["bacdetector"].get("intel", {})
        bac      = intel.get("bac", {})
        findings = bac.get("findings", []) if isinstance(bac, dict) else []
        vulns    = intel.get("vulnerabilities", [])
        all_findings = findings + vulns

        if all_findings:
            high = [f for f in all_findings
                    if f.get("severity","").lower() in ("critical","high")]
            suggestions.append(
                f"[BAC] {len(all_findings)} access control issue(s) found"
                + (f" — {len(high)} critical/high" if high else "")
                + " → review loot"
            )
            if "cmdinj" not in ran:
                suggestions.append("[BAC] Confirmed access control issues → equip CMDinj next")
        else:
            suggestions.append("[BAC] No access control issues detected")

    # ─────────────────────────────────────────────
    # 4. PARAX INTEL
    # ─────────────────────────────────────────────
    if "parax" in results:
        intel = results["parax"].get("intel", {})
        vulns = intel.get("vulnerabilities", [])
        if vulns:
            suggestions.append(
                f"[PARAX] {len(vulns)} parameter risk(s) classified → review loot"
            )

    # ─────────────────────────────────────────────
    # 5. CMDINJ INTEL
    # ─────────────────────────────────────────────
    if "cmdinj" in results:
        intel = results["cmdinj"].get("intel", {})
        vulns = intel.get("vulnerabilities", [])
        if vulns:
            confirmed = [v for v in vulns if v.get("confirmed")]
            suggestions.append(
                f"[CMDINJ] {len(vulns)} injection finding(s)"
                + (f" — {len(confirmed)} confirmed" if confirmed else "")
                + " → review loot"
            )

    # ─────────────────────────────────────────────
    # 6. STALK INTEL
    # ─────────────────────────────────────────────
    if "stalk" in results:
        intel      = results["stalk"].get("intel", {})
        subdomains = intel.get("infrastructure", {}).get("subdomains", [])
        if subdomains and "surfacemap" not in ran:
            suggestions.append(
                f"[STALK] {len(subdomains)} subdomain(s) found → equip SurfaceMAP"
            )

    # ─────────────────────────────────────────────
    # 7. GENERAL: modules run but nothing done yet
    # ─────────────────────────────────────────────
    if "spider" not in ran:
        suggestions.append("[HOWL] No recon data yet → equip Spider first")

    # ─────────────────────────────────────────────
    # Final
    # ─────────────────────────────────────────────
    suggestions = _dedup(suggestions)

    if not suggestions:
        suggestions.append(
            "[HOWL] No immediate attack paths identified — continue manual analysis"
        )

    return suggestions