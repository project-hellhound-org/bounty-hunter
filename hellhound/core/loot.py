"""
Hellhound Loot Engine — Module-Aware Intelligence Renderer
Knows what each module returns and displays it cleanly.
"""

import shutil
from collections import defaultdict
from colorama import Style, init
init(autoreset=True)

# ═══════════════════════════════════════════════════════════════════════
# ANSI CONSTANTS — Hellhound Signature Palette
# ═══════════════════════════════════════════════════════════════════════
R   = Style.RESET_ALL
CR  = "\033[91;1m"       # Bright Red
CW  = "\033[97;1m"       # Bold White
CC  = "\033[38;5;203m"   # Soft Coral Red (Key titles & arrows)
CY  = "\033[38;5;208;1m" # Neon Orange (Parameters & curl PoCs)
CO  = "\033[38;5;208;1m" # Neon Orange (Medium severity)
CDM = "\033[37m"         # Light Grey
CM  = "\033[38;5;208;1m" # Orange
CBL = "\033[38;5;203m"   # Soft Coral Red

# Author metadata
AUTHOR_META = "[ Created by L4ZZ3RJ0D — @l4zz3rj0d ]"

def get_w():
    return shutil.get_terminal_size((120, 24)).columns - 2

def _box_header(title):
    """Print a high-contrast, centered header box."""
    w = get_w()
    inner = w - 4
    print(f"\n{CR}{'=' * w}")
    print(f"{CR}||{CW}{title:^{inner}}{CR}||")
    print(f"{CR}{'=' * w}{R}")

def _section(title, icon=">>"):
    """Print a section header."""
    print(f"\n  {CR}{icon} {CW}{title}{R}")
    print(f"  {CDM}{'─' * (get_w() - 4)}{R}")

def _kv(key, value, indent=4):
    """Print a key:value pair."""
    pad = " " * indent
    print(f"{pad}{CC}{key:<18}{R}: {CW}{value}{R}")

def _bullet(text, indent=6, color=CW):
    """Print a bullet point."""
    pad = " " * indent
    print(f"{pad}{CDM}-{R} {color}{text}{R}")

def _pretty_data(data, indent=0):
    """Recursively formats dictionaries and lists for human-readable output."""
    if isinstance(data, dict):
        if not data: return f"{CDM}{{empty}}{R}"
        lines = []
        for k, v in data.items():
            k_fmt = f"{CC}{k}{R}"
            if isinstance(v, (dict, list)):
                lines.append(f"{' ' * indent}{k_fmt}:\n{_pretty_data(v, indent + 4)}")
            else:
                lines.append(f"{' ' * indent}{k_fmt:<18}: {CW}{v}{R}")
        return "\n".join(lines)
    elif isinstance(data, list):
        if not data: return f"{CDM}[empty]{R}"
        lines = []
        for item in data:
            if isinstance(item, (dict, list)):
                lines.append(f"{' ' * indent}{CDM}-{R}\n{_pretty_data(item, indent + 2)}")
            else:
                lines.append(f"{' ' * indent}{CDM}-{R} {CW}{item}{R}")
        return "\n".join(lines)
    return f"{' ' * indent}{CW}{data}{R}"

def _vuln_block(vuln, indent=6):
    """Render a single vulnerability finding with a premium, organized structure."""
    pad = " " * indent
    sev = str(vuln.get("severity", vuln.get("confidence", "INFO"))).upper()
    vtype = vuln.get("finding_type", vuln.get("type", vuln.get("name", "Vulnerability")))
    
    if sev in ("CRITICAL", "HIGH"): sc = CR
    elif sev in ("MEDIUM",): sc = CO
    elif sev in ("LOW",): sc = CY
    else: sc = CW

    # Title Line
    print(f"\n{pad}{sc}[{sev}]{R} {CW}{vtype.replace('_', ' ').upper()}{R}")
    
    # Core Identity (Path/Method)
    method = vuln.get("method", "GET")
    url = vuln.get("url", "N/A")
    print(f"{pad}  {CC}{method:<8}{R} {CW}{url}{R}")
    
    # Organized Technical Details
    details = []
    
    # IDOR Specifics
    if "original_id" in vuln or "tampered_id" in vuln:
        details.append(("ID Context", f"{CDM}{vuln.get('original_id', 'N/A')}{R} {CC}→{R} {CR}{vuln.get('tampered_id', 'N/A')}{R} {CDM}({vuln.get('id_type', 'unknown')}){R}"))
        if vuln.get("param_name"):
            details.append(("Parameter", f"{CY}{vuln['param_name']}{R} {CDM}({vuln.get('location', 'query')}){R}"))
    
    # Generic Identity
    elif vuln.get("parameter"):
        details.append(("Parameter", f"{CY}{vuln['parameter']}{R}"))

    # Evidence & Impact
    if vuln.get("evidence"):
        ev = vuln["evidence"]
        if isinstance(ev, str) and "|" in ev:
            ev = ev.replace(" | ", f"\n{' ' * (indent + 22)}{CDM}↳{R} ")
        details.append(("Evidence", f"{CW}{ev}{R}"))
    
    # Reproducibility (PoC)
    if vuln.get("poc_curl"):
        details.append(("PoC (curl)", f"{CY}{vuln['poc_curl']}{R}"))

    # Render organized details
    for k, v in details:
        print(f"{pad}  {CC}{k:<18}{R}: {v}")

    # Render EVERYTHING else (unhandled/custom keys) recursively
    handled = ("severity", "confidence", "finding_type", "type", "name", "method", "url", 
               "original_id", "tampered_id", "id_type", "param_name", "location", 
               "parameter", "evidence", "poc_curl", "module", "id", "repro_data", 
               "poc_browser", "poc_session_label", "body_snippet", "status", "source", "session")
    
    # Secondary fields (Status/Session) - Compact
    if vuln.get("status") or vuln.get("session"):
        stat_line = f"{pad}  {CDM}Status: {CW}{vuln.get('status', '?')}{R}  {CDM}| Session: {CW}{vuln.get('session', 'N/A')}{R}"
        print(stat_line)

    # Body Snippet - Specialized rendering
    if vuln.get("body_snippet"):
        snip = vuln["body_snippet"].replace("\n", " ")[:120]
        print(f"{pad}  {CDM}Snippet:{R} {CDM}\"{snip}...\"{R}")

    # Recursive fallback for truly custom module data
    for key, val in vuln.items():
        if key in handled or not val: continue
        print(f"{pad}  {CC}{key.replace('_', ' ').title():<18}{R}:")
        if isinstance(val, (dict, list)):
            print(_pretty_data(val, indent + 22))
        else:
            print(f"{' ' * (indent + 22)}{CW}{val}{R}")

def _render_remaining_intel(intel, handled_keys, indent=4):
    """Renders any keys in the intel dict that weren't handled by the specific renderer."""
    pad = " " * indent
    for k, v in intel.items():
        if k in handled_keys or not v or k == "risk_score": continue
        print(f"\n{pad}{CC}{k.replace('_', ' ').title()}{R}:")
        if isinstance(v, (dict, list)):
            print(_pretty_data(v, indent + 4))
        else:
            print(f"{' ' * (indent + 4)}{CW}{v}{R}")

# ═══════════════════════════════════════════════════════════════════════
# HELPER: CLEAN DATA
# ═══════════════════════════════════════════════════════════════════════

def _clean_item(item):
    """Makes secrets and other dict items human readable."""
    if isinstance(item, dict):
        content = item.get('content') or item.get('value') or item.get('match')
        itype = item.get('type') or item.get('name')
        source = item.get('source') or item.get('file')
        
        res = ""
        if itype: res += f"{CY}[{itype}]{R} "
        if content: res += f"{CW}{content}{R}"
        if source: res += f" {CDM}({source}){R}"
        
        if not res:
            return ", ".join(f"{k}: {v}" for k, v in item.items())
        return res
    return str(item)

# ═══════════════════════════════════════════════════════════════════════
# MODULE-SPECIFIC RENDERERS
# ═══════════════════════════════════════════════════════════════════════

def _render_spider(intel, risk_score):
    summary = intel.get("summary", {})
    endpoints = intel.get("endpoints", [])
    secrets = intel.get("secrets", [])
    tech_stack = intel.get("tech_stack", [])

    _section("SPIDER — Web Crawler Intelligence")
    _kv("Total Endpoints", summary.get("total_endpoints", len(endpoints)))
    _kv("Confirmed", summary.get("confirmed", 0))
    _kv("Secrets Found", summary.get("secrets", len(secrets)))
    _kv("Risk Score", f"{risk_score}")

    if tech_stack:
        print(f"\n    {CC}Tech Stack{R}")
        for tech in tech_stack: _bullet(tech)

    if endpoints:
        print(f"\n    {CC}Endpoints ({len(endpoints)}){R}")
        for ep in endpoints:
            url, method = ep.get("url", ""), ep.get("method", "GET")
            status = ep.get("observed_status", [])
            flags = []
            if ep.get("auth_required"): flags.append(f"{CY}AUTH{R}")
            if ep.get("idor_candidate"): flags.append(f"{CR}IDOR{R}")
            if ep.get("sqli_candidate"): flags.append(f"{CR}SQLi{R}")
            if ep.get("admin_panel"): flags.append(f"{CR}ADMIN{R}")
            flag_str = f" [{' '.join(flags)}]" if flags else ""
            status_str = f" ({','.join(str(s) for s in status)})" if status else ""
            print(f"      {CC}{method:<5}{R} {CW}{url}{R} {CDM}{status_str}{R}{flag_str}")

    if secrets:
        print(f"\n    {CR}Secrets ({len(secrets)}){R}")
        for sec in secrets: _bullet(_clean_item(sec), color=CR)
    
    _render_remaining_intel(intel, ["summary", "endpoints", "secrets", "tech_stack"])

def _render_vulns(module_name, intel):
    vulns = intel.get("vulnerabilities", [])
    if vulns:
        _section(f"{module_name} — Findings ({len(vulns)})")
        for v in vulns: _vuln_block(v)
    _render_remaining_intel(intel, ["vulnerabilities"])

def _render_agent_findings(intel, risk_score=0):
    """Renders structured findings identified and confirmed by the AI reasoning loop."""
    findings = intel.get("findings", []) or intel.get("vulnerabilities", [])
    if isinstance(intel, list):
        findings = intel
    if not findings:
        return
    _section(f"Agent Findings — Validated Triage ({len(findings)})")
    
    # Group findings by severity
    by_sev = defaultdict(list)
    for f in findings:
        if isinstance(f, dict):
            sev = str(f.get("severity", f.get("confidence", "INFO"))).upper()
            by_sev[sev].append(f)
        else:
            by_sev["INFO"].append({"finding_type": str(f), "severity": "INFO"})

    for sev_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        items = by_sev.get(sev_level, [])
        for item in items:
            _vuln_block(item)

def _render_blob(intel):
    files = intel.get("reconstructed", intel.get("recovered_files", intel.get("files", [])))
    secrets = intel.get("secrets", [])
    new_eps = intel.get("new_endpoints", [])
    
    _section(f"BlobUnpacker — Intelligence Extracted")
    if files:
        print(f"\n    {CC}Reconstructed Source ({len(files)}){R}")
        for f in files: _bullet(f)
    if secrets:
        print(f"\n    {CR}Secrets Discovery ({len(secrets)}){R}")
        for s in secrets: _bullet(_clean_item(s), color=CR)
    if new_eps:
        print(f"\n    {CC}New Endpoints Mined ({len(new_eps)}){R}")
        for e in new_eps: _bullet(_clean_item(e))
    _render_remaining_intel(intel, ["reconstructed", "recovered_files", "files", "secrets", "new_endpoints"])

def _render_source_auditor(intel):
    findings = intel.get("vulnerabilities", intel.get("findings", []))
    files = intel.get("reconstructed_files", [])
    
    _section(f"SourceAuditor — Static Analysis Results")
    if files:
        _kv("Files Audited", len(files))
    if findings:
        print(f"\n    {CR}Vulnerabilities Found ({len(findings)}){R}")
        for f in findings: _vuln_block(f)
    _render_remaining_intel(intel, ["vulnerabilities", "findings", "reconstructed_files"])

def _render_generic(module_name, intel):
    _section(f"{module_name} — Intelligence")
    _render_remaining_intel(intel, [])

# ═══════════════════════════════════════════════════════════════════════
# MODULE ROUTER
# ═══════════════════════════════════════════════════════════════════════

MODULE_RENDERERS = {
    "agent":            lambda intel, rs: _render_agent_findings(intel, rs),
    "agent_findings":   lambda intel, rs: _render_agent_findings(intel, rs),
    "spider":           lambda intel, rs: _render_spider(intel, rs),
    "corsbuster":       lambda intel, rs: _render_vulns("CORSbuster", intel),
    "sourceauditor":    lambda intel, rs: _render_source_auditor(intel),
    "surfaceauditor":   lambda intel, rs: _render_generic("SurfaceAuditor", intel),
    "blobunpacker":     lambda intel, rs: _render_blob(intel),
    "wafbuster":        lambda intel, rs: _render_generic("WAFbuster", intel),
    "exmap":            lambda intel, rs: _render_generic("Exmap", intel),
}

# ═══════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINTS
# ═══════════════════════════════════════════════════════════════════════

def render_loot(target, all_results):
    if not all_results:
        print(f"{CY}[!] No intelligence collected in this session.{R}")
        return

    _box_header("HELLHOUND — LOOT")
    _kv("Target", target or "N/A")
    
    total_risk, total_vulns = 0, 0
    for mod, output in all_results.items():
        if not isinstance(output, dict): continue
        intel = output.get("intel", {})
        total_risk += output.get("risk_score", 0)
        for vk in ("vulnerabilities", "findings", "cors_vulnerabilities", "cves", "agent_findings"):
            vlist = intel.get(vk, [])
            if isinstance(vlist, list): total_vulns += len(vlist)

    _kv("Risk Score", f"{total_risk}")
    _kv("Issues Found", f"{total_vulns}")
    _kv("Modules Run", f"{len(all_results)}")

    prio = ["agent", "agent_findings", "spider", "fuzz_hunter", "hydra", "cloudscout", "transport_auditor", "wafbuster", "surfaceauditor", "exmap"]
    sorted_mods = sorted(all_results.keys(), key=lambda x: prio.index(x) if x in prio else 99)

    for mod in sorted_mods:
        output = all_results[mod]
        if not isinstance(output, dict): continue
        intel = output.get("intel", {})
        
        # Comprehensive filtering: Only show if there is non-risk_score data
        has_data = any(v for k, v in intel.items() if k != "risk_score")
        if not has_data: continue

        renderer = MODULE_RENDERERS.get(mod)
        if renderer: renderer(intel, output.get("risk_score", 0))
        else: _render_generic(mod, intel)
    
    w = get_w()
    print(f"\n{CR}{'=' * w}{R}")
    print(f"  {CW}Use 'loot --json' for raw export  |  'loot --export' to save report{R}")
    print(f"{CR}{'=' * w}{R}\n")

def process_framework_results(results_dict):
    all_findings = []
    for mod, output in results_dict.items():
        if not isinstance(output, dict): continue
        intel = output.get("intel", {})
        for vk in ("vulnerabilities", "findings", "cors_vulnerabilities", 
                    "cves", "assets", "secrets", "agent_findings"):
            items = intel.get(vk, [])
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        item["module"] = mod
                        if "id" not in item: item["id"] = f"{mod.upper()}-{len(all_findings)+1:03}"
                        all_findings.append(item)
    return all_findings