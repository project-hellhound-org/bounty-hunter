import re

NAME = "parax"
CATEGORY = "vuln"
DESCRIPTION = "Advanced parameter risk analysis (SQLi, IDOR, XSS, LFI, Open Redirect)"

# Keyword heuristics (substring-based, not strict match)
RISK_PATTERNS = {
    "IDOR_POTENTIAL": ["id", "uid", "user", "account", "profile", "member", "owner", "author", "pid", "msg_id"],
    "SQLI_POTENTIAL": ["search", "query", "select", "where", "filter", "bslug", "slug", "term", "key"],
    "XSS_POTENTIAL": ["name", "msg", "comment", "input", "text", "bio", "title", "body", "subject"],
    "OPEN_REDIRECT": ["redirect", "next", "url", "return", "dest", "destination", "forward"],
    "LFI_POTENTIAL": ["file", "page", "path", "template", "doc", "layout", "inc"],
    "COMMAND_INJECTION": ["cmd", "exec", "system", "shell", "host", "ping", "ip"]
}

SEVERITY_SCORE = {
    "COMMAND_INJECTION": 5,
    "SQLI_POTENTIAL": 4,
    "LFI_POTENTIAL": 4,
    "IDOR_POTENTIAL": 3,
    "XSS_POTENTIAL": 3,
    "OPEN_REDIRECT": 2
}


def classify_param(param_name):
    name = param_name.lower()

    for risk_type, keywords in RISK_PATTERNS.items():
        for k in keywords:
            if k in name:
                return risk_type
    return None


def run(target, emit, options=None):

    emit.info("[*] Param Xray: Deep parameter intelligence analysis...")

    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])

    if not endpoints:
        emit.warn("[!] No endpoints found. Did Spider run?")
        return {"raw": "No endpoints found", "signals": ["NO_ENDPOINTS"]}

    findings = []
    risk_score = 0

    for ep in endpoints:
        url = ep.get("url")
        method = ep.get("method")
        params = ep.get("params", [])
        
        # Normalize params: Spider 12.0 returns a dict of {source: [names]}
        param_list = []
        if isinstance(params, dict):
            for source, p_items in params.items():
                for item in p_items:
                    if isinstance(item, str):
                        param_list.append(item)
                    elif isinstance(item, dict):
                        param_list.append(item.get("name", ""))
        elif isinstance(params, list):
            for p in params:
                if isinstance(p, str):
                    param_list.append(p)
                elif isinstance(p, dict):
                    param_list.append(p.get("name", ""))

        for pname in param_list:
            if not pname: continue
            risk_type = classify_param(pname)

            if risk_type:
                severity = SEVERITY_SCORE.get(risk_type, 1)
                risk_score += severity

                finding = {
                    "type": risk_type,
                    "url": url,
                    "method": method,
                    "parameter": pname,
                    "severity": severity,
                    "confidence": "Heuristic"
                }

                findings.append(finding)

                emit.warn(
                    f"    [!] {risk_type} → {pname} "
                    f"({method} {url})"
                )

    signals = []
    if findings:
        signals.append("PARAM_RISKS_IDENTIFIED")

    # Deduplicate findings
    unique_findings = []
    seen = set()

    for f in findings:
        key = (f["type"], f["url"], f["parameter"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    emit.success(f"[+] {len(unique_findings)} risky parameters detected.")

    return {
        "raw": f"Analyzed {len(endpoints)} endpoints. Found {len(unique_findings)} risks.",
        "intel": {
            "vulnerabilities": unique_findings,
            "risk_score": risk_score
        },
        "signals": signals
    }
