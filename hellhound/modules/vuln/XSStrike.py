import asyncio
import aiohttp
import re
import random
import string
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from hellhound.core import http_utils

NAME = "xsstrike"
CATEGORY = "vuln"
DESCRIPTION = "Context-Aware Reflected XSS Auditor"

OPTIONS = [
    {"name": "concurrency", "type": int, "default": 10, "help": "Concurrent attack threads"},
    {"name": "timeout", "type": int, "default": 10, "help": "Request timeout (seconds)"},
    {"name": "use_polyglots", "type": bool, "default": True, "help": "Use advanced XSS polyglots"},
]

# ─────────────────────────────────────────────────────────────────────────────
# PAYLOADS & CONTEXTS
# ─────────────────────────────────────────────────────────────────────────────

# Simple reflection tokens to identify context
REF_TOKEN = "h3llh0und"

CONTEXT_PROBES = [
    {"name": "HTML_TAG", "payload": f"<{REF_TOKEN}>", "pattern": rf"<{REF_TOKEN}>"},
    {"name": "ATTR_QUOTE", "payload": f"\"{REF_TOKEN}", "pattern": rf"\"{REF_TOKEN}"},
    {"name": "ATTR_SQUOTE", "payload": f"'{REF_TOKEN}", "pattern": rf"'{REF_TOKEN}"},
    {"name": "JS_CONTEXT", "payload": f"';{REF_TOKEN}//", "pattern": rf"';{REF_TOKEN}//"},
]

ADVANCED_PAYLOADS = [
    "<script>alert(1)</script>",
    "\" onmouseover=\"alert(1)",
    "' onmouseover='alert(1)",
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
    "';alert(1)//",
]

# ─────────────────────────────────────────────────────────────────────────────
# AUDITOR ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class XSSAuditor:
    def __init__(self, emit, session, options):
        self.emit = emit
        self.session = session
        self.options = options

    async def check_reflection(self, url, method, pname, original_value):
        """Checks if a parameter is reflected and if characters can be broken out of context."""
        res_list = []
        
        # Phase 1: Context Discovery using a non-malicious token
        probe_token = f"h3ll{random.choice(string.ascii_lowercase)}h"
        try:
            params = {pname: probe_token} if method == "GET" else {}
            data = {pname: probe_token} if method == "POST" else {}
            async with self.session.request(method, url, params=params, data=data, timeout=self.options.get("timeout")) as r:
                body = await r.text()
                if probe_token not in body:
                    return []
                
                # Simple context discovery via distance to markers
                # (Professional tools use a full HTML parser here, but we use high-fidelity heuristics)
                context_type = "BODY"
                token_idx = body.find(probe_token)
                surround = body[max(0, token_idx-20):token_idx+20]
                
                if "<script" in body.lower() and body.lower().find("<script") < token_idx and body.lower().find("</script>") > token_idx:
                    context_type = "SCRIPT"
                elif '="' in surround or "='" in surround:
                    context_type = "ATTRIBUTE"
                
                # Phase 2: Escape Analysis
                # We test if the characters needed to break out of this context are allowed
                breakout_chars = "<>\"'" if context_type == "BODY" else "\";" if context_type == "ATTRIBUTE" else "';-"
                test_payload = f"{probe_token}{breakout_chars}"
                
                params = {pname: test_payload} if method == "GET" else {}
                data = {pname: test_payload} if method == "POST" else {}
                
                async with self.session.request(method, url, params=params, data=data, timeout=self.options.get("timeout")) as r:
                    body_v = await r.text()
                    if test_payload in body_v:
                        res_list.append({
                            "type": "REFLECTED_XSS",
                            "severity": "HIGH",
                            "confidence": "CERTAIN",
                            "context": context_type,
                            "evidence": f"Unescaped reflection of breakout characters '{breakout_chars}' in {context_type} context.",
                            "payload": test_payload
                        })
                    elif probe_token in body_v:
                        # Reflected but likely escaped or filtered
                        res_list.append({
                            "type": "POTENTIAL_XSS",
                            "severity": "LOW",
                            "confidence": "POSSIBLE",
                            "context": context_type,
                            "evidence": f"Reflection found in {context_type} but breakout characters '{breakout_chars}' were filtered/escaped.",
                            "payload": test_payload
                        })
        except:
            pass
        return res_list

async def run(target, emit, options=None):
    emit.info(f"[*] XSSTRIKE: Auditing reflected XSS for {target}")
    
    spider_intel = options.get("spider_intel", {}) if options else {}
    endpoints = spider_intel.get("endpoints", [])
    
    # Priority: params flagged by Hydra as XSS_POTENTIAL
    hydra_intel = options.get("hydra_intel", {}) if options else {}
    surfaces = hydra_intel.get("surfaces", [])
    
    targets = []
    if surfaces:
        targets = [s for s in surfaces if "XSS_POTENTIAL" in s.get("roles", [])]
    
    if not targets and endpoints:
        for ep in endpoints:
            params = ep.get("params", {})
            for p_items in params.values():
                for p in p_items:
                    targets.append({"url": ep.get("url"), "method": ep.get("method", "GET"), "parameter": p})

    if not targets:
        emit.warn("[!] No injection surfaces identified for XSS testing.")
        return {"raw": "No targets", "signals": []}

    emit.info(f"    [i] Targeted audit on {len(targets)} surface(s)...")

    findings = []
    async with aiohttp.ClientSession() as session:
        auditor = XSSAuditor(emit, session, options or {})
        
        for t in targets:
            url = t.get("url")
            method = t.get("method", "GET")
            pname = t.get("parameter")
            
            reflections = await auditor.check_reflection(url, method, pname, "")
            for ref in reflections:
                findings.append({**t, **ref, "severity": ref.get("severity", "MEDIUM"), "confidence": ref.get("confidence", "POSSIBLE")})
                emit.warn(f"        [!] REFLECTION DETECTED: {pname} on {url} ({ref['context']})")

    if findings:
        emit.success(f"[+] XSSTRIKE complete. Found {len(findings)} reflections!")
    else:
        emit.info("[-] No XSS reflections found.")

    return {
        "raw": f"Audited {len(targets)} surfaces. Found {len(findings)} XSS reflections.",
        "intel": {
            "vulnerabilities": findings
        },
        "signals": ["XSS_FOUND" if findings else "NO_XSS"]
    }
