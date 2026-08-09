"""
hellhound/core/agent.py

Autonomous Bug Bounty Reconnaissance & Triage Agent.
Coordinates discovery tools, enforces code-level scope guardrails,
manages target task context, and triages verified findings.
"""

from dataclasses import dataclass, field
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Dict, Any, List, Optional, Callable, Tuple
from urllib.parse import urlparse

import requests

from hellhound.core.scope import ScopeRules, is_in_scope, check_module_against_rules
from hellhound.core.tasks import Target, create_or_load_target, save_target, set_scope
from hellhound.core.ai_utils import (
    load_config,
    call_ai,
    ask_neural_core,
    thinking_animation,
    render_chat_bubble,
    render_ai_box
)
from hellhound.core.http_utils import merge_global_context


logger = logging.getLogger("hellhound.agent")


# ==========================================================
# TOOL DEFINITIONS & SPECIFICATIONS
# ==========================================================

@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: Dict[str, Any]
    executor: Callable[[Dict[str, Any], Target, Any], Dict[str, Any]]


# ==========================================================
# TOOL EXECUTORS (RECON & TRIAGE ONLY)
# ==========================================================

def _find_binary(name: str) -> Optional[str]:
    """Find binary in system PATH as well as standard user Go binary directories."""
    custom_paths = [
        "/home/joe/.pdtm/go/bin",
        "/home/joe/go/bin",
        "/usr/local/bin",
        "/usr/bin",
        str(Path.home() / ".pdtm" / "go" / "bin"),
        str(Path.home() / "go" / "bin")
    ]
    path_env = os.environ.get("PATH", "") + ":" + ":".join(custom_paths)
    return shutil.which(name, path=path_env)


def _resolve_resolvers_path() -> str:
    """Resolve DNS resolvers file, checking repository wordlists, local tool configs, or generating default public resolvers."""
    repo_root = Path(__file__).resolve().parent.parent
    candidates = [
        str(repo_root / "wordlists" / "dns" / "resolvers.txt"),
        str(Path.home() / "HACK-HUB" / "bug-hunting" / "Tools" / "resolvers.txt"),
        str(Path.home() / ".config" / "subfinder" / "resolvers.txt"),
        str(Path.home() / ".config" / "dnsx" / "resolvers.txt"),
        str(Path.home() / ".hellhound" / "resolvers.txt"),
        "/usr/share/seclists/Miscellaneous/dns-resolvers.txt"
    ]
    for c in candidates:
        if os.path.exists(c) and os.path.getsize(c) > 0:
            return c
    default_res = Path.home() / ".hellhound" / "resolvers.txt"
    default_res.parent.mkdir(parents=True, exist_ok=True)
    if not default_res.exists() or default_res.stat().st_size == 0:
        default_res.write_text("1.1.1.1\n8.8.8.8\n9.9.9.9\n8.8.4.4\n1.0.0.1\n")
    return str(default_res)


def _execute_shuffledns(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Active DNS brute-force via shuffledns (massdns-backed) with wildcard handling."""
    domain = (args.get("domain") or target.name).strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc.split(":")[0]

    binary = _find_binary("shuffledns")
    if not binary:
        return {
            "error": "shuffledns not installed",
            "hint": "go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
        }

    # Resolve wordlist path
    repo_root = Path(__file__).resolve().parent.parent
    wordlist_candidates = [
        repo_root / "wordlists" / "dns" / "subdomains.txt",
        Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
        Path("/usr/share/seclists/Discovery/DNS/namelist.txt"),
        Path("/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
    ]
    wordlist = None
    for wc in wordlist_candidates:
        if wc.exists() and wc.stat().st_size > 0:
            wordlist = str(wc)
            break

    if not wordlist:
        return {"error": "No DNS wordlist found in repository or standard SecLists paths."}

    resolvers = _resolve_resolvers_path()
    massdns_bin = _find_binary("massdns") or "/usr/bin/massdns"

    cmd = [binary, "-d", domain, "-w", wordlist, "-r", resolvers, "-mode", "bruteforce", "-silent"]
    if os.path.exists(massdns_bin):
        cmd.extend(["-m", massdns_bin])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        subdomains = [l.strip().lower() for l in proc.stdout.splitlines() if l.strip() and "." in l]
    except Exception as e:
        return {"error": f"shuffledns execution failed: {e}", "domain": domain}

    # Update target state
    if "subdomains" not in target.state:
        target.state["subdomains"] = []
    for s in subdomains:
        if s not in target.state["subdomains"]:
            target.state["subdomains"].append(s)

    return {
        "domain": domain,
        "count": len(subdomains),
        "subdomains": subdomains[:100],
        "total_discovered": len(subdomains)
    }


def _execute_ffuf_vhost(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Virtual-host fuzzing via ffuf to discover vhosts sharing an IP or host."""
    domain = args.get("domain", "").strip().lower() or target.name
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc.split(":")[0]

    target_ip = args.get("target_ip", "").strip() or domain
    binary = _find_binary("ffuf")
    if not binary:
        return {
            "error": "ffuf not installed",
            "hint": "go install github.com/ffuf/ffuf/v2@latest"
        }

    repo_root = Path(__file__).resolve().parent.parent
    wordlist_candidates = [
        repo_root / "wordlists" / "vhosts" / "vhosts.txt",
        Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
    ]
    wordlist = None
    for wc in wordlist_candidates:
        if wc.exists() and wc.stat().st_size > 0:
            wordlist = str(wc)
            break

    if not wordlist:
        return {"error": "No vhost wordlist found."}

    target_url = target_ip if target_ip.startswith(("http://", "https://")) else f"http://{target_ip}"
    cmd = [
        binary,
        "-w", wordlist,
        "-u", target_url,
        "-H", f"Host: FUZZ.{domain}",
        "-mc", "200,301,302,403",
        "-of", "json",
        "-o", "-",
        "-s"
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        results = []
        if proc.stdout.strip():
            data = json.loads(proc.stdout)
            raw_res = data.get("results", [])
            for r in raw_res:
                vhost = r.get("input", {}).get("FUZZ", "")
                status = r.get("status", 0)
                length = r.get("length", 0)
                full_host = f"{vhost}.{domain}" if vhost else ""
                results.append({
                    "host": full_host,
                    "status": status,
                    "length": length
                })
    except Exception as e:
        results = []

    return {
        "domain": domain,
        "target": target_url,
        "vhosts_found": results,
        "count": len(results)
    }


def _execute_ffuf_content(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Content & directory fuzzing via ffuf."""
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    binary = _find_binary("ffuf")
    if not binary:
        return {
            "error": "ffuf not installed",
            "hint": "go install github.com/ffuf/ffuf/v2@latest"
        }

    repo_root = Path(__file__).resolve().parent.parent
    wordlist_candidates = [
        repo_root / "wordlists" / "web" / "directories.txt",
        Path("/usr/share/seclists/Discovery/Web-Content/common.txt")
    ]
    wordlist = None
    for wc in wordlist_candidates:
        if wc.exists() and wc.stat().st_size > 0:
            wordlist = str(wc)
            break

    if not wordlist:
        return {"error": "No directory wordlist found."}

    target_url = url.rstrip("/") + "/FUZZ"
    cmd = [
        binary,
        "-w", wordlist,
        "-u", target_url,
        "-mc", "200,301,302,403",
        "-of", "json",
        "-o", "-",
        "-s"
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        results = []
        if proc.stdout.strip():
            data = json.loads(proc.stdout)
            raw_res = data.get("results", [])
            for r in raw_res:
                path = r.get("input", {}).get("FUZZ", "")
                status = r.get("status", 0)
                length = r.get("length", 0)
                results.append({
                    "url": r.get("url", f"{url}/{path}"),
                    "path": path,
                    "status": status,
                    "length": length
                })
    except Exception as e:
        results = []

    return {
        "target_url": url,
        "discovered_endpoints": results[:100],
        "count": len(results)
    }


def _execute_subfinder(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    domain = args.get("domain") or target.name
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = urlparse(domain).netloc.split(":")[0]

    subdomains = set()

    # 1. Try local subfinder binary if available
    subfinder_bin = shutil.which("subfinder")
    if subfinder_bin:
        try:
            cmd = [subfinder_bin, "-d", domain, "-silent", "-all"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    sub = line.strip().lower()
                    if sub and "." in sub:
                        subdomains.add(sub)
        except Exception as e:
            logger.warning(f"subfinder execution failed: {e}")

    # 2. Fallback to crt.sh certificate transparency lookup
    if not subdomains:
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            r = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for item in name.splitlines():
                        item = item.strip().lower()
                        if item.startswith("*."):
                            item = item[2:]
                        if item and domain in item and "." in item:
                            subdomains.add(item)
        except Exception as e:
            logger.warning(f"crt.sh lookup failed: {e}")

    sub_list = sorted(list(subdomains))
    # Update target state
    if "subdomains" not in target.state:
        target.state["subdomains"] = []
    for s in sub_list:
        if s not in target.state["subdomains"]:
            target.state["subdomains"].append(s)

    return {
        "domain": domain,
        "count": len(sub_list),
        "subdomains": sub_list[:100],  # Return up to 100 in context
        "total_discovered": len(sub_list)
    }


def _execute_httpx(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    raw_target = args.get("target") or target.name
    targets_to_probe = []
    if isinstance(raw_target, list):
        targets_to_probe = raw_target
    else:
        targets_to_probe = [raw_target]

    live_hosts = []

    # 1. Try local httpx binary
    httpx_bin = shutil.which("httpx")
    if httpx_bin:
        try:
            input_data = "\n".join(targets_to_probe)
            cmd = [httpx_bin, "-silent", "-status-code", "-title", "-tech-detect", "-json"]
            proc = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=60)
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    if line.strip():
                        try:
                            item = json.loads(line.strip())
                            live_hosts.append({
                                "url": item.get("url"),
                                "status_code": item.get("status_code"),
                                "title": item.get("title", ""),
                                "tech": item.get("tech", []),
                                "webserver": item.get("webserver", "")
                            })
                        except Exception:
                            pass
        except Exception as e:
            logger.warning(f"httpx binary failed: {e}")

    # 2. Fallback to lightweight HTTP probe
    if not live_hosts:
        for t in targets_to_probe[:20]:
            host = t.strip()
            if not host.startswith(("http://", "https://")):
                urls = [f"https://{host}", f"http://{host}"]
            else:
                urls = [host]
            for u in urls:
                try:
                    r = requests.get(u, timeout=5, verify=False, allow_redirects=True, headers=merge_global_context({}))
                    live_hosts.append({
                        "url": u,
                        "status_code": r.status_code,
                        "title": re.search(r'<title>(.*?)</title>', r.text, re.I).group(1).strip() if re.search(r'<title>(.*?)</title>', r.text, re.I) else "",
                        "tech": [r.headers.get("Server")] if r.headers.get("Server") else [],
                        "webserver": r.headers.get("Server", "")
                    })
                    break
                except Exception:
                    continue

    if "live_hosts" not in target.state:
        target.state["live_hosts"] = []
    for h in live_hosts:
        if h not in target.state["live_hosts"]:
            target.state["live_hosts"].append(h)

    return {
        "count": len(live_hosts),
        "live_hosts": live_hosts
    }


def _execute_subzy(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Subdomain takeover verification (DNS CNAME + Signature response check)."""
    subdomain = args.get("subdomain") or target.name
    subdomain = subdomain.strip().lower()
    if subdomain.startswith(("http://", "https://")):
        subdomain = urlparse(subdomain).netloc.split(":")[0]

    # Signatures of dangling CNAME services
    TAKEOVER_SIGNATURES = {
        "github": ("github.io", "There isn't a GitHub Pages site here."),
        "aws_s3": ("s3.amazonaws.com", "The specified bucket does not exist"),
        "heroku": ("herokudns.com", "No such app"),
        "shopify": ("myshopify.com", "Sorry, this shop is currently unavailable"),
        "fastly": ("fastly.net", "Fastly error: unknown domain"),
        "azure": ("azurewebsites.net", "404 Web Site not found"),
        "tumblr": ("tumblr.com", "Whatever you were looking for doesn't seem to exist"),
        "wordpress": ("wordpress.com", "Do you want to register"),
        "ghost": ("ghost.io", "The thing you were looking for is gone"),
    }

    cname_found = None
    vulnerable = False
    service_matched = None
    fingerprint = ""

    # Check DNS CNAME record
    try:
        cmd = ["dig", "+short", "CNAME", subdomain]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if proc.returncode == 0 and proc.stdout.strip():
            cname_found = proc.stdout.strip().rstrip('.')
    except Exception:
        pass

    if cname_found:
        for s_name, (s_cname_pattern, s_sig) in TAKEOVER_SIGNATURES.items():
            if s_cname_pattern in cname_found:
                service_matched = s_name
                # Check HTTP response body for signature
                try:
                    r = requests.get(f"http://{subdomain}", timeout=6, verify=False)
                    if s_sig in r.text:
                        vulnerable = True
                        fingerprint = s_sig
                except Exception:
                    pass
                break

    result = {
        "subdomain": subdomain,
        "cname": cname_found or "None",
        "service": service_matched or "Unknown",
        "takeover_candidate": vulnerable,
        "evidence": fingerprint if vulnerable else ("CNAME resolved to " + (cname_found or "none"))
    }

    if vulnerable:
        finding = {
            "type": "Subdomain Takeover Candidate",
            "target": subdomain,
            "cname": cname_found,
            "service": service_matched,
            "severity": "HIGH",
            "verified": True
        }
        if finding not in target.findings:
            target.findings.append(finding)
            save_target(target)

    return result


def _execute_dig(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    domain = args.get("domain") or target.name
    record_type = args.get("type", "A").upper()
    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc.split(":")[0]

    records = []
    try:
        cmd = ["dig", "+short", record_type, domain]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if line.strip():
                    records.append(line.strip())
    except Exception as e:
        records.append(f"Error running dig: {e}")

    return {
        "domain": domain,
        "type": record_type,
        "records": records
    }


def _execute_curl(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    url = args.get("url") or target.name
    method = args.get("method", "GET").upper()
    custom_headers = args.get("headers", {})

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    headers = merge_global_context({"global_headers": custom_headers})
    try:
        r = requests.request(
            method=method,
            url=url,
            headers=headers,
            timeout=10,
            verify=False,
            allow_redirects=False
        )
        return {
            "url": url,
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "body_preview": r.text[:1000]
        }
    except Exception as e:
        return {
            "url": url,
            "error": str(e)
        }


def _execute_spider(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    depth = args.get("depth", 2)

    engine = HellhoundEngine()
    opts = {"depth": depth, "max_pages": 50, "target": url}
    try:
        res = engine.run_single("spider", url, options=opts)
        intel = res.get("intel", {}) if isinstance(res, dict) else {}
        endpoints = [ep.get("url") for ep in intel.get("endpoints", []) if isinstance(ep, dict)]
        return {
            "url": url,
            "endpoints_found": len(endpoints),
            "sample_endpoints": endpoints[:30],
            "forms_found": len(intel.get("forms", [])),
            "parameters": intel.get("parameters", [])[:20]
        }
    except Exception as e:
        return {"url": url, "error": f"Spider error: {e}"}


def _execute_wafbuster(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    engine = HellhoundEngine()
    try:
        res = engine.run_single("wafbuster", url)
        return {
            "url": url,
            "result": res
        }
    except Exception as e:
        return {"url": url, "error": f"WAF check error: {e}"}


def _execute_surface_auditor(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    engine = HellhoundEngine()
    try:
        res = engine.run_single("surface_auditor", url)
        return {
            "url": url,
            "result": res
        }
    except Exception as e:
        return {"url": url, "error": f"Surface auditor error: {e}"}


def _execute_cors_checker(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    engine = HellhoundEngine()
    try:
        res = engine.run_single("corsbuster", url)
        return {
            "url": url,
            "result": res
        }
    except Exception as e:
        return {"url": url, "error": f"CORS check error: {e}"}


def _execute_graphql_probe(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    from hellhound.core.engine import HellhoundEngine
    url = args.get("url") or target.name
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    engine = HellhoundEngine()
    try:
        res = engine.run_single("graphql", url)
        return {
            "url": url,
            "result": res
        }
    except Exception as e:
        return {"url": url, "error": f"GraphQL check error: {e}"}


# Tool Registry Map
TOOL_REGISTRY: Dict[str, ToolSpec] = {
    "subfinder": ToolSpec(
        name="subfinder",
        description="Enumerate subdomains for a domain using passive sources and certificate transparency logs.",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target root domain to enumerate subdomains for."}
            },
            "required": ["domain"]
        },
        executor=_execute_subfinder
    ),
    "httpx": ToolSpec(
        name="httpx",
        description="Probe live web services, status codes, page titles, and web technology stack.",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain, URL, or list of subdomains to probe."}
            },
            "required": ["target"]
        },
        executor=_execute_httpx
    ),
    "subzy": ToolSpec(
        name="subzy",
        description="Verify CNAME records and test for potential dangling DNS subdomain takeover vulnerabilities.",
        parameters={
            "type": "object",
            "properties": {
                "subdomain": {"type": "string", "description": "Subdomain to verify for takeover vulnerability."}
            },
            "required": ["subdomain"]
        },
        executor=_execute_subzy
    ),
    "dig": ToolSpec(
        name="dig",
        description="Perform non-destructive DNS queries for A, CNAME, TXT, MX, and NS records.",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to resolve."},
                "type": {"type": "string", "description": "DNS record type: A, CNAME, TXT, MX, NS", "default": "A"}
            },
            "required": ["domain"]
        },
        executor=_execute_dig
    ),
    "curl": ToolSpec(
        name="curl",
        description="Fetch HTTP response headers and body preview for an endpoint with standard BugBounty identity headers.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to request."},
                "method": {"type": "string", "description": "HTTP Method: GET, HEAD, POST", "default": "GET"}
            },
            "required": ["url"]
        },
        executor=_execute_curl
    ),
    "spider": ToolSpec(
        name="spider",
        description="Crawl target web application to discover endpoints, URL parameters, form fields, and JavaScript assets.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base URL of the target application to crawl."},
                "depth": {"type": "integer", "description": "Crawl recursion depth (default: 2)", "default": 2}
            },
            "required": ["url"]
        },
        executor=_execute_spider
    ),
    "wafbuster": ToolSpec(
        name="wafbuster",
        description="Detect WAF / CDN signatures and security headers on the target web application.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to inspect for WAF presence."}
            },
            "required": ["url"]
        },
        executor=_execute_wafbuster
    ),
    "surface_auditor": ToolSpec(
        name="surface_auditor",
        description="Discover exposed API routes, documentation endpoints (OpenAPI/Swagger), and sensitive files.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target web application URL to audit."}
            },
            "required": ["url"]
        },
        executor=_execute_surface_auditor
    ),
    "cors_checker": ToolSpec(
        name="cors_checker",
        description="Audit CORS policy for arbitrary origin reflection and credential exposure.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Endpoint URL to test for CORS misconfiguration."}
            },
            "required": ["url"]
        },
        executor=_execute_cors_checker
    ),
    "graphql_probe": ToolSpec(
        name="graphql_probe",
        description="Detect GraphQL endpoints and check for public introspection availability.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to probe for GraphQL schema."}
            },
            "required": ["url"]
        },
        executor=_execute_graphql_probe
    ),
    "dns_bruteforce": ToolSpec(
        name="dns_bruteforce",
        description=(
            "Active DNS brute-force via shuffledns (massdns-backed with wildcard handling) — use this when passive "
            "subfinder returns few or no results, especially for internal, private, or non-publicly-indexed targets "
            "(e.g. CTF/lab domains) where certificate transparency logs won't have anything indexed."
        ),
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Root domain to brute-force."}
            },
            "required": ["domain"]
        },
        executor=_execute_shuffledns
    ),
    "vhost_fuzz": ToolSpec(
        name="vhost_fuzz",
        description=(
            "Virtual-host fuzzing via ffuf — finds sites sharing an IP that don't "
            "have their own DNS entry, common on CTF infrastructure and internal "
            "environments where multiple challenges/apps share one host."
        ),
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Base domain for the Host header."},
                "target_ip": {"type": "string", "description": "IP or URL to fuzz against."}
            },
            "required": ["domain", "target_ip"]
        },
        executor=_execute_ffuf_vhost
    ),
    "content_discovery": ToolSpec(
        name="content_discovery",
        description="Active path and directory discovery fuzzing via ffuf on live web endpoints to reveal hidden routes and assets.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base URL of the target application to fuzz."}
            },
            "required": ["url"]
        },
        executor=_execute_ffuf_content
    ),
}


# ==========================================================
# AGENT REASONING & EXECUTION LOOP
# ==========================================================

class Agent:
    def __init__(self, target: Optional[Target] = None):
        self.target = target or create_or_load_target("default")
        self.history: List[Dict[str, str]] = []

    def set_target(self, target_name: str) -> Target:
        self.target = create_or_load_target(target_name)
        return self.target

    def _extract_target_from_args(self, args: Dict[str, Any]) -> str:
        for key in ("domain", "target", "url", "subdomain", "host"):
            if key in args and args[key]:
                val = args[key]
                if isinstance(val, list) and val:
                    return str(val[0])
                return str(val)
        return self.target.name

    def execute_tool_call(self, tool_name: str, args: Dict[str, Any], emit: Any = None) -> Dict[str, Any]:
        """
        Executes a tool with hard code-level scope validation before invocation.
        """
        spec = TOOL_REGISTRY.get(tool_name)
        if not spec:
            return {"error": f"Tool '{tool_name}' not found in registry."}

        target_candidate = self._extract_target_from_args(args)

        # Enforce code-level Scope Gate
        if self.target and self.target.scope_rules and self.target.scope_rules.in_scope:
            allowed, reason = is_in_scope(target_candidate, self.target.scope_rules)
            if not allowed:
                msg = f"[!] SCOPE REFUSAL: Action on '{target_candidate}' blocked. Reason: {reason}"
                if emit and hasattr(emit, "warning"):
                    emit.warning(msg)
                return {
                    "error": f"SCOPE_VIOLATION: {reason}",
                    "target": target_candidate,
                    "blocked": True
                }

        # Check for disallowed module flags
        if self.target and self.target.scope_rules:
            allowed, reason = check_module_against_rules(tool_name, self.target.scope_rules)
            if not allowed:
                return {
                    "error": f"RULE_VIOLATION: {reason}",
                    "blocked": True
                }

        try:
            return spec.executor(args, self.target, emit)
        except Exception as e:
            return {"error": f"Tool execution failed: {str(e)}"}

    def handle_message(self, user_text: str, session_context: Optional[Dict[str, Any]] = None, emit: Any = None, max_iterations: int = 15) -> str:
        """
        Main autonomous reasoning and conversational loop.
        """
        if session_context:
            t_name = session_context.get("target") or session_context.get("target_name")
            if t_name and (not self.target or self.target.name != t_name):
                self.set_target(t_name)

        # Check if the user is asking to recon a target without any scope loaded or defined
        lower_text = user_text.lower()
        recon_words = ["recon", "scan", "enumerate", "subdomains", "crawl", "spider", "test", "hunt"]
        has_recon_intent = any(rw in lower_text for rw in recon_words)
        
        # Check if there is a target defined in the prompt or active context
        domain_match = re.search(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})', user_text)
        if domain_match:
            detected_domain = domain_match.group(1).lower().lstrip("*.")
            if self.target.name == "default" or (self.target.name != detected_domain and "." in detected_domain):
                self.set_target(detected_domain)
        elif self.target.name == "default" and self.target.scope_rules.in_scope:
            primary_domain = self.target.scope_rules.in_scope[0].lstrip("*.")
            if primary_domain and "." in primary_domain:
                self.set_target(primary_domain)

        # Scope enforcement gate for fresh un-scoped network recon requests
        if has_recon_intent:
            if not self.target.scope_rules.in_scope and not self.target.scope_raw:
                if self.target.name == "default" and not domain_match:
                    return (
                        "No target or scope is currently set. Please specify a target domain and authorized scope "
                        "(e.g., using `/scope <rules>` or `target: example.com`) before starting reconnaissance."
                    )

        # Build System Prompt with registered tools and current target scope
        tools_summary = "\n".join([
            f"- {name}: {spec.description} | Params: {json.dumps(spec.parameters)}"
            for name, spec in TOOL_REGISTRY.items()
        ])

        scope_summary = "None (Default local allow)"
        if self.target.scope_rules.in_scope:
            scope_summary = f"IN-SCOPE: {self.target.scope_rules.in_scope} | OUT-OF-SCOPE: {self.target.scope_rules.out_scope}"

        system_prompt = f"""\
You are HELLHOUND, an autonomous bug bounty reconnaissance and triage assistant.
Your role: Automate subdomain enumeration, live host discovery, tech detection, takeover verification, endpoint discovery, and triage.
You operate strictly within authorized engagement scope and verify findings factually.

TARGET: {self.target.name}
SCOPE CONSTRAINTS: {scope_summary}
CURRENT FINDINGS: {len(self.target.findings)} verified findings

IMPORTANT BEHAVIORAL RULES:
1. ONLY call tools when the user explicitly requests reconnaissance, scanning, enumeration, or analysis of a target.
2. For greetings ("hello", "hi", "hey"), casual conversation, general questions, or status inquiries, respond conversationally WITHOUT calling any tools.
3. Never run recon tools unless the user mentions a specific target or asks for enumeration/scanning.
4. If a message is ambiguous, ask the user to clarify rather than launching tools.
5. If subfinder/passive enumeration returns few or no results, consider running dns_bruteforce — this is especially important for internal, private, or non-publicly-indexed targets (lab environments, CTF infrastructure, internal tools) where certificate transparency and passive aggregators have nothing indexed. If a target IP is known but subdomain enumeration is coming up empty, consider vhost_fuzz — CTF infrastructure in particular often runs multiple challenges as virtual hosts on one shared IP with no individual DNS entry.

AVAILABLE RECON/TRIAGE TOOLS:
{tools_summary}

TOOL CALLING FORMAT:
To execute one or more tools, respond with a JSON code block:
```json
{{
  "tool": "<tool_name>",
  "args": {{ ... }}
}}
```
If you do not need to run a tool, or after analyzing tool output, provide a clear, concise final answer to the researcher.
"""

        self.history.append({"role": "user", "content": user_text})

        # Iteration loop for multi-step reasoning / tool calls
        for iteration in range(max_iterations):
            # Format history for inference
            ai_resp = ask_neural_core(
                prompt=user_text if iteration == 0 else "Continue analysis based on tool results.",
                system_prompt=system_prompt
            )

            if not ai_resp or not ai_resp.strip():
                return "Analysis completed. No further actions required."

            # Check for JSON tool invocation in the response
            tool_call = None
            json_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', ai_resp)
            if json_match:
                try:
                    parsed = json.loads(json_match.group(1))
                    if isinstance(parsed, dict) and "tool" in parsed:
                        tool_call = parsed
                except Exception:
                    pass
            elif ai_resp.strip().startswith("{") and ai_resp.strip().endswith("}"):
                try:
                    parsed = json.loads(ai_resp.strip())
                    if isinstance(parsed, dict) and "tool" in parsed:
                        tool_call = parsed
                except Exception:
                    pass

            if tool_call and tool_call.get("tool") in TOOL_REGISTRY:
                t_name = tool_call["tool"]
                t_args = tool_call.get("args", {})
                
                if emit and hasattr(emit, "info"):
                    emit.info(f"[*] Executing tool: {t_name} with args: {t_args}")

                tool_result = self.execute_tool_call(t_name, t_args, emit)

                # Feed result back to conversation
                self.history.append({"role": "assistant", "content": ai_resp})
                self.history.append({
                    "role": "user",
                    "content": f"[TOOL RESULT: {t_name}]\n{json.dumps(tool_result, indent=2)}"
                })
                # Update loop prompt for next iteration
                user_text = f"Tool '{t_name}' returned:\n{json.dumps(tool_result, indent=2)}\nEvaluate these findings."
                continue

            # No tool call; return final answer
            self.history.append({"role": "assistant", "content": ai_resp})
            save_target(self.target)
            return ai_resp

        save_target(self.target)
        return "Reached maximum analysis iterations."


# Global singleton agent instance for active session
_global_agent: Optional[Agent] = None

def get_agent(target_name: Optional[str] = None) -> Agent:
    global _global_agent
    if _global_agent is None:
        _global_agent = Agent(create_or_load_target(target_name or "default"))
    elif target_name and _global_agent.target.name != target_name:
        _global_agent.set_target(target_name)
    return _global_agent

def handle_message(user_text: str, session_context: Optional[Dict[str, Any]] = None, emit: Any = None) -> str:
    """Entrypoint for conversational chat queries."""
    target_name = (session_context or {}).get("target")
    agent = get_agent(target_name)
    return agent.handle_message(user_text, session_context=session_context, emit=emit)
