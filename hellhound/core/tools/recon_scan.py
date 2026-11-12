"""
hellhound/core/tools/recon_scan.py - subdomain / host reconnaissance cluster.

Split slice 11 (first big cluster unlocked by tool_shared). Subdomain enumeration
(subfinder, subdomain_sweep, permute_subdomains, resolve_candidates), HTTP probing
(httpx), TLS cert scanning (tls_cert_scan), and subdomain-takeover checks
(takeover_scanner, subzy) — all shell-out tools that now pull their shared plumbing
(_run_cmd_with_heartbeat, _find_binary, _bounded_request) from tool_shared instead
of agent.py. No lazy shims needed. agent.py re-imports every executor; TOOL_REGISTRY
wiring is unchanged.
"""
import os
import re
import json
import socket
import logging
import subprocess
import tempfile
from pathlib import Path

import hellhound
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from hellhound.core.tool_shared import _find_binary, _run_cmd_with_heartbeat, _bounded_request
from hellhound.core.scope import is_in_scope, normalize_host
from hellhound.core.tasks import Target, save_target
from hellhound.core.ai_utils import load_config
from hellhound.core.http_utils import merge_global_context, normalize_headers, normalize_cookies
from hellhound.core.toolcheck import ensure_tool, get_binary_path, is_available, pick_available, install_hint
from hellhound.memory import update_from_subfinder, update_from_httpx, update_from_subzy

logger = logging.getLogger("hellhound.agent")


def _resolve_resolvers_path() -> str:
    """Resolve DNS resolvers file, checking fast local list, tool configs, standard SecLists paths, or generating default public resolvers."""
    repo_root = Path(hellhound.__file__).resolve().parent
    candidates = [
        str(repo_root / "wordlists" / "dns" / "resolvers-fast.txt"),
        "/usr/share/wordlists/seclists/Miscellaneous/dns-resolvers.txt",
        "/usr/share/seclists/Miscellaneous/dns-resolvers.txt",
        str(Path.home() / "HACK-HUB" / "bug-hunting" / "Tools" / "resolvers.txt"),
        str(Path.home() / ".config" / "subfinder" / "resolvers.txt"),
        str(Path.home() / ".config" / "dnsx" / "resolvers.txt"),
        str(Path.home() / ".beast" / "resolvers.txt")
    ]
    for c in candidates:
        if os.path.exists(c) and os.path.getsize(c) > 0:
            return c
    default_res = Path.home() / ".beast" / "resolvers.txt"
    default_res.parent.mkdir(parents=True, exist_ok=True)
    if not default_res.exists() or default_res.stat().st_size == 0:
        default_res.write_text("1.1.1.1\n8.8.8.8\n9.9.9.9\n8.8.4.4\n1.0.0.1\n")
    return str(default_res)


# Every root a wordlist realistically lives under on a hunting box — not just
# the repo's own bundled fallback. Covers Kali's standard system locations
# (both the /usr/share/wordlists symlink farm and the real /usr/share/seclists
# tree), the classic dirb/dirbuster/wfuzz/amass package dirs, common manual
# SecLists clone spots, and the researcher's own home-directory conventions
# (~/HACK-HUB is this researcher's actual layout — see resolvers above).


def _execute_subfinder(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    domain = args.get("domain") or target.name
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = urlparse(domain).netloc.split(":")[0]

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("subfinder", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])
        return {
            "error": "subfinder not installed",
            "message": check["message"],
            "hint": "pdtm -i subfinder"
        }

    subfinder_bin = get_binary_path("subfinder") or "subfinder"
    subdomains = set()

    try:
        cmd = [subfinder_bin, "-d", domain, "-silent", "-all", "-timeout", "10"]
        proc = _run_cmd_with_heartbeat(cmd, timeout=45, emit=emit, label="subfinder (passive OSINT lookup)")
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                sub = line.strip().lower()
                if sub and "." in sub:
                    subdomains.add(sub)
    except Exception as e:
        logger.warning(f"subfinder execution failed: {e}")

    sub_list = sorted(list(subdomains))
    # Update target state and investigation memory
    try:
        update_from_subfinder(target, sub_list)
        save_target(target)
    except Exception:
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


def _execute_permute_subdomains(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Generate subdomain wordlist mutations and permutations using alterx."""
    raw_subdomains = args.get("subdomains") or args.get("domains") or target.state.get("subdomains") or [target.name]
    if isinstance(raw_subdomains, list):
        sub_list = [str(s).strip().lower() for s in raw_subdomains if str(s).strip()]
    elif isinstance(raw_subdomains, str) and "," in raw_subdomains:
        sub_list = [s.strip().lower() for s in raw_subdomains.split(",") if s.strip()]
    else:
        sub_list = [str(raw_subdomains).strip().lower()]

    cleaned = []
    for s in sub_list:
        if s.startswith(("http://", "https://")):
            s = urlparse(s).netloc.split(":")[0]
        if s:
            cleaned.append(s)

    if not cleaned:
        return {"error": "No subdomains provided for permutation generation."}

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("alterx", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])
        return {
            "error": "alterx not installed",
            "message": check["message"],
            "hint": "pdtm -i alterx"
        }

    binary = get_binary_path("alterx") or "alterx"

    limit = int(args.get("limit", 500))
    cmd = [binary, "-silent", "-limit", str(limit)]

    candidates = []
    try:
        input_data = "\n".join(cleaned)
        proc = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=60)
        candidates = [l.strip().lower() for l in proc.stdout.splitlines() if l.strip() and "." in l]
    except Exception as e:
        return {"error": f"alterx execution failed: {e}"}

    return {
        "count": len(candidates),
        "candidates": candidates[:100],  # Return first 100 in context
        "total_generated": len(candidates)
    }


def _execute_resolve_candidates(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Bulk-resolve and filter candidate domain names using dnsx."""
    raw_candidates = args.get("candidates") or args.get("domains") or args.get("subdomains")
    if isinstance(raw_candidates, list):
        cand_list = [str(c).strip().lower() for c in raw_candidates if str(c).strip()]
    elif isinstance(raw_candidates, str) and "," in raw_candidates:
        cand_list = [c.strip().lower() for c in raw_candidates.split(",") if c.strip()]
    elif isinstance(raw_candidates, str) and raw_candidates.strip():
        cand_list = [raw_candidates.strip().lower()]
    else:
        cand_list = target.state.get("subdomains", [target.name])

    cleaned = []
    for c in cand_list:
        if c.startswith(("http://", "https://")):
            c = urlparse(c).netloc.split(":")[0]
        if c:
            cleaned.append(c)

    if not cleaned:
        return {"error": "No candidate domains provided for resolution."}

    # dnsx is the fast path (bulk, concurrent, gives A + CNAME in one pass)
    # but it's one specific Go binary — on a box where it (or pdtm) was
    # never installed, this used to just fail outright with "dnsx not
    # installed" and nothing resolved at all. There's always a way to do
    # plain DNS resolution: dnspython if it happens to be installed, and
    # failing that the Python standard library itself (socket), which is
    # guaranteed present on every Python install with no extra dependency.
    # Falls through in that order rather than refusing to resolve anything.
    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    resolved = []
    used_method = "dnsx"

    if is_available("dnsx") or (auto_install and ensure_tool("dnsx", emit=emit, auto_install=True)["available"]):
        binary = get_binary_path("dnsx") or "dnsx"

        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("\n".join(cleaned) + "\n")
            tmp_path = f.name

        try:
            resolvers = _resolve_resolvers_path()
            cmd = [binary, "-l", tmp_path, "-silent", "-json", "-a", "-cname", "-resp"]
            if resolvers and os.path.exists(resolvers):
                cmd.extend(["-r", resolvers])

            proc = _run_cmd_with_heartbeat(cmd, timeout=120, emit=emit, label="resolve_candidates (DNS resolution)")
            if proc.stdout.strip():
                for line in proc.stdout.splitlines():
                    if line.strip():
                        try:
                            item = json.loads(line.strip())
                            host = item.get("host")
                            if host:
                                resolved.append({
                                    "host": host,
                                    "a": item.get("a", []),
                                    "cname": item.get("cname", []),
                                    "status_code": item.get("status_code", "NOERROR")
                                })
                        except Exception:
                            pass
        except Exception as e:
            return {"error": f"dnsx resolution failed: {e}"}
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
    else:
        if emit and hasattr(emit, "info"):
            emit.info("[*] dnsx not installed — falling back to plain DNS resolution (no CNAME chain, one host at a time, slower on large lists).")
        try:
            import dns.resolver as _dnspython  # type: ignore
            used_method = "dnspython"
        except Exception:
            _dnspython = None
            used_method = "socket"

        import socket
        for host in cleaned:
            a_records: List[str] = []
            cname_records: List[str] = []
            try:
                if _dnspython is not None:
                    try:
                        for rr in _dnspython.resolve(host, "A"):
                            a_records.append(str(rr))
                    except Exception:
                        pass
                    try:
                        for rr in _dnspython.resolve(host, "CNAME"):
                            cname_records.append(str(rr).rstrip("."))
                    except Exception:
                        pass
                else:
                    # Plain stdlib socket — A records only, no CNAME chain
                    # visibility (the OS resolver follows CNAMEs itself
                    # before handing back the final address), but this
                    # requires zero external tools or packages at all.
                    _, aliases, addrs = socket.gethostbyname_ex(host)
                    a_records = list(addrs)
                    cname_records = [a for a in aliases if a != host]
            except (socket.gaierror, Exception):
                continue
            if a_records or cname_records:
                resolved.append({
                    "host": host, "a": a_records, "cname": cname_records,
                    "status_code": "NOERROR",
                })

    # Update target state
    if "subdomains" not in target.state:
        target.state["subdomains"] = []
    for r in resolved:
        h = r["host"]
        if h not in target.state["subdomains"]:
            target.state["subdomains"].append(h)

    return {
        "count": len(resolved),
        "resolved": resolved[:100],
        "total_resolved": len(resolved),
        "method": used_method,
    }


def _execute_subdomain_sweep(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    One call instead of three: subfinder (passive OSINT) -> alterx
    (permutation mutations) -> dnsx (bulk resolve), chained automatically.
    This was explicitly flagged as a session friction point: "give me all
    live subdomains" currently takes the model three separate tool calls,
    manually passing each stage's output into the next. Each stage still
    degrades gracefully on its own (same behavior as calling them
    individually) -- a missing alterx just skips permutation with a note,
    rather than failing the whole sweep, since subfinder's own findings are
    still worth resolving on their own.
    """
    domain = args.get("domain") or target.name
    permute = bool(args.get("permute", True))
    permute_limit = args.get("permute_limit", 300)

    stages: Dict[str, Any] = {}

    subfinder_res = _execute_subfinder({"domain": domain}, target, emit)
    stages["subfinder"] = subfinder_res
    if subfinder_res.get("error"):
        return {
            "domain": domain,
            "stages": stages,
            "error": f"Passive subdomain discovery failed, nothing to permute/resolve: {subfinder_res['error']}",
        }

    passive = list(target.state.get("subdomains") or subfinder_res.get("subdomains") or [])

    permutation_candidates: List[str] = []
    if permute and passive:
        perm_res = _execute_permute_subdomains(
            {"subdomains": passive[:50], "limit": permute_limit}, target, emit
        )
        stages["permute_subdomains"] = perm_res
        if not perm_res.get("error"):
            permutation_candidates = perm_res.get("candidates", [])
    elif permute and not passive:
        stages["permute_subdomains"] = {"skipped": "no passive subdomains found to permute from"}

    to_resolve = sorted(set(passive) | set(permutation_candidates))
    if not to_resolve:
        return {
            "domain": domain,
            "stages": stages,
            "passive_subdomains_found": len(passive),
            "permutation_candidates_generated": len(permutation_candidates),
            "live_hosts_resolved": 0,
            "live_hosts": [],
            "note": "No candidates to resolve.",
        }

    resolve_res = _execute_resolve_candidates({"candidates": to_resolve}, target, emit)
    stages["resolve_candidates"] = resolve_res

    return {
        "domain": domain,
        "stages": stages,
        "passive_subdomains_found": len(passive),
        "permutation_candidates_generated": len(permutation_candidates),
        "live_hosts_resolved": resolve_res.get("total_resolved", 0),
        "live_hosts": resolve_res.get("resolved", [])[:100],
        "resolution_method": resolve_res.get("method"),
    }


def _execute_httpx(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    raw_target = args.get("target") or target.name
    # CAUGHT IN THE WILD: this tool's own schema describes 'target' as
    # "Target domain, URL, or LIST of subdomains" but types it as a plain
    # string — there was never a real array option for the model to use for
    # a batch. So the model (reasonably) did what the description invited:
    # serialized a batch as "host1.com,host2.com,host3.com" in one string.
    # isinstance(raw_target, list) was never true for that, so the whole
    # comma-joined blob became ONE entry in targets_to_probe, got joined
    # into httpx's stdin as a single line, and httpx tried to resolve the
    # literal string "host1.com,host2.com,host3.com" as one (invalid)
    # hostname — 0 live hosts, every time, for every batched call. A
    # single plain hostname with no comma worked fine, which is exactly
    # the "works alone, breaks as a batch" pattern this was producing.
    # Now: accept a real list (if the caller does pass one) AND split a
    # comma/whitespace/newline-separated string into multiple targets.
    targets_to_probe = []
    if isinstance(raw_target, list):
        for item in raw_target:
            targets_to_probe.extend(re.split(r"[,\s]+", str(item).strip()))
    else:
        targets_to_probe = re.split(r"[,\s]+", str(raw_target).strip())
    targets_to_probe = [t for t in targets_to_probe if t]

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("httpx", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])

    live_hosts = []

    # 1. Try local httpx binary if available
    httpx_bin = get_binary_path("httpx") if check["available"] else None
    if httpx_bin:
        try:
            input_data = "\n".join(targets_to_probe)
            cmd = [httpx_bin, "-silent", "-status-code", "-title", "-tech-detect", "-cl", "-location", "-json"]
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
                                "webserver": item.get("webserver", ""),
                                "content_length": item.get("content_length"),
                                "location": item.get("location", "")
                            })
                        except Exception:
                            pass
        except Exception as e:
            logger.warning(f"httpx binary failed: {e}")

    # 2. Fallback to lightweight HTTP probe (runs if binary unavailable or returned no hosts)
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
                        "webserver": r.headers.get("Server", ""),
                        "content_length": len(r.content) if r.content is not None else 0,
                        "location": r.headers.get("Location", "")
                    })
                    break
                except Exception:
                    continue

    # Update target state and investigation memory
    try:
        live_urls = [h.get("url") for h in live_hosts if isinstance(h, dict) and h.get("url")]
        all_techs = []
        for h in live_hosts:
            if isinstance(h, dict):
                for t in h.get("tech", []):
                    if t and t not in all_techs:
                        all_techs.append(t)
        update_from_httpx(target, live_urls, all_techs)
        save_target(target)
    except Exception:
        if "live_hosts" not in target.state:
            target.state["live_hosts"] = []
        for h in live_hosts:
            if h not in target.state["live_hosts"]:
                target.state["live_hosts"].append(h)

    return {
        "count": len(live_hosts),
        "live_hosts": live_hosts
    }


def _execute_tls_cert_scan(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Scan and parse TLS/SSL certificate SANs and CNs using tlsx to discover related infrastructure."""
    raw_target = args.get("hosts") or args.get("target") or args.get("domains") or target.name
    targets_to_scan = []
    if isinstance(raw_target, list):
        targets_to_scan = [str(t).strip() for t in raw_target if str(t).strip()]
    elif isinstance(raw_target, str) and "," in raw_target:
        targets_to_scan = [t.strip() for t in raw_target.split(",") if t.strip()]
    else:
        targets_to_scan = [str(raw_target).strip()]

    cleaned_targets = []
    for t in targets_to_scan:
        if t.startswith(("http://", "https://")):
            t = urlparse(t).netloc.split(":")[0]
        if t:
            cleaned_targets.append(t)

    if not cleaned_targets:
        return {"error": "No valid hosts provided for TLS certificate scan."}

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("tlsx", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])
        return {
            "error": "tlsx not installed",
            "message": check["message"],
            "hint": "pdtm -i tlsx"
        }

    binary = get_binary_path("tlsx") or "tlsx"

    port = str(args.get("port", "443")).strip()
    cmd = [binary, "-san", "-cn", "-so", "-silent", "-json", "-p", port]

    results = []
    discovered_sans = set()
    try:
        input_data = "\n".join(cleaned_targets)
        proc = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=60)
        if proc.stdout.strip():
            for line in proc.stdout.splitlines():
                if line.strip():
                    try:
                        item = json.loads(line.strip())
                        host = item.get("host")
                        cn = item.get("subject_cn", "")
                        sans = item.get("subject_an", [])
                        results.append({
                            "host": host,
                            "ip": item.get("ip", ""),
                            "subject_cn": cn,
                            "subject_an": sans,
                            "issuer_org": item.get("issuer_org", []),
                            "tls_version": item.get("tls_version", ""),
                            "wildcard": item.get("wildcard_certificate", False)
                        })
                        if cn and "." in cn and not cn.startswith("*"):
                            discovered_sans.add(cn.lower())
                        for s in sans:
                            clean_s = s.lower().lstrip("*.")
                            if clean_s and "." in clean_s:
                                discovered_sans.add(clean_s)
                    except Exception:
                        pass
    except Exception as e:
        return {"error": f"tlsx execution failed: {e}", "hosts": cleaned_targets}

    # Update target state with discovered SAN names matching root domain if available
    san_list = sorted(list(discovered_sans))
    if "subdomains" not in target.state:
        target.state["subdomains"] = []
    for s in san_list:
        if target.name in s and s not in target.state["subdomains"]:
            target.state["subdomains"].append(s)

    return {
        "hosts_scanned": cleaned_targets,
        "count": len(results),
        "certificates": results,
        "discovered_domains": san_list[:50]
    }


def _execute_takeover_scanner(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Scan subdomains for takeover vulnerabilities using subjack and signature grep."""
    subdomains = args.get("subdomains")
    if not subdomains:
        subdomains = target.state.get("subdomains", [])
    
    if not subdomains:
        return {"error": "No subdomains found to scan."}

    # Write subdomains to a temp file in target's directory
    sub_file = Path(target.dir) / "takeover_subs_temp.txt"
    try:
        with open(sub_file, "w", encoding="utf-8") as f:
            for s in subdomains:
                f.write(f"{s}\n")
    except Exception as e:
        return {"error": f"Failed to write temporary subdomains file: {e}"}

    script_path = Path(hellhound.__file__).resolve().parent / "tools" / "takeover_scanner.sh"
    if not script_path.exists():
        return {"error": f"takeover_scanner.sh not found at {script_path}"}

    out_dir = Path(target.dir) / "takeover"
    out_dir.mkdir(parents=True, exist_ok=True)
    results_json = out_dir / "results.json"
    if results_json.exists():
        results_json.unlink()

    env = os.environ.copy()
    env["TAKEOVER_OUT_DIR"] = str(out_dir)

    try:
        cmd = [str(script_path), str(sub_file)]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=180)
        
        # Parse JSON output
        results = []
        if results_json.exists():
            with open(results_json, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    results = json.loads(content)
    except Exception as e:
        results = []
        return {"error": f"takeover_scanner execution failed: {e}"}
    finally:
        if sub_file.exists():
            sub_file.unlink()

    # Process and verify candidates
    takeovers_found = []
    for entry in results:
        if isinstance(entry, dict) and entry.get("vulnerable"):
            takeovers_found.append(entry)
            finding = {
                "type": "Subdomain Takeover Candidate",
                "target": entry["subdomain"],
                "cname": entry.get("cname", "None"),
                "service": entry.get("service", "Unknown"),
                "severity": "HIGH",
                "verified": True
            }
            if finding not in target.findings:
                target.findings.append(finding)
    
    if takeovers_found:
        save_target(target)

    return {
        "scanned_count": len(subdomains),
        "takeovers_found": takeovers_found,
        "count": len(takeovers_found)
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
        try:
            update_from_subzy(target, [subdomain])
        except Exception:
            pass
        save_target(target)

    return result
