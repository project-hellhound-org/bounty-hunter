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


_GENTLE_FLAGS = frozenset({"no-rate-limit-testing", "no-dos", "no-automated-scanners"})
_HTTPX_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def _probe_host_live(host: str, headers: Dict[str, str], timeout: int = 6) -> Optional[Dict[str, Any]]:
    """Probe ONE host for a live web service — https first, then http — and
    capture status/title/server. Returns None if neither scheme answers. Never
    raises. A host that already carries a scheme is probed as-is."""
    if host.startswith(("http://", "https://")):
        schemes = [host]
    else:
        schemes = [f"https://{host}", f"http://{host}"]
    for u in schemes:
        try:
            r = requests.get(u, timeout=timeout, verify=False, allow_redirects=True, headers=headers)
            m = _HTTPX_TITLE_RE.search(r.text or "")
            server = r.headers.get("Server", "")
            return {
                "url": u,
                "status_code": r.status_code,
                "title": (m.group(1).strip()[:140] if m else ""),
                "tech": [server] if server else [],
                "webserver": server,
                "content_length": len(r.content) if r.content is not None else 0,
                "location": r.headers.get("Location", ""),
            }
        except Exception:
            continue
    return None


def _concurrent_http_probe(hosts: List[str], target: Target, emit: Any,
                           cap: Optional[int] = None) -> List[Dict[str, Any]]:
    """BATCH, concurrent HTTP liveness for a host list — the no-binary fallback
    for httpx. Replaces the old sequential, 20-host-capped loop so a full
    subdomain list actually gets probed. In-scope only (so a batch spanning
    subdomains never touches an out-of-scope host), concurrency adapts to RoE
    (low fan-out on fragile/strict programs), hard-capped."""
    import concurrent.futures
    rules = getattr(target, "scope_rules", None)
    gentle = bool(set(getattr(rules, "disallowed", []) or []) & _GENTLE_FLAGS)
    if cap is None:
        cap = 60 if gentle else 150
    workers = 6 if gentle else 20

    in_scope: List[str] = []
    for h in hosts:
        probe_host = h if h.startswith(("http://", "https://")) else f"https://{h}"
        allowed, _reason = is_in_scope(probe_host, rules)
        if allowed:
            in_scope.append(h)
        if len(in_scope) >= cap:
            break
    if not in_scope:
        return []
    headers = merge_global_context({})
    out: List[Dict[str, Any]] = []
    workers = max(1, min(workers, len(in_scope)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(lambda h: _probe_host_live(h, headers), in_scope):
            if res:
                out.append(res)
                if emit and hasattr(emit, "info"):
                    try:
                        emit.info(f"[{res['status_code']}] {res['url']}"
                                  + (f"  {res['title']}" if res.get("title") else ""))
                    except Exception:
                        pass
    return out


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

    # Scope-gate the host list BEFORE probing (binary OR fallback) — httpx often
    # gets handed a whole subdomain list, which on a strict program (KWO) can
    # include out-of-scope subdomains. Filtering here keeps BOTH paths in-scope.
    _rules = getattr(target, "scope_rules", None)
    if _rules is not None:
        _kept, _dropped = [], 0
        for _t in targets_to_probe:
            _probe_host = _t if _t.startswith(("http://", "https://")) else f"https://{_t}"
            _ok, _r = is_in_scope(_probe_host, _rules)
            if _ok:
                _kept.append(_t)
            else:
                _dropped += 1
        if _dropped and emit and hasattr(emit, "info"):
            try:
                emit.info(f"httpx: skipped {_dropped} out-of-scope host(s)")
            except Exception:
                pass
        targets_to_probe = _kept
    if not targets_to_probe:
        return {"count": 0, "live_hosts": [], "note": "No in-scope hosts to probe."}

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

    # 2. Fallback to a CONCURRENT HTTP probe (runs if binary unavailable or
    #    returned no hosts). The old fallback was sequential and capped at 20,
    #    so a large subdomain list barely got sampled; this batch-probes the
    #    whole in-scope list in parallel (https+http, title/server), bounded by
    #    RoE so it stays polite on fragile infra.
    if not live_hosts:
        live_hosts = _concurrent_http_probe(targets_to_probe, target, emit)

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


# A compact, high-value common-parameter list (arjun-style). Hidden/unlinked
# params are attack surface a crawler never sees — IDOR ids, SSRF urls, file
# reads, debug/admin toggles, redirects.
_COMMON_PARAMS = [
    "id", "user", "user_id", "userid", "uid", "account", "account_id", "customer",
    "profile", "member", "page", "p", "pid", "cat", "category", "item", "item_id",
    "product", "product_id", "order", "order_id", "invoice", "doc", "document",
    "file", "filename", "path", "dir", "folder", "download", "attachment", "url",
    "uri", "link", "redirect", "redirect_url", "return", "return_url", "returnurl",
    "next", "continue", "dest", "destination", "callback", "jsonp", "domain", "host",
    "site", "server", "ip", "port", "proxy", "fetch", "load", "src", "source",
    "image", "img", "img_url", "avatar", "q", "query", "search", "s", "keyword",
    "term", "filter", "sort", "order_by", "limit", "offset", "start", "count",
    "token", "access_token", "api_key", "apikey", "key", "secret", "auth", "session",
    "sid", "ref", "referrer", "email", "mail", "name", "username", "role", "admin",
    "is_admin", "debug", "test", "dev", "preview", "edit", "action", "cmd", "command",
    "exec", "func", "function", "method", "type", "mode", "format", "view", "template",
    "lang", "locale", "country", "region", "currency", "amount", "price", "qty",
    "status", "state", "flag", "enable", "disable", "show", "hide", "data", "json",
    "xml", "code", "hash", "sig", "signature", "nonce", "timestamp", "date", "year",
]


def _req_simple(url: str, params: Dict[str, str], method: str, headers: Dict[str, str], timeout: int = 8):
    try:
        if method == "POST":
            return requests.post(url, data=params, timeout=timeout, verify=False,
                                 allow_redirects=False, headers=headers)
        return requests.get(url, params=params, timeout=timeout, verify=False,
                           allow_redirects=False, headers=headers)
    except Exception:
        return None


def _run_arjun(url: str, method: str, emit: Any, timeout: int = 180) -> Optional[List[str]]:
    """Drive the real `arjun` binary if it's installed. Returns the discovered
    param names, or None to signal 'arjun unavailable/failed — use the built-in
    fallback'. arjun is the purpose-built tool for this; we only reimplement it
    in pure Python for boxes that don't have it (or strict programs that want
    the gentler built-in)."""
    arjun_bin = get_binary_path("arjun")
    if not arjun_bin:
        return None
    import tempfile
    out_fd, out_path = tempfile.mkstemp(suffix=".json", prefix="hh_arjun_")
    os.close(out_fd)
    cmd = [arjun_bin, "-u", url, "-m", method, "-oJ", out_path, "-q"]
    try:
        _run_cmd_with_heartbeat(cmd, timeout=timeout, emit=emit, label="arjun (hidden-param discovery)")
    except Exception:
        try:
            os.unlink(out_path)
        except Exception:
            pass
        return None
    params: List[str] = []

    def _collect(obj):
        if isinstance(obj, dict):
            if isinstance(obj.get("params"), list):
                params.extend(str(p) for p in obj["params"])
            else:
                for v in obj.values():
                    _collect(v)
        elif isinstance(obj, list):
            for v in obj:
                _collect(v)

    try:
        with open(out_path, "r", encoding="utf-8") as f:
            _collect(json.load(f))
    except Exception:
        return None
    finally:
        try:
            os.unlink(out_path)
        except Exception:
            pass
    return sorted(set(p for p in params if p))


def _execute_param_discover(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Find HIDDEN / unlinked request parameters on an endpoint. Prefers the real
    the IDOR id, SSRF url, file-read path, or debug toggle the server accepts
    but never links, which a crawler can't see. Sends a unique canary across
    BATCHES of candidate params and flags the ones that change the response:
    reflected value, status change, or significant length delta; triggering
    batches are isolated param-by-param to name the exact one.

    Gentle by design: scope-gated, batched (few requests), capped. Great on a
    live endpoint found by recon to expand the testable surface."""
    url = str(args.get("url") or args.get("target") or "").strip()
    if not url:
        return {"error": "param_discover needs a 'url' (a specific endpoint to test)."}
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    rules = getattr(target, "scope_rules", None)
    allowed, reason = is_in_scope(url, rules)
    if not allowed:
        return {"status": "out_of_scope", "note": f"{url} is out of scope — not probing ({reason})."}

    method = str(args.get("method") or "GET").upper()

    # Prefer the real arjun binary — but NOT on a program that forbids
    # automated/rate-limit testing (arjun fires a lot of requests); there we
    # use the gentler, capped built-in. force_builtin=true also skips arjun.
    gentle = bool(set(getattr(rules, "disallowed", []) or []) & _GENTLE_FLAGS)
    if not gentle and not bool(args.get("force_builtin")):
        arjun_params = _run_arjun(url, method, emit)
        if arjun_params is not None:
            try:
                if arjun_params and hasattr(target, "state") and isinstance(target.state, dict):
                    known = target.state.setdefault("parameters", [])
                    for p in arjun_params:
                        if p not in known:
                            known.append(p)
                    save_target(target)
            except Exception:
                pass
            return {
                "status": "success", "url": url, "method": method, "tool": "arjun",
                "found": [{"param": p, "evidence": ["arjun"]} for p in arjun_params],
                "found_count": len(arjun_params),
                "note": (f"arjun found {len(arjun_params)} param(s): {', '.join(arjun_params[:20])}. "
                         "Test these for IDOR/SSRF/LFI/redirect/mass-assignment." if arjun_params else
                         "arjun found no hidden params on this endpoint."),
            }
        # arjun not installed -> fall through to the built-in reflection probe.

    headers = merge_global_context({})
    import secrets as _secrets
    canary = "hhpx" + _secrets.token_hex(4)

    # wordlist = common + anything already discovered + caller extras, deduped.
    extra = args.get("params") or args.get("wordlist") or []
    if isinstance(extra, str):
        extra = re.split(r"[,\s]+", extra)
    state_params = []
    if hasattr(target, "state") and isinstance(target.state, dict):
        sp = target.state.get("parameters") or target.state.get("params") or []
        if isinstance(sp, list):
            state_params = [str(x) for x in sp]
    words = list(dict.fromkeys([w for w in (_COMMON_PARAMS + state_params + list(extra)) if w and str(w).strip()]))
    cap = max(1, min(int(args.get("limit", 160) or 160), 400))
    words = words[:cap]

    base = _req_simple(url, {}, method, headers)
    if base is None:
        return {"error": f"baseline request to {url} failed — endpoint unreachable."}
    base_len = len(base.text or "")
    base_status = base.status_code
    # noise-tolerant length threshold (dynamic tokens/timestamps shift a little)
    len_thresh = max(60, int(base_len * 0.02))

    def _evidence(r):
        if r is None:
            return []
        ev = []
        if canary in (r.text or ""):
            ev.append("reflected")
        if r.status_code != base_status:
            ev.append(f"status {base_status}->{r.status_code}")
        if abs(len(r.text or "") - base_len) > len_thresh:
            ev.append(f"length {base_len}->{len(r.text or '')}")
        return ev

    found = []
    chunk = 25
    isolations = 0
    for i in range(0, len(words), chunk):
        batch = words[i:i + chunk]
        r = _req_simple(url, {w: canary for w in batch}, method, headers)
        if not _evidence(r) or isolations > 8:
            continue
        isolations += 1
        # isolate which param(s) in this batch actually did it
        for w in batch:
            rr = _req_simple(url, {w: canary}, method, headers)
            ev = _evidence(rr)
            if ev:
                found.append({"param": w, "evidence": ev, "status": rr.status_code})
        if emit and hasattr(emit, "info"):
            try:
                emit.info(f"param_discover: {len(found)} candidate param(s) so far")
            except Exception:
                pass

    # persist for later fuzzing/map_surface
    try:
        if found and hasattr(target, "state") and isinstance(target.state, dict):
            known = target.state.setdefault("parameters", [])
            for f in found:
                if f["param"] not in known:
                    known.append(f["param"])
            save_target(target)
    except Exception:
        pass

    return {
        "status": "success",
        "url": url,
        "method": method,
        "tested": len(words),
        "found": found,
        "found_count": len(found),
        "note": (f"{len(found)} hidden param(s) the endpoint reacts to — test these for IDOR/SSRF/LFI/redirect/"
                 "mass-assignment per their names." if found else
                 "No hidden params reacted — the endpoint ignores unknown params, or try method=POST / a bigger limit."),
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


def _execute_waymore(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Deep PASSIVE URL harvest via waymore — pulls from Wayback + Common Crawl
    + OTX + URLScan + VirusTotal in one shot (far more sources than gau or
    wayback_urls alone). Pure OSINT (third-party archives, never the target), so
    safe on strict programs. Needs waymore installed (pipx install waymore).
    Follow with probe_urls to see which of the harvested URLs are still live."""
    domain = str(args.get("domain") or target.name).strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc.split(":")[0]
    if not domain:
        return {"status": "no_domain_given", "note": "waymore needs a domain."}

    waymore_bin = get_binary_path("waymore") or pick_available(["waymore"])
    if not waymore_bin:
        return {"error": "waymore not installed", "hint": install_hint("waymore")}

    out_fd, out_path = tempfile.mkstemp(suffix=".txt", prefix="hh_waymore_")
    os.close(out_fd)
    cmd = [waymore_bin, "-i", domain, "-mode", "U", "-oU", out_path]
    try:
        _run_cmd_with_heartbeat(cmd, timeout=int(args.get("max_runtime", 240) or 240),
                                emit=emit, label="waymore (deep URL harvest)")
    except Exception as e:
        try:
            os.unlink(out_path)
        except Exception:
            pass
        return {"error": f"waymore failed: {e}"}

    urls = []
    try:
        with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
            urls = [ln.strip() for ln in f if ln.strip()]
    except Exception:
        pass
    finally:
        try:
            os.unlink(out_path)
        except Exception:
            pass

    if urls and hasattr(target, "state") and isinstance(target.state, dict):
        existing = target.state.setdefault("wayback_urls", [])
        for u in urls:
            if u not in existing:
                existing.append(u)
        try:
            save_target(target)
        except Exception:
            pass
    return {
        "status": "success", "domain": domain, "url_count": len(urls),
        "urls": urls[:500], "truncated": len(urls) > 500,
        "note": (f"{len(urls)} URL(s) from waymore (wayback+commoncrawl+otx+urlscan+vt). "
                 "Run probe_urls to find which are live, then gf_patterns to triage by bug class."
                 if urls else "waymore returned no URLs for this domain."),
    }


# Built-in param-name sets per vuln class — the gf-pattern fallback when the real
# gf binary / ~/.gf patterns aren't installed.
_GF_BUILTIN = {
    "redirect": {"url", "redirect", "redirect_url", "redir", "return", "return_url", "returnurl",
                 "next", "continue", "dest", "destination", "r", "u", "out", "goto", "to", "target", "link"},
    "ssrf": {"url", "uri", "path", "dest", "host", "site", "target", "feed", "to", "out", "dir",
             "show", "file", "filename", "image_url", "img", "proxy", "callback", "domain", "port",
             "ip", "server", "fetch", "load", "src"},
    "lfi": {"file", "document", "folder", "root", "path", "pg", "style", "pdf", "template",
            "php_path", "doc", "include", "page", "inc", "locate", "show", "type", "view",
            "content", "download", "filename"},
    "sqli": {"id", "select", "report", "role", "update", "query", "user", "name", "sort", "where",
             "search", "params", "process", "row", "view", "table", "from", "sel", "results",
             "fetch", "order", "keyword", "column", "field", "delete", "number", "filter", "cat",
             "category", "pid", "item", "item_id"},
    "ssti": {"template", "preview", "id", "view", "activity", "name", "content", "redirect", "q"},
    "idor": {"id", "user_id", "uid", "account", "account_id", "order", "order_id", "invoice",
             "doc", "file", "number", "no", "key", "profile", "customer", "item_id"},
}


def _gf_patterns_dir() -> Optional[str]:
    """Locate a gf-patterns directory (the JSON files like ssrf.json/lfi.json).
    gf itself only reads ~/.gf and $GF_PATH, so a collection cloned ANYWHERE
    else is invisible to it. Beast is more forgiving: it checks, in order, the
    $GF_PATH env var, a `gf_patterns_dir` set in beast config, the standard
    ~/.gf, and a few common clone spots — so pointing Beast at your patterns is
    one env var or config line, no matter where you cloned them."""
    cands = []
    if os.environ.get("GF_PATH"):
        cands.append(os.environ["GF_PATH"])
    try:
        cfgdir = load_config().get("gf_patterns_dir")
        if cfgdir:
            cands.append(str(cfgdir))
    except Exception:
        pass
    home = Path.home()
    cands += [
        str(home / ".gf"),
        str(home / "Gf-Patterns"),
        str(home / "tools" / "Gf-Patterns"),
        str(home / ".config" / "gf"),
    ]
    for c in cands:
        try:
            p = Path(c).expanduser()
            if p.is_dir() and any(p.glob("*.json")):
                return str(p)
        except Exception:
            continue
    return None


def _load_gf_regexes(pattern_name: str, patterns_dir: str):
    """Load a gf JSON pattern file (e.g. ssrf.json) and compile its regex(es).
    Format: {"flags": "-iE", "patterns": [...]} or {"flags": ..., "pattern": "..."}."""
    f = Path(patterns_dir) / f"{pattern_name}.json"
    if not f.is_file():
        return None
    try:
        data = json.loads(f.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None
    pats = data.get("patterns") or ([data["pattern"]] if data.get("pattern") else [])
    if not pats:
        return None
    reflags = re.IGNORECASE if "i" in str(data.get("flags", "")) else 0
    compiled = []
    for p in pats:
        try:
            compiled.append(re.compile(p, reflags))
        except Exception:
            continue
    return compiled or None


def _execute_gf_patterns(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Triage a big pile of collected URLs into VULN CANDIDATES by class
    (redirect / ssrf / lfi / sqli / ssti / idor / rce / …) — like tomnomnom's gf.
    Loads your gf pattern .json files directly from wherever they live ($GF_PATH,
    beast config `gf_patterns_dir`, ~/.gf, or a common clone dir) so your full
    collection is used; falls back to a built-in param-name matcher if no
    patterns are found. Local processing of already-collected URLs — sends NO
    traffic to the target. Pass urls, or omit to use everything discovered."""
    pattern = str(args.get("pattern") or "all").lower()
    urls = args.get("urls")
    if isinstance(urls, str):
        urls = [urls]
    if not urls:
        st = target.state if isinstance(getattr(target, "state", None), dict) else {}
        pool = []
        for k in ("wayback_urls", "endpoints", "discovered_urls", "urls"):
            v = st.get(k)
            if isinstance(v, list):
                pool.extend(x for x in v if isinstance(x, str))
        urls = pool
    urls = [u for u in (urls or []) if isinstance(u, str) and "?" in u and "=" in u]
    if not urls:
        return {"status": "no_urls",
                "note": "No param-bearing URLs to triage — run wayback_urls/waymore/probe_urls first."}

    patterns_dir = _gf_patterns_dir()
    # For "all": use every pattern file in the dir (your full collection), else
    # the built-in class list.
    if pattern != "all":
        patterns = [pattern]
    elif patterns_dir:
        patterns = sorted({p.stem for p in Path(patterns_dir).glob("*.json")})
    else:
        patterns = list(_GF_BUILTIN.keys())

    results = {}
    used_dir_for = 0
    for pat in patterns:
        matched = []
        compiled = _load_gf_regexes(pat, patterns_dir) if patterns_dir else None
        if compiled:
            used_dir_for += 1
            for u in urls:
                if any(rx.search(u) for rx in compiled):
                    matched.append(u)
        else:  # built-in param-name fallback (pattern file absent)
            names = _GF_BUILTIN.get(pat, set())
            if names:
                for u in urls:
                    q = urlparse(u).query
                    pkeys = {kv.split("=", 1)[0].lower() for kv in q.split("&") if kv}
                    if pkeys & names:
                        matched.append(u)
        if matched:
            results[pat] = sorted(set(matched))[:200]
    total = sum(len(v) for v in results.values())
    source = (f"gf-patterns ({patterns_dir})" if used_dir_for else "built-in")
    return {
        "status": "success",
        "source": source,
        "patterns_dir": patterns_dir,
        "patterns": list(results.keys()),
        "candidates": results,
        "candidate_count": total,
        "note": (f"{total} vuln-candidate URL(s) across {len(results)} class(es) via {source} — test each by its "
                 "class (redirect->open-redirect, ssrf->SSRF, lfi->path-traversal, sqli->injection, idor->access-control)."
                 if total else
                 ("No URLs matched any pattern." if patterns_dir else
                  "No gf patterns found — clone them to ~/.gf or set GF_PATH, or Beast used only its built-in matcher.")),
    }


def _execute_trufflehog_scan(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Scan already-discovered JS files / URLs for LIVE secrets with trufflehog
    (far more detectors + verification than the built-in js_miner). Fetches the
    in-scope content gently (capped, scope-gated) and runs trufflehog over it.
    Needs trufflehog installed."""
    urls = args.get("urls")
    if isinstance(urls, str):
        urls = [urls]
    if not urls:
        st = target.state if isinstance(getattr(target, "state", None), dict) else {}
        urls = [u for u in (st.get("js_routes") or st.get("js_files") or []) if isinstance(u, str)]
        if not urls:
            urls = [u for u in (st.get("endpoints") or []) if isinstance(u, str) and u.endswith(".js")]
    urls = [u for u in (urls or []) if isinstance(u, str) and u.startswith(("http://", "https://"))]
    if not urls:
        return {"status": "no_urls", "note": "No JS/URLs to scan — pass 'urls' or run spider/js_miner first."}

    th_bin = get_binary_path("trufflehog")
    if not th_bin:
        return {"error": "trufflehog not installed", "hint": install_hint("trufflehog")}

    import shutil
    rules = getattr(target, "scope_rules", None)
    headers = merge_global_context({})
    tmpdir = tempfile.mkdtemp(prefix="hh_th_")
    cap = max(1, min(int(args.get("limit", 30) or 30), 100))
    fetched = 0
    try:
        for i, u in enumerate(urls[:cap]):
            ok, _r = is_in_scope(u, rules)
            if not ok:
                continue
            try:
                r = requests.get(u, timeout=8, verify=False, headers=headers)
                if r.status_code == 200 and r.content:
                    with open(os.path.join(tmpdir, f"f{i}.js"), "wb") as f:
                        f.write(r.content[:2_000_000])
                    fetched += 1
            except Exception:
                continue

        findings = []
        if fetched:
            try:
                proc = _run_cmd_with_heartbeat([th_bin, "filesystem", tmpdir, "--json", "--no-update"],
                                               timeout=150, emit=emit, label="trufflehog (secret scan)")
                for line in (proc.stdout or "").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        it = json.loads(line)
                        findings.append({
                            "detector": it.get("DetectorName"),
                            "verified": bool(it.get("Verified")),
                            "raw": (it.get("Raw") or "")[:80],
                        })
                    except Exception:
                        pass
            except Exception:
                pass
    finally:
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass

    verified = [f for f in findings if f.get("verified")]
    return {
        "status": "success", "scanned_files": fetched,
        "findings": findings, "finding_count": len(findings), "verified_count": len(verified),
        "note": (f"trufflehog: {len(verified)} VERIFIED + {len(findings) - len(verified)} unverified secret(s) "
                 f"across {fetched} file(s) — verified ones are live, triage first."
                 if findings else f"trufflehog found no secrets in {fetched} fetched file(s)."),
    }
