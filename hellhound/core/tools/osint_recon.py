"""
hellhound/core/tools/osint_recon.py - passive / OSINT recon tools.

Split slice 5 from agent.py. Five source-agnostic passive-recon tools -
wayback_urls, otx_urls, urlscan_recon, virustotal_lookup, google_dork - that pull
historical/third-party intel about a host and fold any discovered subdomains back
into the target. No agent.py internals: deps are load_config (config), save_target
+ update_from_subfinder (target state), requests, and a lazy googlesearch import
inside google_dork. agent.py re-imports all five executors; TOOL_REGISTRY wiring
is unchanged.
"""
import os
import re
import time
import requests
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional

from hellhound.core.ai_utils import load_config
from hellhound.core.tasks import Target, save_target
from hellhound.core.scope import is_in_scope
from hellhound.memory import update_from_subfinder


# Extensions that make an archived URL worth probing first — config/secret/
# backup/source-ish files are the ones where "still live" actually matters.
_PROBE_PRIORITY_EXT = re.compile(
    r"\.(?:env|git|sql|bak|backup|config|conf|ini|yml|yaml|json|xml|log|"
    r"key|pem|crt|zip|tar|tar\.gz|tgz|gz|7z|rar|db|csv|txt|old|swp|~)(?:$|\?)",
    re.I,
)


def _probe_live_urls(urls: List[str], target: Target, emit: Any,
                     cap: int = 25, delay: float = 0.6) -> Dict[str, Any]:
    """Gently check which archived/passive URLs are STILL live — the step the
    operator flagged as missing ("a lot of urls in wayback but he never checked
    they're still accessible"). This TOUCHES the target, so it is deliberately
    polite: in-scope URLs only (out-of-scope subdomains are skipped via the
    scope gate), interesting files first, a hard cap, a short timeout, and a
    fixed pause between requests so it never looks like a scanner on fragile
    infra. Returns the live hits (status < 400) plus how many were probed."""
    rules = getattr(target, "scope_rules", None)
    # Interesting (sensitive-extension) URLs first, then the rest; dedupe paths.
    ranked = sorted(set(urls), key=lambda u: (0 if _PROBE_PRIORITY_EXT.search(u) else 1, len(u)))
    live: List[Dict[str, Any]] = []
    probed = 0
    skipped_scope = 0
    headers = {"User-Agent": "Mozilla/5.0 (compatible; recon-liveness/1.0)"}
    for u in ranked:
        if probed >= cap:
            break
        allowed, _reason = is_in_scope(u, rules)
        if not allowed:
            skipped_scope += 1
            continue
        try:
            r = requests.get(u, timeout=8, allow_redirects=True, stream=True, headers=headers)
            code = r.status_code
            clen = r.headers.get("Content-Type", "")
            try:
                r.close()
            except Exception:
                pass
        except requests.RequestException:
            code, clen = None, ""
        probed += 1
        if code is not None and code < 400:
            live.append({"url": u, "status": code, "content_type": clen})
        if emit and hasattr(emit, "info") and code is not None:
            try:
                emit.info(f"[{code}] {u}")
            except Exception:
                pass
        time.sleep(delay)
    return {"live_urls": live, "probed_count": probed, "live_count": len(live),
            "skipped_out_of_scope": skipped_scope}


def _execute_wayback_urls(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Pulls archived URLs for a domain from the Wayback Machine's CDX API —
    free, no API key, often turns up old endpoints/params/backup files
    that gau/katana never saw live. Supports subdomain inclusion, a
    sensitive-extension filter, and status-code include/exclude filters.
    """
    domain = str(args.get("domain") or target.name).strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc.split(":")[0]
    if not domain:
        return {
            "status": "no_domain_given",
            "note": "Nah bro, wayback_urls needs a domain — nothing to query the CDX API for. Pass one and call this again.",
        }

    include_subdomains = bool(args.get("include_subdomains", True))
    extensions_only = bool(args.get("extensions_only", False))
    status_codes = str(args.get("status_codes", "")).strip()
    exclude_status_codes = str(args.get("exclude_status_codes", "")).strip()

    ext_regex = (
        r"xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\.gz|tgz|bak|7z|rar|log|"
        r"cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|"
        r"deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc"
    )

    url_pattern = f"*.{domain}/*" if include_subdomains else f"{domain}/*"
    params = {
        "url": url_pattern,
        "collapse": "urlkey",
        "output": "text",
        "fl": "original,statuscode",
    }
    filters = []
    if extensions_only:
        filters.append(f"original:.*\\.({ext_regex})$")
    if status_codes:
        filters.append(f"statuscode:({status_codes.replace(',', '|')})")
    if exclude_status_codes:
        filters.append(f"!statuscode:({exclude_status_codes.replace(',', '|')})")

    try:
        resp = requests.get(
            "https://web.archive.org/cdx/search/cdx",
            params=[*params.items(), *[("filter", f) for f in filters]],
            timeout=30,
        )
    except requests.RequestException as e:
        return {"error": f"Wayback CDX request failed: {e}"}

    if resp.status_code != 200:
        return {"error": f"Wayback CDX returned HTTP {resp.status_code}"}

    urls = []
    seen = set()
    for line in resp.text.splitlines():
        line = line.strip()
        if not line:
            continue
        u = line.split(" ", 1)[0]
        if u and u not in seen:
            seen.add(u)
            urls.append(u)

    if urls:
        existing = target.state.setdefault("wayback_urls", [])
        for u in urls:
            if u not in existing:
                existing.append(u)
        try:
            save_target(target)
        except Exception:
            pass

    result = {
        "domain": domain,
        "url_count": len(urls),
        "urls": urls[:500],
        "truncated": len(urls) > 500,
        "note": (
            f"{len(urls)} archived URL(s) from the Wayback Machine." if urls else
            "No archived URLs found for this domain/filter combination — the CDX index may simply not have this host crawled."
        ),
    }

    # Archived URLs are historical — most are long dead. The find is only
    # actionable once you know which are STILL reachable, so probe the most
    # interesting ones (gently, in-scope only, capped). Default on; set
    # probe_live=False to get the raw list without touching the target.
    if urls and bool(args.get("probe_live", True)):
        cap = int(args.get("probe_limit", 25) or 25)
        cap = max(1, min(cap, 50))  # hard ceiling — stay polite on fragile infra
        if emit and hasattr(emit, "info"):
            try:
                emit.info(f"probing up to {cap} archived URL(s) for liveness (in-scope only)…")
            except Exception:
                pass
        probe = _probe_live_urls(urls, target, emit, cap=cap)
        result.update(probe)
        if probe["live_count"]:
            result["note"] += (f" {probe['live_count']} of {probe['probed_count']} probed are STILL LIVE "
                               f"(status < 400) — these are the ones worth looking at.")
        elif probe["probed_count"]:
            result["note"] += f" Probed {probe['probed_count']}; none still reachable (all archived/dead)."

    return result


def _execute_well_known_probe(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Deterministically fetch and parse the free, zero-impact starting points
    every engagement should read FIRST — robots.txt, sitemap.xml, and
    /.well-known/security.txt — then gently probe the robots Disallow paths for
    liveness.

    This exists because a prompt nudge alone wasn't reliable: on a real run the
    operator saw a sensitive endpoint sitting in robots.txt that Beast never
    mentioned. robots Disallow entries literally point at what the owner wants
    hidden (/admin, /backup/, /.env …), so surfacing + liveness-checking them
    deterministically is high-signal recon. In-scope only, capped, polite."""
    raw = str(args.get("domain") or args.get("url") or target.name).strip()
    if not raw:
        return {"status": "no_domain_given", "note": "well_known_probe needs a domain/url."}
    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    base = f"{parsed.scheme}://{parsed.netloc}"

    rules = getattr(target, "scope_rules", None)
    allowed, reason = is_in_scope(base, rules)
    if not allowed:
        return {"status": "out_of_scope", "note": f"{base} is out of scope — not fetching ({reason})."}

    headers = {"User-Agent": "Mozilla/5.0 (compatible; recon-wellknown/1.0)"}

    def _fetch(path: str) -> Optional[str]:
        try:
            r = requests.get(base + path, timeout=10, allow_redirects=True, headers=headers)
            if r.status_code == 200 and r.text:
                return r.text
        except requests.RequestException:
            return None
        return None

    robots_txt = _fetch("/robots.txt")
    sitemap_xml = _fetch("/sitemap.xml")
    security_txt = _fetch("/.well-known/security.txt")

    disallow_paths: List[str] = []
    allow_paths: List[str] = []
    sitemap_refs: List[str] = []
    if robots_txt:
        for line in robots_txt.splitlines():
            line = line.strip()
            m = re.match(r"(?i)^(dis)?allow\s*:\s*(\S+)", line)
            if m:
                p = m.group(2)
                (disallow_paths if m.group(1) else allow_paths).append(p)
                continue
            sm = re.match(r"(?i)^sitemap\s*:\s*(\S+)", line)
            if sm:
                sitemap_refs.append(sm.group(1))

    sitemap_urls: List[str] = []
    if sitemap_xml:
        sitemap_urls = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", sitemap_xml, re.I)

    security_contacts: List[str] = []
    if security_txt:
        for line in security_txt.splitlines():
            cm = re.match(r"(?i)^contact\s*:\s*(\S+)", line.strip())
            if cm:
                security_contacts.append(cm.group(1))

    # Build full URLs for the robots Disallow paths (globs like /x/* -> /x/)
    # and probe them — these are the owner-flagged "hidden" paths.
    probe_targets: List[str] = []
    seen = set()
    for p in disallow_paths:
        clean = p.split("*", 1)[0]
        if not clean or clean == "/":
            continue
        full = base + ("" if clean.startswith("/") else "/") + clean
        if full not in seen:
            seen.add(full)
            probe_targets.append(full)

    note_bits = []
    if robots_txt:
        note_bits.append(f"robots.txt: {len(disallow_paths)} Disallow")
    if sitemap_urls:
        note_bits.append(f"sitemap.xml: {len(sitemap_urls)} URLs")
    if security_contacts:
        note_bits.append(f"security.txt contact: {security_contacts[0]}")
    if not note_bits:
        note_bits.append("no robots.txt / sitemap.xml / security.txt found")

    result = {
        "status": "success",
        "base": base,
        "robots_found": bool(robots_txt),
        "robots_disallow": disallow_paths[:100],
        "robots_allow": allow_paths[:50],
        "sitemap_urls": sitemap_urls[:200],
        "sitemap_refs": sitemap_refs,
        "security_contacts": security_contacts,
        "note": "; ".join(note_bits),
    }

    if probe_targets and bool(args.get("probe_live", True)):
        cap = max(1, min(int(args.get("probe_limit", 25) or 25), 50))
        if emit and hasattr(emit, "info"):
            try:
                emit.info(f"probing {min(cap, len(probe_targets))} robots.txt Disallow path(s) for liveness…")
            except Exception:
                pass
        probe = _probe_live_urls(probe_targets, target, emit, cap=cap)
        result.update({
            "disallow_probed": probe["probed_count"],
            "disallow_live": probe["live_urls"],
            "disallow_live_count": probe["live_count"],
        })
        if probe["live_count"]:
            result["note"] += (f" — {probe['live_count']} Disallow path(s) are STILL LIVE "
                               f"(owner-hidden but reachable — look here first).")

    # Persist what we learned so later turns/tools can pick it up.
    try:
        if hasattr(target, "state") and isinstance(target.state, dict):
            existing = target.state.setdefault("endpoints", [])
            for h in result.get("disallow_live", []):
                if h["url"] not in existing:
                    existing.append(h["url"])
            save_target(target)
    except Exception:
        pass

    return result


def _execute_otx_urls(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Pulls passive URL intel for a domain from AlienVault OTX's public
    hostname/url_list endpoint — free, no API key. Complements
    wayback_urls/gau with a different crawl source (threat-intel
    sandboxes, sinkholes, OSINT feeds that fed OTX).
    """
    domain = str(args.get("domain") or target.name).strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc.split(":")[0]
    if not domain:
        return {
            "status": "no_domain_given",
            "note": "Nah bro, otx_urls needs a domain — nothing to look up in OTX. Pass one and call this again.",
        }

    page = 1
    limit = 500
    max_pages = int(args.get("max_pages", 10))
    urls: List[str] = []
    seen = set()

    try:
        while page <= max_pages:
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list",
                params={"limit": limit, "page": page},
                timeout=20,
            )
            if resp.status_code != 200:
                break
            data = resp.json() if resp.content else {}
            entries = data.get("url_list") or []
            if not entries:
                break
            for e in entries:
                u = e.get("url")
                if u and u not in seen:
                    seen.add(u)
                    urls.append(u)
            if len(entries) < limit:
                break
            page += 1
    except requests.RequestException as e:
        return {"error": f"AlienVault OTX request failed: {e}"}
    except ValueError:
        return {"error": "AlienVault OTX returned a non-JSON response"}

    if urls:
        existing = target.state.setdefault("otx_urls", [])
        for u in urls:
            if u not in existing:
                existing.append(u)
        try:
            save_target(target)
        except Exception:
            pass

    return {
        "domain": domain,
        "pages_fetched": page,
        "url_count": len(urls),
        "urls": urls[:500],
        "truncated": len(urls) > 500,
        "note": (
            f"{len(urls)} URL(s) from AlienVault OTX passive intel." if urls else
            "No URLs on record in OTX for this domain — that's normal for a host with no threat-intel footprint, not a failure."
        ),
    }


def _execute_urlscan_recon(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Queries urlscan.io's search API for pages it has crawled under this
    domain, pulling out either discovered subdomains or discovered URLs.
    Needs an urlscan.io API key — set with `/apikey urlscan <key>` or the
    URLSCAN_API_KEY env var. The older `/model set-key urlscan <key>`
    still works too (same value, read as a fallback below).
    """
    cfg = load_config()
    tool_keys = cfg.get("tool_api_keys", {}) if isinstance(cfg.get("tool_api_keys"), dict) else {}
    api_keys = cfg.get("api_keys", {}) if isinstance(cfg.get("api_keys"), dict) else {}
    api_key = tool_keys.get("urlscan") or api_keys.get("urlscan") or os.environ.get("URLSCAN_API_KEY", "")
    if not api_key:
        return {
            "status": "no_api_key",
            "note": "Nah bro, urlscan_recon needs an urlscan.io API key — none is configured. Set one first: /apikey urlscan <your_api_key> (free key: https://urlscan.io/user/signup), then retry.",
        }

    domain = str(args.get("domain") or target.name).strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc.split(":")[0]
    if not domain:
        return {
            "status": "no_domain_given",
            "note": "Nah bro, urlscan_recon needs a domain — nothing to search for. Pass one and call this again.",
        }

    mode = str(args.get("mode", "subdomains")).strip().lower()
    if mode not in ("subdomains", "urls"):
        return {
            "status": "unknown_mode",
            "note": f"Nah bro, '{mode}' isn't valid for urlscan_recon — use 'subdomains' or 'urls'.",
        }

    try:
        resp = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"page.domain:{domain}", "size": 100},
            headers={"API-Key": api_key},
            timeout=15,
        )
    except requests.RequestException as e:
        return {"error": f"urlscan.io request failed: {e}"}

    if resp.status_code == 401:
        return {"status": "bad_api_key", "note": "Nah bro, urlscan.io rejected that API key (401) — check it with /apikey urlscan <key> and retry."}
    if resp.status_code != 200:
        return {"error": f"urlscan.io returned HTTP {resp.status_code}"}

    text = resp.text
    results: List[str]
    if mode == "subdomains":
        matched = re.findall(rf"https?://((?:[a-zA-Z0-9_-]+\.)+{re.escape(domain)})", text)
        stripped = [re.sub(r"^https?://", "", u) for u in matched]
        results = sorted({u.split("/")[0] for u in stripped if u.split("/")[0] != domain})
    else:
        matched = re.findall(rf"https?://(?:[a-zA-Z0-9_-]+\.)+{re.escape(domain)}/[^\s\"'>]+", text)
        results = sorted(set(matched))

    if results and mode == "subdomains":
        try:
            update_from_subfinder(target, results)
            save_target(target)
        except Exception:
            existing = target.state.setdefault("subdomains", [])
            for s in results:
                if s not in existing:
                    existing.append(s)

    return {
        "domain": domain,
        "mode": mode,
        "count": len(results),
        "results": results,
        "note": f"{len(results)} {mode} found via urlscan.io's search index." if results else "urlscan.io has no crawled pages under this domain yet.",
    }


def _execute_virustotal_lookup(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Looks up an IP or domain in VirusTotal's public v2 API: resolved
    hostnames (for an IP) and previously-seen-but-undetected URLs — useful
    for finding sibling hosts/forgotten subdomains sitting on shared
    infrastructure. Needs a VirusTotal API key — set with
    `/apikey virustotal <key>` (comma-separate multiple keys there to
    rotate across the free-tier rate limit) or VT_API_KEY env var. The
    older `/model set-key virustotal <key>` still works too (same value,
    read as a fallback below) — /apikey is just the one place to look now.
    """
    cfg = load_config()
    tool_keys = cfg.get("tool_api_keys", {}) if isinstance(cfg.get("tool_api_keys"), dict) else {}
    api_keys = cfg.get("api_keys", {}) if isinstance(cfg.get("api_keys"), dict) else {}
    raw_keys = tool_keys.get("virustotal") or api_keys.get("virustotal") or os.environ.get("VT_API_KEY", "")
    keys = [k.strip() for k in str(raw_keys).split(",") if k.strip()]
    if not keys:
        return {
            "status": "no_api_key",
            "note": "Nah bro, virustotal_lookup needs a VirusTotal API key — none is configured. Set one first: /apikey virustotal <your_api_key> (free key: https://www.virustotal.com/gui/my-apikey), then retry.",
        }

    raw_input = str(args.get("input") or args.get("domain") or args.get("ip") or target.name).strip()
    raw_input = re.sub(r"^https?://", "", raw_input).split("/")[0]
    if not raw_input:
        return {
            "status": "no_input_given",
            "note": "Nah bro, virustotal_lookup needs an IP or domain to look up. Pass one and call this again.",
        }

    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", raw_input))
    endpoint = "ip-address/report" if is_ip else "domain/report"
    param_name = "ip" if is_ip else "domain"
    api_key = keys[0]

    try:
        resp = requests.get(
            f"https://www.virustotal.com/vtapi/v2/{endpoint}",
            params={"apikey": api_key, param_name: raw_input},
            timeout=20,
        )
    except requests.RequestException as e:
        return {"error": f"VirusTotal request failed: {e}"}

    if resp.status_code == 403:
        return {"status": "bad_api_key", "note": "Nah bro, VirusTotal rejected that API key (403) — check it with /apikey virustotal <key> and retry."}
    if resp.status_code == 204:
        return {"status": "rate_limited", "note": "VirusTotal rate-limited this key (204) — the public API is 4 req/min. Wait a bit or add more keys (comma-separated) to /apikey virustotal."}
    if resp.status_code != 200:
        return {"error": f"VirusTotal returned HTTP {resp.status_code}"}

    try:
        data = resp.json()
    except ValueError:
        return {"error": "VirusTotal returned a non-JSON response"}

    hostnames = []
    if is_ip:
        for r in data.get("resolutions", []) or []:
            h = r.get("hostname")
            if h:
                hostnames.append(h)

    undetected_urls = []
    for entry in data.get("undetected_urls", []) or []:
        if isinstance(entry, list) and entry:
            undetected_urls.append(entry[0])

    if hostnames:
        try:
            update_from_subfinder(target, hostnames)
            save_target(target)
        except Exception:
            pass

    return {
        "input": raw_input,
        "is_ip": is_ip,
        "resolved_hostnames": sorted(set(hostnames)),
        "undetected_url_count": len(undetected_urls),
        "undetected_urls": undetected_urls[:200],
        "note": (
            "These are URLs VirusTotal scanned and did NOT flag as malicious — they're just historical sightings, not findings. "
            "Hostnames resolved for this IP can reveal sibling hosts worth adding to subfinder/httpx sweeps."
        ),
    }


def _execute_google_dork(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Runs a Google dork query and returns result URLs. Defaults to scoping
    the query to the active target with `site:<domain>` unless the
    researcher passed a fully custom query. Non-interactive port of the
    researcher's dorking.py (which was written for a human typing into a
    terminal prompt — this takes the same inputs as tool args instead).
    """
    try:
        from googlesearch import search  # type: ignore
    except ImportError:
        return {
            "status": "missing_dependency",
            "note": "Nah bro, google_dork needs the googlesearch-python package and it's not installed. Run: pip install googlesearch-python, then retry.",
        }

    domain = str(args.get("domain") or target.name).strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc.split(":")[0]
    query = str(args.get("query", "")).strip()
    custom_query = str(args.get("custom_query", "")).strip()
    num_results = int(args.get("num_results", 20))
    num_results = max(1, min(num_results, 100))

    if custom_query:
        dork = custom_query
    elif domain:
        dork = f"site:{domain} {query}".strip()
    elif query:
        dork = query
    else:
        return {
            "status": "no_query_given",
            "note": "Nah bro, google_dork needs either a domain (to scope a site: search) or a custom_query. Pass one and call this again.",
        }

    results = []
    try:
        for r in search(dork, num_results=num_results):
            results.append(r)
            if len(results) >= num_results:
                break
    except Exception as e:
        return {"error": f"Google dork search failed: {e}", "dork": dork}

    return {
        "dork": dork,
        "result_count": len(results),
        "results": results,
        "note": (
            f"{len(results)} result(s) for this dork." if results else
            "No results — Google may be rate-limiting unauthenticated searches from this IP if you've run several of these in a row; space them out."
        ),
    }
