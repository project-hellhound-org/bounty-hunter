---
name: ctf-lab-recon
description: Use when targeting CTF challenges, lab environments, training ranges, HackTheBox (HTB), TryHackMe (THM), VulnHub, CTFio, isolated/private targets, or non-indexed domains that are not a live bounty program. Guides active reconnaissance, DNS brute forcing, vhost fuzzing, bypassing passive recon stalls, and automatic single-target scoping.
---

# CTF & Lab Reconnaissance: Active Enumeration Doctrine

Dedicated methodology and operational doctrine for Capture The Flag (CTF) competitions, training ranges, lab environments (HackTheBox, TryHackMe, VulnHub, CTFio, PortSwigger Web Security Academy), and isolated private targets.

Unlike public bug bounty programs where targets are indexed globally and subject to complex organizational scope boundaries, lab environments operate under fundamentally different technical and operational realities.

---

## 0. OBJECTIVE MATCH — READ THIS BEFORE ANY OTHER SECTION

The user's stated task always outranks this doctrine's default workflow. Before running anything, classify the task:

- **"Bypass auth", "reach the console/admin/dashboard", "log in", "take over an account"** → this is an **auth-bypass / credential-discovery** task. The path is: read the page(s) already fetched → check for leaked creds (HTML comments, JS, exposed config/backup files, IDOR on session/role) → attempt login/bypass directly. Do **not** run `dns_bruteforce`, `vhost_fuzz`, or port scanning for this task type unless the app itself is unreachable — a hidden subdomain is not what "auth bypass" means, and running that workflow anyway wastes the whole run on the wrong problem.
- **"Find the app", "there's a hidden service", "enumerate the attack surface"** → this is a **discovery** task. Phases 1–4 below apply.

If the task type is auth-bypass/credential-discovery, skip straight to Phase 0 in Section 2 and stop there once you have a working login — do not continue into Phase 1.

---

## 1. THE PASSIVE RECON FAILURE MODE

### Why Passive Recon Guarantees Zero Results in Labs

Public bug bounty recon relies on passive aggregation:
- Certificate Transparency (CT) logs (`crt.sh`, Censys)
- Passive DNS databases (VirusTotal, SecurityTrails, AlienVault)
- Web archives (Wayback Machine, Common Crawl)

**In a CTF or private lab environment:**
1. **Zero Indexing**: Lab domains (e.g., `*.ctfio.com`, `*.htb`, `*.thm`, `*.local`, `10.10.x.x`) are ephemeral or private. They are never recorded in public CT logs or search engines.
2. **Structural Stalls**: Running passive tools like `subfinder` or querying `crt.sh` is guaranteed to return nothing while incurring network latency and timeouts.
3. **The Rule**: When dealing with a CTF, lab, or isolated private target, **NEVER** rely on passive enumeration. Bypass passive tools immediately and proceed directly to active discovery.

---

## 2. ACTIVE ENUMERATION WORKFLOW

### Phase 0: Read What You Already Fetched (do this FIRST, always)

Before escalating to DNS brute force or vhost fuzzing, fully analyze every response you already have in hand:
- Read the **entire** `body_preview`/HTML of every page already curled or spidered — not just status code and title.
- Check HTML comments (`<!-- -->`), inline `<script>` blocks, and linked `.js`/`.css` files for leaked credentials, internal paths, API keys, or staging hostnames.
- Check for backup/source-leak files adjacent to known paths (`.bak`, `~`, `.git`, `.env`, `.old`, `_old`, source maps).
- If the objective describes a **single application** (e.g. "sign in to reach the console", "no account needed, recon the public site") rather than "find the hidden host/subdomain", treat this as a content-discovery / credential-leak problem, NOT a subdomain-enumeration problem. Do not jump to `dns_bruteforce` or `vhost_fuzz` simply because the domain is a challenge or lab platform — those phases are for when the objective or evidence actually points to a hidden host or multi-tenant vhost, not by default.
- If a recon tool (spider, content discovery) crashes or errors, do not treat that as "0 endpoints found" — treat it as inconclusive, note the error, and fall back to reading the raw responses you already have before concluding there's no attack surface.
- Only proceed to Phase 1 (DNS brute force) if Phase 0 genuinely surfaces nothing exploitable AND the objective implies a hidden host exists.

CTF and lab reconnaissance then proceeds through four tightly coupled active phases:

```
+--------------------------------------------------------------------+
| 1. DNS BRUTEFORCE  -->  2. HTTP PROBING  -->  3. VHOST FUZZING     |
| (dns_bruteforce)        (httpx / ports)       (vhost_fuzz on IP)   |
|                                                       |            |
|                                                       v            |
|                                               4. CONTENT MAPPING   |
|                                               (routes, endpoints)  |
+--------------------------------------------------------------------+
```

### Phase 1: Active DNS Brute-Forcing (`dns_bruteforce`)
- Query DNS servers directly using high-frequency active wordlists.
- Resolves common challenge naming patterns: `api`, `admin`, `dev`, `staging`, `portal`, `auth`, `internal`, `vpn`, `db`, `mail`, `app`, `beta`, `test`, `gateway`, `ws`.
- Identifies CNAME records or direct A records pointing to challenge instances.

### Phase 2: HTTP Probing & Service Fingerprinting (`httpx`)
- Probe resolved hosts and IPs across standard and alternate web ports (`80`, `443`, `8000`, `8080`, `8443`, `8888`, `3000`, `5000`).
- Extract title, response status codes, web servers (Nginx, Apache, Werkzeug, Node.js), and technology headers.
- Identify redirect chains (e.g., HTTP -> HTTPS or hostname redirects).

### Phase 3: Virtual Host Fuzzing (`vhost_fuzz`)
- **CTF Architecture Reality**: In CTF platforms and lab networks, multiple challenge services frequently run as virtual hosts (`Host` header routing) on a **single shared IP address**, often without distinct public DNS records.
- When an IP address or web endpoint is identified, always fuzz the `Host` header (`vhost_fuzz`) using wordlists against the target domain (e.g., `Host: admin.target.ctfio.com`, `Host: dev.target.ctfio.com`).
- Differentiate responses using content-length, status-code, and word-count deltas against the baseline default vhost.

### Phase 4: Web Application Content & Parameter Mapping
- Fuzz hidden routes, static directories, and API endpoints using `ffuf` / active spidering.
- Check common CTF artifacts: `robots.txt`, `.git/`, `.env`, `docker-compose.yml`, backup files (`.bak`, `~`), `/debug`, `/console`, Swagger/OpenAPI docs.

---

## 3. TRIVIAL SCOPE DOCTRINE FOR LAB TARGETS

### No Legal/Business Scoping Overhead

In enterprise bug bounty engagements:
- Scoping is a legal contract requiring out-of-scope domain exclusions, third-party boundary checks, rate-limit agreements, and strict non-destructive constraints.

In CTF & Lab Targets:
- **Scope is Trivial**: The target is solely the challenge host, domain, or IP range specified by the participant (e.g., `topaz.ctfio.com`).
- **No Manual Configuration Required**: HELLHOUND auto-scopes to the target domain (`*.target` and `target`) immediately upon detecting CTF/lab intent.
- **Goal-Driven**: Focus 100% of execution time on identifying exploitable vectors, uncovering hidden vhosts/endpoints, and obtaining flags or proof-of-concept verification.

---

## 4. COMMAND & TOOL ROUTING MATRIX

| Context / Intent | Primary Tool | Secondary / Follow-up | Action Logic |
|---|---|---|---|
| CTF Subdomain Enumeration | `dns_bruteforce` | `httpx` | Skip passive subfinder; brute-force active DNS directly |
| IP Known / DNS Empty | `vhost_fuzz` | `httpx` | Fuzz Host headers against target IP to find multi-tenant challenges |
| Live Service Probing | `httpx` | `dig` / port scan | Probe HTTP/HTTPS services, status codes, tech stack |
| Web Route Discovery | Content fuzzing | Endpoint spidering | Map APIs, debug endpoints, and challenge source leaks |
| Challenge Triage | Vulnerability probing | PoC verification | Test identified vectors (SQLi, IDOR, Command Injection, Auth Bypass) |

---

## 5. SUMMARY CHECKLIST FOR LAB SESSIONS

- [ ] Recognize lab/CTF context (HTB, THM, VulnHub, CTFio, private target).
- [ ] Phase 0: fully read every response already fetched (comments, JS, backup files) before escalating.
- [ ] Confirm the objective actually implies a hidden host before doing subdomain/vhost work.
- [ ] Confirm auto-scoping applied (`*.target`, `target`).
- [ ] Skip passive aggregators; execute `dns_bruteforce` — only if Phase 0 found nothing and a hidden host is implied.
- [ ] Probe all discovered names with `httpx`.
- [ ] Execute `vhost_fuzz` against target IP to catch unindexed challenge hosts.
- [ ] Map high-value endpoints and proceed to challenge exploitation.
