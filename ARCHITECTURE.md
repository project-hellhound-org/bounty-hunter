# Hellhound Framework — Technical Architecture

Hellhound is an autonomous, AI-driven bug bounty reconnaissance, vulnerability discovery, and exploit orchestration framework built for security researchers and penetration testers.

---

## 1. High-Performance Two-Tier Neural Core

Hellhound decouples real-time tool selection from deep vulnerability synthesis to maximize speed and reasoning depth while eliminating LLM latency bottlenecks:

```
Researcher Prompt / Objective
              │
              ▼
┌────────────────────────────────────────────────────────┐
│            ORCHESTRATOR TIER (Fast SLM)                │
│  - Ultra-low latency tool selection loop               │
│  - Pinned Harvested Artifact Blackboard                │
│  - Pre-flight Recon Gating & Mechanical Field Matching │
│  - Low-noise surgical probing doctrine (`curl` first)  │
└────────────────────────────────────────────────────────┘
              │                           ▲
      Executes Tool via                   │ Feeds Result &
   HellhoundEngine Broker                 │ Stores Artifacts
              │                           │
              ▼                           │
┌────────────────────────────────────────────────────────┐
│         TOOL EXECUTION & OFFENSIVE ARSENAL             │
│  - Surgical HTTP (`curl`), Headless SPA (`spider`)     │
│  - Binary Arsenal (Subfinder, DNSX, Naabu, HTTPX)      │
│  - Visual Evidence Capture (`gowitness`)               │
│  - Dynamic Skill Engine (26 Specialized Methodologies) │
└────────────────────────────────────────────────────────┘
              │
              │ Objective Met / Loop Finished ("DONE")
              ▼
┌────────────────────────────────────────────────────────┐
│            SYNTHESIZER TIER (Deep LLM)                 │
│  - High-parameter reasoning model (NVIDIA, Claude,     │
│    Gemini, OpenAI, or local Mistral/Qwen)              │
│  - Attack-chain narrative & PoC generation             │
│  - Evidence verification & false-positive elimination  │
│  - Submission-ready HackerOne / Bugcrowd Markdown      │
└────────────────────────────────────────────────────────┘
```

1. **Orchestrator Tier (Fast Tool Selection Engine)**: Operates with deterministic tool-call generation, evaluating live target responses in milliseconds without token-heavy chain-of-thought overhead. Recommended: NVIDIA NIM (`nvidia/nemotron-3-super-120b-a12b` or `meta/llama-3.3-70b-instruct`) for free users, Claude 3.5 Sonnet / Gemini 2.0 Flash for commercial users, or high-parameter local models (32B+).
2. **Synthesizer Tier (Deep Reasoning LLM)**: Ingests the full tool telemetry, harvested artifacts, and screenshot evidence to produce comprehensive vulnerability assessments, root-cause analyses, and reproduction steps. Recommended: Frontier-class models (NVIDIA Nemotron 120B, Claude 3.5 Sonnet, Gemini 2.0 Pro/Flash, GPT-4o).

---

## 2. Deterministic Artifact Ledger & Blackboard Memory

To prevent *"lost-in-the-middle"* reasoning failures during deep multi-turn exploitation chains, Hellhound incorporates a non-prunable **Harvested Artifact Ledger**:

* **Automated Extraction Hook**: Instrumenting every tool output (`curl`, `spider`, `gowitness`, etc.), `extract_and_store_artifacts()` parses and extracts:
  - Tokens (`auth_token`, `jwt`, `access_token`, `session_token`, `delegation_key`)
  - Cookies (`session`, `sid`, `auth`, `PHPSESSID`)
  - Credentials & Secrets (`mfa_secret`, `api_key`, `password`, `hash`)
  - Delegation & Impersonation endpoints (`/login/impersonate?token=...`, `/auth/claim`)
* **Identity Context Binding**: Harvested values are mechanically tied to their originating identity (e.g., `Dr. Evelyn Harlan / Chief of Medicine / user_id=1`), source URL, and discovery turn.
* **Pinned Prompt Blackboard**: `format_artifact_inventory()` injects a structured, high-visibility ledger at the top of the system prompt on every single turn. This guarantees persistent retention regardless of conversation depth.

---

## 3. Mechanical Cross-Referencing & Pre-Flight Gating

Hellhound enforces deterministic rules to prevent reactive tool-use bias and guesswork:

* **Mechanical Field-Name Matching**: When an endpoint accepts a parameter matching `token|key|secret|auth|session|sid|delegation`, the orchestrator cross-checks the artifact ledger across plausible field variations (`auth_token`, `access_token`, `cmo_secret`), eliminating semantic naming mismatches.
* **Pre-Flight Recon Gating**: When a delegation or authentication handler is discovered, new recon/spidering/fuzzing is strictly gated until existing harvested credentials in the ledger have been tested.
* **Identity Elevation Verification**: Stepping-stone access (e.g., standard user, support account) is treated strictly as an intermediate state. The agent refuses to output `DONE` or claim takeover until the primary requested target account/role is verified via authenticated endpoints (`/profile`, `/admin`, session validation).

---

## 4. Dynamic Methodology Skills Engine

Hellhound houses **27 specialized offensive methodology skills** loaded dynamically into the agent reasoning context:

```
hellhound/skills/
├── access-control/                     # IDOR, Broken Object-Level Auth, Horizontal/Vertical PrivEsc
├── auth-bypass/                        # Token Leaks, Impersonation Chaining, Session Hijacking
├── authentication/                     # OAuth, JWT, 2FA/MFA, Password Recovery, Session Auditing
├── bb-methodology/                     # 5-Phase Bug Bounty Workflow & Session Discipline
├── bug-bounty/                         # Master Playbook & Bounty Lifecycle Orchestration
├── ctf-lab-recon/                      # Active Range Recon, Flag Mining, Stepping-Stone Tactics
├── web2-recon/                         # Subdomain Discovery, Port Mapping, Tech Fingerprinting
├── web2-vuln-classes/                  # Core Web Flaws (IDOR, SSRF, SQLi, XSS, SSTI, CSRF)
├── security-arsenal/                   # Curated Payloads, Filter Bypasses, WAF Evasion
├── server-side-parameter-pollution/    # SSPP Query/Path Injection, Internal API Pollution, Truncation
├── triage-validation/                  # PoC Verification & Strict False-Positive Filtering
├── report-writing/                     # Submission Templates (HackerOne, Bugcrowd, Intigriti)
├── graphql-audit/                      # Introspection, Batching, Field Suggestion Mining
├── web3-audit/                         # EVM/Solidity Vulnerabilities, Reentrancy, Flash Loans
├── meme-coin-audit/                    # Liquidity Pool Manipulation, Honeypots, Bonding Curves
├── mobile-pentest/                     # Android/iOS Static Analysis, Deep Links, Pinning Bypass
├── cicd-security/                      # GitHub Actions/GitLab CI Exploitation, Secret Leakage
├── credential-attack/                  # Password Spraying, Username Enumeration, Credential Auditing
├── client-reverse/                     # Frontend JS Reverse Engineering, Anti-Bot De-obfuscation
├── exposed-source-recon/               # Git Dumps, .env Leaks, Source Maps, Hardcoded Secrets
├── insecure-deserialization/           # Python Pickle, PHP Serialization, Java Gadget Chains
├── llm-prompt-injection/               # Indirect Prompt Injection, System Prompt Extraction
├── prototype-pollution-mass-assignment/# JS Prototype Pollution, Object Merge, Mass Assignment
├── race-condition/                     # Limit-Overrun, Balance Exhaustion, TOCTOU Flaws
├── ssrf/                               # Server-Side Request Forgery, Cloud Metadata Pivot
├── ssti/                               # Template Injection (Jinja2, Twig, Freemarker, Mako)
└── argus/                              # Threat Intelligence Correlation & Entity Graphing
```

Skills are injected on-demand into the orchestrator context via `load_skill(name)`, ensuring relevant vulnerability checklists and payload patterns are available without bloating token windows.

---

## 5. Unified Execution Engine & Scope Security Gate

All offensive actions run through `HellhoundEngine.run_single` with strict execution guardrails:

* **Unconditional Scope Gate (`hellhound/core/scope.py`)**: Evaluates domain names, CIDR ranges, wildcards, and URL paths before network packets leave the system. Out-of-scope targets are unconditionally rejected.
* **Risk Classification & Safety Guardrails**: Maps module actions against testing constraints (`no-dos`, `no-brute-force`, `no-fuzzing`, `no-active-exploitation`).
* **Missing Tool Grace**: Automatically prompts and installs missing binary dependencies on-demand without interrupting the active investigation workflow.

---

## 6. Tool Registry & Model Dispatch Matrix

| Tool Name | Engine / Binary | Category | Description |
|---|---|---|---|
| `curl` | Native HTTP Client | Surgical Probing | Low-noise HTTP probing with automatic cookie reuse, header normalization, and route extraction. |
| `spider` | Headless Playwright | Active SPA Crawling | Deep DOM rendering, background Fetch/XHR interception, parameter extraction, and secret mining. |
| `gowitness` | Gowitness Binary | Visual Recon | Headless browser screenshot capture and visual proof indexing into target workspaces. |
| `httpx` | ProjectDiscovery HTTPX | Service Probing | HTTP status verification, title scraping, redirect tracking, and technology stack fingerprinting. |
| `subfinder` | ProjectDiscovery Subfinder | Passive Recon | Passive subdomain harvesting from certificate transparency logs and OSINT sources. |
| `dns_bruteforce` | Shuffledns + MassDNS | Active DNS | High-throughput DNS brute-forcing with wildcard resolution filtering. |
| `vhost_fuzz` | FFUF | Active Recon | Host header fuzzing to identify unindexed virtual hosts on shared IP addresses. |
| `port_scan` | ProjectDiscovery Naabu | Port Scanning | High-performance SYN/Connect port scanning across standard and custom port ranges. |
| `permute_subdomains` | ProjectDiscovery AlterX | Recon Mutation | Rule-based and permutation subdomain candidate generation. |
| `resolve_candidates` | ProjectDiscovery DNSX | Bulk DNS | Multi-threaded DNS resolution for A, AAAA, CNAME, and PTR records. |
| `tls_cert_scan` | ProjectDiscovery TLSX | TLS Inspection | TLS/SSL certificate parsing and Subject Alternative Names (SAN) extraction. |
| `content_discovery` | FFUF + SecLists | Path Discovery | Wordlist-driven endpoint and directory fuzzing. |
| `fuzz_hunter` | Native FUZZhunter | Smart Fuzzing | Recursive path discovery with dynamic 404 response similarity calibration. |
| `subzy` / `takeover` | Subzy Engine | Subdomain Takeover | Orphaned DNS record and dangling cloud service takeover verification. |
| `wafbuster` | Native WAF Engine | Surface Analysis | WAF/CDN signature profiling (Cloudflare, AWS WAF, Akamai) and bypass heuristics. |
| `surface_auditor` | Native Auditor | Surface Analysis | API route discovery, OpenAPI/Swagger parsing, and sensitive file detection. |
| `cors_checker` | Native CORS Engine | Logic Audit | Origin reflection and credentials-leakage verification. |
| `graphql_probe` | Native GraphQL Engine | API Security | GraphQL endpoint discovery and introspection schema extraction. |
| `hydra` | Native BAC Engine | Logic Flaws | Multi-role differential probing for Broken Access Control and privilege anomalies. |
| `cloudscout` | Native CloudScout | Cloud Assets | Discovers and verifies public AWS S3, Azure Blob, GCP, and Firebase buckets. |
| `transport_auditor` | Native SSL Engine | Transport Audit | TLS cipher suite auditing, HSTS validation, and cookie security flag verification. |
| `hackerone_*` | HackerOne MCP / Intel | Threat Intel | Hacktivity search, policy scope analysis, and disclosed bounty intelligence. |
| `run_terminal_command` | Bash / Host CLI | Custom Execution | Scoped custom command execution for specialized security tools. |

---

## 7. Dual Interface Architecture

Hellhound provides parity across terminal and graphical interfaces:

* **Interactive Terminal UI (`hellhound/core/chat_ui.py`)**: Full-featured CLI environment with real-time token streaming, rich Markdown formatting, command autocomplete, and live progress drawers.
* **Modern Desktop GUI (`hellhound/gui_app.py` & React/Electron Frontend)**: WebSocket-driven interface (`gui_server.py`) featuring interactive topology graphs (`InvestigationGraph`), live findings management (`EvidenceCard`), visual screenshot galleries, and target switching.

---

## 8. Target Persistence & Workspace Management

All hunt intelligence is isolated and persistently serialized under `~/.hellhound/targets/<target_name>/`:

* `task.json`: Complete target state including discovered endpoints, parameter matrices, credentials, session cookies, and the Harvested Artifact Ledger.
* `screenshots/`: Visual proof captured via Gowitness.
* `history`: Multi-turn LLM reasoning context for seamless session resumption.
* `findings`: Structured, validated vulnerability disclosures with reproduction commands and evidence.
