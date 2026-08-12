# Hellhound Framework — Technical Architecture

Hellhound is an AI-driven, chat-centric bug bounty and attack surface discovery framework designed for security researchers and penetration testers.

---

## 1. Unified Interface Architecture

Hellhound is built around a single, unified execution surface:

*   **Chat Terminal UI (`hellhound/core/chat_ui.py`)**: The primary interactive surface providing real-time AI reasoning, multi-turn context, live tool execution feedback, and slash commands.
*   **Desktop App (`hellhound/gui_app.py`)**: A modern desktop interface powered by PyWebView that interacts directly with the same underlying engine, target persistence, and tool registry.
*   **Decoupled Rendering & Engine (`hellhound/core/engine.py`)**: `HellhoundEngine.run_single` acts as the single execution broker for all modules, handling asynchronous event loops (`nest_asyncio`) and routing real-time telemetry via structured `emit` callbacks.

---

## 2. Tool Registry & Model Dispatch System

All capabilities are exposed to the AI reasoning loop through the structured `TOOL_REGISTRY` in `hellhound/core/agent.py`.

### Tool Specification Standard (`ToolSpec`)
Each tool is defined with:
- **`name`**: Tool identifier matching engine module handlers or CLI wrappers.
- **`description`**: Semantic description guiding the model on when and how to invoke the tool.
- **`parameters`**: Strict JSON Schema defining input constraints, data types, and required fields.
- **`executor`**: Wrapper function executing the underlying module via `HellhoundEngine.run_single` and returning normalized dictionaries.

### Tool Registry Matrix
| Tool Name | Module / Backend | Category | Description |
|---|---|---|---|
| `spider` | `hellhound.modules.recon.spider` | Active Recon | Deep DOM crawling, form discovery, parameter harvesting, secret detection, and tech profiling. |
| `httpx` | `projectdiscovery/httpx` | Active Recon | Service probing, HTTP status codes, title scraping, and technology stack fingerprinting. |
| `subfinder` | `projectdiscovery/subfinder` | Passive Recon | Passive subdomain enumeration via certificate transparency logs and public archives. |
| `dns_bruteforce` | `projectdiscovery/shuffledns` | Active Recon | MassDNS-backed active DNS brute-forcing for non-public or lab targets. |
| `vhost_fuzz` | `ffuf/ffuf` | Active Recon | Host header fuzzing to find unindexed virtual hosts on shared IPs. |
| `port_scan` | `projectdiscovery/naabu` | Active Recon | Fast SYN/Connect port scanning for open TCP/UDP services. |
| `permute_subdomains` | `projectdiscovery/alterx` | Recon Mutation | Rule-based and permutation subdomain candidate generation. |
| `resolve_candidates` | `projectdiscovery/dnsx` | Active Recon | High-throughput DNS resolver and wildcard filtering. |
| `tls_cert_scan` | `projectdiscovery/tlsx` | Recon / Intel | TLS certificate inspection and Subject Alternative Names (SAN) extraction. |
| `content_discovery` | `ffuf/ffuf` | Active Recon | High-speed directory and file path fuzzing. |
| `subzy` / `takeover_scanner` | `hellhound.modules.recon` | Takeover | Dangling DNS record and cloud service takeover detection. |
| `hackerone_*` | `hellhound.modules.intel` | Threat Intel | Hacktivity search, policy scope analysis, and bounty statistics. |
| `wafbuster` | `hellhound.modules.recon.WAFbuster` | Surface Analysis | WAF/CDN signature identification and bypass heuristic checks. |
| `surface_auditor` | `hellhound.modules.recon.SurfaceAuditor` | Surface Analysis | API route detection, OpenAPI/Swagger discovery, and sensitive file checks. |
| `cors_checker` | `hellhound.modules.recon.CORSbuster` | Surface Analysis | CORS origin reflection and credential leakage checks. |
| `graphql_probe` | `hellhound.modules.recon.GraphQL` | Surface Analysis | GraphQL endpoint detection and schema introspection queries. |
| `hydra` | `hellhound.modules.analysis.Hydra` | Logic Analysis | Parameter dynamism, differential response analysis, and logic flaw hunting. |
| `cloudscout` | `hellhound.modules.intel.CloudScout` | Cloud Intel | S3, Azure Blob, GCP, and Firebase asset identification from recon data. |
| `transport_auditor` | `hellhound.modules.recon.TransportAuditor` | Transport | SSL/TLS certificate audit, HSTS validation, and cookie security flags. |
| `fuzz_hunter` | `hellhound.modules.recon.FUZZhunter` | Active Recon | Recursive path fuzzing with 404 similarity baseline heuristics. |
| `run_terminal_command` | `bash` / Host CLI | Custom Execution | Scoped custom command execution for specialized tools. |

---

## 3. Autopilot & Scope Guardrails

Hellhound enforces defensive rules-of-engagement before executing any tool:

*   **Target Scope Validation (`hellhound/core/scope.py`)**: Validates domain names, wildcards, and IP boundaries against the active target scope definition before any network call.
*   **Risk Classification (`MODULE_RISK_MAP`)**: Maps module actions against disallowed testing flags (`no-dos`, `no-brute-force`, `no-fuzzing`, `no-active-exploitation`, `no-automated-scanners`).
*   **Circuit Breakers & Rate Limiting (`AutopilotGuard`)**: Enforces rate limits (RPS) and trips safety circuit breakers upon encountering consecutive anomalous error rates.

---

## 4. Target State & Intelligence Persistence

State is persistently managed across sessions in `targets/<target_name>/task.json`:
*   **`target.state["spider_intel"]`**: Central aggregated intelligence (endpoints, forms, parameters, comments, secrets, tech stack) populated by `spider` and consumed by downstream auditors (`hydra`, `cloudscout`, `transport_auditor`, `fuzz_hunter`).
*   **`target.state["history"]`**: Multi-turn LLM reasoning history ensuring continuous context between queries.
*   **`target.findings`**: Structured, verified vulnerability disclosures and anomalous attack surfaces.
