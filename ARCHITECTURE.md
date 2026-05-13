# Hellhound Pentest Framework — Technical Architecture

This document provides a deep-dive into the core engines and modular architecture that power the Hellhound framework.

---

## 1. The Hydra Logic Engine

Hydra is the multi-headed analysis heartbeat of Hellhound. It bridges the gap between reconnaissance and exploitation by understanding the **intent** and **state** of parameters.

### Analysis Heads
*   **Cerberus Head (Entropy)**: Discovers hidden data roles (IDs, Tokens, Secrets) using passive heuristic analysis and technology profiling.
*   **Lailaps Head (Differential)**: Actively probes for dynamism. Identifies how the application reacts to parameter shifts, length deltas, and status code variations.
*   **Geryon Head (Correlation)**: Correlates parameters across distinct endpoints to identify potential cross-context logic flaws.

Hydra acts as the **Intelligence Orchestrator**, automatically recommending and seeding specialized auditors like `IDORdetector` or `CORSbuster` with high-fidelity targets.

---

## 2. Universal Schema-Agnostic Rendering

Hellhound v12.5 utilizes a dynamic rendering engine that decouples module logic from visual representation.

*   **Intelligent UI Hooking**: Modules no longer execute their own `print()` commands. The console automatically detects data clusters, parses them, and organizes them into immersive visual blocks.
*   **Recursive Information Cleaning**: Automated filtering of high-noise data to ensure only high-fidelity signals reach the operator.
*   **High Value Target (HVT) Synthesis**: The engine autonomously correlates output across modules to build a prioritized attack surface.

---

## 3. Apex-King AI Core

The AI Core is an agnostic, multi-tier correlation layer designed for professional offensive speed.

*   **Zero-Config Discovery**: Standardized handshakes establish connectivity with OpenAI, Anthropic, or Google Gemini in seconds.
*   **Specialized Personas**:
    *   **The Strategic Correlator**: Maps independent findings into complex multi-step attack chains.
    *   **The Deep Logic Auditor**: High-fidelity static analysis of reconstructed source code focusing on dangerous sinks.
*   **Non-Blocking Execution**: AI features are isolated in the execution pipeline. Quota limits or network errors never interrupt the core rule-based detection flow.

---

## 4. Module Matrix & Detection Capabilities

### Sensitive Data Exposure
| Check | Module | Signal |
|---|---|---|
| Hardcoded secrets (API keys, JWTs, credentials) | Spider + SourceAuditor | `[SECRET:*]` |
| Logs / backup file exposure (`.log`, `.bak`, `.sql`) | Spider passive extraction | `[Leaked-File]` |
| Weak encryption (MD5, SHA1, RC4, DES) | SourceAuditor SA-013 | Pre-filter → AI verify |
| Client storage leak (sessionStorage, IndexedDB) | SourceAuditor SA-014 | Pre-filter → AI verify |
| Session cookie flags (HttpOnly, Secure, SameSite) | TransportAuditor | TA-02x |

### Infrastructure & Configuration
| Check | Module | Signal |
|---|---|---|
| SSL cert expiry, weak ciphers, deprecated TLS | TransportAuditor | TA-00x |
| Default server/framework pages | SurfaceAuditor | SA-101 |
| CDN misconfiguration + origin IP leak | SurfaceAuditor | SA-102/103 |
| Open ports & unnecessary services | SurfaceAuditor | SA-110 |
| Outdated frontend SDKs | SourceAuditor SA-016 | Pre-filter → AI verify |

---

## 5. Obsidian Neural Attack Graphing

The Attack Graph is the visualization heartbeat of Hellhound, providing a high-fidelity "God's Eye View" of the target's security posture.

*   **Force-Directed Physics (D3-force)**: Utilizes a dynamic physics simulation where nodes attract/repulse based on their relationship density. Highly connected targets (e.g., API Gateways) naturally cluster in the center.
*   **3D Neural Mapping (Three.js)**: Transitions from 2D flat-space to 3D spatial awareness. Nodes are rendered as glowing spheres with emissive intensity scaled by vulnerability severity.
*   **Tactical Interaction**:
    *   **Node Deep-Dive**: Clicking a node triggers a tactical zoom and opens the Forensic Intelligence panel.
    *   **Flow Particles**: Real-time directional particles visualize the "Attack Path" between discovery and exploitation.
    *   **Minimalist HUD**: Tooltips and labels are dynamically hidden to maintain a professional, high-signal interface.
