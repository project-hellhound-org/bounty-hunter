# Hellhound – Modular Red Team Framework

Hellhound is a modular red team framework designed for structured web reconnaissance, attack surface intelligence, and guided exploitation workflows.

It provides a unified, correlation-based execution engine that transforms raw reconnaissance data into actionable attack paths.

Hellhound is built for security professionals who require visibility, modular control, and structured intelligence during web application assessments.

![Hellhound Banner](Images/hellhound.png)

---

## Overview

Modern offensive security engagements often rely on fragmented tooling. Crawlers, fuzzers, scanners, and exploitation scripts operate independently, leaving the operator to manually correlate findings.

Hellhound solves this by acting as an orchestration layer.

Instead of generating isolated output, Hellhound:

- Aggregates intelligence across modules
- Correlates findings into structured attack surfaces
- Quantifies risk using dynamic scoring
- Enables guided exploitation workflows

It is not a scanner.  
It is an intelligence-driven red team framework.

---

## Core Capabilities

### Web Reconnaissance

- SPA-aware intelligent crawling
- REST and API surface discovery
- JavaScript route extraction
- GraphQL endpoint detection
- Technology fingerprinting
- Web Application Firewall detection
- Security header analysis
- Robots.txt intelligence
- Heuristic directory fuzzing

### Attack Surface Intelligence

- Parameter harvesting from HTML and JavaScript
- Risk classification (IDOR, SQLi, LFI, Open Redirect patterns)
- Sensitive route discovery
- Potential secret and key identification
- Structured endpoint modeling

### Vulnerability & Exploitation Support

- Context-aware parameter testing
- Command injection probing
- Vulnerability scanning integration
- Risk validation and scoring

### Intelligence Enrichment

- Credential exposure detection
- Email and employee intelligence
- Cloud asset identification
- Phishing preparation intelligence

---

## Design Philosophy

Hellhound is built on Human-in-the-Loop Automation.

It does not attempt to replace the operator with blind automation. Instead, it:

- Automates correlation
- Structures reconnaissance data
- Highlights high-risk surfaces
- Suggests logical next steps

The operator remains in control while the framework manages context and intelligence flow.

---

## How It Works

Hellhound operates through a centralized execution engine.

Each module:

- Implements a standardized `run(target, emit, options)` interface
- Returns structured intelligence
- Can consume output from previously executed modules

Example intelligence flow:

```
Spider  → Discovers API routes & parameters
Parax   → Analyzes parameters for risk patterns
CMDinj  → Targets system-interaction endpoints
Seige   → Performs vulnerability scanning on mapped routes
Loot    → Aggregates and correlates all findings
Howl    → Suggests next logical attack step
```

This layered workflow enables guided offensive testing rather than random probing.

---

## Key Features

- Modular plugin architecture
- Dynamic module discovery
- Structured attack surface mapping
- Cross-module intelligence correlation
- Risk scoring system
- Interactive operator console
- Session-based engagement tracking
- Extensible framework design

---

## Installation

### Requirements

- Python 3.10+
- pip

### Clone Repository

```bash
git clone https://github.com/l4zz3rj0d/Hellhound-Pentest.git
cd Hellhound-Pentest
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Recommended: Install in Editable Mode

```bash
pip install -e .
```

---

## Usage

Launch the interactive console:

```bash
hellhound console
```

---

## Basic Workflow

Set target:

```
prey https://target.com
```

List available modules:

```
arsenal
```

Run reconnaissance:

```
strike spider
```

Analyze parameters:

```
strike parax
```

Run vulnerability scanning:

```
strike seige
```

View correlated intelligence:

```
loot
```

Get suggested next steps:

```
howl
```

---

## Console Commands

| Command               | Description |
|-----------------------|-------------|
| `prey <domain>`       | Set assessment target |
| `arsenal`             | List available modules |
| `equip <module>`      | Enter module mode |
| `strike`              | Execute module |
| `release`             | Exit module mode |
| `loot`                | View correlated intelligence |
| `loot --summary`      | Executive summary view |
| `loot --export`       | Export report |
| `howl`                | Suggested next actions |
| `status`              | Show framework state |
| `clear`               | Clear console |
| `exit`                | Exit console |

---

## Intelligence & Reporting

Hellhound aggregates results into a structured intelligence store.

The `loot` command provides:

- Risk breakdown by module
- Attack surface metrics
- Security header analysis
- API and endpoint mapping
- Parameter risk classification
- Vulnerability findings
- Signal correlation

Sessions are preserved for engagement tracking and reporting.

---

## Roadmap

- Rule-based automated attack chains
- Advanced endpoint prioritization
- Enhanced secret entropy validation
- CVE correlation engine
- Structured PDF report generation
- Adaptive risk modeling

---

## Intended Use

Hellhound is designed for:

- Authorized penetration testing
- Red team operations
- Security research
- Educational labs

---

## Disclaimer

This tool is intended for authorized security testing and research only.

Users are responsible for ensuring they have explicit permission before testing any systems.

The authors assume no liability for misuse.

---

## Developed By

Project Hellhound

---

## License

MIT License