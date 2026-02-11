#  Hellhound – Modular Red Team Framework

Hellhound Banner

Hellhound is a modular red team framework designed to orchestrate reconnaissance, enumeration, and controlled attack workflows through an interactive CLI console and an optional dashboard interface.

It is built for operators who value structure, intelligence, and extensibility over blind automation.

![Hellhound Banner](Images/hellhound.png)

---

##  Overview

Hellhound provides a structured environment for:

  - Target classification (Host vs Web)
  - Service-aware reconnaissance
  - Module-driven execution
  - Evidence-based decision support
  - Extensible attack chaining

The framework emphasizes control, visibility, and modularity.

---

## What Hellhound Is

  - A modular orchestration framework
  - A Metasploit-style interactive console
  - A service-aware reconnaissance engine
  - A structured hunting environment
  - A platform for extending custom red team modules

---
## Architecture Principles

  - Human-in-the-loop operation
  - Strict module separation (Network, Web, Recon, Enum)
  - Service-aware intelligence engine
  - Structured output and session management
  - Clean CLI abstraction layer
  - Replaceable and extensible components

##  Core Capabilities
### Interactive Console

  - Metasploit-style CLI
  - Target locking (prey)
  - Context-aware module listing (arsenal)
  - Controlled execution (equip → strike)
  - Structured results storage (loot)
  - Ranked recommendations (howl)
  - Alias system for operator efficiency
  - Session management

### Intelligence Engine

  - Nmap XML parsing
  - Service detection and version extraction
  - NSE script analysis
  - Vulnerability hint detection
  - Suggestion engine based on detected services
  - Planned rule-based autonomous hunt mode

---
## Prerequisites

Hellhound does not bundle heavy tools.
You must install and manage external tools yourself.

### Recommended Web Recon Tools

- httpx

- ffuf

- dirsearch

- feroxbuster

- whatweb

- waybackurls

- gau

### Optional (Advanced Recon)

- subfinder

- dnsx

- nuclei

Ensure all tools are available in your PATH.
---

##  Installation

```
# Clone the repository
git clone https://github.com/l4zz3rj0d/Hellhound-Pentest.git
cd Hellhound-Pentest

# Install Python dependencies
pip install .
pip install -r requirements.txt

# Install Go-based tools
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

## Usage
Launch Console Mode
```
hellhound console
```
Launch Hunting MOde
````
hellhound hunt <target>
````

## Hellhound Console Commands
| Command          | Description                    |                    
| ---------------- | ------------------------------ | 
| `prey <ip or domain>`        | Lock onto a target |
| `nmap`           | Run reconnaissance             |                    
| `arsenal`        | List available modules         |                    
| `equip <module>` | Select a module                |                    
| `run / strike`   | Execute module                 |                    
| `howl`           | Suggest next actions           |                    
| `loot`           | View results                   |                    
| `release`        | Exit module mode               |                    
| `auto`           | Intelligent attack chain (WIP) |                    
| `status`         | Show framework state           |                    
| `sessions`       | List previous hunts            |                    
| `clear`          | Clear screen                   |                    
| `exit`           | Exit console                   |                   


## Aliases
````
hunt → prey
use  → equip
run  → strike
ls   → arsenal
q    → exit
cls  → clear
````
## Example Workflow
````
hellhound > prey example.com
[Select target type: WEB]

hellhound > asset_recon
hellhound > dns_recon
hellhound > nmap
hellhound > stalk
hellhound > howl

hellhound > equip vhost
hellhound(vhost) > strike

hellhound > loot

````


## Sessions & Results

Each hunt creates a session:
```
hellhound/storage/<target>_<timestamp>/
```
View inside console:
```
sessions
```

## Roadmap

- Rule-based Hunting Mode

- Service-aware attack chains

- CVE correlation from Nmap output

- Automated exploit suggestions

- Report generation

- AI-assisted attack planning

## Disclaimer

This project is intended only for:

- Education

- Security research

- Authorized penetration testing

⚠️ Do NOT use against systems without explicit permission.

## Developed By

Team Hellhound
