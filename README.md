#  Hellhound – Modular Red Team Framework

Hellhound is a **modular red team framework** designed to orchestrate reconnaissance, enumeration, and attack workflows through an interactive CLI console and an optional GUI dashboard.

This is **not** a one-click auto-hack tool.
Hellhound focuses on **control, intelligence, and extensibility**, giving operators the power to decide *how* the hunt proceeds.

![Hellhound Banner](Images/hellhound.png)

---

##  What Hellhound Is (and Isn’t)

✔ A **framework** that orchestrates tools  
✔ A **Metasploit-style interactive console**  
✔ A **rule-aware hunting engine** (in progress)  
✔ A **GUI dashboard that can actively attack from UI**  

✖ Not just a script runner  
✖ Not blind automation  
✖ Not “scan and forget”

---

## Core Design Philosophy

- Human-in-the-loop decision making
- Evidence-based recommendations
- Strict separation of responsibilities:
  - Asset reconnaissance
  - DNS reconnaissance
  - Network scanning
  - Web intelligence
- Modular, replaceable components
- Console safety over automation

---

##  Key Features

### Console Mode (Primary)
- Interactive Metasploit-style CLI
- Custom Hellhound command language
- Target-type awareness (host vs web)
- Modular execution (`equip → strike`)
- Intelligent, ranked suggestions (`howl`)
- Session and loot management
- Alias system (hunt, use, run, ls, etc.)
- Clean, colorized output
- Extensible module system

### Intelligence Engine
- Combines results from:
  - Asset reconnaissance
  - DNS reconnaissance
  - Network scans (Nmap)
  - Web reconnaissance (`stalk`)
- Produces ranked, evidence-based next steps
- Designed to support future automation safely

### Dashboard Mode (Planned)
- GUI-based hunting and exploitation
- Module execution from UI
- Session visualization
- Intended for users who prefer GUI over CLI

---
## Prerequisites

Hellhound does not bundle heavy tools.
You must install and manage external tools yourself.

### Required

- Linux (Kali Linux recommended)

- Python 3.10+

- pip

- git

### Recommended System Tools

- nmap

- curl

- wget

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
git clone https://github.com/l4zz3rj0d/Hellhound-Pentest.git
cd Hellhound-Pentest
pip install .
pip install -r requirements.txt

````

### Go-Based Tools
```
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

## Usage
Launch Console Mode
```
hellhound console
```
Launch Dashboard Mode
````
hellhound hunt <target>
````

Dashboard runs at:
````
http://127.0.0.1:8080
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

Each module exposes:
````
def run(target, emit, options=None):
    ...
    return output
````

Add a module → register in config.yaml → instantly usable.

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
