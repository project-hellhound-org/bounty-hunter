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

##  Key Features

### Console Mode (Primary)
- Interactive Metasploit-style CLI
- Custom Hellhound command language
- Target-type aware logic (host vs web)
- Modular tool execution (`equip → run`)
- Intelligent suggestions (`howl`)
- Session & loot management
- Alias system (hunt, use, run, ls, etc.)
- Colored, animated startup & output
- Extensible module system

### Dashboard Mode (Secondary)
- GUI-based hunting & exploitation
- Attack execution from UI (not just live logs)
- Target selection & module triggering
- Designed for users who prefer GUI over CLI

### Framework Core
- Modular architecture
- Rule-based attack chaining (Hunting Mode – WIP)
- ReconCombo integration
- Session-based result storage
- Socket.IO-based live logging

---

##  ReconCombo Integration - Thanks to nickyqqq

Hellhound integrates **ReconComboGo**, a powerful Go-based reconnaissance pipeline that includes:

- Subdomain enumeration (subfinder)
- URL collection (gau, katana, ffuf)
- Directory discovery (feroxbuster, dirsearch)
- GF pattern extraction (XSS, SQLi, SSRF, etc.)
- JavaScript file extraction & analysis
- Resume interrupted scans
- Concurrent multi-target processing

ReconCombo is treated as a **first-class web reconnaissance module** inside Hellhound.

---

##  Installation

### Clone Repository
```bash
git clone https://github.com/l4zz3rj0d/Hellhound-Pentest.git
cd Hellhound-Pentest
```
### Install Hellhound
```
pip install .

```

### ReconCombo & Toolchain Setup (Required)

Hellhound does not bundle heavy tools.
You must install them system-wide.

### System Dependencies
```
sudo apt update
sudo apt install -y \
  nmap \
  ffuf \
  nuclei \
  feroxbuster \
  dirsearch \
  git \
  python3-pip

```

### Go-Based Tools
```
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/anew@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/gf@latest

```
Make sure $GOPATH/bin is in your PATH.

### Python Tools
```
git clone https://github.com/s0md3v/uro.git
cd uro
python3 setup.py install --user

```

### GF Patterns (Mandatory)

```
git clone https://github.com/tomnomnom/gf.git ~/.gf

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

hellhound > nmap
hellhound > howl

hellhound > equip reconcombo
hellhound(reconcombo) > run

hellhound > equip vhost
hellhound(vhost) > run

hellhound > loot
````
## Module System

Modules are organized by category:
````
hellhound/modules/
├── network/
├── web/
├── enum/
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
## Project Structure
```
hellhound/
├── cli.py          → Entry point
├── console.py      → Interactive shell
├── core/           → Engine & intelligence
├── modules/        → Tool modules
├── scripts/        → External helpers
├── web/            → Dashboard server
├── storage/        → Sessions & loot
├── config.yaml     → Module registry
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
