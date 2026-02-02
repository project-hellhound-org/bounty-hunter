#  Hellhound – Modular Red Team Framework

Hellhound is a modular penetration testing framework that combines an interactive CLI console with a real-time web dashboard to streamline reconnaissance, enumeration, and attack workflows.

![project hell](/Images/hellhound.png)

This is not a simple automation script.
Hellhound is designed as a framework where tools are orchestrated, results are interpreted, and actions are suggested.

---

## Features

- Interactive CLI console (hellhound console)
- Web dashboard with live scan visualization
- Modular architecture (easy to extend)
- Session-based result storage
- Intelligent auto attack chaining
- Suggestion engine for next attack paths
- Custom command language (Hellhound themed)
- Real-time logging using Socket.IO
- Clean extensible project structure

---

## Installation

```bash
git clone https://github.com/l4zz3rj0d/Hellhound-Pentest.git

cd hellhound
pip install .
sudo apt install -y subfinder httpx-toolkit ffuf nuclei feroxbuster dirsearch git python3-pip
```

### Requirements

- Python 3.8+
- nmap
- ffuf
- bash
- Flask
- Click
- PyYAML
- colorama

---

## Usage

### Launch Console Mode
```bash
hellhound console
```

### Launch Dashboard Mode
```bash
hellhound hunt <target-ip>
```

Dashboard opens at:
```
http://127.0.0.1:8080
```

---

## Hellhound Console Commands

| Command   | Description |
|-----------|--------------|
| prey `<ip>` | Lock onto a target |
| nmap | Run reconnaissance |
| arsenal | List available tools |
| equip `<tool>` | Select a module |
| scope | View module configuration |
| strike | Execute selected module |
| howl | Suggest next actions |
| loot | View gathered results |
| release | Exit module mode |
| exit | Exit console |
| auto | Intelligent attack chain |
| clear | Clear screen |
| status | Show framework status |
| sessions | List previous hunts |

---

## Example Workflow

```text
hellhound > prey 192.168.1.10
hellhound > nmap
hellhound > howl
hellhound > equip vhost
hellhound(vhost) > strike
hellhound > loot
```

---

## Modules

Modules are organized by category:

```
hellhound/modules/
  network/
  web/
  enum/
```

Example modules:
- nmap – service discovery
- vhost – virtual host fuzzing
- dirsearch – directory enumeration
- ftp – FTP enumeration
- nuclei – vulnerability scanning

Each module follows a standard interface:

```python
def run(target, emit):
    ...
    return output
```

Add a module → register in config.yaml → it appears automatically.

---

## Sessions & Results

Each run creates a session:

```
hellhound/storage/<target>_<timestamp>/results.json
```

View inside console:
```bash
sessions
```

---

## Project Structure

```
hellhound/
├── cli.py        → Entry point
├── console.py    → Interactive shell
├── core/         → Engine, logic, intelligence
├── modules/      → Tool modules
├── scripts/      → External helpers
├── web/          → Dashboard server
├── storage/      → Sessions and results
├── config.yaml   → Module registry
```

---

## Vision

Hellhound is built to evolve toward:

- Intelligent service-aware attack chaining
- CVE correlation from version detection
- Automated enumeration workflows
- AI-assisted exploitation planning
- Advanced reporting and evidence collection

The long-term goal is a lightweight, extensible alternative to heavy frameworks.

---

## Disclaimer

This project is intended for:

- Educational use  
- Security research  
- Authorized penetration testing only  

Do NOT use against systems you do not own or have permission to test.

---

## Developed By

Team Hellhound  
L4ZZ3RJ0D  
alph4_rc
