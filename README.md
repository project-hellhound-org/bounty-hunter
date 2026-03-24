<p align="center">
  <img src="Images/hellhound.png" alt="Hellhound" width="600"/>
</p>
<h1 align="center">HELLHOUND</h1>
<h1 align="center">Hellhound-Pentest(In-Dev)</h1>
<p align="center">
  Modular web offensive framework for recon, attack surface mapping, and vulnerability detection.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square"/>
</p>

---

## Overview

HELLHOUND is a console-based red team framework built around a modular plugin system. Modules share intelligence — output from one feeds the next automatically, so findings correlate instead of piling up as isolated results.

```
prey → equip → strike → loot → howl
```

The framework has a strict separation of concerns: the console handles UI, the engine handles execution, modules handle logic. Adding a new module requires no changes to the console or engine.

---

## Modules

| Module | Category | Description |
|---|---|---|
| `Spider` | recon | SPA-aware crawler — endpoints, JS params, secrets, CORS, GraphQL |
| `BACdetector` | vuln | Broken access control — IDOR, RBAC, auth misconfiguration |
| `CMDinj` | exploit | Command injection prober across discovered endpoints |
| `Parax` | analysis | Parameter risk classifier — SQLi, IDOR, LFI pattern detection |
| `Seige` | exploit | Vulnerability scanner across mapped routes |
| `FUZZhunter` | recon | Directory and parameter fuzzing |
| `Fingerprint` | recon | Technology stack and server fingerprinting |
| `CredLeak` | intel | Credential leak and exposed secret detection |

---

## Requirements

- Python 3.10+
- pip

---

## Install

It is recommended to use a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
git clone https://github.com/l4zz3rj0d/Hellhound-Pentest.git
cd Hellhound-Pentest
chmod +x install.sh
./install.sh
```

This installs HELLHOUND as a system-wide command via an editable pip install. Source edits take effect immediately — no reinstall needed.

After install, run from anywhere:

```bash
hellhound
```

---

## Usage

```bash
hellhound
```

| Command | Description |
|---|---|
| `prey <url>` | Set target |
| `arsenal` | List available modules |
| `equip <module>` | Enter module mode |
| `options` | Show module configuration |
| `set <option> <value>` | Configure an option |
| `strike` | Execute the active module |
| `release` | Exit module mode |
| `loot` | View correlated findings (detailed) |
| `loot --summary` | Executive risk summary |
| `loot --json` | Raw JSON dump |
| `loot --export` | Export report to disk |
| `howl` | Get next-step suggestions based on findings |
| `status` | Show session state |

### Example session

```
hellhound > prey http://target.com/
[+] Web target acquired: http://target.com/

hellhound > equip Spider
[+] Spider equipped

hellhound(Spider) > set cookie <session_token>
hellhound(Spider) > strike

[*] Hellhound Spider v12.0 — http://target.com/
[✓] Spider scan complete
[✓] Target: http://target.com/ | Endpoints: 84 | Secrets: 3 | High: 5

hellhound(Spider) > release
hellhound > equip BACdetector
hellhound(BACdetector) > strike   ← Spider intel is auto-fed

hellhound > loot
hellhound > howl
```

## Roadmap

- Automated attack chain execution (`auto` command)
- CVE correlation against discovered tech stack
- PDF report generation
- Adaptive risk scoring model

---

## Disclaimer

For authorized security testing only. You are responsible for obtaining explicit written permission before running this tool against any system you do not own.

---

## Author

Built and maintained by **[l4zz3rj0d](https://github.com/l4zz3rj0d)**

---

## License

MIT
