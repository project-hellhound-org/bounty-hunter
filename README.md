<p align="center">
  <img src="Images/hellhound.png" alt="Hellhound" width="600"/>
</p>

<h1 align="center">Hellhound-Pentest(In-Dev)</h1>

<p align="center">
  Modular red team framework for web recon, attack surface mapping, and guided exploitation workflows.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square"/>
</p>

---

## What it does

Hellhound orchestrates web recon and attack surface mapping through a modular plugin system. Modules share intelligence — output from one feeds the next, so findings correlate instead of pile up.

```
Spider → BACdetector → Parax → CMDinj → Seige → Loot → Howl
```

---

## Modules

| Module | Description |
|---|---|
| `spider` | SPA-aware crawler — endpoints, routes, JS params |
| `bacdetector` | Access control scanner (IDOR, RBAC, auth misconfig) |
| `parax` | Parameter risk classifier (SQLi, IDOR, LFI patterns) |
| `cmdinj` | Command injection prober |
| `seige` | Vulnerability scanner across mapped routes |
| `loot` | Correlated intelligence store + reporting |
| `howl` | Next-step suggestions based on findings |

---

## Requirements

- Python 3.10+
- pip

---

## Install

```bash
git clone https://github.com/l4zz3rj0d/Hellhound-Pentest.git
cd Hellhound-Pentest
pip install -r requirements.txt
```

Optionally, install in editable mode:

```bash
pip install -e .
```

---

## Usage

```bash
hellhound console
```

| Command | Description |
|---|---|
| `prey <domain>` | Set target |
| `arsenal` | List available modules |
| `equip <module>` | Enter module mode |
| `strike` | Run module |
| `release` | Exit module mode |
| `loot` | View correlated findings |
| `loot --summary` | Executive summary |
| `loot --export` | Export report |
| `howl` | Get next-step suggestions |
| `status` | Show framework state |

---

## Roadmap

- Rule-based automated attack chains
- CVE correlation engine
- Enhanced secret entropy validation
- Structured PDF report generation
- Adaptive risk modeling

---

## Disclaimer

For authorized testing only. You are responsible for having explicit permission before running this against any system.

---

## Author

Built and maintained by **[l4zz3rj0d](https://github.com/l4zz3rj0d)**

---

## License

MIT
