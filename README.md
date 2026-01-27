# 🐺 Hellhound Pentest Framework

Hellhound is a modular, interactive pentesting framework that combines a clean CLI experience with a real-time web dashboard. It is designed for learning, automation, and building professional security tooling — not just running commands.

> Think: lightweight Metasploit-style orchestration for recon workflows.

---

## ✨ Features

* Interactive CLI (SEToolkit-style module selection)
* Modular architecture (easy to add new tools/modules)
* Live web dashboard using Flask + Socket.IO
* Session folders per scan
* JSON result export for every run
* External tool integration (Nmap, ffuf, etc.)
* Custom or built-in wordlist support
* Clean process lifecycle (Ctrl+C shuts everything down)

---

## 📂 Project Structure

```
hellhound/
├── cli.py                 # Command line interface
├── config.yaml            # Module descriptions
├── core/
│   └── engine.py          # Orchestrates module execution
├── modules/
│   ├── nmap.py
│   ├── vhost.py
│   └── ...                 # Other modules (nuclei, nikto, etc.)
├── scripts/
│   └── vhost-fuzzer.sh     # External helper scripts
├── wordlists/
│   └── default.txt
├── web/
│   ├── server.py           # Flask dashboard server
│   └── templates/index.html
└── storage/
    └── <target_timestamp>/ # Session folders with results.json
```

---

## ⚙️ Requirements

Before running Hellhound, make sure you have:

* Python 3.9+
* pip
* External tools installed:

  * `nmap`
  * `ffuf`
  * (optional) `nuclei`, `nikto`, etc.

Python dependencies (auto-installed via pip):

* click
* flask
* flask-socketio
* requests
* pyyaml

---

## 🚀 Installation

From the project root:

```bash
pip install .
```

To reinstall after changes:

```bash
pip uninstall hellhound -y
pip install .
```

---

## 🧪 Usage

### Show help

```bash
hellhound --help
```

### List available modules

```bash
hellhound modules
```

### Run a scan

```bash
hellhound hunt 192.168.56.6
```

You will be prompted to:

* Select which modules to run (e.g., nmap, vhost, etc.)
* Provide a custom wordlist (only if VHOST is selected)

The dashboard will launch automatically in your browser.

---

## 📊 Results

Each scan creates a new session folder:

```
hellhound/storage/192.168.56.6_20260127_111852/results.json
```

This JSON file contains all collected outputs from selected modules.

---

## 🧩 Adding New Modules

Create a new file in:

```
hellhound/modules/<tool>.py
```

Each module must expose a function like:

```python
def run(target, emit, *args):
    emit("[+] Module started")
    # tool logic here
    emit("[✓] Module finished")
    return "results"
```

Then register it in `config.yaml`:

```yaml
modules:
  newtool:
    description: "My custom module"
```

It will automatically appear in:

```bash
hellhound modules
```

---

## ⚠️ Disclaimer

Hellhound is built for **educational and authorized security testing only**.

Do not use this tool against systems you do not own or have explicit permission to test.

You are responsible for your actions.

---

## 👨‍💻 Author

Built by a cybersecurity student as a final-year project to learn real-world tooling, architecture, and automation.

---

## 🐺 Final Note

Hellhound is not just a script.
It is a framework you can grow into your own professional toolkit.

Fork it. Extend it. Break it. Improve it. That’s the point.
