# Contributing to Hellhound-Pentest

Welcome to the Hellhound framework. This guide explains how to contribute a new module to the arsenal.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Branching Strategy](#branching-strategy)
3. [Module Requirements](#module-requirements)
4. [Using the Module Scaffold](#using-the-module-scaffold)
5. [Submitting a Pull Request](#submitting-a-pull-request)
6. [CI/CD Checks](#cicd-checks)

---

## Getting Started

**Fork and clone the repository:**

```bash
# 1. Fork the repo on GitHub (click "Fork" in the top-right)

# 2. Clone your fork
git clone https://github.com/<your-username>/Hellhound-Pentest.git
cd Hellhound-Pentest

# 3. Install the framework in development mode
pip install -e ".[dev]"
```

---

## Branching Strategy

The `main` branch is protected. All contributions must come via a feature branch.

```
main
 └── feature/sqli-error-based      ← Your new module
 └── feature/xss-dom-scanner       ← Another contributor's module
 └── fix/fix-stalk-timeout         ← A bug fix (requires approval)
```

**Create your branch:**

```bash
git checkout -b feature/<your-module-name>
```

Use descriptive names:
- `feature/sqli-union-based`
- `feature/xss-reflected`
- `fix/stalk-timeout-bug`

> [!IMPORTANT]
> **Core Protection Enforcement**: All Pull Requests are automatically audited by our CI/CD pipeline. Any modification to files outside `hellhound/modules/`, `requirements.txt`, or `README.md` will be **categorically rejected** unless explicit authorization is granted for a core-level contribution.

---

## Module Requirements

All modules placed in `hellhound/modules/<category>/` **must** satisfy the following:

### Mandatory Metadata (at module level)

```python
DESCRIPTION = "One-line description of what this module does."
CATEGORY    = "vuln"   # recon | analysis | vuln | exploit | intel
```

### Mandatory: `OPTIONS` List

```python
OPTIONS = [
    {"name": "target",  "type": str,  "default": None,  "required": True,  "help": "Target URL"},
    {"name": "verbose", "type": bool, "default": False,  "required": False, "help": "Verbose output"},
]
```

### Mandatory: `run(target_context, options, emit)` Function

```python
def run(target_context: dict, options: dict, emit) -> dict:
    """
    Entry point for the Hellhound engine.
    
    Args:
        target_context: Global framework context (url, cookies, headers, proxy, etc.)
        options:        Module-specific options set by the user via `set`
        emit:           Callable to print colored output to the console
    
    Returns:
        dict: MUST include a 'results' key containing a list of findings.
    """
    findings = []
    # logic...
    findings.append({
        "severity": "HIGH",
        "finding_type":    "SQL Injection",     # Note: use finding_type instead of title
        "url":      target,
        "parameter":"id",
        "proof":    "error in response...",
        "poc_curl": "curl -X GET ..."
    })
    
    # Store dynamic data in the intel schema
    intel_data = {
        "vulnerabilities": findings,
        "endpoints": [{"url": target, "confidence_label": "CONFIRMED"}]
    }
    
    return {"intel": intel_data}
```

### Universal Renderer `intel` Schema

To ensure your findings are rendered beautifully in the `loot` view without modifying the console, your module should return an `intel` dictionary containing categorized lists.

> [!IMPORTANT]
> **Data-Driven Logging Requirement**
> Modules **must not** implement their own `print()` formatting for findings. The framework's Universal Renderer handles all data structures dynamically. Common noisy metadata (e.g., `meta`, `summary`, `risk_score`) is automatically silently suppressed from terminal output to keep the UI clean.

**Supported Vulnerability Schema:**
If your array is named `vulnerabilities` or has security keys, it automatically receives professional High-Fidelity UI formatting.

| Key | Type | Description |
|---|---|---|
| `severity` | string | `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` \| `INFO` |
| `finding_type` | string | Short name of the vulnerability (e.g., "CORS Misconfiguration") |
| `url` | string | The affected endpoint URL |
| `parameter` | string | (Optional) The vulnerable parameter name |
| `proof` | string | (Optional) Evidence or payload used |
| `poc_curl` | string | (Optional) Prepared curl command for reproduction |
| `poc_browser`| string | (Optional) URL to open in browser for reproduction |

Any extra custom keys you add to the dictionary will dynamically render underneath the finding automatically!

**Custom Hooks:**
If your module requires a custom ASCII banner (like the Spider summary block), simply add a `def render_header(self, intel):` method to your class. The Universal UI will auto-detect and execute it.
---

### The `emit` Callable

Use `emit` instead of `print()` to write output. This ensures compatibility with both the console and any future API/GUI.

```python
emit("info",    "Scanning target...")      # [*] cyan
emit("success", "Found endpoint!")         # [+] green
emit("warn",    "Rate limit detected.")    # [!] yellow
emit("error",   "Connection refused.")    # [-] red
```

---

## Using the Module Scaffold

The fastest way to create a valid module is to use the scaffold generator:

```bash
python scaffold_module.py <module_name> [category]
```

**Example:**

```bash
python scaffold_module.py sqli_union vuln
```

This creates `hellhound/modules/vuln/sqli_union.py` with the correct structure pre-filled.

---

## Submitting a Pull Request

1.  **Commit your changes:**
    ```bash
    git add hellhound/modules/<category>/<your_module>.py
    git commit -m "feat: add <module_name> to arsenal"
    ```

2.  **Push your branch:**
    ```bash
    git push origin feature/<your-module-name>
    ```

3.  **Open a Pull Request** on GitHub against the `main` branch.

4.  **Fill in the PR template** with a description of what the module does and any test targets used.

---

## CI/CD Checks

Every Pull Request automatically triggers the **Verify Modules** workflow. It will:

| Check | What It Does |
|---|---|
| **Syntax Check** | `py_compile` on all changed files |
| **Metadata Check** | Ensures `DESCRIPTION` and `CATEGORY` are present |
| **Import Check** | Attempts to import the module to catch missing dependencies |
| **Core Protection**| Fails if files outside `hellhound/modules/` are modified |

> [!IMPORTANT]
> All three checks must **pass** before a PR can be merged into `main`. If a check fails, you will see a detailed error message in the Actions tab. Fix the issue and `git push` to re-trigger the checks automatically.

---

## Governance & Professional Conduct

- **Atomic Contributions**: Keep your PRs focused. One new module per PR. If you have three modules to add, submit three separate PRs.
- **Dependency Accountability**: If your module requires a new library, add it to `requirements.txt`. Ensure the library is reputable and doesn't conflict with existing dependencies.
- **Collaborative Spirit**: Engage with reviewers. The Hellhound team (led by @l4zz3rj0d) provides high-fidelity feedback to ensure every module in the arsenal is production-ready.

---

## Technical Support for Contributors

If you need assistance with module development or logic correlation, you can launch your own **Antigravity AI Agent** within the repository. Antigravity is pre-trained on Hellhound's architecture and can help you:
- Debug your `run()` function logic.
- Verify your `intel` schema formatting.
- Automatically generate your `PULL_REQUEST_TEMPLATE.md` details based on your code.
