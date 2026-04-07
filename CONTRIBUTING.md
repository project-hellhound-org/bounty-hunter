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
 └── fix/fix-stalk-timeout         ← A bug fix
```

**Create your branch:**

```bash
git checkout -b feature/<your-module-name>
```

Use descriptive names:
- `feature/sqli-union-based`
- `feature/xss-reflected`
- `fix/stalk-timeout-bug`

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
        dict: MUST include a 'results' key containing a list of findings
    """
    ...
    return {"results": [...]}
```

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

> [!IMPORTANT]
> All three checks must **pass** before a PR can be merged into `main`. If a check fails, you will see a detailed error message in the Actions tab. Fix the issue and `git push` to re-trigger the checks automatically.

---

## Code Style

- Follow existing module patterns (see `hellhound/modules/vuln/BACdetector.py` as a reference).
- Keep the module focused on a **single vulnerability class**.
- Use `try/except` to handle network errors gracefully — the framework should never crash due to a target being unreachable.
- Do not use `print()` directly. Always use `emit()`.
