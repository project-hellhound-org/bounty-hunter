#!/usr/bin/env python3
"""
scaffold_module.py — Hellhound Module Generator

Generates a correctly structured Hellhound module boilerplate.

Usage:
    python scaffold_module.py <module_name> [category]

Examples:
    python scaffold_module.py sqli_union vuln
    python scaffold_module.py xss_reflected vuln
    python scaffold_module.py js_recon recon
"""

import os
import sys

VALID_CATEGORIES = ["recon", "analysis", "vuln", "exploit", "intel"]


def scaffold(module_name: str, category: str):
    """Generate a new module file from the template."""
    if category not in VALID_CATEGORIES:
        print(f"[!] Invalid category '{category}'. Choose from: {', '.join(VALID_CATEGORIES)}")
        sys.exit(1)

    class_name  = "".join(word.capitalize() for word in module_name.split("_"))
    description = f"{class_name} — {category.capitalize()} module"

    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hellhound", "modules", category)
    os.makedirs(base, exist_ok=True)
    target = os.path.join(base, f"{module_name}.py")

    if os.path.exists(target):
        print(f"[!] Module already exists: {target}")
        sys.exit(1)

    # Build the file content
    lines = [
        "# " + "─" * 69,
        f"#  Hellhound — {class_name}",
        f"#  Category : {category}",
        "# " + "─" * 69,
        "",
        "import asyncio",
        "import aiohttp",
        "",
        "# ── Mandatory Module Metadata ─────────────────────────────────────────",
        f'DESCRIPTION = "{description}"',
        f'CATEGORY    = "{category}"',
        "",
        "# ── Options ───────────────────────────────────────────────────────────",
        "OPTIONS = [",
        "    {",
        '        "name": "target",',
        '        "type": str,',
        '        "default": None,',
        '        "required": True,',
        '        "help": "Target URL (e.g. https://example.com/endpoint)"',
        "    },",
        "    {",
        '        "name": "verbose",',
        '        "type": bool,',
        '        "default": False,',
        '        "required": False,',
        '        "help": "Enable verbose output"',
        "    },",
        "]",
        "",
        "",
        "# ── Core Logic ────────────────────────────────────────────────────────",
        "async def run(target: str, emit, options: dict = None):",
        '    """',
        "    Place your async scanning logic here.",
        '    Use emit.info() | .success() | .warn() | .error() for output.',
        '    """',
        '    emit.info(f"Starting {class_name} on {target}")',
        "",
        "    findings = []",
        "",
        "    # ── TODO: Implement your module logic here ────────────────────────",
        "    # Example:",
        "    # if \"vuln\" in target:",
        "    #     findings.append({",
        '    #         "url": target,',
        '    #         "severity": "HIGH",',
        '    #         "type": "MOCK_VULN",',
        '    #         "evidence": "Found string vuln in URL"',
        "    #     })",
        "    # ─────────────────────────────────────────────────────────────────",
        "",
        "    if findings:",
        '        emit.success(f"Found {len(findings)} vulnerabilities!")',
        "    else:",
        '        emit.info("No findings detected.")',
        "",
        "    return {",
        '        "raw": f"Audited {target}",',
        '        "intel": {"vulnerabilities": findings},',
        '        "signals": ["VULN_FOUND" if findings else "NO_VULN"]',
        "    }",
    ]

    content = "\n".join(lines) + "\n"

    with open(target, "w") as f:
        f.write(content)

    print(f"\n  [✓] Module scaffolded successfully!\n")
    print(f"  File     : {target}")
    print(f"  Category : {category}")
    print(f"  Next     : Open the file and implement your logic in run()")
    print(f"\n  To test  : hellhound > equip {module_name}")
    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    name = sys.argv[1].lower().replace("-", "_").replace(" ", "_")
    cat  = sys.argv[2].lower() if len(sys.argv) >= 3 else "vuln"
    scaffold(name, cat)
