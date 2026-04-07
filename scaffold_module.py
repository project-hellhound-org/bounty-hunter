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
import textwrap

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

    # Build the file content using string concatenation to avoid .format() conflicts
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
        "async def _scan(target_context: dict, options: dict, emit):",
        '    """',
        "    Place your async scanning logic here.",
        '    Use emit("info" | "success" | "warn" | "error", message) for output.',
        "",
        "    Args:",
        "        target_context: Global context (url, cookies, headers, proxy, ai_key...)",
        "        options:        Module options set by the user via `set`",
        "        emit:           Console output callable",
        "",
        "    Returns:",
        "        list: A list of finding dicts.",
        '    """',
        '    target  = options.get("target") or target_context.get("url")',
        '    verbose = options.get("verbose", False)',
        "",
        "    if not target:",
        '        emit("error", "No target set. Use `set target <url>` or `prey <domain>` first.")',
        "        return []",
        "",
        f'    emit("info", f"Starting {class_name} on {{target}}")',
        "",
        "    findings = []",
        "",
        "    # ── TODO: Implement your module logic here ────────────────────────",
        "    #",
        "    # async with aiohttp.ClientSession() as session:",
        "    #     async with session.get(target) as resp:",
        "    #         body = await resp.text()",
        '    #         if "error" in body.lower():',
        "    #             findings.append({",
        '    #                 "url": target,',
        '    #                 "severity": "HIGH",',
        '    #                 "title": "Error message detected",',
        '    #                 "evidence": body[:200]',
        "    #             })",
        '    #             emit("success", f"Finding at {target}")',
        "    # ─────────────────────────────────────────────────────────────────",
        "",
        "    if not findings:",
        '        emit("warn", "No findings detected.")',
        "    else:",
        '        emit("success", f"{len(findings)} finding(s) identified.")',
        "",
        "    return findings",
        "",
        "",
        "# ── Entry Point (called by Hellhound Engine) ──────────────────────────",
        "def run(target_context: dict, options: dict, emit) -> dict:",
        '    """',
        "    Synchronous entry point for the Hellhound console engine.",
        "    Do NOT modify this — it bridges the sync console to the async scan.",
        '    """',
        "    try:",
        "        loop = asyncio.get_event_loop()",
        "        if loop.is_closed():",
        "            loop = asyncio.new_event_loop()",
        "            asyncio.set_event_loop(loop)",
        "        findings = loop.run_until_complete(_scan(target_context, options, emit))",
        "    except Exception as e:",
        '        emit("error", f"Module runtime error: {e}")',
        "        findings = []",
        "",
        '    return {"results": findings}',
    ]

    content = "\n".join(lines) + "\n"

    with open(target, "w") as f:
        f.write(content)

    print(f"\n  [✓] Module scaffolded successfully!\n")
    print(f"  File     : {target}")
    print(f"  Category : {category}")
    print(f"  Next     : Open the file and implement your logic in _scan()")
    print(f"\n  To test  : hellhound > equip {module_name}")
    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    name = sys.argv[1].lower().replace("-", "_").replace(" ", "_")
    cat  = sys.argv[2].lower() if len(sys.argv) >= 3 else "vuln"
    scaffold(name, cat)
