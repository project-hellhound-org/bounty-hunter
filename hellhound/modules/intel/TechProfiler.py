#!/usr/bin/env python3
"""
TechProfiler - Hellhound Intel Intelligence Module
Aggregates technical stack information from across the framework.
"""

from typing import Dict, List, Any, Optional
from hellhound.modules.recon.utils.signatures import WAF_SIGNATURES, TECH_SIGNATURES

# ══════════════════════════════════════════════════════════════════════
# METADATA
# ══════════════════════════════════════════════════════════════════════

NAME        = "techprofiler"
CATEGORY    = "intel"
DESCRIPTION = "Aggregates findings into a unified technical stack profile"

# ══════════════════════════════════════════════════════════════════════
# OPTIONS
# ══════════════════════════════════════════════════════════════════════

OPTIONS = [
    {"name": "show_all", "type": bool, "default": False, "help": "Include low-confidence or passive technology matches"},
]

# ══════════════════════════════════════════════════════════════════════
# PROFILER LOGIC
# ══════════════════════════════════════════════════════════════════════

class Profiler:
    def __init__(self, emit):
        self.emit = emit
        self.stack = {
            "Server": set(),
            "Framework": set(),
            "CMS": set(),
            "WAF": set(),
            "Other": set()
        }
        self.signals = []

    def ingest_raw_text(self, text: str):
        text_lo = text.lower()
        for waf, sigs in WAF_SIGNATURES.items():
            if any(sig in text_lo for sig in sigs):
                self.stack["WAF"].add(waf)

        for cat, components in TECH_SIGNATURES.items():
            if cat not in self.stack: continue
            for sig, name in components.items():
                if sig in text_lo:
                    self.stack[cat].add(name)

    def ingest_paths(self, paths: List[str]):
        path_sigs = {
            "wp-content": ("CMS", "WordPress"),
            "wp-includes": ("CMS", "WordPress"),
            "drupal.js": ("CMS", "Drupal"),
            "joomla": ("CMS", "Joomla"),
            "_next/static": ("Framework", "Next.js"),
            "react-dom": ("Framework", "React"),
            "vue.js": ("Framework", "Vue.js"),
            "django": ("Framework", "Django"),
            "laravel": ("Framework", "Laravel"),
        }
        for path in paths:
            path_lo = path.lower()
            for sig, (cat, name) in path_sigs.items():
                if sig in path_lo:
                    self.stack[cat].add(name)

    def finalize(self) -> Dict[str, Any]:
        report = {k: sorted(list(v)) for k, v in self.stack.items()}
        if report["WAF"]: self.signals.append("WAF_PROTECTED")
        if len(report["Framework"]) > 1: self.signals.append("HYBRID_FRONTEND")
        if report["CMS"]: self.signals.append("CMS_DETECTED")
        return report

# ══════════════════════════════════════════════════════════════════════
# RUN
# ══════════════════════════════════════════════════════════════════════

def run(target: str, emit: Any, options: Optional[Dict[str, Any]] = None):
    options = options or {}
    spider_intel = options.get("spider_intel", {})
    show_all = options.get("show_all", False)

    profiler = Profiler(emit)
    
    if not spider_intel:
        emit.warn("No spider intelligence found. Tech profiling will be limited.")
    else:
        # 1. Ingest tech stack already identified by spider
        spider_stack = spider_intel.get("tech_stack", [])
        for item in spider_stack:
            found = False
            for cat, components in TECH_SIGNATURES.items():
                if item in components.values():
                    profiler.stack[cat].add(item)
                    found = True
                    break
            if not found:
                profiler.stack["Other"].add(item)

        # 2. Ingest paths (URLs)
        urls = [ep.get("url", "") for ep in spider_intel.get("endpoints", [])]
        profiler.ingest_paths(urls)

        # 3. Ingest headers
        for ep in spider_intel.get("endpoints", []):
            headers = ep.get("headers", {})
            for k, v in headers.items():
                profiler.ingest_raw_text(f"{k}: {v}")

    emit.info(f"TechProfiler: Building profile for {target}")

    report = profiler.finalize()
    if not show_all:
        # Filter out very common noise if show_all is False
        for cat in report:
            report[cat] = [i for i in report[cat] if i not in ("Cloudflare", "Bootstrap")]

    any_found = any(report.values())
    if not any_found:
        emit.info("No definitive technologies identified.")
    else:
        emit.success("Technology stack profile constructed.")
        for cat, items in report.items():
            if items:
                emit.info(f"    - {cat}: {', '.join(items)}")

    return {
        "intel": {
            "stack": report,
            "signals": profiler.signals
        },
        "risk_score": 0
    }
