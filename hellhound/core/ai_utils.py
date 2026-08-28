import requests
import json
import logging
import concurrent.futures
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple, Callable, Union

logger = logging.getLogger("hellhound.ai_utils")

# Path to persistent Hellhound configuration
CONFIG_DIR = Path.home() / ".hellhound"
CONFIG_FILE = CONFIG_DIR / "config.json"

def strip_thinking_tags(text: str) -> str:
    """
    Strips chain-of-thought/reasoning blocks (<think>...</think>, <thinking>...</thinking>,
    <reasoning>...</reasoning>) from model output while preserving actual answers.
    Falls back to original unstripped text if stripping leaves an empty string.
    """
    if not text or not isinstance(text, str):
        return text or ""
    
    # Strip complete blocks (non-greedy, case-insensitive, DOTALL)
    cleaned = re.sub(r'<(?:think|thinking|reasoning)>[\s\S]*?</(?:think|thinking|reasoning)>', '', text, flags=re.IGNORECASE).strip()
    
    # Strip trailing unclosed opening tags (in case response was truncated)
    if re.search(r'<(?:think|thinking|reasoning)>', cleaned, flags=re.IGNORECASE):
        cleaned = re.sub(r'<(?:think|thinking|reasoning)>[\s\S]*$', '', cleaned, flags=re.IGNORECASE).strip()
        
    return cleaned if cleaned else text.strip()

def load_config() -> Dict[str, Any]:
    """Loads persistent Hellhound configuration from ~/.hellhound/config.json."""
    default_config: Dict[str, Any] = {
        "ai_provider": "ollama",
        "ai_model": "",
        "orchestrator_provider": "ollama",
        "orchestrator_model": "",
        "synthesizer_provider": "nvidia",
        "synthesizer_model": "nvidia/nemotron-3-super-120b-a12b",
        "api_key": "ollama",
        "researcher_handle": "",
        "max_response_tokens": 8192,
        # Ceiling on tool calls per user turn in Agent.handle_message()'s
        # orchestrator loop. Kept generous (Claude-Code-CLI style — run
        # until DONE, not until an arbitrary shallow cap) because multi-stage
        # chains (recon -> auth bypass -> IDOR -> token swap -> gowitness ->
        # record_finding) routinely need more than a handful of tool calls.
        # The loop already has its own stopping conditions (DONE, duplicate
        # tool-call detection, cancel_check) — this is a hard backstop against
        # a genuinely runaway loop, not the primary control.
        "max_agent_iterations": 60,
        "auto_install_missing_tools": False,
        "show_recaps": True,
        "api_keys": {},
        "global_headers": {},
        "scope": {
            "in_scope": [],
            "out_scope": [],
            "disallowed": [],
            "raw_text": ""
        }
    }
    if not CONFIG_FILE.exists():
        return default_config
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                # Ensure defaults for newly introduced keys
                if "auto_install_missing_tools" not in data:
                    data["auto_install_missing_tools"] = False
                if "max_agent_iterations" not in data:
                    data["max_agent_iterations"] = default_config["max_agent_iterations"]
                # Two-tier model backward compatibility fallbacks
                legacy_prov = data.get("ai_provider", "ollama")
                legacy_model = data.get("ai_model", "")
                if "orchestrator_provider" not in data:
                    data["orchestrator_provider"] = legacy_prov
                if "orchestrator_model" not in data:
                    data["orchestrator_model"] = legacy_model
                if "synthesizer_provider" not in data:
                    data["synthesizer_provider"] = "nvidia" if ("api_keys" in data and "nvidia" in data.get("api_keys", {})) else legacy_prov
                if "synthesizer_model" not in data:
                    data["synthesizer_model"] = "nvidia/nemotron-3-super-120b-a12b" if data.get("synthesizer_provider") == "nvidia" else legacy_model
                return data
            return default_config
    except Exception as e:
        logging.warning(f"Failed to load config from {CONFIG_FILE}: {e}")
        return default_config

def save_config(config: Dict[str, Any]) -> bool:
    """Saves persistent Hellhound configuration to ~/.hellhound/config.json."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        logging.error(f"Failed to save config to {CONFIG_FILE}: {e}")
        return False

# ==========================================================
# HELLHOUND AI PERSONAS
# ==========================================================

AUDIT_PERSONA = """\
[SYSTEM: HELLHOUND IMPACT AUDITOR — TRUE/FALSE POSITIVE + BOUNTY IMPACT]

You are a senior bug bounty triager. Your task is to audit a security finding with extreme prejudice toward false positives.

For each finding, output EXACTLY this structure:

---
**VERDICT**: [TRUE POSITIVE | FALSE POSITIVE | INCONCLUSIVE]

**CONFIDENCE**: [0.0 to 1.0]

**WHY VERDICT**:
- One sentence explaining the core technical reason.

**BUSINESS IMPACT**:
- What data/control/system is at risk?
- Worst-case scenario in plain English.

**BOUNTY TIER ESTIMATE**:
- [Low | Medium | High | Critical] based on impact, not CVSS.

**CHAIN POTENTIAL**:
- If this is real: what 1-2 other findings would make it critical?
- If false positive: what condition would turn it into a true positive?

**REMEDIATION**:
- Code-level fix that breaks the vulnerability.
---
"""

IMPACT_ADVISOR_PERSONA = """\
[SYSTEM: HELLHOUND IMPACT ADVISOR — WORST-CASE CALCULATOR]

You are Hellhound. Your mission: take a security finding and calculate its maximum real-world impact from a bug bounty perspective.

For each finding, output EXACTLY:

---
**FINDING**: [short name]

**WORST-CASE SCENARIO** (one sentence):
- [e.g., Attacker reads any user's private messages without interaction]

**ESCALATION PATHWAYS** (1-3 ways to make this Critical):
1. [Escalation step]

**BOUNTY JUSTIFICATION**:
- Why a program should pay High or Critical for this chain.
---
"""

CORRELATION_PERSONA = """\
[SYSTEM: HELLHOUND CORE — RECON & FINDINGS TRIAGE]

You are Hellhound, an autonomous bug bounty reconnaissance and triage assistant.
Your goal is to organize recon discoveries (subdomains, open ports, live web tech, API routes, CORS/CNAME status) into actionable, non-destructive findings.
"""

ASK_PERSONA = """\
[SYSTEM: HELLHOUND CORE — TACTICAL ADVISORY]

You are Hellhound, a concise, high-fidelity bug bounty research assistant.
Minimalist. Tactical. Zero fluff. Provide factual, technical answers.
"""

ASK_PERSONA_SLM = """\
[SYSTEM: HELLHOUND — ASSISTANT]
You are Hellhound, a capable cybersecurity and bug bounty triage assistant.
You are professional, technical, and concise.
Answer the user's technical questions accurately based on the provided context. If the user asks a casual question, reply naturally.
"""

CORRELATION_PERSONA_SLM = """\
You are Hellhound. Correlate recon findings into clear triage summaries.
Label missing data as [MISSING].
"""

AUDIT_PERSONA_SLM = """\
You are a senior bug bounty triager. Audit this finding.
VERDICT: (TRUE POSITIVE / FALSE POSITIVE / INCONCLUSIVE)
CONFIDENCE: (0.0-1.0)
REASON: (one sentence)
IMPACT: (worst case)
REPORTING STRATEGY: (Low/Medium/High/Critical)
"""

CHAT_PERSONA_SLM = """\
You are Hellhound, a helpful bug bounty research and triage assistant.
For casual conversation: respond naturally and conversationally in 1-3 sentences max.
"""


SYNTHESIZER_PERSONA = """\
You are HELLHOUND, an autonomous bug bounty reconnaissance and triage assistant.

Your job is to tell the researcher exactly what happened, no more, no less. 
Report like a competent colleague sitting next to them, not a press release. 
Dry, direct, a little wit where it fits naturally, but the finding always comes 
first and the personality never gets in the way of the facts. Skepticism is 
the default position, not an occasional flourish, if the evidence doesn't 
prove what it looks like it proves, say that plainly instead of dressing it up.

CORE REPORTING & STATUS PROTOCOL:

1. OBJECTIVE FIDELITY & STATUS CLASSIFICATION (LIVE RECON/ATTACK CAMPAIGNS ONLY)
   If and ONLY IF an active target investigation or attack campaign was executed,
   open the response with the status classification:
   - [STATUS: OBJECTIVE ACHIEVED / FULL TAKEOVER] — target account was compromised.
   - [STATUS: PARTIAL / IN PROGRESS] — stepping-stone access only.
   - [STATUS: BLOCKED / EXHAUSTED] — all attack vectors were tested and failed.

   DO NOT output [STATUS: ...] tags for general Q&A, sample reports, or code discussions.
   
   Never claim a full takeover off the back of a low-privilege account. That's 
   not an optimistic read of the evidence, it's just wrong, and wrong reports 
   waste the researcher's time chasing a win that isn't there.

2. HONEST & ACTIONABLE BREAKDOWN
   Say what was actually done and what evidence backs it, specifically, not 
   "the target was tested" in the vague sense that means nothing. If the 
   objective isn't complete, say exactly which attack vectors are still open 
   and what the next move should be. A status without a next step is half 
   a report.

3. CONCISE, FACTUAL SYNTHESIS
   Technical, evidence-backed, no padding. An HTTP 200 is a response code, 
   not a confirmed vulnerability, treat it as exactly that until something 
   actually proves impact. If the evidence is thin, say the evidence is thin, 
   don't round it up to "likely exploitable" because that sounds better in 
   a report.
"""

# ==========================================================
# UI RENDERING TOKENS & UTILS
# ==========================================================

HR  = "\033[91;1m"   # Hot Red
CY  = "\033[38;5;51m" # HUD Cyan
Y   = "\033[93;1m"   # Yellow
W   = "\033[97m"     # White
DIM = "\033[90m"     # Dim Grey
MUT = "\033[38;5;245m" # Muted
RST = "\033[0m"      # Reset

def _cols():
    import shutil
    return shutil.get_terminal_size((80, 24)).columns

def _section_label(label: str):
    cols = _cols()
    tag_plain_len = 3 + len(label) + 1
    fill = max(0, cols - tag_plain_len - 2)
    return f"  {HR}▸ {label}{RST} {DIM}{'─' * fill}{RST}"

def render_ai_box(text: str, width: int = 0):
    """Renders AI output in terminal prompt style, spanning the full terminal width."""
    import textwrap
    cols = width or _cols()
    max_w = cols - 8

    for line in text.strip().split('\n'):
        line = line.strip()
        if not line:
            print()
            continue
        if line == '---':
            continue

        if line.startswith('**') and line.endswith('**'):
            print(_section_label(line.strip('*').strip()))
            continue

        if '**' in line:
            segments = line.split('**')
            out = "  "
            for j, seg in enumerate(segments):
                if j % 2 == 1:
                    clean_seg = seg.rstrip(':')
                    out += f"{HR}{clean_seg}:{RST} "
                else:
                    out += f"{W}{seg}{RST}"
            print(out)
        elif line.startswith(('-', '•')):
            clean = line.lstrip('-•').strip()
            wrapped = textwrap.wrap(clean, width=max_w - 4) or [clean]
            print(f"    {W}{wrapped[0]}{RST}")
            for cont in wrapped[1:]:
                print(f"    {W}{cont}{RST}")
        elif line[0:1].isdigit() and '.' in line[:3]:
            dot = line.index('.')
            num = line[:dot]
            rest = line[dot+1:].strip()
            wrapped = textwrap.wrap(rest, width=max_w - 6) or [rest]
            print(f"     {Y}{num}.{RST} {W}{wrapped[0]}{RST}")
            for cont in wrapped[1:]:
                print(f"        {W}{cont}{RST}")
        else:
            wrapped = textwrap.wrap(line, width=max_w) or [line]
            for wl in wrapped:
                print(f"  {W}{wl}{RST}")
    print()

def render_session_header(target: str = ""):
    cols = _cols()
    title = " HELLHOUND "
    padding = (cols - len(title)) // 2
    print(f"\n{HR}{'█' * padding}{W}{title}{HR}{'█' * (cols - padding - len(title))}{RST}\n")

def render_session_divider():
    cols = _cols()
    print(f"\n{HR}{'─' * cols}{RST}\n")

def render_session_footer():
    cols = _cols()
    label = " SESSION CLOSED "
    padding = (cols - len(label)) // 2
    print(f"{HR}{'█' * padding}{W}{label}{HR}{'█' * (cols - padding - len(label))}{RST}\n")

def render_chat_bubble(text: str, sender: str = "HELLHOUND"):
    if not text or not text.strip():
        return
    try:
        from rich.console import Console
        from rich.markdown import Markdown
        console = Console()
        print()
        console.print(Markdown(text.strip()))
        print()
    except Exception:
        print(f"\n{text.strip()}\n")

class ThinkingIndicator:
    """Thread-safe floating loader supporting dynamic step emission, tool action trees, and clean shutdown."""
    def __init__(self, label="Let me think", status_callback=None):
        self.label = label
        self.status_callback = status_callback
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.thread = None
        self.start_time = time.time()
        self.token_count = 0
        # Rotating braille spinner — bare frames, no brackets, with red color pulse
        self.frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.pulse_colors = [
            "\033[38;5;196;1m",  # bright red
            "\033[38;5;203;1m",  # coral
            "\033[38;5;210;1m",  # salmon
            "\033[38;5;217;1m",  # light pink
            "\033[38;5;210;1m",  # salmon (back)
            "\033[38;5;203;1m",  # coral (back)
        ]

    def update_tokens(self, n: int):
        """Thread-safe token count update. Call with delta (streaming) or absolute (final)."""
        if n is None:
            return
        with self.lock:
            self.token_count += n

    def set_token_count(self, n: int):
        """Set the authoritative token count (overwrites running estimate)."""
        if n is None:
            return
        with self.lock:
            self.token_count = n

    def start(self):
        self.stop_event.clear()
        self.start_time = time.time()
        self.token_count = 0
        self.thread = threading.Thread(target=self._animate, daemon=True)
        self.thread.start()
        return self

    def _animate(self):
        idx = 0
        while not self.stop_event.is_set():
            with self.lock:
                try:
                    if not self.stop_event.is_set():
                        dot = self.frames[idx % len(self.frames)]
                        elapsed = int(time.time() - self.start_time)
                        tok_suffix = f" · ↓ {self.token_count} tokens" if self.token_count > 0 else ""
                        time_str = f"({elapsed}s{tok_suffix} · esc to interrupt)"
                        if self.status_callback:
                            self.status_callback("status", f"{dot} {self.label}... {time_str}")
                        elif sys.stdout and not sys.stdout.closed:
                            c = self.pulse_colors[idx % len(self.pulse_colors)]
                            msg = f"\r {c}{dot}\033[0m \033[38;5;245m{self.label}...\033[0m \033[38;5;240m{time_str}\033[0m\033[K"
                            sys.stdout.write(msg)
                            sys.stdout.flush()
                except (BrokenPipeError, OSError):
                    break
                except Exception:
                    pass
            idx += 1
            time.sleep(0.08)

    def set_label(self, label: str):
        with self.lock:
            self.label = label
            if self.status_callback:
                self.status_callback("status", f"{self.label}...")
            else:
                try:
                    if not self.stop_event.is_set() and sys.stdout and not sys.stdout.closed:
                        sys.stdout.write("\r" + " " * 80 + "\r")
                        sys.stdout.flush()
                except Exception:
                    pass

    def progress_start(self, desc: str, total: int = 0):
        """engine.run_single()/run_external() call emit.progress_start(name)
        before running a module and emit.progress_stop() in a `finally`
        afterward. On the CLI path a raw ThinkingIndicator is passed as
        `emit` (the GUI path wraps it in GuiEmit, which already defines
        these) — without this alias every module run raised
        AttributeError immediately. Just relabels the already-running
        spinner; does not touch the thread.
        """
        self.set_label(desc)

    def progress_stop(self):
        """Counterpart to progress_start(). Deliberately a no-op rather
        than stopping the indicator thread: one ThinkingIndicator is
        shared across every tool call in a turn (started once in
        chat_ui.py, stopped once in that turn's `finally`), so killing
        the thread here would end the spinner after the first tool call
        in any multi-tool turn.
        """
        pass

    def tool_start(self, tool_name: str, args: Dict[str, Any]):
        """Prints a Claude Code-style action bullet for tool execution."""
        if self.status_callback:
            self.status_callback("tool_start", {"tool": tool_name, "args": args})
            return
        formatted_name = tool_name.replace("_", " ").title().replace(" ", "")
        args_items = []
        for k, v in (args or {}).items():
            val_str = json.dumps(v) if isinstance(v, (dict, list)) else str(v)
            if len(val_str) > 35:
                val_str = val_str[:32] + "..."
            args_items.append(f"{k}={val_str}")
        args_str = ", ".join(args_items)
        if len(args_str) > 75:
            args_str = args_str[:72] + "..."
        with self.lock:
            try:
                if sys.stdout and not sys.stdout.closed:
                    sys.stdout.write("\r" + " " * 80 + "\r")
                    sys.stdout.write(f" \033[38;5;46;1m●\033[0m \033[1;97m{formatted_name}\033[0m\033[38;5;244m({args_str})\033[0m\n")
                    sys.stdout.flush()
            except Exception:
                pass

    def tool_result(self, tool_name: str, result: Any):
        """Prints a nested branch summarizing tool results."""
        if self.status_callback:
            self.status_callback("tool_result", {"tool": tool_name, "result": result})
            return
        summary = self._summarize_result(tool_name, result)
        icon = "✓"
        color = "\033[38;5;46;1m"
        if isinstance(result, dict) and result.get("error"):
            icon = "✗"
            color = "\033[38;5;196;1m"
        elif isinstance(result, dict) and result.get("blocked"):
            icon = "!"
            color = "\033[38;5;220;1m"
        with self.lock:
            try:
                if sys.stdout and not sys.stdout.closed:
                    sys.stdout.write("\r" + " " * 80 + "\r")
                    sys.stdout.write(f"   \033[38;5;240m└\033[0m {color}{icon}\033[0m \033[38;5;250m{summary}\033[0m\n")
                    sys.stdout.flush()
            except Exception:
                pass

    def _summarize_result(self, tool_name: str, result: Any) -> str:
        if not isinstance(result, dict):
            return str(result)[:80]
        if result.get("blocked"):
            return f"\033[38;5;220mBlocked:\033[0m {result.get('error', 'Scope refusal')}"
        if result.get("error"):
            return f"\033[38;5;196mError:\033[0m {result['error']}"

        if tool_name == "port_scan":
            ports = result.get("open_ports", [])
            return f"Discovered {len(ports)} open port(s): {', '.join(map(str, ports[:8]))}{'...' if len(ports) > 8 else ''}"
        elif tool_name == "permute_subdomains":
            count = result.get("permutation_count", len(result.get("candidates", [])))
            return f"Generated {count} candidate permutation(s)"
        elif tool_name == "resolve_candidates":
            resolved = result.get("resolved", [])
            res_items = []
            for r in resolved[:10]:
                if isinstance(r, dict):
                    res_items.append(r.get("host") or r.get("domain") or str(r))
                else:
                    res_items.append(str(r))
            res_str = f": {', '.join(res_items)}{'...' if len(resolved) > 10 else ''}" if resolved else ""
            return f"Resolved {len(resolved)} live host(s) across DNS{res_str}"
        elif tool_name == "subfinder":
            subs = result.get("subdomains", [])
            subs_str = f": {', '.join(subs[:10])}{'...' if len(subs) > 10 else ''}" if subs else ""
            return f"Discovered {len(subs)} subdomain(s) via passive CT sources{subs_str}"
        elif tool_name == "dns_bruteforce":
            subs = result.get("subdomains", [])
            subs_str = f": {', '.join(subs[:10])}{'...' if len(subs) > 10 else ''}" if subs else ""
            return f"Brute-forced {len(subs)} active DNS subdomain(s){subs_str}"
        elif tool_name == "httpx":
            live = result.get("live_hosts", [])
            live_items = []
            for h in live[:10]:
                if isinstance(h, dict):
                    live_items.append(h.get("url") or h.get("host") or str(h))
                else:
                    live_items.append(str(h))
            live_str = f": {', '.join(live_items)}{'...' if len(live) > 10 else ''}" if live else ""
            return f"Probed {len(live)} live HTTP/HTTPS service(s){live_str}"
        elif tool_name == "spider":
            eps = result.get("endpoints_found", 0)
            return f"Crawled application — found {eps} endpoint(s)"
        elif tool_name == "tls_cert_scan":
            names = result.get("subject_names", [])
            return f"Extracted {len(names)} SAN/CN record(s) from TLS certificate"
        elif tool_name == "vhost_fuzz":
            vhosts = result.get("vhosts", [])
            return f"Discovered {len(vhosts)} virtual host(s)"
        elif tool_name == "content_discovery":
            paths = result.get("paths", [])
            return f"Discovered {len(paths)} path(s)"
        elif tool_name in ("subzy", "takeover_scanner"):
            subs = result.get("takeovers", [])
            return f"Scanned {len(subs)} service(s) for subdomain takeover"
        elif tool_name == "hydra":
            vulns = result.get("vulnerabilities", [])
            return f"Audited surface — {len(vulns)} high-impact finding(s)"
        elif tool_name == "cloudscout":
            assets = result.get("assets", [])
            return f"Identified {len(assets)} cloud asset(s)"
        elif tool_name == "transport_auditor":
            findings = result.get("findings", [])
            return f"Audited TLS/transport — {len(findings)} security observation(s)"
        elif tool_name == "fuzz_hunter":
            endpoints = result.get("discovered_endpoints", [])
            return f"Discovered {len(endpoints)} endpoint(s) via parameter fuzzing"
        elif tool_name == "wafbuster":
            waf = result.get("waf", result.get("detected_waf", "None"))
            return f"Fingerprinted WAF: {waf}"
        elif tool_name == "cors_checker":
            vulns = result.get("cors_issues", [])
            return f"Audited CORS — {len(vulns)} misconfiguration(s) found"
        elif tool_name == "graphql_probe":
            schema = result.get("schema_exposed", False)
            return f"Probed GraphQL — schema {'exposed' if schema else 'secured'}"
        elif tool_name == "surface_auditor":
            surfaces = result.get("surfaces", [])
            return f"Audited API attack surfaces — {len(surfaces)} surface(s) analyzed"
        elif tool_name == "jwt_forge":
            role = result.get("forged_payload", {}).get("role", "admin")
            tokens = result.get("forged_tokens", [])
            return f"Forged JWT ({len(tokens)} variant(s), role={role}) — target session updated"
        elif tool_name == "content_discovery":
            paths = result.get("paths") or [r.get("path") for r in result.get("discovered_endpoints", [])]
            count = result.get("count", len(paths))
            if paths:
                sample = ", ".join(f"/{p}" for p in paths[:3])
                if len(paths) > 3:
                    sample += f" (+{len(paths)-3} more)"
                return f"Discovered {count} path(s): {sample}"
            return "Discovered 0 paths"
        elif tool_name == "curl":
            status = result.get("status_code", 0)
            url_val = result.get("url", "")
            routes = result.get("detected_routes", [])
            jwt_info = result.get("jwt_info", {})
            parts = [f"HTTP {status}"]
            if jwt_info:
                parts.append(f"JWT role={jwt_info.get('role', '?')} ({jwt_info.get('alg', '?')})")
            if routes:
                parts.append(f"{len(routes)} route(s) extracted")
            return f"{' · '.join(parts)} — {url_val}"
        elif tool_name == "load_skill":
            skill_val = result.get("skill", "")
            return f"Loaded skill methodology: {skill_val}"
        elif tool_name == "run_terminal_command":
            code = result.get("exit_code", 0)
            out = (result.get("stdout") or result.get("stderr") or "").strip()
            if out:
                clean_out = " ".join(out.split())
                if len(clean_out) > 85:
                    clean_out = clean_out[:82] + "..."
                return f"Exit code {code} — {clean_out}"
            return f"Command executed (exit code {code})"

        keys = [k for k in result.keys() if k not in ("target", "state")]
        if keys:
            first_key = keys[0]
            val = result[first_key]
            if isinstance(val, list):
                return f"Processed {len(val)} {first_key}"
            return f"{first_key}: {str(val)[:60]}"
        return "Operation completed successfully"

    def print_step(self, icon: str, msg: str, color: str = "\033[38;5;203;1m"):
        if self.status_callback:
            event_type = "info"
            if icon == "✓":
                event_type = "success"
            elif icon == "!":
                event_type = "warn"
            elif icon == "✗":
                event_type = "error"
            self.status_callback(event_type, msg)
            return
        with self.lock:
            try:
                if sys.stdout and not sys.stdout.closed:
                    sys.stdout.write("\r" + " " * 80 + "\r")
                    sys.stdout.write(f"   \033[38;5;240m└\033[0m {color}{icon}\033[0m \033[38;5;250m{msg}\033[0m\n")
                    sys.stdout.flush()
            except Exception:
                pass

    def info(self, msg: str):
        self.print_step("*", msg, "\033[38;5;203;1m")

    def success(self, msg: str):
        self.print_step("✓", msg, "\033[38;5;46;1m")

    def warn(self, msg: str):
        self.print_step("!", msg, "\033[38;5;220;1m")

    def warning(self, msg: str):
        self.warn(msg)

    def error(self, msg: str):
        self.print_step("✗", msg, "\033[38;5;196;1m")

    def stop(self):
        self.stop_event.set()
        if not self.status_callback:
            with self.lock:
                try:
                    if sys.stdout and not sys.stdout.closed:
                        sys.stdout.write("\r" + " " * 80 + "\r")
                        sys.stdout.flush()
                except Exception:
                    pass
        if self.thread and self.thread.is_alive():
            try:
                self.thread.join(timeout=0.3)
            except Exception:
                pass

def thinking_animation(label="Let me think"):
    """Start a clean 6-dot floating loader that stays strictly on a single line and never breaks."""
    indicator = ThinkingIndicator(label)
    indicator.start()
    return indicator.thread, indicator.stop_event

def detect_ai_config(api_key: str) -> Tuple[Optional[str], Optional[str]]:
    """Automatically identifies the AI provider based on API key prefix."""
    if not api_key:
        return None, None
    if api_key.startswith("AIza"):
        return "gemini", "gemini-2.0-flash"
    elif api_key.startswith("sk-ant-"):
        return "anthropic", "claude-3-5-sonnet-20240620"
    elif api_key.startswith("nvapi-"):
        return "nvidia", "nvidia/nemotron-3-super-120b-a12b"
    elif api_key.startswith("sk-"):
        return "openai", "gpt-4o"
    elif api_key == "ollama":
        return "ollama", None
    return None, None

def classify_intent(user_input: str) -> str:
    """Lightweight intent classification.
    Most routing is handled natively by the unified model context,
    avoiding brittle keyword lists.
    """
    text = (user_input or "").lower().strip()
    if text in ("hi", "hello", "hey", "ping", "test", "yo"):
        return "chat"
    return "hunt"

def get_default_model(provider: str) -> str:
    """Dynamically determines the default model for a given provider."""
    provider = (provider or "").lower().strip()
    if provider == "ollama" or provider == "local":
        try:
            r = requests.get("http://localhost:11434/api/tags", timeout=2)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                if models:
                    preferred = ["qwen2.5:3b-instruct-q4_0", "llama3.2:3b", "phi3:mini", "gemma2:2b", "llama3:8b", "mistral"]
                    for p in preferred:
                        for m in models:
                            if p in m:
                                return m
                    return models[0]
        except Exception:
            pass
        return "qwen2.5:3b-instruct-q4_0"
    elif provider == "nvidia" or provider == "nim":
        return "nvidia/nemotron-3-super-120b-a12b"
    elif provider == "gemini":
        return "gemini-2.0-flash"
    elif provider == "anthropic":
        return "claude-3-5-sonnet-20240620"
    elif provider == "openai":
        return "gpt-4o"
    return "auto"

def list_available_models() -> List[Dict[str, Any]]:
    """
    Returns a comprehensive list of all accessible local and cloud models.
    """
    cfg = load_config()
    curr_prov = cfg.get("ai_provider", "ollama")
    curr_mod = cfg.get("ai_model", "")
    api_keys = cfg.get("api_keys", {})
    if not isinstance(api_keys, dict):
        api_keys = {}
    if "api_key" in cfg and cfg["api_key"] and cfg["api_key"] != "ollama":
        prov, _ = detect_ai_config(cfg["api_key"])
        if prov and prov not in api_keys:
            api_keys[prov] = cfg["api_key"]

    models_list = []

    # 1. Check Ollama
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        if r.status_code == 200:
            for m in r.json().get("models", []):
                name = m.get("name", "")
                is_curr = (curr_prov == "ollama" and (curr_mod == name or (not curr_mod and name == get_default_model("ollama"))))
                models_list.append({
                    "name": name,
                    "provider": "ollama",
                    "type": "local",
                    "current": is_curr,
                    "size": m.get("size", 0)
                })
    except Exception:
        pass

    # 2. Check NVIDIA NIM
    nv_key = api_keys.get("nvidia") or os.environ.get("NVIDIA_API_KEY") or (cfg.get("api_key") if str(cfg.get("api_key", "")).startswith("nvapi-") else None)
    if nv_key:
        nim_models = [
            "nvidia/nemotron-3-super-120b-a12b",
            "meta/llama-3.3-70b-instruct",
            "meta/llama-3.1-70b-instruct",
            "meta/llama-3.1-8b-instruct",
            "mistralai/mistral-large-2-instruct",
            "deepseek-ai/deepseek-r1"
        ]
        for nm in nim_models:
            is_curr = (curr_prov in ("nvidia", "nim") and curr_mod == nm)
            models_list.append({
                "name": nm,
                "provider": "nvidia",
                "type": "cloud",
                "current": is_curr
            })

    # 3. Check Gemini
    gem_key = api_keys.get("gemini") or os.environ.get("GEMINI_API_KEY") or (cfg.get("api_key") if str(cfg.get("api_key", "")).startswith("AIza") else None)
    if gem_key:
        for gm in ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"]:
            is_curr = (curr_prov == "gemini" and curr_mod == gm)
            models_list.append({
                "name": gm,
                "provider": "gemini",
                "type": "cloud",
                "current": is_curr
            })

    # 4. Check OpenAI
    oa_key = api_keys.get("openai") or os.environ.get("OPENAI_API_KEY") or (cfg.get("api_key") if str(cfg.get("api_key", "")).startswith("sk-") and not str(cfg.get("api_key", "")).startswith("sk-ant-") else None)
    if oa_key:
        for oam in ["gpt-4o", "gpt-4o-mini", "o1-mini"]:
            is_curr = (curr_prov == "openai" and curr_mod == oam)
            models_list.append({
                "name": oam,
                "provider": "openai",
                "type": "cloud",
                "current": is_curr
            })

    # 5. Check Anthropic
    ant_key = api_keys.get("anthropic") or os.environ.get("ANTHROPIC_API_KEY") or (cfg.get("api_key") if str(cfg.get("api_key", "")).startswith("sk-ant-") else None)
    if ant_key:
        for antm in ["claude-3-5-sonnet-20240620", "claude-3-5-haiku-20241022"]:
            is_curr = (curr_prov == "anthropic" and curr_mod == antm)
            models_list.append({
                "name": antm,
                "provider": "anthropic",
                "type": "cloud",
                "current": is_curr
            })

    return models_list

def call_ai(prompt: str, provider: str, api_key: str, model: str = None, timeout: int = 300, system_prompt: str = None, history: list = None, thinking: bool = False, max_tokens: int = None, on_token: Optional[Callable[[str], None]] = None, return_usage: bool = False, cancel_check: Optional[Callable[[], bool]] = None, tools: Optional[List[Dict[str, Any]]] = None) -> Union[Optional[str], Tuple[Optional[str], Optional[int]]]:
    """Unified dispatcher for all supported AI providers. When `tools` is provided, providers attempt native tool calling."""
    provider = (provider or "ollama").lower().strip()
    
    if system_prompt is None:
        system_prompt = ASK_PERSONA_SLM

    active_model = model or get_default_model(provider)

    if provider in ("nvidia", "nim"):
        res = call_nvidia(prompt, api_key, model=active_model, timeout=timeout, history=history, system_prompt=system_prompt, thinking=thinking, max_tokens=max_tokens, on_token=on_token, return_usage=return_usage, cancel_check=cancel_check, tools=tools)
    elif provider == "openai":
        res = call_openai(prompt, api_key, model=active_model, timeout=timeout, history=history, system_prompt=system_prompt, thinking=thinking, max_tokens=max_tokens, on_token=on_token, return_usage=return_usage, tools=tools)
    elif provider == "anthropic":
        res = call_anthropic(prompt, api_key, model=active_model, timeout=timeout, history=history, system_prompt=system_prompt, thinking=thinking, max_tokens=max_tokens, on_token=on_token, return_usage=return_usage, tools=tools)
    elif provider == "gemini":
        res = ask_gemini(api_key, active_model, system_prompt, prompt, max_tokens=max_tokens, timeout=timeout, history=history, thinking=thinking, on_token=on_token, return_usage=return_usage, tools=tools)
    else: # Ollama / Local
        res = call_ollama(prompt, model=active_model, system_prompt=system_prompt, timeout=timeout, history=history, thinking=thinking, max_tokens=max_tokens, on_token=on_token, return_usage=return_usage, cancel_check=cancel_check, tools=tools)

    if return_usage:
        text, tokens = res
        cleaned = strip_thinking_tags(text) if isinstance(text, str) else text
        return (cleaned, tokens)
    
    return strip_thinking_tags(res) if isinstance(res, str) else res

def ask_neural_core(prompt: str, model: str = None, system_prompt: str = None, timeout: int = 300, role: str = "orchestrator", thinking: bool = False, max_tokens: int = None, history: list = None, on_token: Optional[Callable[[str], None]] = None, return_usage: bool = False, cancel_check: Optional[Callable[[], bool]] = None, tools: Optional[List[Dict[str, Any]]] = None) -> Union[Optional[str], Tuple[Optional[str], Optional[int]]]:
    """Config-aware wrapper to query the configured AI provider/model for a specific role (orchestrator vs synthesizer)."""
    cfg = load_config()
    provider = cfg.get(f"{role}_provider") or cfg.get("ai_provider", "ollama")
    active_model = model or cfg.get(f"{role}_model") or cfg.get("ai_model") or get_default_model(provider)

    # Resolve API key: api_keys[provider] → environment variable → legacy api_key field
    api_keys = cfg.get("api_keys", {})
    if not isinstance(api_keys, dict):
        api_keys = {}
    env_map = {
        "nvidia": "NVIDIA_API_KEY",
        "openai": "OPENAI_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
    }
    api_key = (
        api_keys.get(provider)
        or os.environ.get(env_map.get(provider, ""), "")
        or (cfg.get("api_key") if cfg.get("ai_provider") == provider else "")
        or ("ollama" if provider == "ollama" else "")
    )
    if not api_key and provider != "ollama":
        legacy_key = cfg.get("api_key", "")
        if legacy_key and legacy_key != "ollama":
            api_key = legacy_key

    # Graceful fallback: If cloud provider is requested but has no API key configured, route to local orchestrator
    if provider != "ollama" and not api_key:
        fallback_prov = cfg.get("orchestrator_provider") or cfg.get("ai_provider", "ollama")
        if fallback_prov == "ollama" or api_keys.get(fallback_prov) or os.environ.get(env_map.get(fallback_prov, ""), ""):
            provider = fallback_prov
            active_model = cfg.get("orchestrator_model") or cfg.get("ai_model") or get_default_model(provider)
            api_key = api_keys.get(provider) or os.environ.get(env_map.get(provider, ""), "") or "ollama"

    return call_ai(prompt, provider=provider, api_key=api_key, model=active_model, timeout=timeout, system_prompt=system_prompt, history=history, thinking=thinking, max_tokens=max_tokens, on_token=on_token, return_usage=return_usage, cancel_check=cancel_check, tools=tools)

def call_nvidia(prompt: str, api_key: str, model: str = "meta/llama-3.1-70b-instruct", timeout: int = 60, history: list = None, system_prompt: str = None, thinking: bool = False, max_tokens: int = None, on_token: Optional[Callable[[str], None]] = None, return_usage: bool = False, cancel_check: Optional[Callable[[], bool]] = None, tools: Optional[List[Dict[str, Any]]] = None) -> Union[Optional[str], Tuple[Optional[str], Optional[int]]]:
    """REST call to NVIDIA NIM OpenAI-compatible API with SSE streaming. Supports native tool calling."""
    try:
        url = "https://integrate.api.nvidia.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": prompt})

        cfg = load_config()
        resolved_max_tokens = max_tokens or cfg.get("max_response_tokens", 8192)

        payload = {
            "model": model,
            "messages": messages,
            "temperature": 0.5,
            "max_tokens": resolved_max_tokens,
            "stream": True,
            "chat_template_kwargs": {"thinking": thinking}
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
            # Disable streaming for tool calling — simpler to parse non-streamed tool_calls
            payload["stream"] = False
            r = requests.post(url, headers=headers, json=payload, timeout=timeout)
            if r.status_code != 200:
                err = f"Error: NVIDIA NIM API returned {r.status_code} - {r.text[:100]}"
                return (err, None) if return_usage else err
            data = r.json()
            usage_tokens = data.get("usage", {}).get("completion_tokens")
            choice = data.get("choices", [{}])[0]
            msg = choice.get("message", {})
            # Check for native tool calls
            if msg.get("tool_calls"):
                tc = msg["tool_calls"][0]  # Take first tool call
                fn = tc.get("function", {})
                try:
                    parsed_args = json.loads(fn.get("arguments", "{}"))
                except Exception:
                    parsed_args = {}
                result = {"tool": fn.get("name", ""), "args": parsed_args}
                return (result, usage_tokens) if return_usage else result
            # No tool call — return text content
            text = strip_thinking_tags(msg.get("content", "")) or None
            return (text, usage_tokens) if return_usage else text

        r = requests.post(url, headers=headers, json=payload, stream=True, timeout=timeout)
        if r.status_code != 200:
            err = f"Error: NVIDIA NIM API returned {r.status_code} - {r.text[:100]}"
            return (err, None) if return_usage else err

        full_response = []
        token_count = 0
        usage_tokens = None
        for line in r.iter_lines():
            if cancel_check and cancel_check():
                break
            if not line:
                continue
            decoded = line.decode("utf-8").strip()
            if not decoded:
                continue
            if decoded.startswith("data:"):
                data_str = decoded[5:].strip()
                if data_str == "[DONE]":
                    break
                try:
                    chunk = json.loads(data_str)
                    # Capture authoritative usage from final chunk if present
                    if chunk.get("usage"):
                        usage_tokens = chunk["usage"].get("completion_tokens")
                    choices = chunk.get("choices", [])
                    if choices:
                        delta = choices[0].get("delta", {})
                        token = delta.get("content", "")
                        if token:
                            full_response.append(token)
                            token_count += 1
                            if on_token:
                                on_token(token)
                except json.JSONDecodeError:
                    continue

        result = "".join(full_response).strip()
        cleaned = strip_thinking_tags(result)
        text = cleaned if cleaned else None
        if return_usage:
            return (text, usage_tokens if usage_tokens is not None else token_count)
        return text
    except Exception as e:
        err = f"Error: NVIDIA NIM connection failed ({str(e)})"
        return (err, None) if return_usage else err

def call_openai(prompt: str, api_key: str, model: str = "gpt-4o", timeout: int = 30, history: list = None, system_prompt: str = None, thinking: bool = False, max_tokens: int = None, on_token: Optional[Callable[[str], None]] = None, return_usage: bool = False, tools: Optional[List[Dict[str, Any]]] = None) -> Union[Optional[str], Tuple[Optional[str], Optional[int]]]:
    """REST call to OpenAI Chat Completions API with SSE streaming. Supports native tool calling."""
    try:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": prompt})

        cfg = load_config()
        resolved_max_tokens = max_tokens or cfg.get("max_response_tokens", 8192)

        payload = {"model": model, "messages": messages, "temperature": 0.7, "max_tokens": resolved_max_tokens, "stream": True}

        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
            payload["stream"] = False
            r = requests.post(url, headers=headers, json=payload, timeout=timeout)
            if r.status_code != 200:
                err = f"Error: OpenAI API returned {r.status_code}"
                return (err, None) if return_usage else err
            data = r.json()
            usage_tokens = data.get("usage", {}).get("completion_tokens")
            choice = data.get("choices", [{}])[0]
            msg = choice.get("message", {})
            if msg.get("tool_calls"):
                tc = msg["tool_calls"][0]
                fn = tc.get("function", {})
                try:
                    parsed_args = json.loads(fn.get("arguments", "{}"))
                except Exception:
                    parsed_args = {}
                result = {"tool": fn.get("name", ""), "args": parsed_args}
                return (result, usage_tokens) if return_usage else result
            text = strip_thinking_tags(msg.get("content", "")) or None
            return (text, usage_tokens) if return_usage else text
        r = requests.post(url, headers=headers, json=payload, stream=True, timeout=timeout)
        if r.status_code != 200:
            err = f"Error: OpenAI API returned {r.status_code}"
            return (err, None) if return_usage else err

        full_response = []
        token_count = 0
        for line in r.iter_lines():
            if not line:
                continue
            decoded = line.decode("utf-8").strip()
            if not decoded:
                continue
            if decoded.startswith("data:"):
                data_str = decoded[5:].strip()
                if data_str == "[DONE]":
                    break
                try:
                    chunk = json.loads(data_str)
                    choices = chunk.get("choices", [])
                    if choices:
                        delta = choices[0].get("delta", {})
                        token = delta.get("content", "")
                        if token:
                            full_response.append(token)
                            token_count += 1
                            if on_token:
                                on_token(token)
                except json.JSONDecodeError:
                    continue

        result = "".join(full_response).strip()
        cleaned = strip_thinking_tags(result)
        text = cleaned if cleaned else None
        if return_usage:
            return (text, token_count)
        return text
    except Exception as e:
        err = f"Error: OpenAI connection failed ({str(e)})"
        return (err, None) if return_usage else err

def call_anthropic(prompt: str, api_key: str, model: str = "claude-3-5-sonnet-20240620", timeout: int = 30, history: list = None, system_prompt: str = None, thinking: bool = False, max_tokens: int = None, on_token: Optional[Callable[[str], None]] = None, return_usage: bool = False, tools: Optional[List[Dict[str, Any]]] = None) -> Union[Optional[str], Tuple[Optional[str], Optional[int]]]:
    """REST call to Anthropic Messages API with SSE streaming. Supports native tool calling."""
    try:
        url = "https://api.anthropic.com/v1/messages"
        headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}
        
        messages = []
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": prompt})

        cfg = load_config()
        resolved_max_tokens = max_tokens or cfg.get("max_response_tokens", 8192)

        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": resolved_max_tokens,
            "temperature": 0.7,
            "stream": bool(on_token)
        }
        if system_prompt:
            payload["system"] = system_prompt

        if tools:
            # Convert OpenAI-format tools to Anthropic format
            anthropic_tools = []
            for t in tools:
                fn = t.get("function", t)
                anthropic_tools.append({
                    "name": fn.get("name", ""),
                    "description": fn.get("description", ""),
                    "input_schema": fn.get("parameters", {"type": "object", "properties": {}})
                })
            payload["tools"] = anthropic_tools
            payload["stream"] = False
            r = requests.post(url, headers=headers, json=payload, timeout=timeout)
            if r.status_code != 200:
                err = f"Error: Anthropic API returned {r.status_code}"
                return (err, None) if return_usage else err
            data = r.json()
            usage_tokens = data.get("usage", {}).get("output_tokens")
            # Check for tool_use content blocks
            for block in data.get("content", []):
                if block.get("type") == "tool_use":
                    result = {"tool": block.get("name", ""), "args": block.get("input", {})}
                    return (result, usage_tokens) if return_usage else result
            # No tool call — extract text
            text_parts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
            text = strip_thinking_tags(" ".join(text_parts).strip()) or None
            return (text, usage_tokens) if return_usage else text

        r = requests.post(url, headers=headers, json=payload, stream=bool(on_token), timeout=timeout)
        if r.status_code != 200:
            err = f"Error: Anthropic API returned {r.status_code}"
            return (err, None) if return_usage else err
        
        token_count = 0
        usage_tokens = None
        if on_token:
            full_response = []
            for line in r.iter_lines():
                if line:
                    decoded = line.decode("utf-8") if isinstance(line, bytes) else line
                    if decoded.startswith("data:"):
                        data_str = decoded[5:].strip()
                        if data_str == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data_str)
                            if chunk.get("type") == "message_start":
                                msg_info = chunk.get("message", {})
                                if "usage" in msg_info:
                                    usage_tokens = msg_info["usage"].get("output_tokens")
                            elif chunk.get("type") == "message_delta":
                                if "usage" in chunk:
                                    usage_tokens = chunk["usage"].get("output_tokens")
                            elif chunk.get("type") == "content_block_delta":
                                delta = chunk.get("delta", {})
                                if delta.get("type") == "text_delta":
                                    token = delta.get("text", "")
                                    if token:
                                        full_response.append(token)
                                        token_count += 1
                                        on_token(token)
                        except json.JSONDecodeError:
                            continue
            result = "".join(full_response).strip()
            cleaned = strip_thinking_tags(result)
            text = cleaned if cleaned else None
            if return_usage:
                return (text, usage_tokens if usage_tokens is not None else token_count)
            return text
        else:
            data = r.json()
            if "usage" in data:
                usage_tokens = data["usage"].get("output_tokens")
            raw_content = data["content"][0]["text"] if "content" in data and data["content"] else None
            text = strip_thinking_tags(raw_content) if raw_content else None
            if return_usage:
                return (text, usage_tokens)
            return text
    except Exception as e:
        err = f"Error: Anthropic connection failed ({str(e)})"
        return (err, None) if return_usage else err

def ask_gemini(api_key: str, model: str, system_prompt: str, user_message: str, max_tokens: int = None, timeout: int = 20, history: list = None, thinking: bool = False, on_token: Optional[Callable[[str], None]] = None, return_usage: bool = False, tools: Optional[List[Dict[str, Any]]] = None) -> Union[Optional[str], Tuple[Optional[str], Optional[int]]]:
    """Gemini API caller with SSE streaming support. Supports native function calling."""
    try:
        contents = []
        if history:
            for turn in history:
                role = "user" if turn["role"] == "user" else "model"
                contents.append({"role": role, "parts": [{"text": turn["content"]}]})
        contents.append({"role": "user", "parts": [{"text": user_message}]})

        cfg = load_config()
        resolved_max_tokens = max_tokens or cfg.get("max_response_tokens", 8192)

        payload = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": resolved_max_tokens,
                "temperature": 0.85,
                "topP": 0.9
            }
        }

        if tools:
            # Convert OpenAI-format tools to Gemini functionDeclarations
            func_decls = []
            for t in tools:
                fn = t.get("function", t)
                params = fn.get("parameters", {"type": "object", "properties": {}})
                # Gemini doesn't support additionalProperties — strip it
                clean_params = {k: v for k, v in params.items() if k != "additionalProperties"}
                func_decls.append({
                    "name": fn.get("name", ""),
                    "description": fn.get("description", ""),
                    "parameters": clean_params
                })
            payload["tools"] = [{"functionDeclarations": func_decls}]
            # Use non-streaming for tool calling
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
            r = requests.post(url, json=payload, timeout=timeout)
            if r.status_code != 200:
                err = f"Error: Gemini API returned {r.status_code} - {r.text[:100]}"
                return (err, None) if return_usage else err
            data = r.json()
            usage_tokens = data.get("usageMetadata", {}).get("candidatesTokenCount")
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                for part in parts:
                    if "functionCall" in part:
                        fc = part["functionCall"]
                        result = {"tool": fc.get("name", ""), "args": fc.get("args", {})}
                        return (result, usage_tokens) if return_usage else result
                # No function call — extract text
                raw_text = "".join(p.get("text", "") for p in parts if "text" in p)
                text = strip_thinking_tags(raw_text.strip()) or None
                return (text, usage_tokens) if return_usage else text
            err = "Error: No candidates in response"
            return (err, None) if return_usage else err
        endpoint = "streamGenerateContent?alt=sse" if on_token else "generateContent"
        sep = "&" if "?" in endpoint else "?"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:{endpoint}{sep}key={api_key}"

        r = requests.post(url, json=payload, stream=bool(on_token), timeout=timeout)
        if r.status_code != 200:
            err = f"Error: Gemini API returned {r.status_code} - {r.text[:100]}"
            return (err, None) if return_usage else err

        token_count = 0
        usage_tokens = None
        if on_token:
            full_response = []
            for line in r.iter_lines():
                if line:
                    decoded = line.decode("utf-8") if isinstance(line, bytes) else line
                    if decoded.startswith("data:"):
                        data_str = decoded[5:].strip()
                        if data_str == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data_str)
                            if "usageMetadata" in chunk:
                                usage_tokens = chunk["usageMetadata"].get("candidatesTokenCount")
                            candidates = chunk.get("candidates", [])
                            if candidates:
                                parts = candidates[0].get("content", {}).get("parts", [])
                                token = "".join(part.get("text", "") for part in parts if "text" in part and not part.get("thought", False))
                                if token:
                                    full_response.append(token)
                                    token_count += 1
                                    on_token(token)
                        except json.JSONDecodeError:
                            continue
            result = "".join(full_response).strip()
            cleaned = strip_thinking_tags(result)
            text = cleaned if cleaned else None
            if return_usage:
                return (text, usage_tokens if usage_tokens is not None else token_count)
            return text
        else:
            data = r.json()
            if "usageMetadata" in data:
                usage_tokens = data["usageMetadata"].get("candidatesTokenCount")
            if "candidates" not in data:
                err = f"Error: No candidates in response"
                return (err, None) if return_usage else err
            parts = data["candidates"][0]["content"]["parts"]
            raw_text = "".join(part["text"] for part in parts if "text" in part)
            cleaned = strip_thinking_tags(raw_text.strip())
            text = cleaned if cleaned else "Error: Empty response text"
            if return_usage:
                return (text, usage_tokens)
            return text
    except Exception as e:
        err = f"Error: Gemini connection failed ({str(e)})"
        return (err, None) if return_usage else err

def call_gemini(prompt: str, api_key: str, model: str = "gemini-2.0-flash", timeout: int = 30) -> str:
    res = ask_gemini(api_key, model, ASK_PERSONA, prompt, timeout=timeout)
    return res if res else "Error: AI analysis failed."

class _RepetitionGuard:
    """
    Detects the classic small-local-model failure mode: the model gets
    stuck regenerating the same sentence over and over instead of
    progressing (e.g. "Let me check the baseline response..." x40).

    This is NOT a planner/state-machine issue -- it's a token-generation
    degeneracy in the underlying model, most visible on low-temperature
    passes with small quantized models. The fix belongs at the streaming
    layer: watch the accumulating text for an exact phrase repeating past
    a small threshold, and cut generation off there instead of riding it
    out to max_tokens.
    """

    def __init__(self, min_phrase_len: int = 40, max_repeats: int = 2):
        self.min_phrase_len = min_phrase_len
        self.max_repeats = max_repeats
        self._buffer = ""

    def feed(self, chunk: str) -> bool:
        """Returns True the moment a loop is detected -- caller should stop."""
        self._buffer += chunk
        # Only worth checking once we have enough text for a real phrase,
        # and only re-check periodically (on sentence-ish boundaries) so
        # this stays cheap on a hot streaming loop.
        if len(self._buffer) < self.min_phrase_len * (self.max_repeats + 1):
            return False
        if chunk and chunk[-1] not in ".!?\n" and len(self._buffer) % 24 != 0:
            return False

        tail = self._buffer[-self.min_phrase_len:]
        occurrences = self._buffer.count(tail)
        return occurrences > self.max_repeats


def call_ollama(prompt: str, model: str = None, system_prompt: str = None, timeout: int = 300, history: list = None, thinking: bool = False, max_tokens: int = None, on_token: Optional[Callable[[str], None]] = None, return_usage: bool = False, cancel_check: Optional[Callable[[], bool]] = None, tools: Optional[List[Dict[str, Any]]] = None) -> Union[Optional[str], Tuple[Optional[str], Optional[int]]]:
    """REST call to local Ollama API using chat endpoint. Supports native tool calling."""
    try:
        model = model or get_default_model("ollama")
        url = "http://localhost:11434/api/chat"
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": prompt})
        
        cfg = load_config()
        resolved_max_tokens = max_tokens or cfg.get("max_response_tokens", 8192)
        
        n_ctx = 4096
        n_predict = resolved_max_tokens
        temp = 0.7

        if system_prompt:
            if "For casual conversation:" in system_prompt:
                n_ctx = 512
                n_predict = 64
                temp = 0.6
            elif "HELLHOUND Orchestrator" in system_prompt:
                n_ctx = 1024
                n_predict = 192
                temp = 0.2

        payload = {
            "model": model,
            "messages": messages,
            "stream": True,
            "keep_alive": -1,
            "options": {
                "temperature": temp,
                "top_p": 0.9,
                "num_predict": n_predict,
                "num_ctx": n_ctx,
                # Small quantized models degenerate into exact-sentence
                # loops without this — was previously unset, i.e. running
                # on whatever the model's Modelfile happened to default to.
                "repeat_penalty": 1.3,
                "repeat_last_n": 256,
            }
        }
        if not thinking:
            payload["think"] = False

        # Native tool calling path
        if tools:
            payload["tools"] = tools
            payload["stream"] = False  # Non-streamed for simpler tool_calls parsing
            r = requests.post(url, json=payload, timeout=timeout)
            if r.status_code != 200:
                err = f"Error: Ollama returned status {r.status_code}"
                return (err, None) if return_usage else err
            data = r.json()
            eval_count = data.get("eval_count")
            msg = data.get("message", {})
            # Check for native tool calls
            if msg.get("tool_calls"):
                tc = msg["tool_calls"][0]
                fn = tc.get("function", {})
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {}
                result = {"tool": fn.get("name", ""), "args": args}
                return (result, eval_count) if return_usage else result
            # No tool call — return text content
            text = strip_thinking_tags(msg.get("content", "")) or None
            return (text, eval_count) if return_usage else text
        
        r = requests.post(url, json=payload, stream=True, timeout=timeout)
        if r.status_code != 200:
            err = f"Error: Ollama returned status {r.status_code}"
            return (err, None) if return_usage else err
            
        full_response = []
        token_count = 0
        eval_count = None
        repeat_guard = _RepetitionGuard()
        looped = False
        for line in r.iter_lines():
            if cancel_check and cancel_check():
                break
            if line:
                try:
                    chunk = json.loads(line.decode("utf-8"))
                    token = chunk.get("message", {}).get("content", "") or chunk.get("response", "")
                    if token:
                        full_response.append(token)
                        token_count += 1
                        if on_token:
                            on_token(token)
                        if repeat_guard.feed(token):
                            looped = True
                            break
                    if chunk.get("done", False):
                        eval_count = chunk.get("eval_count")
                        break
                except json.JSONDecodeError:
                    continue

        result = "".join(full_response).strip()
        if looped:
            # Trim the trailing repeated tail rather than handing back a
            # response that visibly loops, then close out on whatever
            # substantive content came before the loop started.
            trimmed = re.sub(r'(.{40,}?)(\1){1,}\s*$', r'\1', result, flags=re.DOTALL)
            result = trimmed.strip() or result
            logger.warning("Ollama generation loop detected and truncated (model=%s)", model)
        cleaned = strip_thinking_tags(result)
        text = cleaned if cleaned else "Error: Ollama returned an empty response."
        if return_usage:
            return (text, eval_count if eval_count is not None else token_count)
        return text

    except requests.exceptions.Timeout:
        err = "Error: Local AI (Ollama) timed out."
        return (err, None) if return_usage else err
    except Exception as e:
        err = f"Error: Local AI connection failed ({str(e)})"
        return (err, None) if return_usage else err

def ping_ollama(model: str = None) -> bool:
    """Fast health check for Ollama."""
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=2)
        if r.status_code != 200:
            return False
        if model:
            models = [m["name"] for m in r.json().get("models", [])]
            return any(model in m for m in models)
        return True
    except Exception:
        return False