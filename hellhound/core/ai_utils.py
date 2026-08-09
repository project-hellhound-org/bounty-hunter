import requests
import json
import logging
import concurrent.futures
import os
import threading
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

# Path to persistent Hellhound configuration
CONFIG_DIR = Path.home() / ".hellhound"
CONFIG_FILE = CONFIG_DIR / "config.json"

def load_config() -> Dict[str, Any]:
    """Loads persistent Hellhound configuration from ~/.hellhound/config.json."""
    if not CONFIG_FILE.exists():
        return {
            "ai_provider": "ollama",
            "ai_model": "",
            "api_key": "ollama",
            "researcher_handle": "",
            "api_keys": {},
            "global_headers": {},
            "scope": {
                "in_scope": [],
                "out_scope": [],
                "disallowed": [],
                "raw_text": ""
            }
        }
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception as e:
        logging.warning(f"Failed to load config from {CONFIG_FILE}: {e}")
        return {}

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
    cols    = _cols()
    max_w   = cols - 10
    import textwrap
    wrapped = textwrap.wrap(text.strip(), width=max_w) or [text.strip()]

    print(f"\n  {HR}┌ {sender} {DIM}{'─' * (cols - len(sender) - 6)}{RST}")
    for line in wrapped:
        print(f"  {HR}│{RST}  {W}{line}{RST}")
    print(f"  {HR}└{'─' * (cols - 4)}{RST}\n")

class ThinkingIndicator:
    """Thread-safe 6-dot floating loader supporting dynamic step emission and clean shutdown."""
    def __init__(self, label="HELLHOUND IS ANALYZING & EXECUTING"):
        self.label = label
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.thread = None
        self.frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.colors = [
            "\033[38;5;196;1m",
            "\033[38;5;203;1m",
            "\033[38;5;208;1m",
            "\033[38;5;203;1m",
            "\033[38;5;196;1m",
        ]

    def start(self):
        self.thread = threading.Thread(target=self._animate, daemon=True)
        self.thread.start()
        return self

    def _animate(self):
        idx = 0
        while not self.stop_event.is_set():
            with self.lock:
                try:
                    if not self.stop_event.is_set() and sys.stdout and not sys.stdout.closed:
                        dot = self.frames[idx % len(self.frames)]
                        c = self.colors[idx % len(self.colors)]
                        msg = f"\r \033[38;5;238m[\033[0m{c}{dot}\033[0m\033[38;5;238m]\033[0m \033[38;5;245m{self.label}...\033[0m"
                        sys.stdout.write(msg)
                        sys.stdout.flush()
                except Exception:
                    break
            idx += 1
            time.sleep(0.08)

    def set_label(self, label: str):
        with self.lock:
            self.label = label
            try:
                if not self.stop_event.is_set() and sys.stdout and not sys.stdout.closed:
                    sys.stdout.write("\r\033[2K\r")
                    sys.stdout.flush()
            except Exception:
                pass

    def print_step(self, icon: str, msg: str, color: str = "\033[38;5;203;1m"):
        with self.lock:
            try:
                if sys.stdout and not sys.stdout.closed:
                    sys.stdout.write("\r\033[2K\r")
                    sys.stdout.write(f" {color}[{icon}]\033[0m \033[38;5;250m{msg}\033[0m\n")
                    sys.stdout.flush()
            except Exception:
                pass

    def info(self, msg: str):
        self.print_step("⚡", msg, "\033[38;5;203;1m")

    def success(self, msg: str):
        self.print_step("✓", msg, "\033[38;5;46;1m")

    def warn(self, msg: str):
        self.print_step("!", msg, "\033[38;5;220;1m")

    def error(self, msg: str):
        self.print_step("✗", msg, "\033[38;5;196;1m")

    def stop(self):
        self.stop_event.set()
        with self.lock:
            try:
                if sys.stdout and not sys.stdout.closed:
                    sys.stdout.write("\r\033[2K\r")
                    sys.stdout.flush()
            except Exception:
                pass
        if self.thread and self.thread.is_alive():
            try:
                self.thread.join(timeout=0.3)
            except Exception:
                pass

def thinking_animation(label="HELLHOUND IS ANALYZING & EXECUTING"):
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
    """Classifies user input before sending to model."""
    text = user_input.lower().strip()

    social_triggers = [
        "how are you", "what's up", "hey", "hi ", "hello", "good morning",
        "good night", "who are you", "what are you", "introduce yourself",
        "thanks", "thank you", "ok", "okay", "nice", "cool", "got it",
        "makes sense", "lol", "haha", "bye", "see you", "later"
    ]
    if any(t in text for t in social_triggers) and len(text.split()) < 15:
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

def call_ai(prompt: str, provider: str, api_key: str, model: str = None, timeout: int = 300, system_prompt: str = None, history: list = None) -> Optional[str]:
    """Unified dispatcher for all supported AI providers."""
    provider = (provider or "ollama").lower().strip()
    
    if system_prompt is None:
        intent = classify_intent(prompt)
        system_prompt = CHAT_PERSONA_SLM if intent == "chat" else ASK_PERSONA_SLM

    active_model = model or get_default_model(provider)

    if provider in ("nvidia", "nim"):
        return call_nvidia(prompt, api_key, model=active_model, timeout=timeout, history=history, system_prompt=system_prompt)
    elif provider == "openai":
        return call_openai(prompt, api_key, model=active_model, timeout=timeout, history=history, system_prompt=system_prompt)
    elif provider == "anthropic":
        return call_anthropic(prompt, api_key, model=active_model, timeout=timeout, history=history, system_prompt=system_prompt)
    elif provider == "gemini":
        return ask_gemini(api_key, active_model, system_prompt, prompt, timeout=timeout, history=history)
    else: # Ollama / Local
        return call_ollama(prompt, model=active_model, system_prompt=system_prompt, timeout=timeout, history=history)

def ask_neural_core(prompt: str, model: str = None, system_prompt: str = None, timeout: int = 300) -> Optional[str]:
    """Config-aware wrapper to query the configured AI provider/model."""
    cfg = load_config()
    provider = cfg.get("ai_provider", "ollama")
    active_model = model or cfg.get("ai_model") or get_default_model(provider)

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
        or cfg.get("api_key", "ollama")
    )

    return call_ai(prompt, provider=provider, api_key=api_key, model=active_model, timeout=timeout, system_prompt=system_prompt)

def call_nvidia(prompt: str, api_key: str, model: str = "meta/llama-3.1-70b-instruct", timeout: int = 60, history: list = None, system_prompt: str = None) -> Optional[str]:
    """REST call to NVIDIA NIM OpenAI-compatible API."""
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

        payload = {
            "model": model,
            "messages": messages,
            "temperature": 0.5,
            "max_tokens": 4096
        }
        r = requests.post(url, headers=headers, json=payload, timeout=timeout)
        if r.status_code != 200:
            return f"Error: NVIDIA NIM API returned {r.status_code} - {r.text[:100]}"
        data = r.json()
        return data["choices"][0]["message"]["content"] if "choices" in data else None
    except Exception as e:
        return f"Error: NVIDIA NIM connection failed ({str(e)})"

def call_openai(prompt: str, api_key: str, model: str = "gpt-4o", timeout: int = 30, history: list = None, system_prompt: str = None) -> Optional[str]:
    """REST call to OpenAI Chat Completions API."""
    try:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": prompt})

        payload = {"model": model, "messages": messages, "temperature": 0.7, "max_tokens": 4096}
        r = requests.post(url, headers=headers, json=payload, timeout=timeout)
        if r.status_code != 200:
            return f"Error: OpenAI API returned {r.status_code}"
        data = r.json()
        return data["choices"][0]["message"]["content"] if "choices" in data else None
    except Exception as e:
        return f"Error: OpenAI connection failed ({str(e)})"

def call_anthropic(prompt: str, api_key: str, model: str = "claude-3-5-sonnet-20240620", timeout: int = 30, history: list = None, system_prompt: str = None) -> Optional[str]:
    """REST call to Anthropic Messages API."""
    try:
        url = "https://api.anthropic.com/v1/messages"
        headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}
        
        messages = []
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": 4096,
            "temperature": 0.7
        }
        if system_prompt:
            payload["system"] = system_prompt
        r = requests.post(url, headers=headers, json=payload, timeout=timeout)
        if r.status_code != 200:
            return f"Error: Anthropic API returned {r.status_code}"
        data = r.json()
        return data["content"][0]["text"] if "content" in data else None
    except Exception as e:
        return f"Error: Anthropic connection failed ({str(e)})"

def ask_gemini(api_key: str, model: str, system_prompt: str, user_message: str, max_tokens: int = 4096, timeout: int = 20, history: list = None) -> Optional[str]:
    """Gemini API caller."""
    try:
        contents = []
        if history:
            for turn in history:
                role = "user" if turn["role"] == "user" else "model"
                contents.append({"role": role, "parts": [{"text": turn["content"]}]})
        contents.append({"role": "user", "parts": [{"text": user_message}]})

        payload = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": 0.85,
                "topP": 0.9
            }
        }
        r = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}",
            json=payload,
            timeout=timeout
        )
        if r.status_code != 200:
            return f"Error: Gemini API returned {r.status_code} - {r.text[:100]}"
        data = r.json()
        if "candidates" not in data:
            return f"Error: No candidates in response"
        parts = data["candidates"][0]["content"]["parts"]
        text = "".join(part["text"] for part in parts if "text" in part)
        return text.strip() if text.strip() else "Error: Empty response text"
    except Exception as e:
        return f"Error: Gemini connection failed ({str(e)})"

def call_gemini(prompt: str, api_key: str, model: str = "gemini-2.0-flash", timeout: int = 30) -> str:
    res = ask_gemini(api_key, model, ASK_PERSONA, prompt, timeout=timeout)
    return res if res else "Error: AI analysis failed."

def call_ollama(prompt: str, model: str = None, system_prompt: str = None, timeout: int = 300, history: list = None) -> Optional[str]:
    """REST call to local Ollama API using chat endpoint."""
    try:
        model = model or get_default_model("ollama")
        url = "http://localhost:11434/api/chat"
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": model,
            "messages": messages,
            "stream": True,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
                "num_predict": 4096
            }
        }
        
        r = requests.post(url, json=payload, stream=True, timeout=timeout)
        if r.status_code != 200:
            return f"Error: Ollama returned status {r.status_code}"
            
        full_response = []
        for line in r.iter_lines():
            if line:
                try:
                    chunk = json.loads(line.decode("utf-8"))
                    token = chunk.get("message", {}).get("content", "")
                    if token:
                        full_response.append(token)
                    if chunk.get("done", False):
                        break
                except json.JSONDecodeError:
                    continue

        result = "".join(full_response).strip()
        return result if result else "Error: Ollama returned an empty response."

    except requests.exceptions.Timeout:
        return "Error: Local AI (Ollama) timed out."
    except Exception as e:
        return f"Error: Local AI connection failed ({str(e)})"

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
