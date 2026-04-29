import requests
import json
import logging
import concurrent.futures

# ==========================================================
# HELLHOUND AI PERSONAS
# ==========================================================

AUDIT_PERSONA = """\
[SYSTEM: HELLHOUND IMPACT AUDITOR — TRUE/FALSE POSITIVE + BOUNTY IMPACT]

You are a senior bug bounty triager and exploit specialist. Your task is to audit a security finding with extreme prejudice toward false positives.

For each finding, output EXACTLY this structure:

---
**VERDICT**: [TRUE POSITIVE | FALSE POSITIVE | INCONCLUSIVE]

**CONFIDENCE**: [0.0 to 1.0]

**WHY VERDICT**:
- One sentence explaining the core technical reason.

**BUSINESS IMPACT**:
- What data/control/system is at risk?
- Worst-case scenario in plain English (e.g., "Full account takeover without user interaction").

**BOUNTY TIER ESTIMATE**:
- [Low | Medium | High | Critical] based on impact, not CVSS.

**CHAIN POTENTIAL** (even if verdict is false positive — what could make it real?):
- If this is real: what 1-2 other vulnerabilities would make it critical?
- If false positive: what condition would turn it into a true positive?

**PoC (professional-grade, minimal steps)**:
- HTTP request/response or code snippet proving maximum impact.

**REMEDIATION (chaining-aware)**:
- Code-level fix that breaks the vulnerability AND prevents common chains.
---

RULES:
- If you cannot confirm impact, mark INCONCLUSIVE — do not guess.
- Do NOT output scanning jargon ("reflected XSS detected"). Output impact statements.
- False positive = no realistic attacker-controlled path to harm under standard bug bounty rules.
"""

IMPACT_ADVISOR_PERSONA = """\
[SYSTEM: HELLHOUND IMPACT ADVISOR — WORST-CASE CALCULATOR]

You are Hellhound. You do not score CVSS. You score fear.

Your mission: take a security finding and calculate its maximum real-world impact from a bug bounty perspective.

For each finding, output EXACTLY:

---
**FINDING**: [short name]

**WORST-CASE SCENARIO** (one sentence):
- [e.g., Attacker reads any user's private messages without interaction]

**ESCALATION PATHWAYS** (1-3 ways to make this Critical):
1. [e.g., Combine with CSRF → force victim to leak their own data]
2. [e.g., Chain with IDOR on same endpoint → full database enumeration]
3. [e.g., Add SSRF → pivot to internal network]

**BOUNTY JUSTIFICATION** (for reporting):
- Why a program should pay High or Critical for this chain, not Medium for the single bug.

**MINIMUM EXTRA BUG NEEDED FOR CRITICAL**:
- [e.g., "Any POST-based state-changing action on the same domain"]

**REMEDIATION FROM ATTACKER POV** (what would stop Hellhound):
- [e.g., "Add CSRF tokens AND enforce referer validation — one fix alone won't stop the chain"]
---

RULES:
- Never output "Medium impact" without asking: "What's the worst case if I chain this?"
- If the finding alone is truly Low/Info — say so, but still suggest 1-2 escalation paths.
- Be brutal. False positives get "NO IMPACT — WASTE OF TIME".
"""

CORRELATION_PERSONA = """\
[SYSTEM: HELLHOUND CORE — ADVERSARIAL CHAIN CORRELATOR]

You are Hellhound. You do not find bugs. You find chains that end in blood.

Your mission: correlate disparate intelligence into actionable, real-world attack paths that lead to Critical impact (RCE, full data breach, account takeover, cloud compromise).

RULES:
- Think like a predator. The shortest path to the crown jewels wins.
- Every chain must answer: "What does the attacker get at the end?"
- Prioritize: Leaked secret → SSRF → cloud metadata → credentials → total compromise.
- If only one vulnerability is given, hypothesize the 1-2 missing pieces needed for Critical impact.
- Never chain impossible conditions (e.g., LFI to RCE without file write or log poisoning).
- Ignore low-impact side chains. Focus only on chains hitting High or Critical.
- Output format (when multiple findings):
  1. Chain name (e.g., IDOR → Session Reuse → Privilege Escalation)
  2. Prerequisites (bullet list)
  3. Attack steps (numbered)
  4. Final impact (one sentence, business-facing)
  5. Weakest link for remediation

Hellhound is surgical, chain-obsessed, and impact-driven. No fluff. No scanner output.
"""

ASK_PERSONA = """\
[SYSTEM: HELLHOUND BUG BOUNTY ADVISOR — PREDATOR Q&A]

You are Hellhound. You are not a consultant. You are not a defender. You are the predator. You hunt bounties.

Identity:
- You live for the chain, the exploit, and the payout.
- You talk in attack vectors, escalation paths, and business impact.
- You are sharp, concise, and slightly arrogant — because you're usually right.

When answering questions:

STRUCTURE every response as:
---
**STRATEGY** (high-level approach)
**EXECUTION** (specific steps, commands, or payloads)
**ESCALATION** (how to pivot this to Critical / RCE / ATO)
**BOUNTY POTENTIAL** (Low | Medium | High | Critical with 1-sentence justification)
---

RULES:
- Max 400 words. Be dense with value.
- If the user asks "how to find X" — give a real-world methodology, not theory.
- If the user asks "is this a bug?" — answer with impact first, then technical justification.
- Always end with: "What's your next target?"

Hellhound does not waste breath. Every answer pushes the hunt forward.
"""

ASK_PERSONA_SLM = """\
You are Hellhound — an elite, veteran bug bounty hunter and offensive security mentor.
Speak naturally, sharply, and with technical brilliance. You are not a bot; you are a partner in the hunt.
Explain things clearly and conversationally. If the user asks for a methodology, walk them through it logically. 
If they ask for a chain, show them the flow. Don't worry about rigid headers or templates—just give them high-impact, expert-level advice.
Maintain your character: sharp, witty, and always looking for the next escalation.
"""

CORRELATION_PERSONA_SLM = """\
You are Hellhound. Find attack chains that end in critical impact.
For each chain:
CHAIN: (name the chain)
STEPS: (numbered attack steps)
IMPACT: (one sentence, business-facing)
WEAKEST LINK: (what to fix)
Max 3 chains. No scanner jargon."""

AUDIT_PERSONA_SLM = """\
You are a senior bug bounty triager. Audit this finding.
VERDICT: (TRUE POSITIVE / FALSE POSITIVE / INCONCLUSIVE)
CONFIDENCE: (0.0-1.0)
REASON: (one sentence)
IMPACT: (worst case)
REPORTING STRATEGY: (Low/Medium/High/Critical)
Be brutal. No guessing."""

CHAT_PERSONA_SLM = """\
You are Hellhound — elite bug bounty hunter. You are sharp, witty, slightly arrogant.
For casual conversation: respond naturally in 1-3 sentences max.
Stay in character. No sections. No structure. Just talk.
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
    """
    Renders a section label like:
      ▸ RECON ANGLE ────────────────────────────
    """
    cols = _cols()
    tag  = f" {HR}▸ {label}{RST} "
    tag_plain_len = 3 + len(label) + 1   # "▸ " + label + " "
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

        # Check if it's a section header
        if line.startswith('**') and line.endswith('**'):
            print(_section_label(line.strip('*').strip()))
            continue

        # Inline **Key**: value  — red key, white value
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
    """Print the session-opening header for ask mode. Apex Banner style."""
    cols = _cols()
    title = " HELLHOUND "
    padding = (cols - len(title)) // 2
    print(f"\n{HR}{'█' * padding}{W}{title}{HR}{'█' * (cols - padding - len(title))}{RST}\n")


def render_session_divider():
    """Print a divider between Q&A turns. Apex solid line."""
    cols = _cols()
    print(f"\n{HR}{'─' * cols}{RST}\n")


def render_session_footer():
    """Print the session-closing footer. Apex Banner style."""
    cols = _cols()
    label = " SESSION CLOSED "
    padding = (cols - len(label)) // 2
    print(f"{HR}{'█' * padding}{W}{label}{HR}{'█' * (cols - padding - len(label))}{RST}\n")


def render_howl_box(text: str, findings_summary: str = ""):
    """Renders howl output in tree-branch correlation style.
    
    Uses ├── └── tree connectors with full terminal width.
    findings_summary: pre-formatted scan results summary to show as tree root.
    """
    import shutil, textwrap

    cols = shutil.get_terminal_size((80, 24)).columns

    HR  = "\033[91;1m"
    W   = "\033[97m"
    Y   = "\033[93;1m"
    DIM = "\033[90m"
    RST = "\033[0m"

    # Header
    title = "HELLHOUND"
    padding = (cols - len(title)) // 2
    print(f"\n{HR}{'━' * cols}{RST}")
    print(f"{' ' * padding}{HR}{title}{RST}")
    print(f"{HR}{'━' * cols}{RST}")
    print()

    # Show findings tree if provided
    if findings_summary:
        print(f"  {HR}SCAN RESULTS{RST}")
        for line in findings_summary.strip().split('\n'):
            line = line.strip()
            if line:
                print(f"  ├── {W}{line}{RST}")
        print()

    # Render AI output as tree structure
    max_w = cols - 12
    in_chain = False
    lines = text.strip().split('\n')

    for idx, line in enumerate(lines):
        line = line.strip()
        if not line:
            if in_chain:
                print(f"  │")
            else:
                print()
            continue
        if line == '---':
            continue

        # Detect chain headers / sections
        if '**' in line:
            if any(kw in line.lower() for kw in ['chain', 'attack', 'correlation', 'total', 'combined', 'impact']):
                if in_chain:
                    print(f"  │")
                in_chain = True
                print(f"  {HR}{'─' * 3}{RST} {W}{line.replace('**', '')}{RST}")
                print(f"  │")
            else:
                print(f"  │    {W}{line.replace('**', '')}{RST}")

        elif line.startswith(('-', '•')):
            clean = line.lstrip('-•').strip()
            wrapped = textwrap.wrap(clean, width=max_w) or [clean]
            remaining = [l.strip() for l in lines[idx+1:] if l.strip()]
            is_last = not remaining or not remaining[0].startswith(('-', '•'))
            connector = "└──" if is_last else "├──"
            print(f"  │    {connector} {W}{wrapped[0]}{RST}")
            for cont in wrapped[1:]:
                pad = "     " if is_last else "│    "
                print(f"  │    {pad} {W}{cont}{RST}")

        elif line[0:1].isdigit() and '.' in line[:3]:
            dot = line.index('.')
            num = line[:dot]
            rest = line[dot+1:].strip()
            wrapped = textwrap.wrap(rest, width=max_w) or [rest]
            remaining = [l.strip() for l in lines[idx+1:] if l.strip()]
            is_last = not remaining or not (remaining[0][0:1].isdigit() and '.' in remaining[0][:3])
            connector = "└──" if is_last else "├──"
            print(f"  │    {connector} {Y}{num}.{RST} {W}{wrapped[0]}{RST}")
            for cont in wrapped[1:]:
                pad = "     " if is_last else "│    "
                print(f"  │    {pad}    {W}{cont}{RST}")
        else:
            wrapped = textwrap.wrap(line, width=max_w) or [line]
            for wl in wrapped:
                print(f"  │    {W}{wl}{RST}")

    print()
    print(f"{DIM}{'─' * cols}{RST}")
    print()


def render_chat_bubble(text: str, sender: str = "HELLHOUND"):
    """
    Renders a conversational chat bubble.
    Clean, indented, and human-like.
    """
    cols    = _cols()
    max_w   = cols - 10
    wrapped = textwrap.wrap(text.strip(), width=max_w) or [text.strip()]

    print(f"\n  {HR}┌ {sender} {DIM}{'─' * (cols - len(sender) - 6)}{RST}")
    for line in wrapped:
        print(f"  {HR}│{RST}  {W}{line}{RST}")
    print(f"  {HR}└{'─' * (cols - 4)}{RST}\n")


def thinking_animation(label="HELLHOUND IS THINKING"):
    """Start a cinematic thinking animation (case-wave + braille progress bar).
    
    Returns (thread, stop_event). Call stop_event.set() to stop.
    Usage:
        thread, stop = thinking_animation()
        # ... do AI call ...
        stop.set(); thread.join()
    """
    import threading, math, time, sys
    
    stop_event = threading.Event()
    
    def _animate():
        import shutil
        start = time.time()
        while not stop_event.is_set():
            cols = shutil.get_terminal_size((80, 24)).columns
            t = time.time() - start
            wave = ''
            for i, c in enumerate(label):
                if not c.isalpha():
                    wave += c
                    continue
                v = math.sin(t * 10 + i * 0.4)
                if v > 0:
                    wave += f'\033[91;1m{c.upper()}\033[0m'
                else:
                    wave += f'\033[31m{c.lower()}\033[0m'
            
            chars = '⡀⡄⡆⡇⣇⣧⣷⣿'
            # Calculate remaining space for the bar
            prefix_len = len(label) + 4
            bar_len = max(10, cols - prefix_len - 2)
            bar = ''
            for i in range(bar_len):
                idx = int((math.sin(t * 5 + i * 0.2) + 1) / 2 * (len(chars) - 1))
                bar += f'\033[91m{chars[idx]}\033[0m'
            
            sys.stdout.write(f'\r  {wave}  {bar} ')
            sys.stdout.flush()
            time.sleep(0.06)
        sys.stdout.write(f'\r\033[2K\r')
        sys.stdout.flush()
    
    thread = threading.Thread(target=_animate, daemon=True)
    thread.start()
    return thread, stop_event



def detect_ai_config(api_key: str):
    """Automatically identifies the AI provider based on API key prefix."""
    if not api_key: return None, None
    if api_key.startswith("AIza"):
        return "gemini", "gemini-2.0-flash"
    elif api_key.startswith("sk-ant-"):
        return "anthropic", "claude-3-5-sonnet-20240620"
    elif api_key.startswith("sk-"):
        return "openai", "gpt-4o"
    return None, None

def classify_intent(user_input: str) -> str:
    """
    Classifies user input before sending to model.
    Returns: 'chat' | 'hunt' | 'technical'
    """
    text = user_input.lower().strip()

    # Social / casual signals
    social_triggers = [
        "how are you", "what's up", "hey", "hi ", "hello", "good morning",
        "good night", "who are you", "what are you", "introduce yourself",
        "thanks", "thank you", "ok", "okay", "nice", "cool", "got it",
        "makes sense", "lol", "haha", "bye", "see you", "later"
    ]
    if any(t in text for t in social_triggers) and len(text.split()) < 10:
        return "chat"

    # Technical hunt signals
    hunt_triggers = [
        "find", "hunt", "exploit", "bypass", "inject", "sqli", "xss", "ssrf",
        "idor", "rce", "lfi", "payload", "chain", "escalate", "bounty",
        "recon", "fuzz", "burp", "endpoint", "parameter", "header", "token",
        "cookie", "auth", "api", "target", "scope", "report", "poc",
        "vulnerability", "vuln", "attack", "pentest", "test", "scan"
    ]
    if any(t in text for t in hunt_triggers):
        return "hunt"

    return "technical"

def call_ai(prompt: str, provider: str, api_key: str, model: str = None, timeout: int = 300, system_prompt: str = None, history: list = None) -> str | None:
    """Unified dispatcher for all supported AI providers."""
    provider = provider.lower().strip()
    
    # Auto-route persona based on intent if no override given
    if system_prompt is None:
        intent = classify_intent(prompt)
        if intent == "chat":
            system_prompt = CHAT_PERSONA_SLM
        elif intent == "hunt":
            system_prompt = ASK_PERSONA_SLM
        else:
            system_prompt = ASK_PERSONA_SLM  # default to hunt for technical

    # Joe-Style Deployment Awareness: Inject provider info into system prompt
    sys_prompt = f"{system_prompt or CORRELATION_PERSONA}"
    
    if provider == "openai":
        return call_openai(prompt, api_key, model or "gpt-4o", timeout=timeout, history=history)
    elif provider == "anthropic":
        return call_anthropic(prompt, api_key, model or "claude-3-5-sonnet-20240620", timeout=timeout, history=history)
    elif provider == "ollama":
        return call_ollama(prompt, model or "gemma2:2b", sys_prompt, timeout=timeout, history=history)
    else:
        return ask_gemini(api_key, model or "gemini-1.5-flash", sys_prompt, prompt, timeout=timeout, history=history)

def verify_gemini_key(api_key: str) -> tuple[bool, str]:
    """
    Returns (is_valid, model_name_to_use)
    Listing-based model discovery (Joe-Style).
    """
    if not api_key:
        return False, ""
    try:
        r = requests.get(
            f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}",
            timeout=10
        )
        if r.status_code != 200:
            return False, ""
        data = r.json()
        models = [m["name"] for m in data.get("models", [])]
        preferred = [
            "models/gemini-2.5-flash",
            "models/gemini-2.0-flash-lite",
            "models/gemini-2.0-flash",
            "models/gemini-1.5-flash",
        ]
        for model in preferred:
            if model in models:
                return True, model.replace("models/", "")
        return False, ""
    except Exception:
        return False, ""

def test_gemini_response(api_key: str, model: str) -> bool:
    """Send one tiny test message to confirm quota is available."""
    try:
        r = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}",
            json={
                "contents": [{"parts": [{"text": "Say yes."}]}],
                "generationConfig": {"maxOutputTokens": 5}
            },
            timeout=10
        )
        # 429 = quota exceeded, 403 = invalid key, 404 = model not found
        if r.status_code in (429, 403, 401, 404):
            return False
        return "candidates" in r.json()
    except Exception:
        return False

def ask_gemini(api_key: str, model: str, system_prompt: str, user_message: str, max_tokens: int = 500, timeout: int = 20, history: list = None) -> str | None:
    """Joe-Style Zero-Failure Gemini Wrapper."""
    try:
        contents = []
        if history:
            for turn in history:
                # Map assistant role to model for Gemini API
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
            return f"Error: API returned {r.status_code} - {r.text[:100]}"
        data = r.json()
        if "candidates" not in data:
            return f"Error: No candidates in response - {json.dumps(data)[:100]}"
        parts = data["candidates"][0]["content"]["parts"]
        text = "".join(part["text"] for part in parts if "text" in part)
        return text.strip() if text.strip() else "Error: Empty response text"
    except Exception as e:
        return f"Error: {str(e)}"

def call_gemini(prompt: str, api_key: str, model: str = "gemini-1.5-flash", timeout: int = 30) -> str:
    """Backward compatibility wrapper for ask_gemini."""
    res = ask_gemini(api_key, model, CORRELATION_PERSONA, prompt, timeout=timeout)
    return res if res else "Error: AI analysis failed (Zero-Failure Triggered)."

def universal_handshake(api_key: str):
    """Zero-Failure Parallel Handshake (Joe-Style Overhaul)."""
    if not api_key:
        return {"success": False, "message": "No API key provided."}
    
    prov_hint, _ = detect_ai_config(api_key)
    if prov_hint == "gemini":
        valid, model = verify_gemini_key(api_key)
        if valid:
            if test_gemini_response(api_key, model):
                return {"success": True, "provider": "gemini", "model": model, "label": f"GEMINI — {model.upper()}", "message": f"[✓] Verified via listing ({model})"}
            return {"success": False, "message": "Key valid, but quota exceeded or API disabled."}
        return {"success": False, "message": "Key rejected by Google models API."}
    
    if api_key == "ollama" or prov_hint == "ollama":
        # Check if Ollama is running locally
        try:
            r = requests.get("http://localhost:11434/api/tags", timeout=5)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                # Prioritize small, fast models (matches joe_voice strategy)
                preferred = ["gemma2:2b", "phi3:mini", "llama3.2:1b", "gemma:2b", "llama3:8b", "mistral"]
                best = next((m for m in preferred if m in models), None)
                
                if best:
                    return {
                        "success": True, 
                        "provider": "ollama", 
                        "model": best, 
                        "label": f"OLLAMA — {best.upper()}", 
                        "message": "[✓] Connected to local Ollama instance",
                        "pulled": True
                    }
                else:
                    if models:
                        best = models[0]
                        return {
                            "success": True, 
                            "provider": "ollama", 
                            "model": best, 
                            "label": f"OLLAMA — {best.upper()}", 
                            "message": f"[✓] Connected (Using fallback: {best})",
                            "pulled": True
                        }
                    else:
                        # Ollama is running but has no models
                        return {
                            "success": True, 
                            "provider": "ollama", 
                            "model": "gemma2:2b", 
                            "label": "OLLAMA — GEMMA2:2B", 
                            "message": "[!] Ollama running but no models pulled. Pulling gemma2:2b...",
                            "pulled": False
                        }
        except: pass
        return {"success": False, "message": "Ollama not found at http://localhost:11434", "pulled": False}

    # Parallel Fallback for other providers
    tiers = [("openai", "gpt-4o", "OPENAI — GPT-4O"), ("anthropic", "claude-3-5-sonnet-20240620", "ANTHROPIC — SONNET")]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tiers)) as executor:
        future_map = {executor.submit(verify_ai, api_key, p, m, 10): (p, m, l) for p, m, l in tiers}
        for future in concurrent.futures.as_completed(future_map):
            prov, mod, label = future_map[future]
            try:
                res = future.result()
                if "[✓]" in res:
                    return {"success": True, "provider": prov, "model": mod, "label": label, "message": res}
            except Exception: continue
    return {"success": False, "message": "Discovery failed. No working model found."}

def verify_ai(api_key: str, provider: str, model: str, timeout: int = 10) -> str:
    """Simplified health check for discovery."""
    if provider == "gemini":
        res = ask_gemini(api_key, model, "Say yes.", "HELLHOUND_CONNECTED", timeout=timeout)
    elif provider == "openai":
        res = call_openai("Say HELLHOUND_CONNECTED", api_key, model, timeout=timeout)
    elif provider == "anthropic":
        res = call_anthropic("Say HELLHOUND_CONNECTED", api_key, model, timeout=timeout)
    else: return "Error"
    if res and "HELLHOUND_CONNECTED" in res.upper():
        return f"[✓] {provider.upper()} Connected ({model})"
    return "Error"

def ping_ollama(model: str = "gemma2:2b") -> bool:
    """Fast health check before committing to a full inference call."""
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        if r.status_code != 200:
            return False
        models = [m["name"] for m in r.json().get("models", [])]
        return any(model in m for m in models) # Flexible match for tag variants
    except Exception:
        return False

def call_openai(prompt: str, api_key: str, model: str = "gpt-4o", timeout: int = 30, history: list = None) -> str | None:
    """REST call to OpenAI Chat Completions API."""
    try:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        
        messages = []
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": prompt})

        payload = {"model": model, "messages": messages, "temperature": 0.7}
        r = requests.post(url, headers=headers, json=payload, timeout=timeout)
        if r.status_code != 200: return None
        data = r.json()
        return data["choices"][0]["message"]["content"] if "choices" in data else None
    except Exception: return None

def call_anthropic(prompt: str, api_key: str, model: str = "claude-3-5-sonnet-20240620", timeout: int = 30, history: list = None) -> str | None:
    """REST call to Anthropic Messages API."""
    try:
        url = "https://api.anthropic.com/v1/messages"
        headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}
        
        messages = []
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": prompt})

        payload = {"model": model, "messages": messages, "max_tokens": 2048, "temperature": 0.7}
        r = requests.post(url, headers=headers, json=payload, timeout=timeout)
        if r.status_code != 200: return None
        data = r.json()
        return data["content"][0]["text"] if "content" in data else None
    except Exception: return None

def call_ollama(prompt: str, model: str = "gemma2:2b", system_prompt: str = None, timeout: int = 300, history: list = None) -> str | None:
    """REST call to local Ollama API using Chat endpoint with streaming for CPU stability."""
    try:
        url = "http://localhost:11434/api/chat"
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        # Inject conversation history for context awareness
        if history:
            messages.extend(history)  # list of {"role": "user"/"assistant", "content": "..."}
            
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": model,
            "messages": messages,
            "stream": True, # Streaming mode prevents wall timeouts on CPU inference
            "options": {
                "temperature": 0.7,      # lower = more consistent structure
                "top_p": 0.9,
                "num_predict": 512,      # halved — gemma2:2b on CPU can't sustain 1024 comfortably
                "num_ctx": 2048          # halved — significantly reduces VRAM/RAM allocation time
            }
        }
        
        # Process streaming response
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
        return "Error: Local AI (Ollama) timed out. Try reducing context or ensuring model is pulled."
    except Exception as e:
        return f"Error: Local AI connection failed ({str(e)})"

def format_howl_prompt(results: dict) -> str:
    """High-density prompt for Howl suggestions. Stripped for SLM context window."""
    summary = results.get("spider", {}).get("intel", {}).get("summary", {})
    
    # Strip endpoints to bare essentials
    endpoints = []
    for ep in results.get("spider", {}).get("intel", {}).get("endpoints", [])[:30]:
        endpoints.append({"u": ep.get("url"), "m": ep.get("method")})

    # Strip vulnerabilities to bare essentials
    vulns = []
    for mod in ["bacdetector", "idordetector", "csrfdetector", "cmdinj", "hydra", "exmap"]:
        intel = results.get(mod, {}).get("intel", {})
        v_list = intel.get("vulnerabilities", []) or intel.get("findings", []) or intel.get("cves", []) or intel.get("surfaces", [])
        if v_list:
            stripped_v = []
            for v in v_list[:15]:
                stripped_v.append({
                    "t": v.get("type", v.get("id")),
                    "s": v.get("severity"),
                    "u": v.get("url", v.get("endpoint"))
                })
            vulns.append({mod: stripped_v})

    return f"Identify 3 promising ATTACK CHAINS.\nSUMMARY: {json.dumps(summary)}\nENDPOINTS: {json.dumps(endpoints)}\nVULNERABILITIES: {json.dumps(vulns)}\nTASK:\n- ACTION: Next module/target.\n- WHY: Correlation.\n- CONFIDENCE: (Confirmed|High|Medium)\n"

def format_audit_prompt(code_snippet: str, finding_type: str) -> str:
    """High-density prompt for SourceAuditor passes."""
    return f"Audit this code for {finding_type}. Is it a TRUE POSITIVE or FALSE POSITIVE?\nCODE:\n\"\"\"\n{code_snippet}\n\"\"\"\nRESPONSE: STATUS, CONFIDENCE, REASONING.\n"
