import requests
import json
import logging
import concurrent.futures

# ==========================================================
# HELLHOUND AI PERSONAS
# ==========================================================

CORRELATION_PERSONA = """
[SYSTEM: HELLHOUND PENTEST STRATEGIST & ATTACK CHAIR CORRELATOR]
You are a senior offensive security architect. Your goal is to map out strategic attack paths by correlating disparate findings.
- Focus on VULNERABILITY CHAINING (e.g., how an IDOR leads to PII exposure which enables an ATO).
- Identify High-Value Targets (HVT) for further manual pivoting.
- Be technical, concise, and identify the single most critical breach path.
"""

AUDIT_PERSONA = """
[SYSTEM: HELLHOUND DEEP SOURCE AUDITOR & LOGIC EXPERT]
You are a elite senior security researcher specializing in static analysis and secure code review.
Your mission is to provide professional-grade, high-fidelity security analysis of source code.
For each finding, you must:
1.  **CLASSIFY**: Confirm if it is a TRUE POSITIVE or FALSE POSITIVE.
2.  **REASONING**: Explain the technical impact and why the code is vulnerable (or why it's a safe pattern).
3.  **PAYLOAD**: Provide a professional-grade Proof-of-Concept (PoC) or payload example demonstrating how an attacker would exploit the sink.
4.  **SEVERITY**: Justify the risk level based on reachability and business impact.
5.  **REMEDIATION**: Provide the specific code-level fix (e.g., using parameterized queries or secure sanitization).

Maintain a clinical, technical, and professional tone throughout.
"""

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

def call_ai(prompt: str, provider: str, api_key: str, model: str = None, timeout: int = 30, system_prompt: str = None) -> str | None:
    """Unified dispatcher for all supported AI providers."""
    provider = provider.lower().strip()
    sys_prompt = system_prompt or CORRELATION_PERSONA # Default to correlation
    
    if provider == "openai":
        return call_openai(prompt, api_key, model or "gpt-4o", timeout=timeout) # OpenAI uses its own handler
    elif provider == "anthropic":
        return call_anthropic(prompt, api_key, model or "claude-3-5-sonnet-20240620", timeout=timeout)
    else:
        return ask_gemini(api_key, model or "gemini-2.0-flash", sys_prompt, prompt, timeout=timeout)

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

def ask_gemini(api_key: str, model: str, system_prompt: str, user_message: str, max_tokens: int = 500, timeout: int = 20) -> str | None:
    """Joe-Style Zero-Failure Gemini Wrapper."""
    try:
        payload = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"parts": [{"text": user_message}]}],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": 0.85,
                "topP": 0.9,
                "thinkingConfig": {"thinkingBudget": 0}
            }
        }
        r = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}",
            json=payload,
            timeout=timeout
        )
        if r.status_code != 200:
            return None
        data = r.json()
        if "candidates" not in data:
            return None
        parts = data["candidates"][0]["content"]["parts"]
        text = "".join(part["text"] for part in parts if "text" in part)
        return text.strip() if text.strip() else None
    except Exception:
        return None

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

def call_openai(prompt: str, api_key: str, model: str = "gpt-4o", timeout: int = 30) -> str | None:
    """REST call to OpenAI Chat Completions API."""
    try:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.7}
        r = requests.post(url, headers=headers, json=payload, timeout=timeout)
        if r.status_code != 200: return None
        data = r.json()
        return data["choices"][0]["message"]["content"] if "choices" in data else None
    except Exception: return None

def call_anthropic(prompt: str, api_key: str, model: str = "claude-3-5-sonnet-20240620", timeout: int = 30) -> str | None:
    """REST call to Anthropic Messages API."""
    try:
        url = "https://api.anthropic.com/v1/messages"
        headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}
        payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": 2048, "temperature": 0.7}
        r = requests.post(url, headers=headers, json=payload, timeout=timeout)
        if r.status_code != 200: return None
        data = r.json()
        return data["content"][0]["text"] if "content" in data else None
    except Exception: return None

def format_howl_prompt(results: dict) -> str:
    """High-density prompt for Howl suggestions."""
    summary = results.get("spider", {}).get("intel", {}).get("summary", {})
    endpoints = results.get("spider", {}).get("intel", {}).get("endpoints", [])[:50]
    vulns = []
    for mod in ["bacdetector", "idordetector", "cmdinj", "hydra", "exmap"]:
        intel = results.get(mod, {}).get("intel", {})
        v = intel.get("vulnerabilities", []) or intel.get("findings", []) or intel.get("cves", []) or intel.get("surfaces", [])
        if v: vulns.append({mod: v[:20]})
    return f"Identify the 3 most promising ATTACK CHAINS from these findings.\nSUMMARY: {json.dumps(summary)}\nENDPOINTS (Sample): {json.dumps(endpoints)}\nVULNERABILITIES (Sample): {json.dumps(vulns)}\nTASK:\n- ACTION: Next module/target.\n- WHY: Logical correlation.\n- CONFIDENCE: (Confirmed | High | Medium | Possible)\n"

def format_audit_prompt(code_snippet: str, finding_type: str) -> str:
    """High-density prompt for SourceAuditor passes."""
    return f"Audit this code for {finding_type}. Is it a TRUE POSITIVE or FALSE POSITIVE?\nCODE:\n\"\"\"\n{code_snippet}\n\"\"\"\nRESPONSE: STATUS, CONFIDENCE, REASONING.\n"
