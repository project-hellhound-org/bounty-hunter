import requests
import json
import logging

# ==========================================================
# HELLHOUND AI UTILS: MULTI-PROVIDER
# ==========================================================

def call_ai(prompt: str, provider: str, api_key: str, model: str = None) -> str:
    """Unified dispatcher for all supported AI providers."""
    provider = provider.lower().strip()
    
    if provider == "openai":
        return call_openai(prompt, api_key, model or "gpt-4o")
    elif provider == "anthropic":
        return call_anthropic(prompt, api_key, model or "claude-3-5-sonnet-20240620")
    else:
        # Default to Gemini
        return call_gemini(prompt, api_key, model or "gemini-1.5-flash")

def call_gemini(prompt: str, api_key: str, model: str = "gemini-1.5-flash") -> str:
    """REST call to Google Gemini API."""
    if not api_key:
        return "Error: No AI API key provided."

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    headers = {'Content-Type': 'application/json'}
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.7, "maxOutputTokens": 2048}
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        if "candidates" in data and data["candidates"]:
            parts = data["candidates"][0].get("content", {}).get("parts", [])
            if parts:
                return parts[0].get("text", "Error: Empty response.")
        return f"Error: Unexpected response format: {data}"
    except Exception as e:
        return f"Error connecting to Gemini: {str(e)}"

def call_openai(prompt: str, api_key: str, model: str = "gpt-4o") -> str:
    """REST call to OpenAI Chat Completions API."""
    if not api_key:
        return "Error: No OpenAI API key provided."

    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        if "choices" in data and data["choices"]:
            return data["choices"][0].get("message", {}).get("content", "Error: Empty response.")
        return f"Error: Unexpected response format: {data}"
    except Exception as e:
        return f"Error connecting to OpenAI: {str(e)}"

def call_anthropic(prompt: str, api_key: str, model: str = "claude-3-5-sonnet-20240620") -> str:
    """REST call to Anthropic Messages API."""
    if not api_key:
        return "Error: No Anthropic API key provided."

    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 2048,
        "temperature": 0.7
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        if "content" in data and data["content"]:
            return data["content"][0].get("text", "Error: Empty response.")
        return f"Error: Unexpected response format: {data}"
    except Exception as e:
        return f"Error connecting to Anthropic: {str(e)}"

def format_howl_prompt(results: dict) -> str:
    """Formats current framework 'loot' into a high-density prompt for Howl suggestions."""
    summary = results.get("spider", {}).get("intel", {}).get("summary", {})
    endpoints = results.get("spider", {}).get("intel", {}).get("endpoints", [])[:50]
    secrets = results.get("spider", {}).get("intel", {}).get("secrets", [])
    vulns = []
    
    for mod in ["bacdetector", "idordetector", "cmdinj", "parax", "exmap"]:
        intel = results.get(mod, {}).get("intel", {})
        v = intel.get("vulnerabilities", []) or intel.get("findings", []) or intel.get("cves", [])
        if v:
            vulns.append({mod: v[:20]})

    prompt = f"""
[SYSTEM: HELLHOUND PENTEST CORRELATOR]
Identify the 3 most promising ATTACK CHAINS from these findings.
SUMMARY: {json.dumps(summary)}
ENDPOINTS (Sample): {json.dumps(endpoints)}
VULNERABILITIES (Sample): {json.dumps(vulns)}

TASK:
- ACTION: Next module/target.
- WHY: Logical correlation.
- CONFIDENCE: (Confirmed | High | Medium | Possible)
"""
    return prompt

def format_audit_prompt(code_snippet: str, finding_type: str) -> str:
    """Formats a code snippet for a Deep AI Audit pass."""
    prompt = f"""
[SYSTEM: HELLHOUND SOURCE AUDITOR]
Audit this code for {finding_type}. Is it a TRUE POSITIVE or FALSE POSITIVE?
CODE:
\"\"\"
{code_snippet}
\"\"\"
RESPONSE: STATUS, CONFIDENCE, REASONING.
"""
    return prompt
