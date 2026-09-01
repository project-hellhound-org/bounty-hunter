"""
hellhound/core/skills.py

Skill-Aware Reasoning System for HELLHOUND Bug Bounty Framework.
Discovers, indexes, searches, and loads methodology skills from:
  1. Shipped skills: `hellhound/skills/`
  2. User custom skills: `~/.hellhound/skills/` (user skills override shipped skills)

Provides lightweight metadata discovery, term-based relevance search,
phase/triage-aware routing, model-adaptive context injection, and reference loading.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
import re
import os
import logging

logger = logging.getLogger(__name__)

# Base directories for skill discovery
BUNDLED_SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"
USER_SKILLS_DIR = Path.home() / ".hellhound" / "skills"


@dataclass
class SkillMeta:
    """Lightweight metadata descriptor parsed from SKILL.md YAML frontmatter."""
    name: str
    description: str
    path: str
    references_dir: Optional[str] = None
    is_user_defined: bool = False


def _parse_yaml_frontmatter(content: str) -> Tuple[Dict[str, str], str]:
    """
    Extracts YAML frontmatter (between first pair of ---) and the remaining body.
    Returns (metadata_dict, body_markdown).
    """
    if not content.startswith("---"):
        return {}, content

    parts = content.split("---", 2)
    if len(parts) < 3:
        return {}, content

    frontmatter_raw = parts[1]
    body = parts[2].strip()

    meta: Dict[str, str] = {}
    current_key: Optional[str] = None
    current_val: List[str] = []

    for line in frontmatter_raw.splitlines():
        line_str = line.strip()
        if not line_str or line_str.startswith("#"):
            continue

        m = re.match(r"^([a-zA-Z0-9_-]+):\s*(.*)$", line_str)
        if m:
            if current_key:
                meta[current_key] = " ".join(current_val).strip()
            current_key = m.group(1).strip()
            val = m.group(2).strip()
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1].strip()
            current_val = [val] if val else []
        elif current_key:
            val = line_str
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1].strip()
            current_val.append(val)

    if current_key:
        meta[current_key] = " ".join(current_val).strip()

    return meta, body


def discover_skills() -> Dict[str, SkillMeta]:
    """
    Scans `hellhound/skills/` and `~/.hellhound/skills/` for `*/SKILL.md` files.
    Parses ONLY YAML frontmatter (name, description) to maintain lightweight overhead.
    User-defined skills (~/.hellhound/skills/) override bundled ones of the same name.
    """
    registry: Dict[str, SkillMeta] = {}

    # 1. Shipped/Bundled skills
    if BUNDLED_SKILLS_DIR.exists() and BUNDLED_SKILLS_DIR.is_dir():
        for skill_dir in BUNDLED_SKILLS_DIR.iterdir():
            if skill_dir.is_dir():
                skill_file = skill_dir / "SKILL.md"
                if skill_file.exists() and skill_file.is_file():
                    try:
                        # Read frontmatter only (first 4KB is ample for frontmatter)
                        with open(skill_file, "r", encoding="utf-8", errors="ignore") as f:
                            sample = f.read(4096)
                        meta_dict, _ = _parse_yaml_frontmatter(sample)
                        name = meta_dict.get("name", skill_dir.name)
                        desc = meta_dict.get("description", "")
                        ref_dir = skill_dir / "references"
                        ref_path = str(ref_dir) if (ref_dir.exists() and ref_dir.is_dir()) else None
                        registry[name] = SkillMeta(
                            name=name,
                            description=desc,
                            path=str(skill_file),
                            references_dir=ref_path,
                            is_user_defined=False
                        )
                    except Exception as e:
                        logger.warning(f"Error reading skill {skill_file}: {e}")

    # 2. User skills (~/.hellhound/skills/)
    if USER_SKILLS_DIR.exists() and USER_SKILLS_DIR.is_dir():
        for skill_dir in USER_SKILLS_DIR.iterdir():
            if skill_dir.is_dir():
                skill_file = skill_dir / "SKILL.md"
                if skill_file.exists() and skill_file.is_file():
                    try:
                        with open(skill_file, "r", encoding="utf-8", errors="ignore") as f:
                            sample = f.read(4096)
                        meta_dict, _ = _parse_yaml_frontmatter(sample)
                        name = meta_dict.get("name", skill_dir.name)
                        desc = meta_dict.get("description", "")
                        ref_dir = skill_dir / "references"
                        ref_path = str(ref_dir) if (ref_dir.exists() and ref_dir.is_dir()) else None
                        registry[name] = SkillMeta(
                            name=name,
                            description=desc,
                            path=str(skill_file),
                            references_dir=ref_path,
                            is_user_defined=True
                        )
                    except Exception as e:
                        logger.warning(f"Error reading user skill {skill_file}: {e}")

    return registry


SKILL_USAGE_FILE = USER_SKILLS_DIR.parent / "skill_usage.json"


def get_short_description(desc: str, max_len: int = 160) -> str:
    """Extracts a concise, single-line human-friendly summary from a skill description."""
    if not desc:
        return ""
    clean = " ".join(desc.strip().split())
    # Strip common AI prompt triggers if substantial text exists before them
    for trigger in [" Use when ", " Covers ", " Guide ", " Never use "]:
        if trigger in clean:
            idx = clean.find(trigger)
            if idx > 20:
                clean = clean[:idx].strip()

    # Check if em-dash split yields a meaningful > 20 char prefix
    parts = re.split(r"\s+[—–]\s+", clean)
    if parts and len(parts[0]) >= 20 and len(parts[0]) <= max_len:
        return parts[0].strip().rstrip(".")
    elif parts and len(parts) > 1:
        combined = f"{parts[0]} — {parts[1]}"
        if len(combined) <= max_len:
            return combined.strip().rstrip(".")
        clean = combined

    # Fallback sentence split
    sentence = re.split(r"\.\s+", clean)[0]
    if len(sentence) > max_len:
        truncated = sentence[:max_len].rsplit(" ", 1)[0]
        return truncated.rstrip(",.-;:—") + "..."
    return sentence.strip().rstrip(".")


def get_skill_usage_counts() -> Dict[str, int]:
    """Retrieves stored execution frequency counts for methodology skills and commands."""
    if not SKILL_USAGE_FILE.exists():
        return {}
    try:
        import json
        with open(SKILL_USAGE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def record_skill_usage(skill_name: str):
    """Increments the execution frequency count for a given skill or slash command."""
    if not skill_name:
        return
    try:
        import json
        counts = get_skill_usage_counts()
        name = skill_name.lstrip("/").lower()
        counts[name] = counts.get(name, 0) + 1
        SKILL_USAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(SKILL_USAGE_FILE, "w", encoding="utf-8") as f:
            json.dump(counts, f, indent=2)
    except Exception as e:
        logger.debug(f"Failed to record skill usage for {skill_name}: {e}")


def _tokenize(text: str) -> Set[str]:
    """Tokenizes text into lowercase alphanumeric keywords and subwords."""
    # Split on whitespace, punctuation, hyphens, underscores
    words = re.findall(r"[a-zA-Z0-9_\-\./]+", text.lower())
    tokens = set()
    for w in words:
        tokens.add(w)
        # Split sub-tokens if hyphenated or dotted
        for sub in re.split(r"[-_/\.]+", w):
            if len(sub) > 1:
                tokens.add(sub)
    return tokens


# Specificity weights for domain-specific skills over generic broad guides
SPECIFICITY_KEYWORDS: Dict[str, List[str]] = {
    "ctf-lab-recon": ["ctf", "lab", "htb", "thm", "hackthebox", "tryhackme", "vulnhub", "ctfio", "training range", "isolated target", "private target", "non-indexed"],
    "graphql-audit": ["graphql", "introspection", "query", "mutation", "schema", "gql", "apollo"],
    "cicd-security": ["cicd", "ci/cd", "github actions", "gitlab-ci", "workflow", "runner", "actions"],
    "client-reverse": ["reverse", "signing", "signature", "anti-bot", "sensor", "hmac", "token", "obfuscat", "webpack", "wasm", "jsvmp"],
    "mobile-pentest": ["mobile", "apk", "ipa", "android", "ios", "frida", "jadx", "objection", "deeplink"],
    "web3-audit": ["web3", "smart contract", "solidity", "ethereum", "evm", "reentrancy", "flash loan"],
    "meme-coin-audit": ["meme", "memecoin", "solana", "rugpull", "pump.fun", "bonding curve", "liquidity"],
    "credential-attack": ["credential", "spray", "bruteforce", "stuffing", "password", "login", "jwt"],
    "argus": ["argus", "scanner", "scan-suite", "automated scanner", "pipeline", "vuln scan"],
    "security-arsenal": ["arsenal", "payload", "bypass", "waf", "polyglot", "filter", "obfuscation"],
    "web2-recon": ["subdomain", "recon", "dns", "asn", "ffuf", "httpx", "crawler", "jsluice", "endpoints"],
    "triage-validation": ["validate", "validation", "triage", "gate", "7-question", "validity", "false positive", "kill signal", "cvss"],
    "report-writing": ["report", "write report", "summary", "submission", "remediation", "hackerone", "bugcrowd"],
    "bb-methodology": ["methodology", "where am i", "what should i do next", "what next", "workflow", "mindset", "phase", "strategy"],
    "auth-bypass": ["auth", "bypass", "forgot password", "reset link", "email leak", "host header", "jwt", "token", "algorithm confusion", "alg:none", "public key", "takeover", "account takeover"],
    "authentication": ["auth", "login", "jwt", "oauth", "password", "2fa", "mfa", "captcha", "bot detection", "saml"],
    "exposed-source-recon": ["git", ".git", "exposed git", "dangling cname", "subdomain takeover", "source code leak", "source leak", "cname takeover"],
    "insecure-deserialization": ["deserialization", "pickle", "pyyaml", "unserialize", "ysoserial", "objectinputstream", "gadget chain", "yaml.load"],
    "llm-prompt-injection": ["prompt injection", "llm", "chatbot", "system prompt", "guardrail", "jailbreak", "ai agent", "prompt leakage"],
    "prototype-pollution-mass-assignment": ["prototype pollution", "__proto__", "constructor.prototype", "mass assignment", "object merge", "polluted", "nested field"],
    "race-condition": ["race condition", "toctou", "concurrency", "parallel requests", "rate limit bypass", "double spend", "coupon race"],
    "ssrf": ["ssrf", "server-side request forgery", "metadata", "169.254.169.254", "internal port", "webhook", "pdf converter", "headless browser"],
    "ssti": ["ssti", "template injection", "jinja2", "ejs", "twig", "freemarker", "velocity", "handlebars", "{{7*7}}"],
    "server-side-parameter-pollution": ["sspp", "parameter pollution", "http parameter pollution", "hpp", "query string pollution", "%23", "%26", "truncat", "server-side parameter pollution", "parameter injection", "internal api query"]
}


# Known CTF / Lab platform domain patterns & suffixes
CTF_DOMAIN_PATTERNS = (
    ".ctfio.com",
    ".ctfio",
    ".hackthebox.com",
    ".hackthebox.eu",
    ".htb",
    ".tryhackme.com",
    ".thm",
    ".vulnhub.com",
    ".root-me.org",
    ".pwnable.kr",
    ".pwnable.tw",
    ".pwnable.xyz",
    ".ctfd.io",
    ".overthewire.org",
    ".portswigger-labs.net",
    ".pentesterlab.com",
    ".challs.io",
    ".chal.pw",
    ".ctf.live",
    ".local",
    ".test",
    ".internal",
)


def is_ctf_domain_pattern(domain: str) -> bool:
    """
    Checks if a domain/host matches known CTF or lab platform domain patterns.
    """
    if not domain or not domain.strip():
        return False
    d = domain.lower().strip().lstrip("*.")
    if d in ("localhost", "127.0.0.1"):
        return True
    for suffix in CTF_DOMAIN_PATTERNS:
        clean_suf = suffix.lstrip(".")
        if d == clean_suf or d.endswith(suffix) or d.endswith("." + clean_suf):
            return True
    if re.search(r'(^|\.)ctf[\.-]', d):
        return True
    try:
        import ipaddress
        ip = ipaddress.ip_address(d)
        if ip.is_private or ip.is_loopback:
            return True
    except Exception:
        pass
    return False


def is_ctf_auto_scope_eligible(target_name: str, user_text: str = "") -> bool:
    """
    Determines whether a target is eligible for automatic scoping without manual /scope.
    Requires:
      1. Target domain matches verified CTF/lab platform infrastructure (e.g. .ctfio.com, .htb, .tryhackme.com, localhost)
         AND context or domain confirms CTF/lab nature.
      OR
      2. User text contains explicit high-confidence multi-word authorization phrases
         ('training range', 'isolated target', 'private target', 'non-indexed target', 'non-indexed lab').

    A bare token like 'lab' or 'test' alone against a regular public domain (e.g. 'targetcorp.example')
    will NEVER qualify for auto-scoping.
    """
    if not target_name:
        return False

    # 1. Target domain matches CTF domain patterns
    if is_ctf_domain_pattern(target_name):
        return True

    # 2. Check for explicit multi-word isolation authorization phrases in user text
    q_lower = user_text.lower() if user_text else ""
    explicit_phrases = [
        "training range",
        "isolated target",
        "private target",
        "non-indexed target",
        "non-indexed lab"
    ]
    if any(phrase in q_lower for phrase in explicit_phrases):
        return True

    return False


def is_ctf_lab_context(user_text: str) -> bool:
    """
    Checks if the user's message indicates a CTF, lab environment, training range,
    or isolated non-indexed target.
    Reads triggers dynamically from the `ctf-lab-recon` skill's description and keywords.
    """
    if not user_text or not user_text.strip():
        return False

    q_lower = user_text.lower()
    q_tokens = _tokenize(user_text)

    # 1. Check against specificity keywords for ctf-lab-recon
    for kw in SPECIFICITY_KEYWORDS.get("ctf-lab-recon", []):
        if " " in kw:
            if kw in q_lower:
                return True
        elif kw in q_tokens:
            return True

    # 2. Check against description tokens of ctf-lab-recon dynamically from registry
    registry = discover_skills()
    skill = registry.get("ctf-lab-recon")
    if skill and skill.description:
        desc_tokens = _tokenize(skill.description)
        # Exclude common generic stopwords from triggering
        stopwords = {"use", "when", "targeting", "or", "that", "are", "not", "a", "live", "bounty", "program", "guides", "and", "the", "for", "to", "in", "is"}
        sig_tokens = {t for t in desc_tokens if len(t) > 2 and t not in stopwords}
        overlap = q_tokens.intersection(sig_tokens)
        # High confidence match if specific distinctive triggers overlap
        ctf_triggers = {"ctf", "lab", "htb", "thm", "hackthebox", "tryhackme", "vulnhub", "ctfio"}
        if overlap.intersection(ctf_triggers):
            return True

    return False


def search_skills(query: str, max_results: int = 2, min_score: float = 0.12) -> List[SkillMeta]:
    """
    Matches query text (user message + conversation context) against skill descriptions and names.
    Calculates weighted term overlap and specificity bonuses.
    Returns top matches clearing the minimum score threshold.
    """
    registry = discover_skills()
    if not registry or not query.strip():
        return []

    q_lower = query.lower()
    q_tokens = _tokenize(query)

    scored: List[Tuple[float, SkillMeta]] = []

    for name, skill in registry.items():
        score = 0.0
        desc_lower = skill.description.lower()
        desc_tokens = _tokenize(skill.description)

        # 1. Exact skill name mentioned in query
        if name.lower() in q_lower or name.replace("-", " ") in q_lower:
            score += 3.0

        # 2. Token overlap between query and description
        matching_tokens = q_tokens.intersection(desc_tokens)
        if matching_tokens:
            # Score based on proportion of query keywords present
            overlap_ratio = len(matching_tokens) / max(len(q_tokens), 1)
            score += overlap_ratio * 2.0

        # 3. Domain specificity boosts
        if name in SPECIFICITY_KEYWORDS:
            for kw in SPECIFICITY_KEYWORDS[name]:
                if kw in q_lower:
                    score += 1.8
                    break

        # 4. Check for high-signal phrases in description
        for phrase in [
            "start of any bug bounty", "what should i do next", "7-question gate",
            "request-signing", "graphql", "smart contract", "anti-bot",
            "idor", "xss", "ssrf", "sqli", "race condition", "prototype pollution",
            "oauth", "saml", "subdomain takeover"
        ]:
            if phrase in q_lower and phrase in desc_lower:
                score += 1.5

        if score >= min_score:
            scored.append((score, skill))

    # Sort descending by score
    scored.sort(key=lambda item: item[0], reverse=True)

    # Prefer specific skills over general ones if multiple matches
    results = [s for _, s in scored[:max_results]]
    return results


def load_skill_body(name: str) -> str:
    """Reads and returns the full markdown body (below the frontmatter) for a skill."""
    registry = discover_skills()
    skill = registry.get(name)
    if not skill:
        return ""

    try:
        with open(skill.path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        _, body = _parse_yaml_frontmatter(content)
        return body.strip()
    except Exception as e:
        logger.error(f"Failed to load skill body for {name}: {e}")
        return ""


def load_skill_section(name: str, query: str = "") -> str:
    """
    Extracts the most relevant section(s) from a skill markdown for small-context models.
    Splits by '## ' headings and matches against query tokens.
    """
    body = load_skill_body(name)
    if not body:
        return ""

    sections = re.split(r"(?m)^(?=##\s+)", body)
    if len(sections) <= 1 or not query.strip():
        # Truncate to reasonable length for small models if no sections
        return body[:3000]

    q_tokens = _tokenize(query)
    scored_sections: List[Tuple[int, str]] = []

    for sec in sections:
        sec_tokens = _tokenize(sec)
        overlap = len(q_tokens.intersection(sec_tokens))
        scored_sections.append((overlap, sec))

    scored_sections.sort(key=lambda s: s[0], reverse=True)

    # Pick top 2 sections
    top_secs = [s[1] for s in scored_sections[:2] if s[0] > 0]
    if not top_secs:
        return sections[0][:3000]

    return "\n\n".join(top_secs)


def load_skill_reference(skill_name: str, filename: str) -> Optional[str]:
    """
    Loads a supplementary reference file from the skill's `references/` subfolder.
    Prevents path traversal and validates directory safety.
    """
    registry = discover_skills()
    skill = registry.get(skill_name)
    if not skill or not skill.references_dir:
        return None

    ref_dir = Path(skill.references_dir).resolve()
    target_file = (ref_dir / filename).resolve()

    # Safety check: ensure target_file is within ref_dir
    try:
        target_file.relative_to(ref_dir)
    except ValueError:
        logger.warning(f"Path traversal attempt blocked: {skill_name} / {filename}")
        return None

    if not target_file.exists() or not target_file.is_file():
        return None

    try:
        with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error reading skill reference {target_file}: {e}")
        return None


def is_directed_task(user_text: str) -> bool:
    """
    Detects an explicit, concrete task: a specific target (URL/host) paired
    with an action verb describing what to do to it — e.g. "bypass auth on
    https://example.com/login", "log in and reach the admin console at x.com".
    When True, the user has already told the agent exactly what to do, so
    broad session-start methodology (bb-methodology / ctf-lab-recon) should
    NOT be injected — it would compete with, rather than inform, an
    instruction the user already made explicit. Technology-specific skills
    (Rule 3, e.g. graphql-audit) can still fire independently.
    """
    if not user_text:
        return False
    q_lower = user_text.lower()
    has_target = bool(re.search(r"https?://\S+", q_lower)) or bool(re.search(r"\b[a-z0-9.-]+\.[a-z]{2,}(/\S*)?\b", q_lower))
    action_verbs = [
        "bypass", "log in", "login", "sign in", "take over", "takeover",
        "exploit", "reach the", "get us to", "get access", "access the",
        "retrieve", "extract", "escalate", "dump", "exfiltrate",
        "find a way to", "break into", "compromise"
    ]
    has_action = any(v in q_lower for v in action_verbs)
    return has_target and has_action


def get_relevant_skills_prompt(
    user_text: str,
    history_len: int = 0,
    has_target: bool = False,
    is_small_model: bool = False,
    max_skills: int = 2
) -> str:
    """
    Deliberately inert. This used to auto-inject skill content by guessing
    intent from the message text (session-start heuristics, "triage"/
    "report" keyword matching, a fuzzy search-skills topic match) — three
    separate Python-side heuristics all deciding what the user meant
    before the model ever saw the message. All three turned out to
    misfire in practice (a bare "hello" triggering full hunting
    methodology; "what can you do for me" fuzzy-matching "403-bypass" and
    "security-arsenal" via search_skills). Every one of those was the
    same mistake: a keyword/string check standing in for the model's own
    judgment on a genuinely ambiguous question — exactly what `load_skill`
    and the always-visible SKILL MENU (see agent.py's orchestrator prompt)
    already exist to solve properly. Skill selection now happens
    entirely there: the model reads the menu and pulls what it decides it
    needs via `load_skill(name)`, for every message, with zero Python-side
    guessing. This function is kept only so its call sites and signature
    don't need to change; it always returns "".
    """
    return ""
