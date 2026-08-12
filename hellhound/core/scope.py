"""
hellhound/core/scope.py

Target-Scope Security Guard System.
Enforces strict in-scope / out-of-scope domain boundaries, wildcard evaluation,
path-level exclusions, and program rule / prohibited testing constraints.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Tuple, Optional, Dict, Any
import fnmatch
import ipaddress
import re
from urllib.parse import urlparse


# Standardized Disallowed Rule Flags
RULE_FLAGS = {
    "no-dos": ["dos", "denial of service", "ddos", "stress test", "volumetric"],
    "no-brute-force": ["brute force", "bruteforce", "credential stuffing", "password spraying", "hydra"],
    "no-automated-scanners": ["automated scanner", "automated scanning", "vulnerability scanner", "burp active scan", "zap active"],
    "no-rate-limit-testing": ["rate limit", "rate-limit", "rate limiting", "throttling"],
    "no-fuzzing": ["fuzzing", "fuzz", "payload fuzzing", "wordlist fuzzing"],
    "no-active-exploitation": ["active exploitation", "rce execution", "data destruction", "modifying data", "active exploit", "poc only", "poc-only"],
}

# Module Risk Classifications
MODULE_RISK_MAP = {
    "hydra": ["no-brute-force", "no-dos", "no-rate-limit-testing", "no-automated-scanners"],
    "subbrute": ["no-brute-force", "no-dos", "no-automated-scanners"],
    "fuzzhunter": ["no-fuzzing", "no-dos", "no-automated-scanners"],
    "exmap": ["no-active-exploitation"],
}


@dataclass
class ScopeRules:
    """
    Structured representation of engagement scope and rules.
    """
    in_scope: List[str] = field(default_factory=list)
    out_scope: List[str] = field(default_factory=list)
    disallowed: List[str] = field(default_factory=list)
    raw_text: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScopeRules":
        if not isinstance(data, dict):
            return cls()
        return cls(
            in_scope=list(data.get("in_scope", [])),
            out_scope=list(data.get("out_scope", [])),
            disallowed=list(data.get("disallowed", [])),
            raw_text=str(data.get("raw_text", ""))
        )


def _normalize_host(target: str) -> Tuple[str, str]:
    """
    Extracts the normalized hostname/domain and path from a target string.
    Supports URLs, hostname:port, raw domains, and IP addresses.
    """
    target = target.strip()
    if not target:
        return "", ""

    if not target.startswith(("http://", "https://")) and "://" not in target:
        # Check if there is a path component
        if "/" in target:
            target = "https://" + target
        else:
            target = "https://" + target

    try:
        parsed = urlparse(target)
        hostname = (parsed.hostname or parsed.netloc.split(":")[0] or "").lower().rstrip(".")
        path = parsed.path or "/"
        return hostname, path
    except Exception:
        # Fallback regex extraction
        clean = re.sub(r"^https?://", "", target, flags=re.IGNORECASE)
        host = clean.split("/")[0].split(":")[0].lower().rstrip(".")
        path = "/" + "/".join(clean.split("/")[1:]) if "/" in clean else "/"
        return host, path


def _match_pattern(host: str, path: str, pattern: str) -> bool:
    """
    Checks if host and path match a scope pattern.
    Supports wildcards (*.example.com), IP ranges/CIDRs, and path prefixes.
    """
    pattern = pattern.strip().lower()
    if not pattern:
        return False

    pat_host, pat_path = _normalize_host(pattern)

    # 1. IP / CIDR check
    try:
        if "/" in pattern and not pattern.startswith("http"):
            net = ipaddress.ip_network(pattern, strict=False)
            target_ip = ipaddress.ip_address(host)
            return target_ip in net
    except Exception:
        pass

    # 2. Host matching (Wildcards and Subdomains)
    host_match = False
    if pat_host.startswith("*."):
        suffix = pat_host[2:]
        if host == suffix or host.endswith("." + suffix):
            host_match = True
    elif "*" in pat_host:
        host_match = fnmatch.fnmatch(host, pat_host)
    else:
        if host == pat_host:
            host_match = True
        elif pat_host and host.endswith("." + pat_host):
            host_match = True

    if not host_match:
        return False

    # 3. Path matching if pattern includes a specific path
    if pat_path and pat_path != "/":
        if not path.startswith(pat_path):
            return False

    return True


def is_in_scope(target: str, rules: Optional[ScopeRules]) -> Tuple[bool, str]:
    """
    Determines if a target is authorized for testing based on ScopeRules.
    Enforces deny-overrides-allow logic.

    Returns:
        (allowed: bool, reason: str)
    """
    if not rules:
        return True, "No scope rules configured (default allow)"

    host, path = _normalize_host(target)
    if not host:
        return False, f"Invalid target format: '{target}'"

    # Step 1: Out-of-Scope check (Deny overrides allow)
    for out_pat in rules.out_scope:
        if _match_pattern(host, path, out_pat):
            return False, f"Target '{target}' matches out-of-scope exclusion rule '{out_pat}'"

    # Step 2: In-Scope check
    if rules.in_scope:
        for in_pat in rules.in_scope:
            if _match_pattern(host, path, in_pat):
                return True, f"Target '{target}' matches in-scope rule '{in_pat}'"
        return False, f"Target '{target}' is not within any defined in-scope targets ({', '.join(rules.in_scope[:3])})"

    # Default allow when in_scope is empty and not excluded
    return True, "Target permitted (no explicit in-scope whitelist restriction)"


def check_module_against_rules(module_name: str, rules: Optional[ScopeRules]) -> Tuple[bool, str]:
    """
    Cross-references a vulnerability module's risk profile against program restriction flags.

    Returns:
        (allowed: bool, reason: str)
    """
    if not rules or not rules.disallowed:
        return True, "Module permitted"

    norm_name = module_name.lower().replace("_", "").replace("-", "")
    matching_mod = next((k for k in MODULE_RISK_MAP if k.replace("_", "") == norm_name), None)

    if matching_mod:
        risks = MODULE_RISK_MAP[matching_mod]
        for disallowed_flag in rules.disallowed:
            flag_norm = disallowed_flag.lower().strip()
            if flag_norm in risks:
                return False, f"Module '{module_name}' is prohibited by engagement rule: '{disallowed_flag}'"

    return True, "Module permitted under engagement rules"


def parse_program_rules(raw_text: str) -> ScopeRules:
    """
    Parses unstructured text, markdown, or program summaries (HackerOne, Bugcrowd, etc.)
    into a structured ScopeRules instance.
    """
    if not raw_text or not raw_text.strip():
        return ScopeRules(raw_text=raw_text)

    in_scope: List[str] = []
    out_scope: List[str] = []
    disallowed: List[str] = []

    lines = re.split(r"[\n\r\|]+", raw_text)
    current_section = "in_scope"  # default section

    section_headers = {
        "in_scope": [
            r"^#*\s*in[\s_-]scope",
            r"^#*\s*eligible\s*targets?",
            r"^#*\s*scope",
            r"^#*\s*included\s*assets?",
            r"^#*\s*targets?",
            r"^#*\s*assets?\s*/\s*in[\s_-]scope"
        ],
        "out_scope": [
            r"^#*\s*out[\s_-]of[\s_-]scope",
            r"^#*\s*out[\s_-]scope",
            r"^#*\s*exclusions?",
            r"^#*\s*excluded\s*targets?",
            r"^#*\s*ineligible",
            r"^#*\s*non[\s_-]targets?"
        ],
        "disallowed": [
            r"^#*\s*disallowed",
            r"^#*\s*restrictions?",
            r"^#*\s*rules\s*of\s*engagement",
            r"^#*\s*prohibited\s*(actions|activities)?",
            r"^#*\s*out[\s_-]of[\s_-]bounds",
            r"^#*\s*unacceptable\s*behavior"
        ]
    }

    # Extract target candidates: domains, wildcards, URLs, IP ranges
    target_regex = re.compile(
        r"(?:\*\.)?[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?::\d+)?(?:/[^\s`\"'<>]*)?"
        r"|https?://[^\s`\"'<]+"
        r"|\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"
    )

    for line in lines:
        clean_line = line.strip()
        if not clean_line:
            continue

        lower_line = clean_line.lower()

        # Check section header transition (and inline definitions like 'Targets: a.com, b.com')
        header_matched = False
        remaining_line = clean_line
        for sec, patterns in section_headers.items():
            for p in patterns:
                m_hdr = re.search(p, lower_line)
                if m_hdr:
                    current_section = sec
                    header_matched = True
                    # Remove the header prefix if there is a colon
                    if ":" in clean_line:
                        remaining_line = clean_line.split(":", 1)[1].strip()
                    else:
                        remaining_line = ""
                    break
            if header_matched:
                break

        target_text_to_scan = remaining_line if header_matched else clean_line

        # Check for disallowed flags in the line
        for flag_name, keywords in RULE_FLAGS.items():
            if any(kw in lower_line for kw in keywords) or flag_name in lower_line:
                if flag_name not in disallowed:
                    disallowed.append(flag_name)

        # If we are in the disallowed section, also extract any standard bullet items
        if current_section == "disallowed" and target_text_to_scan:
            for item in re.split(r"[,;\n\r]+", target_text_to_scan):
                item_clean = re.sub(r"^[\*\-\+\d\.\s\|\`]+", "", item).strip()
                if item_clean:
                    for flag_name, keywords in RULE_FLAGS.items():
                        if any(kw in item_clean.lower() for kw in keywords) or flag_name in item_clean.lower():
                            if flag_name not in disallowed:
                                disallowed.append(flag_name)

        # Extract targets if in scope/out scope sections
        if target_text_to_scan and current_section in ("in_scope", "out_scope"):
            # Strip list bullets, backticks, pipes, and numbered list prefixes (e.g. '1. ')
            clean_text = re.sub(r"^[*\-+|\s`]+|^\d+\.\s+", "", target_text_to_scan)
            matches = target_regex.findall(clean_text)
            for m in matches:
                m_clean = m.strip("`'\",;|()[]{}")
                if not m_clean or len(m_clean) < 3:
                    continue
                # Only filter out generic informational platforms
                if m_clean.lower() in ("github.com", "hackerone.com", "bugcrowd.com", "intigriti.com"):
                    continue

                if current_section == "in_scope":
                    if m_clean not in in_scope:
                        in_scope.append(m_clean)
                elif current_section == "out_scope":
                    if m_clean not in out_scope:
                        out_scope.append(m_clean)

    # If no section was explicitly found, extract all valid domains into in_scope
    if not in_scope and not out_scope:
        for match in target_regex.findall(raw_text):
            m_clean = match.strip("`'\",;|()[]{}")
            if m_clean and len(m_clean) >= 3 and m_clean not in in_scope:
                in_scope.append(m_clean)

    return ScopeRules(
        in_scope=in_scope,
        out_scope=out_scope,
        disallowed=disallowed,
        raw_text=raw_text
    )
