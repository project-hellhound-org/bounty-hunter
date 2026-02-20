import subprocess
import shutil
import re

NAME = "Seige"
CATEGORY = "vuln"
DESCRIPTION = "Silent Vulnerability Scanning (Nikto & Nuclei with Risk Scoring)"

# -------------------------------------------------
# Helpers
# -------------------------------------------------

def tool_exists(tool):
    return shutil.which(tool) is not None

def run_cmd(cmd, timeout=180):
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            universal_newlines=True,
            timeout=timeout
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "Scan timed out (Tool took too long)", -1
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not found in PATH", -2
    except Exception as e:
        return "", str(e), -1

def parse_nikto(output):
    findings = []
    lines = output.split('\n')
    for line in lines:
        if "+" in line:
            clean_line = line.strip()
            # Filter out pure info noise if desired, but keeping for risk calculation
            if "OSVDB" in clean_line or "Retrieved" in clean_line or "X-Frame-Options" in clean_line or "Server:" in clean_line:
                findings.append(clean_line)
    return findings

def parse_nuclei_text(text_output):
    """
    Parses the standard Nuclei text output.
    Matches: [CVE-ID] [Protocol] [Severity] URL/Info
    """
    findings = []
    pattern = re.compile(r'^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.+)$')
    lines = text_output.replace('\r\n', '\n').split('\n')
    
    for line in lines:
        match = pattern.match(line.strip())
        if match:
            cve_id, protocol, severity, info = match.groups()
            # Clean up info part
            info_short = info[:60] + "..." if len(info) > 60 else info
            findings.append(f"[{severity.upper()}] {cve_id} on {protocol}: {info_short}")
            
    return findings

def calculate_risk(nikto_findings, nuclei_findings):
    """
    Calculates a risk score based on the findings.
    Adapted from user request logic to fit Nuclei/Nikto string output.
    """
    risk_score = 0

    # 1. Score Nuclei Findings (Higher Weight)
    for v in nuclei_findings:
        v_upper = v.upper()
        if "[CRITICAL]" in v_upper:
            risk_score += 10  # Critical: Confirmed RCE or similar
        elif "[HIGH]" in v_upper:
            risk_score += 7   # High
        elif "[MEDIUM]" in v_upper:
            risk_score += 4   # Medium
        elif "[LOW]" in v_upper or "[INFO]" in v_upper:
            risk_score += 1   # Low/Info
        else:
            risk_score += 2   # Baseline risk for unclassified

    # 2. Score Nikto Findings (Lower Weight - mostly info/config)
    risk_score += len(nikto_findings) * 2

    return risk_score

# -------------------------------------------------
# Scanner Engine
# -------------------------------------------------

class SeigeEngine:

    def __init__(self, target, emit):
        self.target = target
        self.emit = emit
        self.results = {
            "nikto": [],
            "nuclei": []
        }

    def run_nikto(self):
        if not tool_exists("nikto"):
            self.emit.warn("[!] 'nikto' command not found.")
            return

        # Removed leading [*] to prevent duplication with console logger
        self.emit.info("Starting Nikto Scan...")
        cmd = ["nikto", "-h", self.target, "-ask", "no", "-Tuning", "1", "-Display", "V"]
        stdout, stderr, returncode = run_cmd(cmd)
        
        if returncode != 0 and stderr:
            self.emit.error(f"    [!] Nikto Error: {stderr}")

        findings = parse_nikto(stdout)
        if not findings and "+" in stdout:
             findings = ["Nikto found potential issues (parsing failed)"]
        
        self.results["nikto"] = findings
        if self.results["nikto"]:
            self.emit.success(f"[+] Nikto found {len(self.results['nikto'])} items.")
        else:
            self.emit.info("[-] Nikto found no vulnerabilities.")

    def run_nuclei(self):
        if not tool_exists("nuclei"):
            self.emit.warn("[!] 'nuclei' command not found.")
            return

        self.emit.info("Starting Nuclei Scan...")
        
        cmd = [
            "nuclei", 
            "-u", self.target, 
            "-s", "critical,high,medium", 
            "-stats"
        ]
        
        stdout, stderr, returncode = run_cmd(cmd, timeout=180)
        
        if not stdout:
            self.emit.error("[!] Nuclei returned NO OUTPUT.")
            if stderr:
                self.emit.error(f"    [!] STDERR: {stderr[:300]}")
        else:
            self.emit.info(f"Nuclei Output captured ({len(stdout)} chars). Parsing...")

        findings = parse_nuclei_text(stdout)
        self.results["nuclei"] = findings
        
        if self.results["nuclei"]:
            self.emit.success(f"[+] Nuclei found {len(self.results['nuclei'])} vulnerabilities.")
        else:
            self.emit.warn("[-] Nuclei found no vulnerabilities.")

    def run(self):
        self.run_nikto()
        self.run_nuclei()
        return self.results

# -------------------------------------------------
# Entry Point
# -------------------------------------------------

def run(target, emit, options=None):
    # Removed leading [*] here to prevent double prefix
    emit.info(f"Seige: Active scan on {target}")
    
    scanner = SeigeEngine(target, emit)
    scan_results = scanner.run()
    
    # Calculate Risk Score
    risk_score = calculate_risk(scan_results["nikto"], scan_results["nuclei"])
    
    # Silent Mode: Do NOT print detailed findings here. 
    # Only mention the summary.
    
    nikto_count = len(scan_results["nikto"])
    nuclei_count = len(scan_results["nuclei"])
    
    signals = []
    if nikto_count > 0: signals.append("NIKTO_VULNS_FOUND")
    if nuclei_count > 0: signals.append("NUCLEI_VULNS_FOUND")
    if not signals: signals.append("SCAN_CLEAN")

    return {
        "raw": f"Nikto: {nikto_count} | Nuclei: {nuclei_count}",
        "intel": {
            "nikto_findings": scan_results["nikto"],
            "nuclei_findings": scan_results["nuclei"],
            "risk_score": risk_score  # <--- Injecting the calculated score
        },
        "signals": signals
    }