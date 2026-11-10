"""
hellhound/core/tools/network_recon.py - network / port reconnaissance.

Split slice 6 from agent.py. port_scan (nmap/rustscan-backed port sweep) and
nmap_service_scan (targeted service/version detection) both shell out directly
via subprocess - no agent.py internals. agent.py re-imports both executors so
TOOL_REGISTRY wiring is unchanged.
"""
import json
import socket
import subprocess
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from hellhound.core.ai_utils import load_config
from hellhound.core.tasks import Target
from hellhound.core.toolcheck import ensure_tool, get_binary_path


def _execute_port_scan(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Port scanning via naabu to discover open TCP/UDP ports and non-standard web services."""
    raw_target = args.get("hosts") or args.get("target") or args.get("host") or target.name
    targets_to_scan = []
    if isinstance(raw_target, list):
        targets_to_scan = [str(t).strip() for t in raw_target if str(t).strip()]
    elif isinstance(raw_target, str) and "," in raw_target:
        targets_to_scan = [t.strip() for t in raw_target.split(",") if t.strip()]
    else:
        targets_to_scan = [str(raw_target).strip()]

    cleaned_targets = []
    for t in targets_to_scan:
        if t.startswith(("http://", "https://")):
            t = urlparse(t).netloc.split(":")[0]
        if t:
            cleaned_targets.append(t)

    if not cleaned_targets:
        return {"error": "No valid hosts provided for port scan."}

    auto_install = bool(load_config().get("auto_install_missing_tools", False))
    check = ensure_tool("naabu", emit=emit, auto_install=auto_install)
    if not check["available"]:
        if emit and hasattr(emit, "warn"):
            emit.warn(check["message"])
        return {
            "error": "naabu not installed",
            "message": check["message"],
            "hint": "pdtm -i naabu"
        }

    binary = get_binary_path("naabu") or "naabu"

    ports = str(args.get("ports", "top-100")).strip().lower()
    exclude_ports = args.get("exclude_ports")

    cmd = [binary, "-j", "-silent"]
    if ports in ("top-100", "top100", "100"):
        cmd.extend(["-tp", "100"])
    elif ports in ("top-1000", "top1000", "1000"):
        cmd.extend(["-tp", "1000"])
    elif ports in ("full", "all", "top-full"):
        cmd.extend(["-tp", "full"])
    else:
        cmd.extend(["-p", ports])

    if exclude_ports:
        cmd.extend(["-exclude-ports", str(exclude_ports)])

    open_ports = []
    try:
        input_data = "\n".join(cleaned_targets)
        proc = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=120)
        if proc.stdout.strip():
            for line in proc.stdout.splitlines():
                if line.strip():
                    try:
                        item = json.loads(line.strip())
                        open_ports.append({
                            "host": item.get("host"),
                            "ip": item.get("ip", ""),
                            "port": item.get("port"),
                            "protocol": item.get("protocol", "tcp"),
                            "tls": item.get("tls", False)
                        })
                    except Exception:
                        pass
    except Exception as e:
        return {"error": f"naabu execution failed: {e}", "hosts": cleaned_targets}

    # Update target state
    if "open_ports" not in target.state:
        target.state["open_ports"] = []
    for p in open_ports:
        if p not in target.state["open_ports"]:
            target.state["open_ports"].append(p)

    return {
        "hosts_scanned": cleaned_targets,
        "count": len(open_ports),
        "open_ports": open_ports
    }


def _execute_nmap_service_scan(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Deep service/vuln enumeration via nmap (-sV -sC --script vuln,default)
    against a host's already-discovered open ports (run port_scan/naabu
    first, or pass explicit ports). This is heavier and noisier than
    naabu's plain port discovery — gated against engagement rules
    (no-automated-scanners / no-dos) via check_module_against_rules.
    Needs nmap on PATH and usually root/CAP_NET_RAW for the SYN scan
    (falls back to a TCP connect scan if that's unavailable).
    """
    host = str(args.get("host") or args.get("hosts") or target.name).strip().lower()
    if host.startswith(("http://", "https://")):
        host = urlparse(host).netloc.split(":")[0]
    if not host:
        return {
            "status": "no_host_given",
            "note": "Nah bro, nmap_service_scan needs a host — nothing to scan. Pass one and call this again.",
        }

    nmap_bin = get_binary_path("nmap")
    if not nmap_bin:
        return {"error": "nmap not installed", "hint": "apt install nmap  (or the equivalent for your OS)"}

    ports = args.get("ports")
    if not ports:
        state_ports = target.state.get("open_ports", {}).get(host) if isinstance(target.state.get("open_ports"), dict) else None
        if state_ports:
            ports = ",".join(str(p) for p in state_ports)
    if not ports:
        return {
            "status": "no_ports_given",
            "note": "Nah bro, nmap_service_scan needs ports to target — run port_scan first to discover open ports, then pass them here explicitly (e.g. ports='80,443,8080').",
        }

    scan_flag = "-sS"
    try:
        probe = subprocess.run([nmap_bin, "-sS", "-p", "1", "127.0.0.1"], capture_output=True, text=True, timeout=10)
        if probe.returncode != 0 and "requires root" in (probe.stderr or "").lower():
            scan_flag = "-sT"
    except Exception:
        scan_flag = "-sT"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as tmp:
        out_path = tmp.name

    cmd = [
        nmap_bin, scan_flag, "-sV", "-sC", "--script", "vuln,default",
        "--open", "--reason", "-T4", "-Pn",
        "-p", str(ports), "-oX", out_path, host,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return {"error": "nmap timed out after 180s — try a narrower port list."}
    except Exception as e:
        return {"error": f"nmap execution failed: {e}"}

    try:
        root = ET.parse(out_path).getroot()
    except Exception:
        return {"error": "nmap produced no parseable XML output", "stderr": (proc.stderr or "")[-500:]}
    finally:
        try:
            os.unlink(out_path)
        except Exception:
            pass

    open_services = []
    script_findings = []
    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        addr = addr_el.get("addr") if addr_el is not None else host
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            svc = {
                "host": addr,
                "port": port_el.get("portid"),
                "protocol": port_el.get("protocol"),
                "service": service_el.get("name") if service_el is not None else "",
                "product": service_el.get("product") if service_el is not None else "",
                "version": service_el.get("version") if service_el is not None else "",
            }
            open_services.append(svc)
            for script_el in port_el.findall("script"):
                script_findings.append({
                    "host": addr, "port": port_el.get("portid"),
                    "script_id": script_el.get("id"),
                    "output": (script_el.get("output") or "")[:2000],
                })

    return {
        "host": host,
        "scan_type": "SYN" if scan_flag == "-sS" else "TCP connect (no raw-socket privileges)",
        "open_services": open_services,
        "script_findings": script_findings,
        "note": (
            f"{len(open_services)} open service(s), {len(script_findings)} NSE script hit(s) (vuln+default scripts). "
            "NSE 'vuln' script hits are leads, not confirmed vulnerabilities — verify each one manually before record_finding."
        ),
    }
