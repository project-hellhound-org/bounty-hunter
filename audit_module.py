#!/usr/bin/env python3
"""
HELLHOUND — Vulnerability Audit Base Class
Provides core utilities for fuzzing, payload injection, and differential analysis.
"""

import sys
import asyncio
import aiohttp
import argparse
from typing import List, Dict, Any
from hellhound.core.emit import Emit
from hellhound.core import http_utils

class VulnerabilityAuditor:
    """
    Advanced base class for vulnerability detection modules.
    Inherit from this to build custom auditors (SQLi, XSS, SSRF, etc).
    """
    
    def __init__(self, emit: Emit = None):
        self.emit = emit or Emit()
        self.findings = []
        self.risk_score = 0
        self.timeout = 10
        self.headers = {
            "User-Agent": "Hellhound/12.5 (Offensive Security Framework)",
            "Accept": "*/*"
        }

    async def probe(self, url: str, method: str = "GET", params: Dict = None, data: Dict = None) -> Dict:
        """Helper to perform asynchronous HTTP requests with standard error handling."""
        try:
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.request(method, url, params=params, data=data, timeout=self.timeout, ssl=False) as resp:
                    return {
                        "status": resp.status,
                        "text": await resp.text(),
                        "headers": dict(resp.headers),
                        "url": str(resp.url)
                    }
        except Exception as e:
            self.emit.error(f"Request failed to {url}: {str(e)}")
            return None

    def create_finding(self, ftype: str, url: str, severity: str, evidence: str, poc: str = None):
        """Standardized method to record a security finding."""
        finding = {
            "type": ftype,
            "url": url,
            "severity": severity.upper(),
            "evidence": evidence,
            "poc_curl": poc,
            "timestamp": http_utils.get_timestamp() if hasattr(http_utils, 'get_timestamp') else None
        }
        self.findings.append(finding)
        
        # Calculate risk increment
        risk_map = {"CRITICAL": 50, "HIGH": 30, "MEDIUM": 15, "LOW": 5, "INFO": 1}
        self.risk_score += risk_map.get(severity.upper(), 0)
        
        self.emit.found(f"[{severity.upper()}] {ftype} detected at {url}")
        return finding

    async def run(self, target: str, args: argparse.Namespace):
        """Subclasses MUST implement this logic."""
        raise NotImplementedError("Audit modules must implement the run() method.")

if __name__ == "__main__":
    print("[!] This is a base class and should not be run directly.")
    print("[*] Inherit from VulnerabilityAuditor to build your own Hellhound modules.")
