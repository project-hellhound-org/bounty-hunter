import unittest
from unittest.mock import patch, MagicMock
from hellhound.core.agent import (
    Agent,
    TOOL_REGISTRY,
    _execute_port_scan,
    _execute_permute_subdomains,
    _execute_resolve_candidates,
    _execute_tls_cert_scan,
    _execute_httpx,
    _execute_spider
)
from hellhound.core.tasks import Target, ScopeRules


class TestReconToolsAndPipeline(unittest.TestCase):
    def setUp(self):
        self.scope = ScopeRules(in_scope=["*.ctfio.com", "ctfio.com", "example.com", "*.example.com"])
        self.target = Target(name="ctfio.com", scope_rules=self.scope)
        self.agent = Agent(target=self.target)

    def test_tool_registry_contains_new_tools(self):
        expected_tools = [
            "port_scan",
            "permute_subdomains",
            "resolve_candidates",
            "tls_cert_scan",
            "httpx",
            "spider",
            "dns_bruteforce",
            "vhost_fuzz",
            "content_discovery"
        ]
        for t in expected_tools:
            self.assertIn(t, TOOL_REGISTRY, f"Tool '{t}' missing from TOOL_REGISTRY")
            self.assertIsNotNone(TOOL_REGISTRY[t].executor)

    @patch("subprocess.run")
    @patch("hellhound.core.agent._find_binary")
    def test_execute_port_scan_success(self, mock_find_bin, mock_run):
        mock_find_bin.return_value = "/mock/naabu"
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = '{"host":"ctfio.com","ip":"10.10.10.5","port":80,"protocol":"tcp","tls":false}\n{"host":"ctfio.com","ip":"10.10.10.5","port":8080,"protocol":"tcp","tls":true}\n'
        mock_run.return_value = mock_proc

        res = _execute_port_scan({"hosts": "ctfio.com", "ports": "top-100"}, self.target, None)
        self.assertEqual(res["count"], 2)
        self.assertEqual(len(res["open_ports"]), 2)
        self.assertEqual(res["open_ports"][0]["port"], 80)
        self.assertEqual(res["open_ports"][1]["port"], 8080)
        self.assertIn(res["open_ports"][0], self.target.state["open_ports"])

    @patch("subprocess.run")
    @patch("hellhound.core.agent._find_binary")
    def test_execute_permute_subdomains_success(self, mock_find_bin, mock_run):
        mock_find_bin.return_value = "/mock/alterx"
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "admin.ctfio.com\ndev.ctfio.com\nstaging.ctfio.com\n"
        mock_run.return_value = mock_proc

        res = _execute_permute_subdomains({"subdomains": ["ctfio.com"]}, self.target, None)
        self.assertEqual(res["count"], 3)
        self.assertIn("admin.ctfio.com", res["candidates"])
        self.assertIn("dev.ctfio.com", res["candidates"])

    @patch("subprocess.run")
    @patch("hellhound.core.agent._find_binary")
    def test_execute_resolve_candidates_success(self, mock_find_bin, mock_run):
        mock_find_bin.return_value = "/mock/dnsx"
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = '{"host":"admin.ctfio.com","a":["10.10.10.20"],"status_code":"NOERROR"}\n'
        mock_run.return_value = mock_proc

        res = _execute_resolve_candidates({"candidates": ["admin.ctfio.com", "invalid.ctfio.com"]}, self.target, None)
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["resolved"][0]["host"], "admin.ctfio.com")
        self.assertIn("admin.ctfio.com", self.target.state["subdomains"])

    @patch("subprocess.run")
    @patch("hellhound.core.agent._find_binary")
    def test_execute_tls_cert_scan_success(self, mock_find_bin, mock_run):
        mock_find_bin.return_value = "/mock/tlsx"
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = '{"host":"ctfio.com","ip":"10.10.10.5","subject_cn":"ctfio.com","subject_an":["api.ctfio.com","auth.ctfio.com"],"tls_version":"tls13"}\n'
        mock_run.return_value = mock_proc

        res = _execute_tls_cert_scan({"hosts": "ctfio.com"}, self.target, None)
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["certificates"][0]["subject_cn"], "ctfio.com")
        self.assertIn("api.ctfio.com", res["discovered_domains"])
        self.assertIn("auth.ctfio.com", res["discovered_domains"])
        self.assertIn("api.ctfio.com", self.target.state["subdomains"])

    @patch("subprocess.run")
    @patch("hellhound.core.agent._find_binary")
    def test_execute_httpx_captures_cl_and_location(self, mock_find_bin, mock_run):
        mock_find_bin.return_value = "/mock/httpx"
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = '{"url":"https://ctfio.com","status_code":301,"title":"Redirect","webserver":"nginx","content_length":178,"location":"https://www.ctfio.com"}\n'
        mock_run.return_value = mock_proc

        res = _execute_httpx({"target": "ctfio.com"}, self.target, None)
        self.assertEqual(res["count"], 1)
        host = res["live_hosts"][0]
        self.assertEqual(host["status_code"], 301)
        self.assertEqual(host["content_length"], 178)
        self.assertEqual(host["location"], "https://www.ctfio.com")

    @patch("hellhound.core.engine.HellhoundEngine.run_single")
    def test_execute_spider_delegation(self, mock_run_single):
        mock_run_single.return_value = {
            "intel": {
                "endpoints": [{"url": "https://ctfio.com/api/v1/users"}, {"url": "https://ctfio.com/login"}],
                "forms": [{"action": "/login"}],
                "parameters": ["user", "pass"]
            }
        }

        res = _execute_spider({"url": "https://ctfio.com", "depth": 2}, self.target, None)
        self.assertEqual(res["endpoints_found"], 2)
        self.assertEqual(res["forms_found"], 1)
        self.assertIn("https://ctfio.com/login", res["sample_endpoints"])

    def test_agent_scope_gate_on_new_tools(self):
        # Disallowed target out of scope
        res = self.agent.execute_tool_call("port_scan", {"hosts": "evil-unauthorized.org"})
        self.assertTrue(res.get("blocked", False))
        self.assertIn("SCOPE_VIOLATION", res.get("error", ""))


if __name__ == "__main__":
    unittest.main()
