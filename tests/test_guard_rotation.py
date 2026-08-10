import unittest
import time
import os
import tempfile
from pathlib import Path

from hellhound.core.guard import RateLimiter, CircuitBreaker, SafeMethodPolicy, AutopilotGuard
from hellhound.core.rotation import needs_rotation, rotate, rotate_if_needed, list_backups, total_bytes, purge_backups
from hellhound.core.tasks import Target, create_or_load_target, save_target
from hellhound.core.agent import Agent, BASELINE_RULES_PROMPT
from hellhound.core.scope import ScopeRules


class TestRateLimiter(unittest.TestCase):
    def test_recon_vs_test_intervals(self):
        limiter = RateLimiter(recon_rps=10.0, test_rps=2.0)
        self.assertAlmostEqual(limiter.recon_interval, 0.1)
        self.assertAlmostEqual(limiter.test_interval, 0.5)

    def test_wait_pacing(self):
        limiter = RateLimiter(recon_rps=100.0, test_rps=50.0)
        w1 = limiter.wait("example.com", is_recon=True)
        self.assertEqual(w1, 0.0)
        # Immediate next request should wait a small fraction
        w2 = limiter.wait("example.com", is_recon=True)
        self.assertGreaterEqual(w2, 0.0)


class TestCircuitBreaker(unittest.TestCase):
    def test_breaker_trip_and_cooldown(self):
        cb = CircuitBreaker(threshold=3, cooldown=0.2)
        host = "dead-host.local"
        self.assertFalse(cb.is_tripped(host))

        # 1st failure
        self.assertFalse(cb.record_failure(host))
        # 2nd failure
        self.assertFalse(cb.record_failure(host))
        # 3rd failure - trips
        self.assertTrue(cb.record_failure(host))
        self.assertTrue(cb.is_tripped(host))

        # Status check
        status = cb.get_status(host)
        self.assertTrue(status["tripped"])
        self.assertEqual(status["failures"], 3)

        # Wait for cooldown to expire
        time.sleep(0.25)
        # Should now allow probe retry (is_tripped becomes False)
        self.assertFalse(cb.is_tripped(host))

        # Success resets failure count
        cb.record_success(host)
        self.assertFalse(cb.is_tripped(host))
        self.assertEqual(cb.get_status(host)["failures"], 0)


class TestSafeMethodPolicy(unittest.TestCase):
    def test_safe_methods(self):
        policy = SafeMethodPolicy()
        self.assertTrue(policy.is_safe("GET"))
        self.assertTrue(policy.is_safe("get"))
        self.assertTrue(policy.is_safe("HEAD"))
        self.assertTrue(policy.is_safe("OPTIONS"))

        self.assertFalse(policy.is_safe("POST"))
        self.assertFalse(policy.is_safe("PUT"))
        self.assertFalse(policy.is_safe("DELETE"))
        self.assertFalse(policy.is_safe("PATCH"))

    def test_check_decisions(self):
        policy = SafeMethodPolicy()
        res_get = policy.check("GET", "https://example.com/api")
        self.assertEqual(res_get["decision"], "allow")

        res_post = policy.check("POST", "https://example.com/api/delete")
        self.assertEqual(res_post["decision"], "require_approval")


class TestAutopilotGuard(unittest.TestCase):
    def test_guard_flow(self):
        guard = AutopilotGuard(circuit_threshold=2, circuit_cooldown=10.0, safe_methods_only=True)
        url = "https://target.com/test"

        # Safe GET should allow
        res = guard.check_request("GET", url)
        self.assertEqual(res["decision"], "allow")

        # Mutating POST should require approval
        res = guard.check_request("POST", url)
        self.assertEqual(res["decision"], "require_approval")

        # Record failures to trip circuit breaker
        guard.record_failure("target.com")
        guard.record_failure("target.com")

        # Now GET should be blocked
        res = guard.check_request("GET", url)
        self.assertEqual(res["decision"], "block")

        # Success resets
        guard.record_success("target.com")
        res = guard.check_request("GET", url)
        self.assertEqual(res["decision"], "allow")


class TestRotation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = Path(self.temp_dir.name) / "test_target.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_rotation_flow(self):
        # Create file with 200 bytes
        self.test_file.write_text("A" * 200)

        self.assertTrue(needs_rotation(self.test_file, max_bytes=100))
        self.assertFalse(needs_rotation(self.test_file, max_bytes=500))

        # Rotate
        rotated = rotate_if_needed(self.test_file, max_bytes=100, keep=3)
        self.assertTrue(rotated)

        # Check backup exists
        backup1 = self.test_file.with_suffix(self.test_file.suffix + ".1")
        self.assertTrue(backup1.exists())
        self.assertEqual(backup1.stat().st_size, 200)

        # Write new content and rotate again
        self.test_file.write_text("B" * 300)
        rotate_if_needed(self.test_file, max_bytes=100, keep=3)
        backup2 = self.test_file.with_suffix(self.test_file.suffix + ".2")
        self.assertTrue(backup2.exists())
        self.assertEqual(backup2.stat().st_size, 200)
        self.assertEqual(backup1.stat().st_size, 300)

        # List backups
        backups = list_backups(self.test_file, keep=3)
        self.assertEqual(len(backups), 2)

        # Purge
        purged = purge_backups(self.test_file, keep=3)
        self.assertEqual(purged, 2)
        self.assertEqual(len(list_backups(self.test_file, keep=3)), 0)


class TestAgentIntegration(unittest.TestCase):
    def test_agent_guard_integration(self):
        agent = Agent()
        # Ensure guard is instantiated
        self.assertIsNotNone(agent.guard)

        # Allow example.com in scope so we specifically test the AutopilotGuard layer
        agent.target.scope_rules.in_scope = ["example.com", "*.example.com"]

        # Mutating method (POST) should require approval
        res = agent.execute_tool_call(
            "httpx",
            {"url": "https://example.com", "method": "POST"}
        )
        self.assertTrue(res.get("requires_approval"))

        # Baseline doctrine presence
        self.assertIn("Baseline Reconnaissance & Triage Doctrine", BASELINE_RULES_PROMPT)
        self.assertIn("RECONNAISSANCE & TRIAGE ONLY", BASELINE_RULES_PROMPT)

    def test_agent_circuit_breaker_trip(self):
        agent = Agent()
        agent.target.scope_rules.in_scope = ["failing-host.com"]
        agent.guard._breaker.threshold = 3

        # Simulate 3 failures
        for _ in range(3):
            agent.guard.record_failure("failing-host.com")

        # Now tool call to failing host should be blocked by circuit breaker
        res = agent.execute_tool_call(
            "httpx",
            {"url": "https://failing-host.com/login", "method": "GET"}
        )
        self.assertTrue(res.get("blocked"))
        self.assertIn("blocked", res.get("error", "").lower())

    def test_save_target_rotation(self):
        target = Target(name="test_rotation_target")
        # Add dummy history to exceed custom rotation cap
        target.state["large_payload"] = "X" * 1000
        save_target(target)

        from hellhound.core.tasks import get_target_path
        path = Path(get_target_path("test_rotation_target"))
        self.assertTrue(path.exists())

        # Test rotate_if_needed on target path with small max_bytes
        rotated = rotate_if_needed(path, max_bytes=500, keep=3)
        self.assertTrue(rotated)
        backup = path.with_suffix(path.suffix + ".1")
        self.assertTrue(backup.exists())

        # Cleanup
        if path.exists():
            path.unlink()
        if backup.exists():
            backup.unlink()


if __name__ == "__main__":
    unittest.main()
