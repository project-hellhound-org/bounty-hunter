"""
hellhound/core/guard.py

Defensive Guardrails & Pre-Request Verification:
- RateLimiter: Per-host request pacing separating recon vs. test RPS.
- CircuitBreaker: Auto-tripping threshold on dead/failing hosts with cooldown.
- SafeMethodPolicy: Strict gate allowing safe read-only and standard mutating
  methods (GET/HEAD/OPTIONS/POST/PUT/PATCH), requiring explicit human
  approval only for destructive actions (DELETE, or paths that indicate
  deletion/wipe/purge intent).
- AutopilotGuard: Unified pre-request guard.
"""

from typing import Dict, Any, Optional, Set
import time


class RateLimiter:
    """Per-host rate limiter for autonomous requests.

    Tracks last request time per host and enforces minimum interval.
    """

    def __init__(self, recon_rps: float = 10.0, test_rps: float = 1.0):
        """
        Args:
            recon_rps: Max requests per second for recon operations.
            test_rps: Max requests per second for active testing operations.
        """
        self._last_request: Dict[str, float] = {}
        self.recon_interval = 1.0 / max(0.001, recon_rps)
        self.test_interval = 1.0 / max(0.001, test_rps)

    def wait(self, host: str, is_recon: bool = False) -> float:
        """Wait until the rate limit allows the next request.

        Returns:
            The number of seconds waited.
        """
        interval = self.recon_interval if is_recon else self.test_interval
        now = time.monotonic()
        last = self._last_request.get(host, 0.0)
        elapsed = now - last
        wait_time = max(0.0, interval - elapsed)

        if wait_time > 0:
            time.sleep(wait_time)

        self._last_request[host] = time.monotonic()
        return wait_time


class CircuitBreaker:
    """Circuit breaker — prevents hammering blocked, dead, or failing hosts.

    If consecutive_failures reaches threshold, the breaker trips.
    """

    def __init__(self, threshold: int = 5, cooldown: float = 60.0):
        """
        Args:
            threshold: Number of consecutive failures before tripping.
            cooldown: Seconds to wait before allowing a retry.
        """
        self.threshold = threshold
        self.cooldown = cooldown
        self._failures: Dict[str, int] = {}
        self._tripped_at: Dict[str, float] = {}

    def record_success(self, host: str) -> None:
        """Reset failure count for a host."""
        self._failures[host] = 0
        self._tripped_at.pop(host, None)

    def record_failure(self, host: str) -> bool:
        """Record a failure. Returns True if the breaker just tripped."""
        self._failures[host] = self._failures.get(host, 0) + 1
        if self._failures[host] >= self.threshold:
            self._tripped_at[host] = time.monotonic()
            return True
        return False

    def is_tripped(self, host: str) -> bool:
        """Check if the breaker is tripped for a host."""
        if host not in self._tripped_at:
            return False
        elapsed = time.monotonic() - self._tripped_at[host]
        if elapsed >= self.cooldown:
            # Cooldown expired — allow one probe retry
            self._failures[host] = self.threshold - 1
            del self._tripped_at[host]
            return False
        return True

    def get_status(self, host: str) -> Dict[str, Any]:
        """Get the current circuit breaker status for a host."""
        return {
            "host": host,
            "failures": self._failures.get(host, 0),
            "tripped": self.is_tripped(host),
            "threshold": self.threshold,
        }


class SafeMethodPolicy:
    """Enforce a guard against destructive actions during autonomous operation.

    Read AND standard mutating methods (GET/HEAD/OPTIONS/POST/PUT/PATCH) are
    allowed without approval — POST/PUT/PATCH are core to bug hunting (login,
    form submission, API/IDOR testing) and gating them defeats the point of
    autonomous testing.

    Only genuinely destructive actions require human approval:
      - DELETE, always.
      - Any method whose URL path contains a destructive-intent keyword
        (delete, destroy, remove, purge, wipe, drop, truncate, format,
        deprovision, terminate, reset-all).
    """

    DEFAULT_SAFE: Set[str] = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"}
    DESTRUCTIVE_METHODS: Set[str] = {"DELETE"}
    DESTRUCTIVE_PATH_KEYWORDS = (
        "delete", "destroy", "remove", "purge", "wipe", "drop",
        "truncate", "format", "deprovision", "terminate", "reset-all",
    )

    def __init__(
        self,
        safe_methods: Optional[Set[str]] = None,
        enabled: bool = True,
    ):
        self._safe = {m.upper() for m in (safe_methods if safe_methods is not None else self.DEFAULT_SAFE)}
        self._enabled = enabled

    def _is_destructive_path(self, url: str) -> bool:
        u = (url or "").lower()
        return any(kw in u for kw in self.DESTRUCTIVE_PATH_KEYWORDS)

    def is_safe(self, method: str, url: str = "") -> bool:
        """Return True if the request is safe to send without approval."""
        if not self._enabled:
            return True
        method_upper = method.upper()
        if method_upper in self.DESTRUCTIVE_METHODS:
            return False
        if self._is_destructive_path(url):
            return False
        return method_upper in self._safe

    def check(self, method: str, url: str) -> Dict[str, Any]:
        """Return a structured decision for the given method + URL."""
        method_upper = method.upper()
        if self.is_safe(method_upper, url):
            return {"decision": "allow", "method": method_upper, "url": url}
        if method_upper in self.DESTRUCTIVE_METHODS:
            reason = f"Destructive method {method_upper} requires human approval"
        else:
            reason = "URL path indicates a destructive action — requires human approval"
        return {
            "decision": "require_approval",
            "method": method_upper,
            "url": url,
            "reason": reason,
        }


class AutopilotGuard:
    """Unified pre-request guard for autonomous agent operations.

    Integrates CircuitBreaker + RateLimiter + SafeMethodPolicy into a single
    check_request() call that returns allow / block / require_approval.

    Check order:
      1. Circuit breaker (host blocked? -> block)
      2. Safe method policy (unsafe method? -> require_approval)
      3. Allow
    """

    def __init__(
        self,
        circuit_threshold: int = 5,
        circuit_cooldown: float = 60.0,
        recon_rps: float = 10.0,
        test_rps: float = 1.0,
        safe_methods_only: bool = True,
        safe_methods: Optional[Set[str]] = None,
    ):
        self._breaker = CircuitBreaker(
            threshold=circuit_threshold,
            cooldown=circuit_cooldown,
        )
        self._limiter = RateLimiter(recon_rps=recon_rps, test_rps=test_rps)
        self._method_policy = SafeMethodPolicy(
            safe_methods=safe_methods,
            enabled=safe_methods_only,
        )

    @staticmethod
    def _extract_host(url: str) -> str:
        """Extract host (with port if present) from a URL or domain candidate."""
        if not url:
            return "unknown"
        # Strip scheme
        if "://" in url:
            url = url.split("://", 1)[1]
        # Strip path & query
        host = url.split("/", 1)[0].split("?", 1)[0]
        # Strip userinfo
        if "@" in host:
            host = host.rsplit("@", 1)[1]
        return host.strip().lower()

    def check_request(self, method: str, url: str) -> Dict[str, Any]:
        """Check whether a request should proceed.

        Returns:
            dict with 'decision': 'allow', 'block', or 'require_approval'.
        """
        host = self._extract_host(url)

        # 1. Circuit breaker
        if self._breaker.is_tripped(host):
            return {
                "decision": "block",
                "method": method.upper(),
                "url": url,
                "host": host,
                "reason": f"Circuit breaker tripped for {host} after consecutive failures (cooldown in effect)",
            }

        # 2. Safe method policy
        method_check = self._method_policy.check(method, url)
        if method_check["decision"] != "allow":
            return method_check

        # 3. Allow
        return {
            "decision": "allow",
            "method": method.upper(),
            "url": url,
            "host": host,
        }

    def record_failure(self, host: str) -> bool:
        """Record a failure for circuit breaker. Returns True if breaker just tripped."""
        cleaned_host = self._extract_host(host)
        return self._breaker.record_failure(cleaned_host)

    def record_success(self, host: str) -> None:
        """Record a success — resets circuit breaker for the host."""
        cleaned_host = self._extract_host(host)
        self._breaker.record_success(cleaned_host)

    def get_host_status(self, host: str) -> Dict[str, Any]:
        """Get circuit breaker status for a host."""
        cleaned_host = self._extract_host(host)
        cb_status = self._breaker.get_status(cleaned_host)
        return {
            "host": cleaned_host,
            "failures": cb_status["failures"],
            "circuit_tripped": cb_status["tripped"],
            "circuit_threshold": cb_status["threshold"],
        }
