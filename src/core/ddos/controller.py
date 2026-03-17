"""DDoS resilience testing controller with safety controls.

Uses k6 or Locust for load generation with circuit breaker protections.
"""

from dataclasses import dataclass, field


@dataclass
class SafetyLimits:
    max_rps: int = 1000
    max_duration_seconds: int = 300
    error_rate_abort_threshold: float = 0.5  # 50%
    response_time_abort_multiplier: float = 2.0  # 200% of baseline


@dataclass
class ResilienceTestResult:
    peak_rps: float = 0.0
    avg_response_ms: float = 0.0
    error_rate: float = 0.0
    time_to_mitigate_ms: float | None = None
    aborted: bool = False
    abort_reason: str | None = None
    metrics: list[dict] = field(default_factory=list)


class ResilienceController:
    def __init__(self, limits: SafetyLimits | None = None):
        self.limits = limits or SafetyLimits()

    def validate_config(self, rps: int, duration: int) -> None:
        if rps > self.limits.max_rps:
            raise ValueError(f"RPS {rps} exceeds maximum {self.limits.max_rps}")
        if duration > self.limits.max_duration_seconds:
            raise ValueError(
                f"Duration {duration}s exceeds maximum {self.limits.max_duration_seconds}s"
            )

    def build_k6_command(self, target_url: str, rps: int, duration: int) -> list[str]:
        """Build k6 command as a safe list."""
        self.validate_config(rps, duration)
        return [
            "run",
            "--vus",
            str(rps),
            "--duration",
            f"{duration}s",
            "--out",
            "json=/dev/stdout",
            "-e",
            f"TARGET_URL={target_url}",
            "/scripts/resilience.js",
        ]

    def should_abort(
        self,
        baseline_response_ms: float,
        current_response_ms: float,
        current_error_rate: float,
    ) -> tuple[bool, str | None]:
        """Circuit breaker check."""
        if current_error_rate > self.limits.error_rate_abort_threshold:
            return True, f"Error rate {current_error_rate:.1%} exceeds threshold"

        max_response = baseline_response_ms * self.limits.response_time_abort_multiplier
        if current_response_ms > max_response:
            return True, (
                f"Response time {current_response_ms:.0f}ms exceeds "
                f"{self.limits.response_time_abort_multiplier}x baseline"
            )

        return False, None
