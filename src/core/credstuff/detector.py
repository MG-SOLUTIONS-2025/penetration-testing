"""Credential stuffing detection — analyze auth logs for attack patterns."""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class AuthEvent:
    timestamp: datetime
    source_ip: str
    username: str
    success: bool
    response_time_ms: float


@dataclass
class DetectionResult:
    is_attack: bool
    confidence: float  # 0.0 - 1.0
    indicators: list[str]
    source_ips: list[str]
    affected_usernames: list[str]
    event_count: int


def detect_credential_stuffing(
    events: list[AuthEvent],
    failure_rate_threshold: float = 0.9,
    unique_user_threshold: int = 10,
    response_time_std_threshold: float = 50.0,  # ms — automated tools have low variance
) -> DetectionResult:
    """Analyze a batch of auth events for credential stuffing indicators."""
    if not events:
        return DetectionResult(
            is_attack=False,
            confidence=0.0,
            indicators=[],
            source_ips=[],
            affected_usernames=[],
            event_count=0,
        )

    indicators = []
    confidence = 0.0

    # Group by source IP
    ip_events: dict[str, list[AuthEvent]] = {}
    for e in events:
        ip_events.setdefault(e.source_ip, []).append(e)

    # Check each source IP
    suspicious_ips = []
    all_usernames = set()

    for ip, ip_evts in ip_events.items():
        failures = sum(1 for e in ip_evts if not e.success)
        total = len(ip_evts)
        usernames = {e.username for e in ip_evts}

        failure_rate = failures / total if total > 0 else 0

        # High failure rate from single IP
        if failure_rate >= failure_rate_threshold and total >= 5:
            indicators.append(
                f"High failure rate ({failure_rate:.0%}) from {ip} ({total} attempts)"
            )
            confidence += 0.3
            suspicious_ips.append(ip)

        # Many unique usernames from single IP
        if len(usernames) >= unique_user_threshold:
            indicators.append(f"Many unique usernames ({len(usernames)}) from {ip}")
            confidence += 0.3
            if ip not in suspicious_ips:
                suspicious_ips.append(ip)

        all_usernames.update(usernames)

        # Low response time variance (automated)
        if len(ip_evts) >= 5:
            times = [e.response_time_ms for e in ip_evts]
            import statistics

            if statistics.stdev(times) < response_time_std_threshold:
                indicators.append(f"Low response time variance from {ip} (automated pattern)")
                confidence += 0.2

    confidence = min(1.0, confidence)

    return DetectionResult(
        is_attack=confidence >= 0.5,
        confidence=round(confidence, 2),
        indicators=indicators,
        source_ips=suspicious_ips,
        affected_usernames=list(all_usernames),
        event_count=len(events),
    )
