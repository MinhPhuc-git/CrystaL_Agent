from datetime import datetime, timedelta, timezone

from crystal.normalization.auth import AuthEvent
from crystal.risk.rules.bruteforce import BruteForceRule


def event(i: int, eid: int = 4625, minute: int | None = None, ip: str | None = "203.0.113.8") -> AuthEvent:
    t = datetime(2026, 11, 2, 12, minute or 0, i, tzinfo=timezone.utc)
    return AuthEvent(f"e{i}", eid, t, "LAB-PC", "Admin", ip, "3", "0xC000006D", "Security")


def test_fifth_failed_logon_creates_finding_and_dedupes():
    rule = BruteForceRule(threshold=5)
    assert all(rule.process(event(i)) is None for i in range(1, 5))
    finding = rule.process(event(5))
    assert finding is not None
    assert finding.count == 5
    assert finding.severity == "high"
    assert rule.process(event(5)) is None


def test_success_and_lockout_are_context_not_failures():
    rule = BruteForceRule(threshold=2)
    assert rule.process(event(1, 4624)) is None
    assert rule.process(event(2, 4740)) is None
    assert rule.process(event(3)) is None


def test_different_sources_are_not_combined():
    rule = BruteForceRule(threshold=2)
    assert rule.process(event(1, ip="198.51.100.1")) is None
    assert rule.process(event(2, ip="198.51.100.2")) is None


def test_old_events_fall_outside_window():
    rule = BruteForceRule(threshold=2, window=timedelta(minutes=5))
    old = AuthEvent("old", 4625, datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc), "pc", "a", "1.2.3.4", None, None, "Security")
    new = AuthEvent("new", 4625, datetime(2026, 11, 2, 12, 6, tzinfo=timezone.utc), "pc", "a", "1.2.3.4", None, None, "Security")
    assert rule.process(old) is None
    assert rule.process(new) is None
