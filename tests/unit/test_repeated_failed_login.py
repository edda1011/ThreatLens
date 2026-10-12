"""Deterministic event-time detection scenarios."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from threatlens.config import DetectionConfig
from threatlens.detection.aggregator import EventAggregator
from threatlens.detection.repeated_failed_login import (
    ALLOWED_LATENESS,
    RepeatedFailedLoginRule,
)
from threatlens.models.alert import AccessOutcome, Alert, Confidence, Severity
from threatlens.models.event import FailedLogonDetails, IngestionMode, SecurityEvent

START = datetime(2026, 10, 12, 12, tzinfo=UTC)


def event(number: int, seconds: float, **details: object) -> SecurityEvent:
    timestamp = START + timedelta(seconds=seconds)
    fields: dict[str, object] = {
        "target_username": "alice",
        "target_domain": "TEST-PC",
        "source_ip": "192.0.2.55",
        "logon_type": 10,
    }
    fields.update(details)
    return SecurityEvent(
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        event_id=4625,
        record_id=number,
        timestamp_utc=timestamp,
        collected_at_utc=max(START, timestamp),
        hostname="TEST-PC",
        category="failed_logon",
        ingestion_mode=IngestionMode.LIVE,
        details=FailedLogonDetails(**fields),  # type: ignore[arg-type]
    )


def feed(rule: RepeatedFailedLoginRule, item: SecurityEvent) -> Alert | None:
    return rule.process(item, now=item.collected_at_utc)


def test_medium_then_high_emit_only_twice_and_share_identity() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    emitted = [alert for n in range(1, 16) if (alert := feed(rule, event(n, n)))]

    assert [alert.severity for alert in emitted] == [Severity.MEDIUM, Severity.HIGH]
    assert [alert.event_count for alert in emitted] == [5, 10]
    assert emitted[0].alert_id == emitted[1].alert_id
    assert rule.active_alerts[0].event_count == 15
    assert emitted[0].access_outcome is AccessOutcome.NOT_EVALUATED
    assert emitted[0].confidence is Confidence.MEDIUM


@pytest.mark.parametrize("last", [120, 120.001])
def test_medium_window_boundary(last: float) -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n in range(1, 5):
        assert feed(rule, event(n, 0)) is None
    alert = feed(rule, event(5, last))
    assert (alert is not None) is (last == 120)


@pytest.mark.parametrize("last", [300, 300.001])
def test_high_window_boundary(last: float) -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    # No five-event cluster fits inside the shorter Medium window.
    for n in range(1, 10):
        feed(rule, event(n, (n - 1) * 33))
    alert = feed(rule, event(10, last))
    assert (alert is not None) is (last == 300)
    if alert is not None:
        assert alert.severity is Severity.HIGH


def test_period_resets_after_exact_cooldown() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n in range(1, 6):
        feed(rule, event(n, n))
    previous = rule.active_alerts[0]
    assert feed(rule, event(6, 605)) is None
    assert not rule.active_alerts
    for n in range(7, 11):
        alert = feed(rule, event(n, 600 + n))
    assert alert is not None
    assert alert.severity is Severity.MEDIUM
    assert alert.event_count == 5
    assert alert.alert_id != previous.alert_id


def test_continuous_activity_keeps_period_open_after_ten_minutes() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n in range(1, 6):
        feed(rule, event(n, n))
    identity = rule.active_alerts[0].alert_id
    assert feed(rule, event(6, 400)) is None
    assert feed(rule, event(7, 800)) is None
    assert rule.active_alerts[0].alert_id == identity
    assert rule.active_alerts[0].event_count == 7


@pytest.mark.parametrize(
    "details",
    [
        {"target_username": "bob"},
        {"target_domain": "OTHER-DOMAIN"},
        {"source_ip": "192.0.2.56"},
        {"source_ip": None},
        {"logon_type": 3},
    ],
)
def test_distinct_groups_do_not_merge(details: dict[str, object]) -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n in range(1, 5):
        feed(rule, event(n, n))
    assert feed(rule, event(5, 5, **details)) is None


def test_different_hosts_do_not_merge() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n in range(1, 5):
        feed(rule, event(n, n))
    assert feed(rule, replace(event(5, 5), hostname="OTHER-PC")) is None


def test_case_changes_do_not_split_a_windows_account() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n in range(1, 5):
        feed(rule, event(n, n))
    alert = feed(
        rule, replace(event(5, 5, target_username="ALICE"), hostname="test-pc")
    )
    assert alert is not None


def test_missing_source_has_low_confidence_and_explicit_reason() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n in range(1, 6):
        alert = feed(rule, event(n, n, source_ip=None))
    assert alert is not None
    assert alert.confidence is Confidence.LOW
    assert any("unavailable" in reason for reason in alert.reasons)


def test_duplicate_records_do_not_increase_counts() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n in range(1, 5):
        feed(rule, event(n, n))
    for _ in range(10):
        assert feed(rule, event(4, 4)) is None
    alert = feed(rule, event(5, 5))
    assert alert is not None
    assert alert.event_count == 5
    assert rule.diagnostic_counts["duplicate_event"] == 10


def test_late_event_can_complete_a_recent_window() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n in range(1, 5):
        feed(rule, event(n, 10 + n))
    alert = feed(rule, event(5, 0))
    assert alert is not None
    assert alert.first_seen_utc == START
    assert alert.last_seen_utc == START + timedelta(seconds=14)


def test_late_event_near_cooldown_is_not_split_by_another_account() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n in range(1, 6):
        feed(rule, event(n, n))
    identity = rule.active_alerts[0].alert_id
    feed(rule, event(6, 605, target_username="bob"))
    assert feed(rule, event(7, 590)) is None
    assert rule.active_alerts[0].alert_id == identity
    assert rule.active_alerts[0].event_count == 6


def test_delayed_predecessor_does_not_enter_an_already_reset_period() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n in range(1, 6):
        feed(rule, event(n, n))
    feed(rule, event(6, 605))
    assert feed(rule, event(7, 590)) is None
    assert rule.diagnostic_counts["late_period_event"] == 1
    for n in range(8, 11):
        assert feed(rule, event(n, 606)) is None
    assert not rule.active_alerts
    alert = feed(rule, event(11, 607))
    assert alert is not None and alert.event_count == 5


def test_lookback_and_live_evidence_can_trigger_together() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n in range(1, 5):
        feed(rule, replace(event(n, -30 + n), ingestion_mode=IngestionMode.LOOKBACK))
    alert = feed(rule, event(5, 0))
    assert alert is not None
    assert alert.ingestion_mode is IngestionMode.MIXED


def test_out_of_scope_timestamps_and_event_types_are_diagnosed() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    assert feed(rule, event(1, -601)) is None
    assert rule.process(event(2, 6), now=START) is None
    assert feed(rule, replace(event(3, 0), event_id=4624)) is None
    feed(rule, event(4, 100))
    assert feed(rule, event(5, 69)) is None
    assert rule.diagnostic_counts["outside_lookback"] == 1
    assert rule.diagnostic_counts["future_event"] == 1
    assert rule.diagnostic_counts["unsupported_event"] == 1
    assert rule.diagnostic_counts["late_event"] == 1


def test_expiration_releases_groups_and_dedup_state() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n in range(1, 6):
        feed(rule, event(n, n))
    rule.expire(now=START + timedelta(minutes=11))
    assert not rule.active_alerts
    assert rule.active_group_count == 0
    assert rule.retained_event_count == 0


def test_dedup_storage_expires_after_its_retention_boundary() -> None:
    aggregator = EventAggregator(DetectionConfig(), ALLOWED_LATENESS)
    item = event(1, 0)
    assert aggregator.add(item) is not None
    aggregator.prune(START + timedelta(seconds=630))
    assert aggregator.add(item) is None
    aggregator.prune(START + timedelta(seconds=631))
    assert aggregator.add(item) is not None


def test_idle_group_observations_expire_before_the_period_closes() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n in range(1, 6):
        feed(rule, event(n, n))
    rule.expire(now=START + timedelta(seconds=336))
    assert rule.active_group_count == 1
    assert rule.retained_event_count == 0
    assert rule.active_alerts[0].event_count == 5


def test_old_observations_are_pruned_during_continuous_activity() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n in range(1, 100):
        feed(rule, event(n, n * 30))
    assert rule.active_group_count == 1
    assert rule.retained_event_count == 11


def test_custom_configuration_is_used() -> None:
    rule = RepeatedFailedLoginRule(
        started_at=START, config=DetectionConfig(medium_threshold=2, high_threshold=3)
    )
    assert feed(rule, event(1, 0)) is None
    medium = feed(rule, event(2, 1))
    high = feed(rule, event(3, 2))
    assert medium is not None and medium.severity is Severity.MEDIUM
    assert high is not None and high.severity is Severity.HIGH


def test_lookback_uses_event_time_instead_of_collection_time() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n, seconds in enumerate([-600, -568, -536, -504, -472], start=1):
        assert feed(rule, event(n, seconds)) is None
    # All five were collected together, but span 128 seconds in event time.
    assert not rule.active_alerts


def test_lateness_and_future_tolerance_boundaries() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    assert rule.process(event(1, 5), now=START) is None
    assert rule.diagnostic_counts["future_event"] == 0
    assert rule.process(event(2, 5.001), now=START) is None
    feed(rule, event(3, 100))
    feed(rule, event(4, 70))
    assert rule.diagnostic_counts["late_event"] == 0
    feed(rule, event(5, 69.999))
    assert rule.diagnostic_counts["late_event"] == 1


def test_period_count_does_not_replace_rolling_threshold_count() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n in range(1, 11):
        assert feed(rule, event(n, n * 100)) is None
    assert not rule.active_alerts


def test_local_login_recommendations_do_not_assume_remote_access() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n in range(1, 6):
        alert = feed(rule, event(n, n, source_ip=None, logon_type=2))
    assert alert is not None
    assert not any("remote access" in action for action in alert.recommended_actions)


def test_emitted_alert_is_an_immutable_snapshot() -> None:
    rule = RepeatedFailedLoginRule(started_at=START)
    for n in range(1, 6):
        emitted = feed(rule, event(n, n))
    assert emitted is not None
    feed(rule, event(6, 6))
    assert emitted.event_count == 5
    assert rule.active_alerts[0].event_count == 6
