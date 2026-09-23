"""Contracts for user-facing failed-logon alerts."""

import json
from datetime import UTC, datetime

import pytest

from threatlens.models.alert import AccessOutcome, Alert, Confidence, Severity
from threatlens.models.event import IngestionMode


def make_alert(**changes: object) -> Alert:
    values: dict[str, object] = {
        "alert_id": "alert-1",
        "rule_id": "repeated_failed_login",
        "first_seen_utc": datetime(2026, 9, 2, 12, tzinfo=UTC),
        "last_seen_utc": datetime(2026, 9, 2, 12, 1, tzinfo=UTC),
        "event_count": 5,
        "severity": Severity.MEDIUM,
        "confidence": Confidence.LOW,
        "title": "Repeated failed logins",
        "summary": "Five failed logins were observed.",
        "target_username": "alice",
        "source_ip": None,
        "logon_type": 10,
        "access_outcome": AccessOutcome.NOT_EVALUATED,
        "ingestion_mode": IngestionMode.MIXED,
        "reasons": ("Source address unavailable",),
        "recommended_actions": ("Check recent account activity",),
        "technical_details": {"event_id": 4625},
    }
    values.update(changes)
    return Alert(**values)  # type: ignore[arg-type]


def test_alert_serialization_is_stable_json_data() -> None:
    alert = make_alert()
    encoded = alert.to_dict()

    assert alert.schema_version == 1
    assert encoded["first_seen_utc"] == "2026-09-02T12:00:00Z"
    assert encoded["severity"] == "medium"
    assert encoded["confidence"] == "low"
    assert encoded["access_outcome"] == "not_evaluated"
    assert encoded["ingestion_mode"] == "mixed"
    assert encoded["reasons"] == ["Source address unavailable"]
    assert encoded["technical_details"] == {"event_id": 4625}
    assert "raw_data" not in encoded
    json.dumps(encoded)


def test_alert_rejects_bad_time_range_and_count() -> None:
    with pytest.raises(ValueError, match="event_count"):
        make_alert(event_count=0)
    with pytest.raises(ValueError, match="first_seen_utc"):
        make_alert(first_seen_utc=datetime(2026, 9, 2, 12, 2, tzinfo=UTC))


def test_alert_rejects_naive_timestamps() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        make_alert(last_seen_utc=datetime(2026, 9, 2, 12, 1))


def test_alert_technical_details_are_immutable() -> None:
    supplied = {"event_id": 4625}
    alert = make_alert(technical_details=supplied)
    supplied["event_id"] = 1

    assert alert.technical_details["event_id"] == 4625
    with pytest.raises(TypeError):
        alert.technical_details["event_id"] = 1  # type: ignore[index]
