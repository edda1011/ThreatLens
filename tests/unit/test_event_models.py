"""Contracts for normalized failed-logon events."""

import json
from datetime import UTC, datetime, timedelta, timezone

import pytest

from threatlens.models.event import FailedLogonDetails, IngestionMode, SecurityEvent


def make_event(**changes: object) -> SecurityEvent:
    values: dict[str, object] = {
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_id": 4625,
        "record_id": 42,
        "timestamp_utc": datetime(2026, 9, 2, 12, tzinfo=UTC),
        "collected_at_utc": datetime(2026, 9, 2, 12, 1, tzinfo=UTC),
        "hostname": "DESKTOP-TEST",
        "category": "failed_logon",
        "ingestion_mode": IngestionMode.LOOKBACK,
        "details": FailedLogonDetails(target_username="alice"),
    }
    values.update(changes)
    return SecurityEvent(**values)  # type: ignore[arg-type]


def test_event_identity_is_stable_and_serializable() -> None:
    event = make_event()
    encoded = event.to_dict()

    assert event.event_uid == make_event().event_uid
    assert event.event_uid != make_event(record_id=43).event_uid
    assert event.schema_version == 1
    assert encoded["event_uid"] == event.event_uid
    assert encoded["timestamp_utc"] == "2026-09-02T12:00:00Z"
    assert encoded["ingestion_mode"] == "lookback"
    assert encoded["details"]["source_ip"] is None
    assert "raw_data" not in encoded
    json.dumps(encoded)


def test_aware_timestamps_are_normalized_to_utc() -> None:
    event = make_event(
        timestamp_utc=datetime(2026, 9, 2, 20, tzinfo=timezone(timedelta(hours=8)))
    )

    assert event.timestamp_utc == datetime(2026, 9, 2, 12, tzinfo=UTC)


@pytest.mark.parametrize("field", ["timestamp_utc", "collected_at_utc"])
def test_naive_timestamps_are_rejected(field: str) -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        make_event(**{field: datetime(2026, 9, 2, 12)})


@pytest.mark.parametrize(
    ("field", "value"),
    [("hostname", ""), ("channel", ""), ("record_id", 0), ("event_id", 0)],
)
def test_invalid_identity_is_rejected(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        make_event(**{field: value})


def test_missing_target_username_is_rejected() -> None:
    with pytest.raises(ValueError, match="target_username"):
        FailedLogonDetails(target_username="")


def test_individual_event_cannot_have_mixed_ingestion() -> None:
    with pytest.raises(ValueError, match="mixed"):
        make_event(ingestion_mode=IngestionMode.MIXED)


def test_models_are_immutable() -> None:
    event = make_event()

    with pytest.raises(AttributeError):
        event.hostname = "OTHER"  # type: ignore[misc]
