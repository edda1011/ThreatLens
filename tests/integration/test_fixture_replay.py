"""Replay stored records through the production normalizer."""

from datetime import UTC, datetime
from pathlib import Path

from threatlens.models.event import IngestionMode, SecurityEvent
from threatlens.normalization.failed_logon import (
    NormalizationFailure,
    normalize_failed_logon,
)


def test_replay_continues_after_a_bad_event() -> None:
    directory = Path(__file__).parents[1] / "fixtures" / "windows_4625"
    events: list[SecurityEvent] = []
    failures: list[NormalizationFailure] = []
    for path in sorted(directory.glob("*.xml")):
        result = normalize_failed_logon(
            path.read_text(encoding="utf-8"),
            datetime(2026, 9, 2, 12, 1, tzinfo=UTC),
            IngestionMode.LIVE,
        )
        if isinstance(result, SecurityEvent):
            events.append(result)
        else:
            failures.append(result)

    assert len(events) == 6
    assert len(failures) == 1
    assert len({event.event_uid for event in events}) == 6
    assert all(event.ingestion_mode is IngestionMode.LIVE for event in events)
