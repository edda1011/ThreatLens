"""Synthetic XML traverses normalization and the actual rule engine."""

from datetime import UTC, datetime
from pathlib import Path

from threatlens.detection.repeated_failed_login import RepeatedFailedLoginRule
from threatlens.models.alert import Severity
from threatlens.models.event import IngestionMode, SecurityEvent
from threatlens.normalization.failed_logon import normalize_failed_logon


def test_xml_replay_emits_medium_and_high_once() -> None:
    now = datetime(2026, 9, 2, 12, 1, tzinfo=UTC)
    template = (
        Path(__file__).parents[1] / "fixtures" / "windows_4625" / "rdp.xml"
    ).read_text(encoding="utf-8")
    rule = RepeatedFailedLoginRule(started_at=now)
    alerts = []
    for record_id in range(1, 11):
        xml = template.replace(
            "<EventRecordID>2</EventRecordID>",
            f"<EventRecordID>{record_id}</EventRecordID>",
        )
        result = normalize_failed_logon(xml, now, IngestionMode.LOOKBACK)
        assert isinstance(result, SecurityEvent)
        alert = rule.process(result, now=now)
        if alert is not None:
            alerts.append(alert)

    assert [alert.severity for alert in alerts] == [Severity.MEDIUM, Severity.HIGH]
    assert alerts[0].alert_id == alerts[1].alert_id
    assert alerts[-1].technical_details["trigger_window_count"] == 10
