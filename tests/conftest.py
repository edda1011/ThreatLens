"""Synthetic alert shared by presentation tests."""

from datetime import UTC, datetime

import pytest

from threatlens.models.alert import AccessOutcome, Alert, Confidence, Severity
from threatlens.models.event import IngestionMode


@pytest.fixture
def sample_alert() -> Alert:
    return Alert(
        alert_id="alert-1",
        rule_id="repeated_failed_login",
        first_seen_utc=datetime(2026, 10, 12, 12, tzinfo=UTC),
        last_seen_utc=datetime(2026, 10, 12, 12, 1, tzinfo=UTC),
        event_count=5,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        title="Possible repeated login attempt",
        summary="5 failed logon events were observed during this alert period.",
        target_username="测试用户",
        source_ip="192.0.2.55",
        logon_type=10,
        access_outcome=AccessOutcome.NOT_EVALUATED,
        ingestion_mode=IngestionMode.MIXED,
        reasons=("At trigger time, 5 failures occurred within 120 seconds.",),
        recommended_actions=(
            "Check whether the source belongs to one of your devices.",
        ),
        technical_details={
            "event_id": 4625,
            "target_domain": "TEST-PC",
            "trigger_window_seconds": 120,
            "trigger_window_count": 5,
            "status": "0xc000006d",
        },
    )
