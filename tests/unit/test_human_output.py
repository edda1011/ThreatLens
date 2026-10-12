"""Human-readable alerts remain clear and safe for a terminal."""

from dataclasses import replace

import pytest

from threatlens.models.alert import Alert, Confidence
from threatlens.models.event import IngestionMode
from threatlens.output.human import format_human


def test_alert_answers_the_user_questions(sample_alert: Alert) -> None:
    result = format_human(sample_alert)
    for heading in (
        "What happened?",
        "Why might this be suspicious?",
        "Was access successful?",
        "How serious is it?",
        "What should I do now?",
    ):
        assert heading in result
    assert "Severity: MEDIUM" in result
    assert "Confidence: Medium" in result
    assert "Not evaluated" in result
    assert "测试用户" in result
    assert "192.0.2.55" in result
    assert "2026-10-12T12:00:00Z" in result
    assert "No successful login" not in result
    assert "Technical details" not in result


def test_missing_source_is_explained(sample_alert: Alert) -> None:
    result = format_human(
        replace(sample_alert, source_ip=None, confidence=Confidence.LOW)
    )
    assert "Source: Unavailable" in result
    assert "Confidence: Low" in result
    assert "None" not in result


@pytest.mark.parametrize(
    ("mode", "label"),
    [
        (IngestionMode.LOOKBACK, "Startup lookback"),
        (IngestionMode.LIVE, "Live monitoring"),
        (IngestionMode.MIXED, "Startup lookback and live monitoring"),
    ],
)
def test_ingestion_mode_is_visible(
    sample_alert: Alert, mode: IngestionMode, label: str
) -> None:
    result = format_human(replace(sample_alert, ingestion_mode=mode))
    assert label in result


def test_technical_details_are_optional_and_last(sample_alert: Alert) -> None:
    result = format_human(sample_alert, technical=True)
    assert "Technical details" in result
    assert "Event ID: 4625" in result
    assert "Logon type: 10" in result
    assert "Domain: TEST-PC" in result
    assert result.index("Technical details") > result.index("What should I do now?")


def test_untrusted_control_characters_cannot_inject_terminal_output(
    sample_alert: Alert,
) -> None:
    result = format_human(
        replace(
            sample_alert,
            target_username="alice\nCRITICAL\x1b[31m",
            reasons=("message\r\nsecond line",),
        )
    )
    assert "\x1b" not in result
    assert "alice\\nCRITICAL\\x1b[31m" in result
    assert "message\\r\\nsecond line" in result
