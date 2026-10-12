"""Versioned JSON Lines and identifier redaction."""

import json
from dataclasses import replace

import pytest

from threatlens.models.alert import Alert
from threatlens.output.jsonl import format_jsonl


def test_jsonl_uses_stable_alert_schema(sample_alert: Alert) -> None:
    line = format_jsonl(sample_alert)
    payload = json.loads(line)
    assert line.endswith("\n")
    assert len(line.splitlines()) == 1
    assert payload == sample_alert.to_dict()
    assert payload["schema_version"] == 1
    assert payload["access_outcome"] == "not_evaluated"
    assert payload["first_seen_utc"] == "2026-10-12T12:00:00Z"
    assert "测试用户" in line


def test_json_strings_do_not_create_extra_lines(sample_alert: Alert) -> None:
    line = format_jsonl(replace(sample_alert, target_username="alice\nother"))
    assert len(line.splitlines()) == 1
    assert json.loads(line)["target_username"] == "alice\nother"


def test_unknown_technical_fields_cannot_export_raw_events(sample_alert: Alert) -> None:
    alert = replace(
        sample_alert,
        technical_details={"event_id": 4625, "raw_xml": "<Event>private</Event>"},
    )
    payload = json.loads(format_jsonl(alert))
    assert payload["technical_details"] == {"event_id": 4625}
    assert "private" not in format_jsonl(alert)


def test_redacted_jsonl_masks_identifiers_and_mentions(sample_alert: Alert) -> None:
    alert = replace(
        sample_alert,
        summary="测试用户 received failures from 192.0.2.55 in TEST-PC.",
        reasons=("Review 测试用户 on test-pc.",),
    )
    line = format_jsonl(alert, redact=True)
    payload = json.loads(line)
    for identifier in ("测试用户", "192.0.2.55", "TEST-PC", "test-pc"):
        assert identifier not in line
    assert payload["target_username"] == "[redacted]"
    assert payload["source_ip"] == "[redacted]"
    assert payload["technical_details"]["target_domain"] == "[redacted]"
    assert payload["event_count"] == 5
    assert payload["access_outcome"] == "not_evaluated"
    assert alert.target_username == "测试用户"


def test_redaction_preserves_missing_values(sample_alert: Alert) -> None:
    payload = json.loads(
        format_jsonl(replace(sample_alert, source_ip=None), redact=True)
    )
    assert payload["source_ip"] is None


@pytest.mark.parametrize("character", ["\u2028", "\u0085", "\u202e", "\ud800"])
def test_unicode_controls_are_json_escaped(sample_alert: Alert, character: str) -> None:
    line = format_jsonl(replace(sample_alert, title=f"before{character}after"))
    assert len(line.splitlines()) == 1
    assert character not in line
    assert json.loads(line)["title"] == f"before{character}after"
    line.encode("utf-8")
