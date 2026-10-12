"""The actual CLI exercises XML, detection, display, and explicit saving."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from threatlens import cli

FIXTURES = Path(__file__).parents[1] / "fixtures"
SCENARIO = FIXTURES / "repeated_failed_login"


def invoke(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "threatlens", *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


@pytest.mark.parametrize("command", [(), ("monitor",), ("replay",)])
def test_help(command: tuple[str, ...]) -> None:
    result = invoke(*command, "--help")
    assert result.returncode == 0
    assert "ThreatLens" in result.stdout


def test_replay_jsonl_escalates_one_alert() -> None:
    result = invoke("replay", str(SCENARIO), "--output", "jsonl")
    assert result.returncode == 0, result.stderr
    alerts = [json.loads(line) for line in result.stdout.splitlines()]
    assert [alert["severity"] for alert in alerts] == ["medium", "high"]
    assert [alert["event_count"] for alert in alerts] == [5, 10]
    assert alerts[0]["alert_id"] == alerts[1]["alert_id"]
    assert alerts[1]["access_outcome"] == "not_evaluated"
    assert alerts[1]["ingestion_mode"] == "lookback"
    assert "Offline replay" in result.stderr
    assert "not live monitoring" in result.stderr


def test_human_replay_and_technical_details() -> None:
    result = invoke("replay", str(SCENARIO), "--technical")
    assert result.returncode == 0
    assert "Severity: MEDIUM" in result.stdout
    assert "Severity: HIGH" in result.stdout
    assert "Was access successful?\nNot evaluated." in result.stdout
    assert "Technical details" in result.stdout
    assert "Event ID: 4625" in result.stdout


def test_malformed_record_does_not_prevent_replay() -> None:
    result = invoke("replay", str(FIXTURES / "windows_4625"), "--output", "jsonl")
    assert result.returncode == 0
    assert result.stdout == ""
    assert "invalid_xml=1" in result.stderr
    assert "<Event" not in result.stderr


def test_threshold_and_window_overrides() -> None:
    result = invoke(
        "replay",
        str(SCENARIO),
        "--output",
        "jsonl",
        "--medium-threshold",
        "2",
        "--high-threshold",
        "3",
        "--medium-window",
        "15s",
        "--high-window",
        "30s",
        "--cooldown",
        "1m",
    )
    assert result.returncode == 0, result.stderr
    alerts = [json.loads(line) for line in result.stdout.splitlines()]
    assert [alert["event_count"] for alert in alerts] == [2, 3]
    assert alerts[-1]["technical_details"]["trigger_window_seconds"] == 30


def test_lookback_is_anchored_to_fixture_time() -> None:
    result = invoke("replay", str(SCENARIO), "--lookback", "10s", "--output", "jsonl")
    assert result.returncode == 0
    assert result.stdout == ""
    assert "outside_lookback=8" in result.stderr


def test_saved_alerts_are_redacted(tmp_path: Path) -> None:
    output = tmp_path / "alerts.jsonl"
    result = invoke("replay", str(SCENARIO), "--save-alerts", str(output))
    assert result.returncode == 0, result.stderr
    text = output.read_text(encoding="utf-8")
    alerts = [json.loads(line) for line in text.splitlines()]
    assert len(alerts) == 2
    assert all(alert["target_username"] == "[redacted]" for alert in alerts)
    assert "sample-admin" not in text
    assert "192.0.2.55" not in text
    assert "TEST-PC" not in text
    assert "sample-admin" in result.stdout


def test_existing_file_is_never_overwritten(tmp_path: Path) -> None:
    output = tmp_path / "existing.jsonl"
    output.write_text("keep", encoding="utf-8")
    result = invoke("replay", str(SCENARIO), "--save-alerts", str(output))
    assert result.returncode == 1
    assert result.stdout == ""
    assert output.read_text(encoding="utf-8") == "keep"
    assert str(output) not in result.stderr


@pytest.mark.parametrize(
    "arguments",
    [
        ("--lookback", "0m"),
        ("--lookback", "25h"),
        ("--lookback", "forever"),
        ("--output", "xml"),
        ("--medium-threshold", "0"),
        ("--medium-threshold", "10"),
        ("--high-window", "1m"),
        ("--cooldown", "1m"),
        ("--output", "jsonl", "--technical"),
        ("--unknown",),
    ],
)
def test_invalid_options(arguments: tuple[str, ...]) -> None:
    result = invoke("replay", str(SCENARIO), *arguments)
    assert result.returncode == 2
    assert result.stdout == ""
    assert "error:" in result.stderr
    assert "Traceback" not in result.stderr


def test_missing_source_is_an_input_error(tmp_path: Path) -> None:
    result = invoke("replay", str(tmp_path / "private-name.xml"))
    assert result.returncode == 2
    assert "private-name" not in result.stderr
    assert "Traceback" not in result.stderr


def test_single_xml_file_is_supported() -> None:
    result = invoke("replay", str(SCENARIO / "01.xml"))
    assert result.returncode == 0
    assert result.stdout == ""


def test_default_monitor_reports_unimplemented(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main([]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "monitoring" in captured.err.lower()


def test_unsupported_system(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert cli.main(["--lookback", "30m"]) == 1
    assert "Unsupported system" in capsys.readouterr().err
