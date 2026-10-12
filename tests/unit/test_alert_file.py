"""Explicit saving does not overwrite evidence or retain identifiers."""

import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from threatlens.models.alert import Alert
from threatlens.output.sink import AlertFileSink, AlertOutputError


def test_default_sink_opens_no_file(sample_alert: Alert) -> None:
    with patch("builtins.open") as opening, AlertFileSink() as sink:
        sink.write(sample_alert)
    opening.assert_not_called()


def test_explicit_file_is_utf8_redacted_jsonl(
    tmp_path: Path, sample_alert: Alert
) -> None:
    destination = tmp_path / "alerts.jsonl"
    with AlertFileSink(destination) as sink:
        sink.write(replace(sample_alert, title="登录失败提醒"))
        sink.write(sample_alert)
        # A completed write is visible even before the sink closes.
        lines = destination.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
    payload = json.loads(lines[0])
    assert payload["title"] == "登录失败提醒"
    assert payload["target_username"] == "[redacted]"
    assert "192.0.2.55" not in destination.read_text(encoding="utf-8")


def test_existing_file_is_preserved(tmp_path: Path) -> None:
    destination = tmp_path / "evidence.jsonl"
    destination.write_text("existing evidence", encoding="utf-8")
    with pytest.raises(AlertOutputError, match="new file"):
        AlertFileSink(destination)
    assert destination.read_text(encoding="utf-8") == "existing evidence"


def test_missing_parent_fails_before_monitoring(tmp_path: Path) -> None:
    with pytest.raises(AlertOutputError):
        AlertFileSink(tmp_path / "missing" / "alerts.jsonl")
    assert not (tmp_path / "missing").exists()


def test_permission_error_is_sanitized() -> None:
    with (
        patch("builtins.open", side_effect=PermissionError("private path")),
        pytest.raises(AlertOutputError) as failure,
    ):
        AlertFileSink(Path("alerts.jsonl"))
    assert "private path" not in str(failure.value)


def test_write_after_close_is_an_error(tmp_path: Path, sample_alert: Alert) -> None:
    sink = AlertFileSink(tmp_path / "alerts.jsonl")
    sink.close()
    with pytest.raises(AlertOutputError, match="closed"):
        sink.write(sample_alert)


def test_flush_error_is_reported_and_handle_is_closed(sample_alert: Alert) -> None:
    with patch("builtins.open") as opening:
        stream = opening.return_value
        stream.flush.side_effect = OSError("private path")
        with (
            pytest.raises(AlertOutputError, match="write failed") as failure,
            AlertFileSink(Path("alerts.jsonl")) as sink,
        ):
            sink.write(sample_alert)
        assert "private path" not in str(failure.value)
        stream.close.assert_called_once()


def test_partial_write_is_an_error(sample_alert: Alert) -> None:
    with patch("builtins.open") as opening:
        opening.return_value.write.return_value = 1
        with (
            pytest.raises(AlertOutputError, match="incomplete"),
            AlertFileSink(Path("alerts.jsonl")) as sink,
        ):
            sink.write(sample_alert)


def test_close_error_is_sanitized() -> None:
    with patch("builtins.open") as opening:
        opening.return_value.close.side_effect = OSError("private path")
        sink = AlertFileSink(Path("alerts.jsonl"))
        with pytest.raises(AlertOutputError, match="close") as failure:
            sink.close()
        assert "private path" not in str(failure.value)
        sink.close()
