"""Safe replay boundaries and collector-independent output failures."""

from __future__ import annotations

import io
import sys
from pathlib import Path
from typing import NoReturn

import pytest

from threatlens import cli, replay
from threatlens.detection.repeated_failed_login import RepeatedFailedLoginRule
from threatlens.output.sink import AlertFileSink, AlertOutputError
from threatlens.pipeline import run_pipeline
from threatlens.replay import ReplayInputError, load_replay, replay_files

SCENARIO = Path(__file__).parents[1] / "fixtures" / "repeated_failed_login"


def test_replay_sorts_events_not_filenames() -> None:
    batch = load_replay(list(reversed(replay_files(SCENARIO))))
    assert [event.record_id for event in batch.events] == list(range(101, 111))
    assert batch.started_at == batch.events[-1].timestamp_utc


def test_empty_directory_and_invalid_only(tmp_path: Path) -> None:
    with pytest.raises(ReplayInputError, match="no XML files"):
        replay_files(tmp_path)
    malformed = tmp_path / "private.xml"
    malformed.write_text("<Event>private-data", encoding="utf-8")
    with pytest.raises(ReplayInputError, match="no valid"):
        load_replay(replay_files(tmp_path))


def test_bad_utf8_is_skipped(tmp_path: Path) -> None:
    malformed = tmp_path / "bad.xml"
    malformed.write_bytes(b"\xff")
    batch = load_replay([malformed, SCENARIO / "01.xml"])
    assert len(batch.events) == 1
    assert batch.diagnostic_counts == {"invalid_xml": 1}


def test_replay_size_and_count_caps(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(replay, "MAX_REPLAY_FILES", 1)
    with pytest.raises(ReplayInputError, match="limited"):
        replay_files(SCENARIO)
    monkeypatch.setattr(replay, "MAX_REPLAY_CHARACTERS", 1)
    with pytest.raises(ReplayInputError, match="limited"):
        load_replay([SCENARIO / "01.xml"])


def test_unreadable_record_has_safe_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def unreadable(*args: object, **kwargs: object) -> NoReturn:
        raise PermissionError("private-account: private-path")

    monkeypatch.setattr(Path, "open", unreadable)
    with pytest.raises(ReplayInputError) as caught:
        load_replay([SCENARIO / "01.xml"])
    assert "private" not in str(caught.value)


def test_output_validated_before_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def must_not_read(*args: object, **kwargs: object) -> NoReturn:
        pytest.fail("records were read before the requested output was validated")

    monkeypatch.setattr(cli, "load_replay", must_not_read)
    assert (
        cli.main(
            [
                "replay",
                str(SCENARIO),
                "--save-alerts",
                str(tmp_path / "missing" / "out.jsonl"),
            ]
        )
        == 1
    )


def test_interrupt_closes_requested_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def interrupt(*args: object, **kwargs: object) -> NoReturn:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run_pipeline", interrupt)
    output = tmp_path / "stopped.jsonl"
    assert cli.main(["replay", str(SCENARIO), "--save-alerts", str(output)]) == 0
    assert "Stopped." in capsys.readouterr().err
    # Windows refuses replacement of an open file; this also verifies cleanup.
    output.rename(tmp_path / "closed.jsonl")


def test_default_replay_creates_no_files(tmp_path: Path) -> None:
    for source in replay_files(SCENARIO):
        (tmp_path / source.name).write_bytes(source.read_bytes())
    before = set(tmp_path.iterdir())
    assert cli.main(["replay", str(tmp_path)]) == 0
    assert set(tmp_path.iterdir()) == before


def test_xml_named_output_is_not_replayed(tmp_path: Path) -> None:
    (tmp_path / "event.xml").write_bytes((SCENARIO / "01.xml").read_bytes())
    assert (
        cli.main(
            ["replay", str(tmp_path), "--save-alerts", str(tmp_path / "output.xml")]
        )
        == 0
    )


class BrokenOutput(io.StringIO):
    def write(self, text: str) -> int:
        raise OSError("private-console-data")


class ShortOutput(io.StringIO):
    def write(self, text: str) -> int:
        return len(text) - 1


@pytest.mark.parametrize("stream_type", [BrokenOutput, ShortOutput])
def test_injected_output_failure(stream_type: type[io.StringIO]) -> None:
    batch = load_replay(replay_files(SCENARIO))
    rule = RepeatedFailedLoginRule(started_at=batch.started_at)
    with AlertFileSink() as sink, pytest.raises(AlertOutputError) as caught:
        run_pipeline(iter(batch.events), rule=rule, stream=stream_type(), sink=sink)
    assert "private" not in str(caught.value)


def test_console_failure_is_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdout", BrokenOutput())
    assert cli.main(["replay", str(SCENARIO)]) == 1


def test_status_failure_prevents_alert_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stderr", BrokenOutput())
    assert cli.main(["replay", str(SCENARIO)]) == 1
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("timestamp", ["0001-01-01T00:00:00", "9999-12-31T23:59:59"])
def test_extreme_timestamp_is_safe_input_error(tmp_path: Path, timestamp: str) -> None:
    xml = (
        (SCENARIO / "01.xml")
        .read_text(encoding="utf-8")
        .replace("2026-09-02T12:00:00", timestamp)
    )
    source = tmp_path / "event.xml"
    source.write_text(xml, encoding="utf-8")
    assert cli.main(["replay", str(source)]) == 2
