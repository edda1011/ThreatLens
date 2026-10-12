"""Collector-independent detection and output for normalized event iterables."""

from collections.abc import Iterable
from typing import TextIO

from threatlens.detection.repeated_failed_login import RepeatedFailedLoginRule
from threatlens.models.event import SecurityEvent
from threatlens.output.human import format_human
from threatlens.output.jsonl import format_jsonl
from threatlens.output.sink import AlertFileSink, AlertOutputError


def run_pipeline(
    events: Iterable[SecurityEvent],
    *,
    rule: RepeatedFailedLoginRule,
    stream: TextIO,
    sink: AlertFileSink,
    jsonl: bool = False,
    technical: bool = False,
) -> int:
    """Accept an injected collector; emit only new alerts and escalations."""
    emitted = 0
    for event in events:
        alert = rule.process(event, now=max(rule.started_at, event.collected_at_utc))
        if alert is None:
            continue
        text = (
            format_jsonl(alert) if jsonl else format_human(alert, technical=technical)
        )
        if not jsonl:
            text += "\n"
        try:
            if stream.write(text) != len(text):
                raise AlertOutputError("Console alert output was incomplete.")
            stream.flush()
        except (OSError, UnicodeError):
            raise AlertOutputError("Console alert output failed.") from None
        sink.write(alert)
        emitted += 1
    return emitted
