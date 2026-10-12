"""Bounded, developer-only XML replay without Windows APIs or raw persistence."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from threatlens.models.event import IngestionMode, SecurityEvent
from threatlens.normalization.failed_logon import (
    MAX_XML_CHARACTERS,
    NormalizationFailure,
    normalize_failed_logon,
)

MAX_REPLAY_FILES = 10_000
MAX_REPLAY_CHARACTERS = 16_777_216


class ReplayInputError(ValueError):
    """An actionable error that never includes input paths or event contents."""


@dataclass(frozen=True, slots=True)
class ReplayBatch:
    events: list[SecurityEvent]
    started_at: datetime
    diagnostic_counts: Counter[str]


def replay_files(source: Path) -> list[Path]:
    """Snapshot single-event XML inputs before an optional output file is created."""
    try:
        if source.is_file() and source.suffix.lower() == ".xml":
            return [source]
        if not source.is_dir():
            raise ReplayInputError(
                "Replay requires an XML file or a directory of XML files."
            )
        paths = []
        for path in source.iterdir():
            if path.suffix.lower() == ".xml" and path.is_file():
                paths.append(path)
                if len(paths) > MAX_REPLAY_FILES:
                    raise ReplayInputError("Replay is limited to 10,000 XML files.")
    except (OSError, ValueError) as error:
        if isinstance(error, ReplayInputError):
            raise
        raise ReplayInputError(
            "Could not inspect replay input. Check local read permissions."
        ) from None
    if not paths:
        raise ReplayInputError("Replay input contains no XML files.")
    return sorted(paths)


def load_replay(paths: list[Path]) -> ReplayBatch:
    """Normalize then sort fixtures; simulate startup at the newest valid event.

    Only normalized models are retained. Input is UTF-8, one Windows Event per
    file, and at most 16 Mi characters across the entire replay batch.
    """
    events = []
    diagnostics: Counter[str] = Counter()
    characters = 0
    collected_at = datetime.now(UTC)
    for path in paths:
        try:
            with path.open(encoding="utf-8-sig") as stream:
                xml = stream.read(MAX_XML_CHARACTERS + 1)
        except UnicodeError:
            diagnostics["invalid_xml"] += 1
            continue
        except (OSError, ValueError):
            raise ReplayInputError(
                "Could not read a replay file. Check local read permissions."
            ) from None
        characters += len(xml)
        if characters > MAX_REPLAY_CHARACTERS:
            raise ReplayInputError(
                "Replay is limited to 16 Mi characters of XML input."
            )
        result = normalize_failed_logon(xml, collected_at, IngestionMode.LOOKBACK)
        if isinstance(result, NormalizationFailure):
            diagnostics[result.code.value] += 1
        else:
            events.append(result)
    if not events:
        raise ReplayInputError("Replay contains no valid Security 4625 records.")
    events.sort(key=lambda event: (event.timestamp_utc, event.record_id))
    return ReplayBatch(events, events[-1].timestamp_utc, diagnostics)
