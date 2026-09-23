"""Structured security alert data contract."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

from threatlens.models.event import IngestionMode, utc_datetime, utc_string


class Severity(StrEnum):
    MEDIUM = "medium"
    HIGH = "high"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AccessOutcome(StrEnum):
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True, slots=True)
class Alert:
    alert_id: str
    rule_id: str
    first_seen_utc: datetime
    last_seen_utc: datetime
    event_count: int
    severity: Severity
    confidence: Confidence
    title: str
    summary: str
    target_username: str
    source_ip: str | None
    logon_type: int | None
    access_outcome: AccessOutcome
    ingestion_mode: IngestionMode
    reasons: tuple[str, ...]
    recommended_actions: tuple[str, ...]
    technical_details: Mapping[str, str | int | None]

    schema_version: ClassVar[int] = 1

    def __post_init__(self) -> None:
        for name in ("alert_id", "rule_id", "title", "summary", "target_username"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} is required")
        if self.event_count <= 0:
            raise ValueError("event_count must be positive")

        object.__setattr__(self, "first_seen_utc", utc_datetime(self.first_seen_utc))
        object.__setattr__(self, "last_seen_utc", utc_datetime(self.last_seen_utc))
        if self.first_seen_utc > self.last_seen_utc:
            raise ValueError("first_seen_utc must not be after last_seen_utc")

        object.__setattr__(self, "reasons", tuple(self.reasons))
        object.__setattr__(self, "recommended_actions", tuple(self.recommended_actions))
        object.__setattr__(
            self, "technical_details", MappingProxyType(dict(self.technical_details))
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "first_seen_utc": utc_string(self.first_seen_utc),
            "last_seen_utc": utc_string(self.last_seen_utc),
            "event_count": self.event_count,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "title": self.title,
            "summary": self.summary,
            "target_username": self.target_username,
            "source_ip": self.source_ip,
            "logon_type": self.logon_type,
            "access_outcome": self.access_outcome.value,
            "ingestion_mode": self.ingestion_mode.value,
            "reasons": list(self.reasons),
            "recommended_actions": list(self.recommended_actions),
            "technical_details": dict(self.technical_details),
        }
