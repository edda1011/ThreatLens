"""Normalized security event data contracts."""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Any, ClassVar


class IngestionMode(StrEnum):
    LOOKBACK = "lookback"
    LIVE = "live"
    MIXED = "mixed"  # An alert may combine lookback and live evidence.


def utc_datetime(value: datetime) -> datetime:
    """Normalize an aware timestamp to UTC; reject ambiguous local time."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC)


def utc_string(value: datetime) -> str:
    """Use one stable UTC representation in serialized records."""
    return value.isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class FailedLogonDetails:
    target_username: str
    target_domain: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    workstation_name: str | None = None
    logon_type: int | None = None
    status: str | None = None
    sub_status: str | None = None
    authentication_package: str | None = None
    process_name: str | None = None

    def __post_init__(self) -> None:
        if not self.target_username.strip():
            raise ValueError("target_username is required")

    def to_dict(self) -> dict[str, Any]:
        return {item.name: getattr(self, item.name) for item in fields(self)}


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    provider: str
    channel: str
    event_id: int
    record_id: int
    timestamp_utc: datetime
    collected_at_utc: datetime
    hostname: str
    category: str
    ingestion_mode: IngestionMode
    details: FailedLogonDetails
    event_uid: str = field(init=False)

    schema_version: ClassVar[int] = 1

    def __post_init__(self) -> None:
        for name in ("provider", "channel", "hostname", "category"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} is required")
        if self.event_id <= 0 or self.record_id <= 0:
            raise ValueError("event_id and record_id must be positive")
        if self.ingestion_mode is IngestionMode.MIXED:
            raise ValueError("an individual event cannot have mixed ingestion mode")

        object.__setattr__(self, "timestamp_utc", utc_datetime(self.timestamp_utc))
        object.__setattr__(
            self, "collected_at_utc", utc_datetime(self.collected_at_utc)
        )
        identity = f"{self.hostname}\0{self.channel}\0{self.record_id}"
        object.__setattr__(
            self, "event_uid", sha256(identity.encode("utf-8")).hexdigest()
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_uid": self.event_uid,
            "provider": self.provider,
            "channel": self.channel,
            "event_id": self.event_id,
            "record_id": self.record_id,
            "timestamp_utc": utc_string(self.timestamp_utc),
            "collected_at_utc": utc_string(self.collected_at_utc),
            "hostname": self.hostname,
            "category": self.category,
            "ingestion_mode": self.ingestion_mode.value,
            "details": self.details.to_dict(),
        }
