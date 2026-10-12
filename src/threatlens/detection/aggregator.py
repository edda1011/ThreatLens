"""Group observations and discard expired in-memory evidence."""

from __future__ import annotations

from bisect import bisect_left, insort
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from heapq import heappop, heappush

from threatlens.config import DetectionConfig
from threatlens.models.alert import Alert
from threatlens.models.event import IngestionMode, SecurityEvent

type GroupKey = tuple[str, str | None, str, str | None, int | None]


def group_key(event: SecurityEvent) -> GroupKey:
    details = event.details
    return (
        event.hostname.casefold(),
        details.source_ip,
        details.target_username.casefold(),
        details.target_domain.casefold() if details.target_domain is not None else None,
        details.logon_type,
    )


@dataclass(slots=True)
class AlertPeriod:
    first_seen: datetime
    last_seen: datetime
    reset_boundary: datetime | None = None
    event_count: int = 0
    observations: list[datetime] = field(default_factory=list)
    modes: set[IngestionMode] = field(default_factory=set)
    alert: Alert | None = None

    @property
    def ingestion_mode(self) -> IngestionMode:
        return IngestionMode.MIXED if len(self.modes) > 1 else next(iter(self.modes))

    def count_in(self, window: timedelta) -> int:
        cutoff = self.last_seen - window
        return len(self.observations) - bisect_left(self.observations, cutoff)


class EventAggregator:
    def __init__(self, config: DetectionConfig, allowed_lateness: timedelta) -> None:
        self.config = config
        self.periods: dict[GroupKey, AlertPeriod] = {}
        self._seen: set[str] = set()
        self._seen_times: list[tuple[datetime, str]] = []
        self._allowed_lateness = allowed_lateness
        self._dedup_retention = config.cooldown + allowed_lateness

    def prune(self, reference: datetime) -> None:
        # ponytail: scan active groups; use an expiry heap if group volume grows.
        for key, period in list(self.periods.items()):
            if reference - period.last_seen >= self._dedup_retention:
                del self.periods[key]
            else:
                cutoff = reference - self.config.high_window - self._allowed_lateness
                del period.observations[: bisect_left(period.observations, cutoff)]
        cutoff = reference - self._dedup_retention
        while self._seen_times and self._seen_times[0][0] < cutoff:
            _, uid = heappop(self._seen_times)
            self._seen.remove(uid)

    def add(self, event: SecurityEvent) -> AlertPeriod | None:
        if event.event_uid in self._seen:
            return None
        self._seen.add(event.event_uid)
        heappush(self._seen_times, (event.timestamp_utc, event.event_uid))
        key = group_key(event)
        period = self.periods.get(key)
        if (
            period is None
            or event.timestamp_utc - period.last_seen >= self.config.cooldown
        ):
            boundary = (
                period.last_seen + self.config.cooldown if period is not None else None
            )
            period = AlertPeriod(
                event.timestamp_utc, event.timestamp_utc, reset_boundary=boundary
            )
            self.periods[key] = period
        period.first_seen = min(period.first_seen, event.timestamp_utc)
        period.last_seen = max(period.last_seen, event.timestamp_utc)
        period.event_count += 1
        period.modes.add(event.ingestion_mode)
        insort(period.observations, event.timestamp_utc)
        cutoff = period.last_seen - self.config.high_window
        del period.observations[: bisect_left(period.observations, cutoff)]
        return period
