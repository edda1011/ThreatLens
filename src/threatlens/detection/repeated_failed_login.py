"""Repeated failed-logon detection with explicit event-time boundaries."""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
from datetime import datetime, timedelta
from uuid import uuid4

from threatlens.config import DetectionConfig
from threatlens.detection.aggregator import AlertPeriod, EventAggregator, group_key
from threatlens.models.alert import AccessOutcome, Alert, Confidence, Severity
from threatlens.models.event import SecurityEvent, utc_datetime

ALLOWED_LATENESS = timedelta(seconds=30)
FUTURE_TOLERANCE = timedelta(seconds=5)


class RepeatedFailedLoginRule:
    def __init__(
        self, *, started_at: datetime, config: DetectionConfig | None = None
    ) -> None:
        self.config = config if config is not None else DetectionConfig()
        self.started_at = utc_datetime(started_at)
        self._lookback_boundary = self.started_at - self.config.lookback
        self._watermark: datetime | None = None
        self._aggregator = EventAggregator(self.config, ALLOWED_LATENESS)
        self.diagnostic_counts: Counter[str] = Counter()

    @property
    def active_alerts(self) -> tuple[Alert, ...]:
        return tuple(
            period.alert
            for period in self._active_periods()
            if period.alert is not None
        )

    @property
    def active_group_count(self) -> int:
        return len(self._active_periods())

    def _active_periods(self) -> tuple[AlertPeriod, ...]:
        if self._watermark is None:
            return ()
        return tuple(
            period
            for period in self._aggregator.periods.values()
            if self._watermark - period.last_seen < self.config.cooldown
        )

    @property
    def retained_event_count(self) -> int:
        return sum(
            len(period.observations) for period in self._aggregator.periods.values()
        )

    def expire(self, *, now: datetime) -> None:
        """Release idle state; call periodically when the collector has no events."""
        reference = utc_datetime(now)
        if self._watermark is not None:
            reference = max(reference, self._watermark)
        self._watermark = reference
        self._aggregator.prune(reference)

    def process(self, event: SecurityEvent, *, now: datetime) -> Alert | None:
        """Return an alert only on its first trigger or severity escalation."""
        now = utc_datetime(now)
        timestamp = event.timestamp_utc
        failure: str | None = None
        if event.event_id != 4625 or event.channel != "Security":
            failure = "unsupported_event"
        elif timestamp < self._lookback_boundary:
            failure = "outside_lookback"
        elif timestamp > now + FUTURE_TOLERANCE:
            failure = "future_event"
        elif (
            self._watermark is not None
            and timestamp < self._watermark - ALLOWED_LATENESS
        ):
            failure = "late_event"
        if failure is not None:
            self.diagnostic_counts[failure] += 1
            return None

        self._watermark = max(timestamp, self._watermark or timestamp)
        self._aggregator.prune(self._watermark)
        existing = self._aggregator.periods.get(group_key(event))
        if (
            existing is not None
            and existing.reset_boundary is not None
            and timestamp < existing.reset_boundary
        ):
            # Do not merge a delayed predecessor into an already reset alert period.
            self.diagnostic_counts["late_period_event"] += 1
            return None
        period = self._aggregator.add(event)
        if period is None:
            self.diagnostic_counts["duplicate_event"] += 1
            return None

        severity: Severity | None = None
        if period.count_in(self.config.high_window) >= self.config.high_threshold:
            severity = Severity.HIGH
        elif period.count_in(self.config.medium_window) >= self.config.medium_threshold:
            severity = Severity.MEDIUM

        previous = period.alert
        if severity is not None and (
            previous is None
            or previous.severity is Severity.MEDIUM
            and severity is Severity.HIGH
        ):
            period.alert = self._create_alert(event, period, severity)
            return period.alert
        if previous is not None:
            period.alert = replace(
                previous,
                first_seen_utc=period.first_seen,
                last_seen_utc=period.last_seen,
                event_count=period.event_count,
                ingestion_mode=period.ingestion_mode,
                summary=self._summary(period),
            )
        return None

    @staticmethod
    def _summary(period: AlertPeriod) -> str:
        return (
            f"{period.event_count} failed logon events were observed "
            "for this account during this alert period."
        )

    def _create_alert(
        self, event: SecurityEvent, period: AlertPeriod, severity: Severity
    ) -> Alert:
        window = (
            self.config.high_window
            if severity is Severity.HIGH
            else self.config.medium_window
        )
        count = period.count_in(window)
        seconds = int(window.total_seconds())
        reasons = [
            f"At trigger time, {count} failures occurred within {seconds} seconds.",
            "Repeated failures may be password guessing or an application "
            "using outdated credentials.",
        ]
        missing_source = event.details.source_ip is None
        if missing_source:
            reasons.append(
                "Source address unavailable; multiple local sources may be combined."
            )
        actions = [
            "Review saved credentials in services or scheduled tasks "
            "if the failures are expected.",
            "If the activity is unfamiliar, review account security and "
            "change the password from a trusted device.",
        ]
        if not missing_source:
            actions.insert(
                0, "Check whether the source belongs to one of your devices."
            )
        if event.details.logon_type in {3, 10}:
            actions.append("Disable remote access that you do not use.")
        return Alert(
            alert_id=period.alert.alert_id if period.alert is not None else uuid4().hex,
            rule_id="repeated_failed_login",
            first_seen_utc=period.first_seen,
            last_seen_utc=period.last_seen,
            event_count=period.event_count,
            severity=severity,
            confidence=Confidence.LOW if missing_source else Confidence.MEDIUM,
            title="Possible repeated login attempt",
            summary=self._summary(period),
            target_username=event.details.target_username,
            source_ip=event.details.source_ip,
            logon_type=event.details.logon_type,
            access_outcome=AccessOutcome.NOT_EVALUATED,
            ingestion_mode=period.ingestion_mode,
            reasons=tuple(reasons),
            recommended_actions=tuple(actions),
            technical_details={
                "event_id": 4625,
                "target_domain": event.details.target_domain,
                "trigger_window_seconds": seconds,
                "trigger_window_count": count,
            },
        )
