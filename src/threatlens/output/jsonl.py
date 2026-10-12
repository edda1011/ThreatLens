"""Versioned JSON Lines with explicit redaction for saved alerts."""

from __future__ import annotations

import json
import re

from threatlens.models.alert import Alert

REDACTED = "[redacted]"


def technical_details(alert: Alert) -> dict[str, str | int | None]:
    """Export only documented technical fields, never arbitrary raw payloads."""
    result: dict[str, str | int | None] = {}
    for name, value in alert.technical_details.items():
        if name in {"event_id", "trigger_window_seconds", "trigger_window_count"}:
            if value is None or type(value) is int:
                result[name] = value
        elif name == "target_domain":
            if value is None or isinstance(value, str):
                result[name] = value
        elif name in {"status", "sub_status"} and (
            value is None
            or (
                isinstance(value, str) and re.fullmatch(r"0[xX][0-9a-fA-F]{1,8}", value)
            )
        ):
            result[name] = value
    return result


def format_jsonl(alert: Alert, *, redact: bool = False) -> str:
    """Serialize one alert; return exactly one JSON object and a newline."""
    payload = alert.to_dict()
    details = technical_details(alert)
    payload["technical_details"] = details
    if redact:
        identifiers = [alert.target_username]
        if alert.source_ip is not None:
            identifiers.append(alert.source_ip)
        domain = details.get("target_domain")
        if isinstance(domain, str) and domain:
            identifiers.append(domain)
        patterns = [
            re.compile(rf"(?<!\w){re.escape(value)}(?!\w)", re.IGNORECASE)
            for value in sorted(set(identifiers), key=len, reverse=True)
        ]

        def redact_text(value: str) -> str:
            for pattern in patterns:
                value = pattern.sub(REDACTED, value)
            return value

        payload["target_username"] = REDACTED
        payload["source_ip"] = REDACTED if alert.source_ip is not None else None
        if "target_domain" in details:
            details["target_domain"] = REDACTED if domain is not None else None
        for name in ("title", "summary"):
            payload[name] = redact_text(payload[name])
        for name in ("reasons", "recommended_actions"):
            payload[name] = [redact_text(value) for value in payload[name]]

    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False)
    # Escape terminal controls and Unicode line separators as valid JSON escapes.
    return (
        "".join(
            char if char.isprintable() else json.dumps(char, ensure_ascii=True)[1:-1]
            for char in encoded
        )
        + "\n"
    )
