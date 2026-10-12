"""Plain-language alerts with optional secondary technical details."""

from threatlens.models.alert import Alert
from threatlens.models.event import IngestionMode, utc_string
from threatlens.output.jsonl import technical_details


def _safe_text(value: str) -> str:
    return "".join(char if char.isprintable() else ascii(char)[1:-1] for char in value)


def format_human(alert: Alert, *, technical: bool = False) -> str:
    """Render an alert without terminal escape codes or implied attack success."""
    modes = {
        IngestionMode.LOOKBACK: "Startup lookback (before monitoring started)",
        IngestionMode.LIVE: "Live monitoring",
        IngestionMode.MIXED: "Startup lookback and live monitoring",
    }
    lines = [
        _safe_text(alert.title),
        f"Severity: {alert.severity.value.upper()}",
        f"Confidence: {alert.confidence.value.title()}",
        "",
        "What happened?",
        _safe_text(alert.summary),
        f"Account: {_safe_text(alert.target_username)}",
        f"Source: {_safe_text(alert.source_ip) if alert.source_ip else 'Unavailable'}",
        f"First observed (UTC): {utc_string(alert.first_seen_utc)}",
        f"Last observed (UTC): {utc_string(alert.last_seen_utc)}",
        f"Evidence: {modes[alert.ingestion_mode]}",
        "",
        "Why might this be suspicious?",
        *[f"- {_safe_text(reason)}" for reason in alert.reasons],
        "",
        "Was access successful?",
        "Not evaluated. ThreatLens v0.1 monitors failed logins only; "
        "it does not assess successful access.",
        "",
        "How serious is it?",
        f"Severity: {alert.severity.value.upper()} indicates the potential impact.",
        f"Confidence: {alert.confidence.value.title()} "
        "describes the evidence strength.",
        "Repeated failures can also be caused by saved or mistyped credentials.",
        "",
        "What should I do now?",
        *[f"- {_safe_text(action)}" for action in alert.recommended_actions],
    ]
    if technical:
        logon_type = (
            str(alert.logon_type) if alert.logon_type is not None else "Unavailable"
        )
        lines.extend(
            [
                "",
                "Technical details",
                f"Logon type: {logon_type}",
            ]
        )
        labels = {
            "event_id": "Event ID",
            "target_domain": "Domain",
            "trigger_window_seconds": "Trigger window (seconds)",
            "trigger_window_count": "Failures in trigger window",
            "status": "Status",
            "sub_status": "Sub-status",
        }
        for name, value in technical_details(alert).items():
            text = _safe_text(str(value)) if value is not None else "Unavailable"
            lines.append(f"{labels[name]}: {text}")
    return "\n".join(lines) + "\n"
