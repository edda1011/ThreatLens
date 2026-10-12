"""Normalize Security 4625 XML without retaining raw event data."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from ipaddress import ip_address
from xml.etree import ElementTree as ET

from threatlens.models.event import (
    FailedLogonDetails,
    IngestionMode,
    SecurityEvent,
    utc_datetime,
)

MAX_XML_CHARACTERS = 1_048_576
NAMESPACE = "{http://schemas.microsoft.com/win/2004/08/events/event}"
PROVIDER = "Microsoft-Windows-Security-Auditing"


class FailureCode(StrEnum):
    INVALID_XML = "invalid_xml"
    UNSAFE_XML = "unsafe_xml"
    UNSUPPORTED_EVENT = "unsupported_event"
    INVALID_IDENTITY = "invalid_identity"
    INVALID_TIMESTAMP = "invalid_timestamp"


@dataclass(frozen=True, slots=True)
class NormalizationFailure:
    """A safe diagnostic: no original field values or XML are included."""

    code: FailureCode


def _text(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value if value and value != "-" else None


def _integer(value: str | None, maximum: int = 4_294_967_295) -> int | None:
    if value is None or not value.isascii() or not value.isdecimal():
        return None
    try:
        number = int(value)
    except ValueError:
        return None
    return number if number <= maximum else None


def _source_ip(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        address = ip_address(value)
    except ValueError:
        return None
    # Windows can represent an IPv4 source as an IPv4-mapped IPv6 address.
    if address.version == 6 and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


def normalize_failed_logon(
    xml: str, collected_at_utc: datetime, ingestion_mode: IngestionMode
) -> SecurityEvent | NormalizationFailure:
    """Return a normalized event or sanitized failure for a single record.

    Windows event XML requires neither DTDs nor custom entities. Reject those
    constructs before parsing and cap input size to bound parser resource use.
    """
    if len(xml) > MAX_XML_CHARACTERS or "<!DOCTYPE" in xml or "<!ENTITY" in xml:
        return NormalizationFailure(FailureCode.UNSAFE_XML)
    try:
        root = ET.fromstring(xml)
    except (ET.ParseError, UnicodeError):
        return NormalizationFailure(FailureCode.INVALID_XML)
    if root.tag != f"{NAMESPACE}Event":
        return NormalizationFailure(FailureCode.INVALID_XML)

    system = root.find(f"{NAMESPACE}System")
    event_data = root.find(f"{NAMESPACE}EventData")
    if system is None or event_data is None:
        return NormalizationFailure(FailureCode.INVALID_IDENTITY)

    provider = system.find(f"{NAMESPACE}Provider")
    if (
        provider is None
        or provider.get("Name") != PROVIDER
        or _text(system.findtext(f"{NAMESPACE}Channel")) != "Security"
        or _text(system.findtext(f"{NAMESPACE}EventID")) != "4625"
    ):
        return NormalizationFailure(FailureCode.UNSUPPORTED_EVENT)

    data: dict[str, str | None] = {}
    for item in event_data.findall(f"{NAMESPACE}Data"):
        name = item.get("Name")
        if name is None:
            continue
        if name in data:
            return NormalizationFailure(FailureCode.INVALID_IDENTITY)
        data[name] = _text(item.text)

    hostname = _text(system.findtext(f"{NAMESPACE}Computer"))
    record_id = _integer(_text(system.findtext(f"{NAMESPACE}EventRecordID")), 2**64 - 1)
    username = data.get("TargetUserName")
    if (
        not hostname
        or not record_id
        or not username
        or ingestion_mode is IngestionMode.MIXED
    ):
        return NormalizationFailure(FailureCode.INVALID_IDENTITY)

    time_created = system.find(f"{NAMESPACE}TimeCreated")
    timestamp = time_created.get("SystemTime") if time_created is not None else None
    if not timestamp:
        return NormalizationFailure(FailureCode.INVALID_TIMESTAMP)
    try:
        event_time = utc_datetime(datetime.fromisoformat(timestamp))
        collected_time = utc_datetime(collected_at_utc)
    except ValueError:
        return NormalizationFailure(FailureCode.INVALID_TIMESTAMP)

    return SecurityEvent(
        provider=PROVIDER,
        channel="Security",
        event_id=4625,
        record_id=record_id,
        timestamp_utc=event_time,
        collected_at_utc=collected_time,
        hostname=hostname,
        category="failed_logon",
        ingestion_mode=ingestion_mode,
        details=FailedLogonDetails(
            target_username=username,
            target_domain=data.get("TargetDomainName"),
            source_ip=_source_ip(data.get("IpAddress")),
            source_port=_integer(data.get("IpPort"), 65535),
            workstation_name=data.get("WorkstationName"),
            logon_type=_integer(data.get("LogonType")),
            status=data.get("Status"),
            sub_status=data.get("SubStatus"),
            authentication_package=data.get("AuthenticationPackageName"),
            process_name=data.get("ProcessName"),
        ),
    )
