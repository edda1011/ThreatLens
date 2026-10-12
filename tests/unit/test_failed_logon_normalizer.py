"""4625 normalization without Windows APIs or live device data."""

from datetime import UTC, datetime
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from threatlens.models.event import IngestionMode, SecurityEvent
from threatlens.normalization.failed_logon import (
    MAX_XML_CHARACTERS,
    FailureCode,
    NormalizationFailure,
    normalize_failed_logon,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "windows_4625"
COLLECTED_AT = datetime(2026, 9, 2, 12, 1, tzinfo=UTC)


def normalize(xml: str) -> SecurityEvent | NormalizationFailure:
    return normalize_failed_logon(xml, COLLECTED_AT, IngestionMode.LOOKBACK)


def test_named_fields_and_windows_timestamp_precision() -> None:
    result = normalize((FIXTURES / "rdp.xml").read_text(encoding="utf-8"))
    assert isinstance(result, SecurityEvent)
    assert result.details.target_username == "sample-admin"
    assert result.details.source_ip == "192.0.2.55"
    assert result.details.source_port == 51234
    assert result.details.logon_type == 10
    assert result.details.target_domain == "TEST-PC"
    assert result.details.authentication_package == "NTLM"
    assert result.details.workstation_name == "TEST-CLIENT"
    assert result.details.process_name is None
    assert result.details.status == "0xc000006d"
    assert result.details.sub_status == "0xc000006a"
    assert result.timestamp_utc == datetime(2026, 9, 2, 12, 0, 0, 123456, UTC)
    assert result.collected_at_utc == COLLECTED_AT
    assert result.ingestion_mode is IngestionMode.LOOKBACK


@pytest.mark.parametrize(
    ("filename", "username", "ip", "logon_type"),
    [
        ("local.xml", "sample-user", "127.0.0.1", 2),
        ("ipv6.xml", "sample-user", "2001:db8::1", 3),
        ("machine.xml", "TEST-CLIENT$", "192.0.2.56", 3),
        ("missing_optional.xml", "sample-user", None, None),
        ("reordered.xml", "sample-user", "::1", 2),
    ],
)
def test_fixture_variants(
    filename: str, username: str, ip: str | None, logon_type: int | None
) -> None:
    result = normalize((FIXTURES / filename).read_text(encoding="utf-8"))
    assert isinstance(result, SecurityEvent)
    assert result.details.target_username == username
    assert result.details.source_ip == ip
    assert result.details.logon_type == logon_type


def test_unknown_status_is_preserved_and_duplicate_uid_is_stable() -> None:
    xml = (FIXTURES / "ipv6.xml").read_text(encoding="utf-8")
    first, second = normalize(xml), normalize(xml)
    assert isinstance(first, SecurityEvent)
    assert isinstance(second, SecurityEvent)
    assert first.details.status == "0xDEADBEEF"
    assert first.event_uid == second.event_uid


def test_ipv4_mapped_ipv6_uses_the_same_source_identity() -> None:
    xml = (FIXTURES / "rdp.xml").read_text(encoding="utf-8")
    result = normalize(xml.replace("192.0.2.55", "::ffff:192.0.2.55"))
    assert isinstance(result, SecurityEvent)
    assert result.details.source_ip == "192.0.2.55"


def test_namespace_prefix_does_not_change_field_mapping() -> None:
    xml = (FIXTURES / "rdp.xml").read_text(encoding="utf-8")
    # Default and prefixed namespaces identify the same Windows elements.
    prefixed = ET.tostring(ET.fromstring(xml), encoding="unicode")
    assert normalize(prefixed) == normalize(xml)


@pytest.mark.parametrize("address", ["", "-", "not-an-ip"])
def test_unavailable_source_address_becomes_none(address: str) -> None:
    xml = (FIXTURES / "rdp.xml").read_text(encoding="utf-8")
    result = normalize(xml.replace("192.0.2.55", address))
    assert isinstance(result, SecurityEvent)
    assert result.details.source_ip is None


@pytest.mark.parametrize("port", ["-", "bad", "-1", "65536"])
def test_invalid_optional_port_becomes_none(port: str) -> None:
    xml = (FIXTURES / "rdp.xml").read_text(encoding="utf-8")
    result = normalize(xml.replace("51234", port))
    assert isinstance(result, SecurityEvent)
    assert result.details.source_port is None


@pytest.mark.parametrize(
    ("old", "new", "code"),
    [
        (
            "<EventID>4625</EventID>",
            "<EventID>4624</EventID>",
            FailureCode.UNSUPPORTED_EVENT,
        ),
        (
            "<Channel>Security</Channel>",
            "<Channel>System</Channel>",
            FailureCode.UNSUPPORTED_EVENT,
        ),
        ("Microsoft-Windows-Security-Auditing", "Other", FailureCode.UNSUPPORTED_EVENT),
        (
            "<EventRecordID>2</EventRecordID>",
            "<EventRecordID>bad</EventRecordID>",
            FailureCode.INVALID_IDENTITY,
        ),
        ("<Computer>TEST-PC</Computer>", "<Computer />", FailureCode.INVALID_IDENTITY),
        (
            '<Data Name="TargetUserName">sample-admin</Data>',
            "",
            FailureCode.INVALID_IDENTITY,
        ),
        ("2026-09-02T12:00:00.123456700Z", "not-a-time", FailureCode.INVALID_TIMESTAMP),
        (
            "2026-09-02T12:00:00.123456700Z",
            "2026-09-02T12:00:00",
            FailureCode.INVALID_TIMESTAMP,
        ),
    ],
)
def test_invalid_required_data_is_diagnosed(
    old: str, new: str, code: FailureCode
) -> None:
    xml = (FIXTURES / "rdp.xml").read_text(encoding="utf-8")
    result = normalize(xml.replace(old, new))
    assert result == NormalizationFailure(code)
    assert "sample-admin" not in repr(result)
    assert "192.0.2.55" not in repr(result)


@pytest.mark.parametrize(
    "xml",
    [
        "<Event><System><EventID>4625</EventID>",
        '<!DOCTYPE Event [<!ENTITY account "private">]><Event>&account;</Event>',
        "<Event />",
        "x" * (MAX_XML_CHARACTERS + 1),
        "<Event>\ud800</Event>",
    ],
    ids=["malformed", "entity-declaration", "wrong-root", "oversized", "bad-unicode"],
)
def test_unsafe_or_malformed_xml_is_rejected(xml: str) -> None:
    result = normalize(xml)
    assert isinstance(result, NormalizationFailure)
    assert result.code in {FailureCode.INVALID_XML, FailureCode.UNSAFE_XML}


def test_duplicate_named_fields_are_rejected() -> None:
    xml = (FIXTURES / "rdp.xml").read_text(encoding="utf-8")
    result = normalize(
        xml.replace(
            "</EventData>", '<Data Name="TargetUserName">other</Data></EventData>'
        )
    )
    assert result == NormalizationFailure(FailureCode.INVALID_IDENTITY)


def test_invalid_collection_timestamp_is_diagnosed() -> None:
    xml = (FIXTURES / "rdp.xml").read_text(encoding="utf-8")
    result = normalize_failed_logon(xml, datetime(2026, 9, 2), IngestionMode.LIVE)
    assert result == NormalizationFailure(FailureCode.INVALID_TIMESTAMP)
