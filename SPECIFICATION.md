# ThreatLens v0.1 Specification

**Status:** Approved

**Date:** 2026-09-01

**Product:** ThreatLens — a local-first personal security monitoring and incident-awareness tool for Windows users

## 1. Purpose

ThreatLens v0.1 validates the product's most important technical premise: Windows Security Event Log data can be collected reliably, normalized, grouped into meaningful patterns, and explained to a non-technical user without overstating what the evidence proves.

The first release is deliberately narrow. It monitors Windows failed-logon events (Event ID 4625), identifies repeated failures against the same account from the same source, and emits clear CLI alerts. It does not attempt to establish whether a compromise succeeded.

ThreatLens is not an antivirus, EDR, SIEM, or guarantee that a device is secure.

## 2. Supported Environment and Delivery

v0.1 officially targets:

- Windows 11 x64
- Windows 10 22H2 x64 on a best-effort basis
- A foreground Python CLI launched manually with administrator privileges

The release is distributed as Python source with reproducible dependency installation and a documented virtual-environment workflow. It does not include an executable installer, code signing, automatic updates, startup registration, or a Windows Service.

Monitoring stops when the process exits. Pressing `Ctrl+C` performs a clean, successful shutdown.

Windows Server, Windows on ARM, older Windows releases, and 32-bit systems are outside the supported v0.1 test matrix.

## 3. Product and Safety Principles

- Raw security logs remain on the device by default.
- No data is uploaded or sent to an external service.
- No passwords are collected.
- No Windows settings are changed automatically.
- ThreatLens does not silently elevate its privileges.
- The user can stop monitoring at any time.
- A weak signal is never described as proof of an attack or compromise.
- Collection health is reported separately from device security.
- Early releases recommend actions but do not block, delete, quarantine, or remediate automatically.

## 4. Scope

### 4.1 Included

- Preflight checks for platform, Security Log access, and available telemetry
- A 10-minute startup lookback, configurable through a validated CLI option
- Continued monitoring of new Security Event ID 4625 records
- Normalization of failed-logon XML into a stable internal model
- In-process event deduplication
- In-memory rolling-window aggregation
- One repeated-failed-login detection rule
- Medium-to-High alert escalation and notification cooldown
- Human-readable CLI output
- Stable JSON Lines output
- Optional explicit saving of structured alerts
- Unit, fixture-replay, and manual Windows integration tests
- Documentation for setup, required permissions, audit behavior, privacy, limitations, and troubleshooting

### 4.2 Explicitly excluded

- Successful-login correlation using Event ID 4624
- Password-spraying detection across multiple accounts
- New-account or privilege-group detections
- PowerShell, Defender, and Firewall telemetry
- SQLite or another database
- Persistent history or a cross-restart checkpoint
- A public 0–100 risk score
- GUI, dashboard, FastAPI, or notifications
- A Windows Service, installer, or automatic updater
- Threat-intelligence enrichment
- MITRE ATT&CK mapping
- Automated blocking or system changes

## 5. Architecture

```text
Preflight Check
      |
      v
Windows Event Reader
      |
      v
4625 Normalizer
      |
      v
In-Memory Event Aggregator
      |
      v
Repeated Failed Login Rule
      |
      v
Alert Formatter
      |
      +----> Human-Readable CLI
      |
      +----> JSONL / Optional Alert File
```

The application is a single foreground process. Components communicate through typed models and narrow interfaces so future collectors, rules, and storage implementations can be added without coupling the detection engine to Windows API objects.

Responsibilities remain separate:

- **Preflight:** determines whether monitoring can start and describes limitations.
- **Collector:** retrieves the requested Windows records and manages lookback/live handoff.
- **Normalizer:** parses a record without assigning malicious intent.
- **Aggregator:** maintains the minimum in-memory state needed for rolling windows and deduplication.
- **Rule:** evaluates grouped events and creates or upgrades alerts.
- **Formatter:** produces user-facing text or schema-stable JSONL.

No database or local API is introduced in v0.1.

## 6. Collection and Startup Behavior

The collector queries only the Windows Security channel for Event ID 4625.

Startup proceeds as follows:

1. Validate CLI arguments and any output path.
2. Run platform, architecture, privilege, Security Log access, and telemetry preflight checks.
3. Query the previous 10 minutes by default.
4. Process lookback records in event-time order.
5. Establish the live-monitoring boundary using Event Record IDs.
6. Begin continuous monitoring of new 4625 records.
7. Deduplicate any overlap between lookback and live collection.

The lookback duration is configurable, for example with `--lookback 30m`, but must be positive and may not exceed 24 hours. There is no cross-restart checkpoint. Restarting ThreatLens intentionally repeats the configured lookback; duplicated records are suppressed only within the current process.

Each event records whether it entered through `lookback` or `live` ingestion. An alert states when its evidence includes pre-start events.

## 7. Telemetry Health and Error Handling

ThreatLens reports one of these monitoring states:

- **Healthy:** Security Log collection is operating as expected.
- **Limited telemetry:** collection works, but relevant audit coverage cannot be confirmed or important fields are unavailable.
- **Permission required:** Security Log access is unavailable with the current privileges.
- **Unsupported system:** the host is outside the supported platform boundary.
- **Monitoring interrupted:** collection failed during operation and could not recover.
- **Stopped:** the user ended monitoring normally.

`Healthy` means that the collector is functioning; it does not mean the device is safe.

Error behavior:

- Insufficient permission prevents startup and produces actionable administrator-launch guidance.
- An inaccessible Security Log prevents startup.
- ThreatLens explains how to inspect or manually enable relevant audit policy, but never changes it.
- A malformed individual record produces a sanitized diagnostic and is skipped without stopping monitoring.
- A transient collection failure receives a small, bounded number of retries with backoff.
- A persistent collection failure changes the state to `Monitoring interrupted` and exits non-zero.
- An unwritable requested alert file is detected before monitoring begins.
- Debug and exception output must not include complete raw events, usernames, or IP addresses.
- `Ctrl+C` changes the state to `Stopped` and exits successfully.

## 8. Event Data Contract

### 8.1 Common event envelope

```text
SecurityEvent
- schema_version
- event_uid
- provider
- channel
- event_id
- record_id
- timestamp_utc
- collected_at_utc
- hostname
- category
- ingestion_mode       # lookback | live
- details              # FailedLogonDetails in v0.1
```

### 8.2 Failed-logon details

```text
FailedLogonDetails
- target_username
- target_domain
- source_ip
- source_port
- workstation_name
- logon_type
- status
- sub_status
- authentication_package
- process_name
```

Contract rules:

- All internal timestamps are timezone-aware UTC values.
- Absent data is represented explicitly as null; ThreatLens does not invent values.
- `event_uid` is deterministically derived from stable source identity, including hostname, channel, and record ID.
- Unknown optional XML fields do not invalidate an otherwise usable event.
- A missing or invalid timestamp, record identity, hostname, or target username makes the record ineligible for detection and increments a sanitized diagnostic counter.
- Full raw XML is not retained during ordinary runtime.
- Sanitized raw XML may exist only in test fixtures.
- The schema is versioned from the first release.

## 9. Alert Data Contract

```text
Alert
- schema_version
- alert_id
- rule_id
- first_seen_utc
- last_seen_utc
- event_count
- severity
- confidence
- title
- summary
- target_username
- source_ip
- logon_type
- access_outcome
- ingestion_mode
- reasons[]
- recommended_actions[]
- technical_details
```

In v0.1:

- `severity` expresses the potential impact if the pattern is malicious.
- `confidence` expresses the strength and completeness of the evidence.
- `access_outcome` is the stable enum value `not_evaluated` in v0.1. Human-readable output explains that successful access was not evaluated; it must not say the attack failed.
- Technical details may include Event ID, logon type, status, and sub-status, but are visually secondary in human-readable output.
- JSONL field names and value types form a documented, versioned contract.

## 10. Detection Rule

### 10.1 Rule identity

v0.1 implements one rule: repeated failed logins against the same account from the same source and logon context.

Primary grouping key:

```text
hostname + source_ip + target_username + logon_type
```

When `source_ip` is unavailable, the fallback key is:

```text
hostname + target_username + logon_type
```

An alert created from the fallback key has Low confidence and explicitly states that the source address was unavailable.

### 10.2 Default thresholds

- 5 matching failures within 2 minutes: Medium
- 10 matching failures within 5 minutes: High
- Below the Medium threshold: no security alert
- Critical is unavailable in v0.1 because failed logins alone do not justify it

The thresholds are defaults for product validation, not claims that every matching pattern is malicious.

### 10.3 Alert lifecycle

For a single grouping key:

```text
Count 1-4: no alert
Count 5: emit a Medium alert
Count 6-9: update in-memory evidence without repeated output
Count 10: emit an update escalating the existing alert to High
Count >10: update the count without repeated output during cooldown
```

The default cooldown is 10 minutes and is measured from the most recent matching event. An alert period closes after the grouping key receives no matching event for the full cooldown duration. The next matching event starts a fresh period with a count of one; it does not immediately inherit the previous period's severity. Within an active period, output occurs only when Medium is first reached or the alert escalates to High.

### 10.4 Time and ordering

- Detection windows use `timestamp_utc`, not collection time.
- `collected_at_utc` is retained for latency diagnostics.
- Duplicate event UIDs are ignored.
- Mildly out-of-order events are inserted into the appropriate event-time window.
- Events older than the selected lookback boundary are ineligible.
- Invalid or implausibly future timestamps are diagnosed and excluded.
- Lookback and live events may contribute to the same window.

## 11. Configuration

v0.1 exposes only bounded, validated settings:

- Lookback duration
- Medium threshold and window
- High threshold and window
- Cooldown duration
- Human-readable or JSONL output
- Optional structured-alert output path

There is no scripting language, dynamically executable rule, or arbitrary expression engine.

Validation must reject non-positive durations or thresholds, lookback values over 24 hours, a High threshold that is not greater than the Medium threshold, a High window shorter than the Medium window, and other internally inconsistent settings. Invalid configuration prevents monitoring from starting and produces an actionable error.

## 12. Output and Data Retention

Human-readable output answers:

- What happened?
- Why might it be suspicious?
- Was successful access evaluated?
- How serious is the observed pattern?
- What can the user safely do next?

Suggested actions remain contextual and non-destructive, such as checking whether the source belongs to a known device, reviewing the affected account, changing a password from a trusted device if activity is unfamiliar, and disabling unused remote access.

By default:

- No raw XML is written to disk.
- No username, IP address, or alert history is persisted.
- Only the minimum rolling-window state remains in memory.
- In-memory state disappears when the process exits.

`--output jsonl` sends versioned structured alerts to standard output. An explicit `--save-alerts <path>` enables local persistence of structured alerts. The requested path is validated before collection begins. Saving raw events is not supported in v0.1.

## 13. Testing

### 13.1 Unit tests

Pure tests cover:

- XML field extraction and absent fields
- UTC conversion
- Event UID stability
- Grouping keys and fallback behavior
- Threshold and rolling-window boundaries
- Medium-to-High escalation
- Cooldown behavior
- Duplicate and out-of-order records
- Configuration validation
- Alert schema and wording invariants

These tests do not require administrator access or a live Security Log.

### 13.2 Fixture replay

Sanitized 4625 XML fixtures cover:

- Local interactive failures
- RDP and other network logons
- Present and absent source addresses
- IPv4, IPv6, loopback, and `-`
- Machine accounts
- Missing optional fields
- Malformed XML
- Duplicate and out-of-order records
- Known field variations across supported Windows versions

Fixture replay uses the same normalizer, aggregator, and rule pipeline as live collection.

### 13.3 Manual Windows integration tests

A documented controlled test verifies:

- Permission and platform preflight
- Lookback/live handoff
- Real 4625 collection
- Human-readable and JSONL output
- Graceful `Ctrl+C` shutdown
- Clear behavior when telemetry is unavailable

The documentation does not instruct ordinary users to perform dangerous activity on a production machine.

## 14. Acceptance Criteria

v0.1 is complete only when:

- It runs from source on the supported Windows x64 test matrix.
- Preflight distinguishes healthy, limited, permission-denied, and unsupported states.
- It performs the default 10-minute lookback and then monitors new events.
- Lookback/live handoff avoids observable omissions and suppresses overlap duplicates.
- Supported 4625 XML normalizes into the approved contract.
- Default thresholds, escalation, and cooldown behave deterministically.
- Missing source IP lowers confidence and is explained.
- Output never equates absent success evidence with a failed attack.
- Human-readable and JSONL outputs conform to documented contracts.
- Raw logs and sensitive identifiers are not persisted by default.
- A malformed record does not stop the monitoring pipeline.
- Automated tests cover the core pipeline without a live Security Log.
- Static analysis, unit tests, and fixture replay pass.
- README documentation covers installation, privilege and audit requirements, operation, privacy, limitations, troubleshooting, and shutdown.

## 15. Future Evolution

After v0.1 is completed and validated, the next design cycle may add Event ID 4624 and successful-login-after-failures correlation. Persistence, account-change detections, PowerShell and Defender telemetry, UI, notifications, threat intelligence, and packaging remain separate future increments. Each requires its own approved specification rather than being silently folded into v0.1.
