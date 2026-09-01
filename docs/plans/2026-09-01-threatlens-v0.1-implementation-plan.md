# ThreatLens v0.1 Implementation Plan

**Status:** Draft for user approval

**Date:** 2026-09-01

**Design:** `docs/specs/2026-09-01-threatlens-v0.1-design.md`

## Objective

Implement the approved ThreatLens v0.1 scope as a foreground Windows CLI that reads Event ID 4625, normalizes failed-logon records, detects repeated failures in memory, and emits careful human-readable or JSONL alerts.

The implementation is divided into independently verifiable increments. Platform-independent behavior is completed before the live Windows collector so that most development and testing does not require administrator privileges or real failed logins.

## Technical Baseline

- Python: 3.12 through 3.14
- Packaging: `pyproject.toml` with a `src/` layout
- Runtime Windows integration: `pywin32`, installed only on Windows
- Models and validation: standard-library dataclasses and enums unless implementation evidence justifies another dependency
- CLI: standard-library `argparse`
- XML parsing: secure standard-library parsing of Windows Event XML
- Testing: `pytest`
- Linting and formatting: `ruff`
- Type checking: `mypy`
- Test coverage: `coverage` through `pytest-cov`
- Dependency locking: `pip-tools` generating `requirements.lock` from `pyproject.toml`
- Application package: `threatlens`
- CLI entry point: `threatlens`

Resolved application and development dependencies must be pinned in a committed `requirements.lock` generated with `pip-compile pyproject.toml --extra dev`. `pyproject.toml` remains the human-maintained dependency source. No framework, database, web server, telemetry SDK, or cloud dependency is permitted in v0.1.

## Target Repository Structure

```text
ThreatLens/
├── docs/
│   ├── plans/
│   └── specs/
├── src/
│   └── threatlens/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── config.py
│       ├── diagnostics.py
│       ├── models/
│       │   ├── alert.py
│       │   └── event.py
│       ├── collection/
│       │   ├── base.py
│       │   ├── preflight.py
│       │   └── windows_event_log.py
│       ├── normalization/
│       │   └── failed_logon.py
│       ├── detection/
│       │   ├── aggregator.py
│       │   └── repeated_failed_login.py
│       └── output/
│           ├── human.py
│           └── jsonl.py
├── tests/
│   ├── fixtures/
│   │   └── windows_4625/
│   ├── integration/
│   └── unit/
├── .gitignore
├── LICENSE
├── README.md
└── pyproject.toml
```

The structure is a target, not permission to create unused abstraction. Files are added only when their corresponding task begins.

## Phase 1 — Repository and Quality Baseline

### Task 1.1: Establish project metadata

Create:

- `pyproject.toml`
- `requirements.lock`
- `.gitignore`
- `LICENSE`
- `src/threatlens/__init__.py`
- `src/threatlens/__main__.py`
- `tests/`

Requirements:

- Declare the supported Python range.
- Define the `threatlens` console entry point.
- Keep `pywin32` behind a Windows platform marker.
- Generate `requirements.lock` from `pyproject.toml`; never edit the lock manually.
- Configure pytest, Ruff, and mypy in `pyproject.toml` where supported.
- Ignore virtual environments, caches, coverage output, build artifacts, local alert files, and environment files.
- Use the MIT License only after confirming the repository owner intends that license.

Verification:

```powershell
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m mypy src
python -m threatlens --help
```

Commit boundary: `chore: initialize Python project`

### Task 1.2: Document contributor workflow

Expand `README.md` only enough to explain the v0.1 status, supported systems, installation for contributors, test commands, privacy posture, and explicit non-goals. Do not advertise unfinished monitoring capabilities as complete.

Verification: follow the setup instructions in a clean virtual environment.

Commit boundary: `docs: add v0.1 development setup`

## Phase 2 — Stable Domain Models

### Task 2.1: Write model contract tests first

Add tests for:

- timezone-aware UTC validation
- required event identity fields
- nullable optional failed-logon fields
- immutable or mutation-controlled models
- enum values for ingestion mode, severity, confidence, and access outcome
- deterministic JSON-compatible serialization
- schema version presence

Expected initial result: tests fail because the models do not exist.

### Task 2.2: Implement event and alert models

Implement the approved `SecurityEvent`, `FailedLogonDetails`, and `Alert` contracts. Use explicit types and reject naive datetimes. Keep serialization separate from display formatting.

Verification:

```powershell
python -m pytest tests/unit/test_event_models.py tests/unit/test_alert_models.py
python -m mypy src
```

Commit boundary: `feat: add security event and alert models`

## Phase 3 — Event ID 4625 Normalization

### Task 3.1: Add sanitized XML fixtures

Create representative, synthetic or fully sanitized fixtures for:

- local interactive logon failure
- remote/RDP-style failure
- IPv4 source
- IPv6 source
- loopback source
- missing or `-` source
- machine account
- missing optional fields
- unknown extra fields
- malformed XML
- duplicate record identity
- differing field order

Every fixture must contain invented hostnames, accounts, addresses, and identifiers. Add a fixture provenance note stating that no personal or production security data is included.

### Task 3.2: Write normalizer tests first

Test:

- namespace-aware XML parsing
- lookup by Windows `Data Name`, not element position
- UTC timestamp parsing
- normalization of blank and `-` values to null where appropriate
- preservation of unknown numeric status values as data
- deterministic `event_uid`
- safe rejection of the wrong channel or Event ID
- diagnostic classification for invalid key fields
- absence of raw XML in returned models and exception messages

### Task 3.3: Implement the normalizer

Create a pure function that accepts an Event XML string and collection timestamp, returning either a normalized event or a typed, sanitized normalization failure. It must have no Windows API dependency.

Verification:

```powershell
python -m pytest tests/unit/test_failed_logon_normalizer.py
python -m pytest tests/integration/test_fixture_replay.py
```

Commit boundary: `feat: normalize Windows failed logon events`

## Phase 4 — In-Memory Detection Engine

### Task 4.1: Define configuration and validation tests

Cover:

- 10-minute default and 24-hour maximum lookback
- default Medium 5/2-minute threshold
- default High 10/5-minute threshold
- default 10-minute inactivity cooldown
- positive values
- High count greater than Medium count
- High window not shorter than Medium window
- stable grouping behavior with and without source IP

### Task 4.2: Implement validated configuration

Keep configuration as typed application data. Do not add YAML, TOML rule loading, arbitrary expressions, or executable plugins.

### Task 4.3: Write aggregator and rule tests first

Use a controllable clock and explicit event timestamps. Cover:

- counts below threshold
- Medium at exactly 5 events in 2 minutes
- High at exactly 10 events in 5 minutes
- events just outside each boundary
- Medium-to-High update of one alert period
- no repeated output at counts 6–9 or above 10
- reset after 10 minutes without matching activity
- distinct hostname, source IP, username, and logon type groups
- absent source IP with Low confidence
- duplicate event suppression
- mildly out-of-order events
- events outside lookback
- invalid future timestamps
- safe pruning of expired in-memory state

### Task 4.4: Implement aggregation and detection

Implement the smallest data structures that satisfy the tests. The detector returns explicit outcomes such as no output, new Medium alert, or High escalation. It does not print, write files, call Windows APIs, or mutate OS state.

Verification:

```powershell
python -m pytest tests/unit/test_detection_config.py
python -m pytest tests/unit/test_repeated_failed_login.py
python -m pytest --cov=threatlens.detection --cov-report=term-missing
```

Commit boundary: `feat: detect repeated failed logins`

## Phase 5 — Safe Alert Presentation

### Task 5.1: Write output contract tests first

Cover:

- required human-readable questions
- `access_outcome` rendered as not evaluated
- no claim that an attack failed or succeeded
- severity and confidence shown independently
- missing source explained without presenting `None` or `-` as an address
- technical details visually secondary
- stable JSONL field names and enum values
- one valid JSON object per line
- UTF-8 output
- output file opened and validated before monitoring

### Task 5.2: Implement human and JSONL formatters

Formatters consume alerts and return serialized output. They must not receive or serialize raw XML. Recommended actions are deterministic templates tied to the observed failed-login pattern.

### Task 5.3: Implement optional alert sink

Write only structured alerts when the user explicitly supplies `--save-alerts`. Fail before collection if the path is invalid or unwritable. Do not add raw-event saving.

Verification:

```powershell
python -m pytest tests/unit/test_human_output.py tests/unit/test_jsonl_output.py
```

Commit boundary: `feat: add safe alert output formats`

## Phase 6 — CLI and Offline Replay

### Task 6.1: Define CLI behavior tests

Cover:

- `--help`
- default `monitor` command
- `--lookback`
- `--output human|jsonl`
- `--save-alerts`
- threshold and window overrides
- invalid argument messages
- unsupported platform behavior
- exit-code contract

Add a developer-only fixture replay path that exercises the same normalizer and detector used by live collection. It must not appear as a false claim of live monitoring.

### Task 6.2: Wire the platform-independent pipeline

Connect configuration, fixture input, normalization, aggregation, detection, and formatting. Use dependency injection at the collector boundary so the CLI can be tested without Windows APIs.

Verification:

```powershell
python -m threatlens --help
python -m threatlens replay tests/fixtures/windows_4625
python -m pytest tests/integration/test_cli_replay.py
```

Commit boundary: `feat: add CLI and fixture replay pipeline`

## Phase 7 — Windows Preflight and Collection

### Task 7.1: Isolate the Windows adapter

Define a narrow collector protocol independently from `pywin32`. Import Windows-only modules inside the adapter or behind platform guards so model, normalizer, rule, and replay tests run on non-Windows environments.

### Task 7.2: Implement and test preflight

Preflight reports:

- supported Windows version and x64 architecture
- administrator/privilege status
- Security channel readability
- best-effort audit telemetry assessment
- `Healthy`, `Limited telemetry`, `Permission required`, or `Unsupported system`

Unit tests mock OS and API boundaries. Tests assert that preflight never changes audit policy, registry, firewall, services, or privileges.

### Task 7.3: Implement lookback collection

Query Security Event ID 4625 within the selected event-time range. Bound memory use and result iteration. Convert native records to XML at the adapter boundary.

### Task 7.4: Implement live collection and handoff

Use Event Record IDs and in-process event UIDs to create an overlap-safe boundary between lookback and live processing. Ensure subscription handles are closed on normal exit and failure.

### Task 7.5: Implement bounded recovery

Classify transient and terminal collector failures, perform a small bounded retry with backoff, then emit `Monitoring interrupted` and return a non-zero exit code when recovery fails.

Verification:

```powershell
python -m pytest tests/unit/test_preflight.py tests/unit/test_windows_collector.py
python -m pytest tests/integration/test_collector_handoff.py
```

Commit boundary: `feat: collect Windows failed logon events`

## Phase 8 — End-to-End Hardening

### Task 8.1: Run deterministic full-pipeline scenarios

Replay fixtures for:

- no alert
- Medium alert
- High escalation
- missing source with Low confidence
- mixed unrelated groups
- duplicate and out-of-order records
- lookback-to-live overlap
- malformed record followed by valid records

Snapshot only stable structured output. Avoid brittle snapshots of terminal decoration.

### Task 8.2: Privacy and wording checks

Add automated assertions that:

- raw XML cannot reach output models or diagnostic messages
- default execution creates no alert-history file
- known prohibited certainty phrases do not appear
- saved alerts contain only documented fields
- external network libraries and calls are absent

### Task 8.3: Resource and shutdown checks

Verify bounded rolling-window memory, expired-state pruning, closed file and Windows handles, and graceful `Ctrl+C` behavior.

Verification:

```powershell
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy src
```

Commit boundary: `test: harden v0.1 monitoring pipeline`

## Phase 9 — Documentation and Release Candidate

### Task 9.1: Complete user documentation

Update README and focused documents to cover:

- product positioning and v0.1 limitations
- supported Windows versions and Python versions
- administrator requirement
- audit-policy inspection and manual configuration guidance
- installation and operation
- lookback and output options
- example sanitized alerts
- monitoring health meanings
- privacy and retention behavior
- stopping monitoring
- troubleshooting
- developer tests and fixture provenance

Documentation must clearly state that ThreatLens is not a replacement for antivirus or EDR and that absence of alerts is not proof of safety.

### Task 9.2: Manual Windows acceptance pass

On a controlled supported Windows x64 device:

1. Test non-admin preflight failure.
2. Test administrator startup.
3. Confirm 10-minute lookback.
4. Confirm live 4625 observation in a safe test environment.
5. Confirm overlap deduplication.
6. Confirm human and JSONL output.
7. Confirm optional structured-alert saving.
8. Confirm `Ctrl+C` cleanup.
9. Confirm no raw event persistence or external traffic.

Record only sanitized results in the repository.

### Task 9.3: Release readiness review

Check every acceptance criterion in the design specification. Resolve all failures; do not mark an item complete based only on an untested assumption.

Final verification:

```powershell
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy src
python -m build
```

Commit boundary: `docs: complete ThreatLens v0.1 documentation`

## Implementation Rules

- Use test-first development for normalizer, detection, formatting, configuration, and CLI behavior.
- Keep Windows API code behind one adapter boundary.
- Do not add a future-phase feature because an abstraction could support it.
- Do not persist raw events.
- Do not introduce external network calls.
- Do not automatically change Windows configuration.
- Do not claim successful or unsuccessful compromise from 4625-only evidence.
- Keep commits scoped to the boundaries listed above; do not combine unrelated phases.
- Stop and amend the design if implementation evidence requires a user-visible behavior change.

## Definition of Plan Completion

The plan is complete when all nine phases pass their verification commands, the manual Windows acceptance record is sanitized and documented, and every acceptance criterion in the approved design is demonstrably satisfied.
