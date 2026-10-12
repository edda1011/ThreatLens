# ThreatLens

ThreatLens is a local-first personal security monitoring and incident-awareness
tool for Windows users. Its goal is to translate Windows security activity into
clear, cautious alerts that explain what happened, why it may matter, and what
the user can safely do next.

> [!IMPORTANT]
> ThreatLens is currently pre-alpha. The repository contains the approved v0.1
> design, Python project foundation, typed models, a tested 4625 XML parser,
> an in-memory failed-login detection engine, alert formatters, and an optional
> redacted alert-file writer, and a working offline replay CLI. Live Windows
> monitoring is not implemented yet.

ThreatLens is not a replacement for antivirus, EDR, or professional incident
response. The absence of an alert does not prove that a device is safe.

## v0.1 Goal

The first release will:

- run as a foreground command-line tool on supported Windows systems;
- read failed-logon events (Windows Security Event ID 4625);
- normalize relevant event fields into a stable internal model;
- detect repeated failures against the same account from the same source;
- provide Medium and High alerts without claiming that an attack succeeded;
- display human-readable output or versioned JSON Lines; and
- keep raw Windows security logs on the device.

See [SPECIFICATION.md](SPECIFICATION.md) for the approved product behavior and
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for the delivery sequence.

## Current Status

Completed:

- Python package and CLI entry-point foundation
- typed security-event and alert models
- Event ID 4625 XML normalization with synthetic fixture tests
- repeated failed-login detection with rolling windows, escalation, and inactivity cooldown
- human-readable and JSONL alert formatters
- optional saving of redacted JSONL alerts to a new local file
- CLI configuration validation and developer-only offline XML replay
- reproducible dependency lock
- pytest, Ruff, mypy, coverage, and build configuration
- MIT License

Not yet implemented:

- Windows Security Event Log collection
- Windows preflight and live monitoring

The default `monitor` command currently exits with a clear not-implemented
message. It does not read real Windows logs or report active protection.

The human formatter shows severity and confidence separately, explains that
successful access was not evaluated, and places optional technical details last.
JSONL output follows the versioned alert schema.

The file writer is disabled by default. When explicitly enabled, it masks account
names, source IP addresses, and domains; retains timestamps, counts, severity,
and confidence; writes UTF-8 JSONL; and refuses to overwrite an existing file.
Console output includes identifiers so users can investigate local activity.

## Offline Replay (Development Only)

From the repository with the virtual environment activated:

```powershell
python -m threatlens --help
python -m threatlens replay --help
python -m threatlens replay tests/fixtures/repeated_failed_login
python -m threatlens replay tests/fixtures/repeated_failed_login --output jsonl
```

The repeated-login scenario emits Medium at 5 failures, then High at 10 failures,
using the same alert ID. These are synthetic records, not real device activity.
The original `tests/fixtures/windows_4625` directory exercises varied event
shapes and one malformed record; it does not trigger an alert at default thresholds.

Replay accepts one UTF-8 XML file or a directory of single-event XML files
(non-recursive, case-insensitive `.xml` extension). It normalizes records using
the existing parser, sorts by event time, and simulates startup at the newest
valid event timestamp. `--lookback` is measured backward from that simulated
startup, not today's clock. All replay records are labeled `lookback`; the human
formatter's startup wording refers to this simulation. Replay is not live
monitoring and does not test Windows permissions or collection reliability.

Supported options, supplied after `replay <source>` or `monitor`:

- `--lookback 10m` (maximum `24h`)
- `--output human|jsonl` (default `human`)
- `--technical` (human output only)
- `--medium-threshold 5 --medium-window 2m`
- `--high-threshold 10 --high-window 5m`
- `--cooldown 10m`
- `--save-alerts <new-file>` (redacted JSONL, regardless of console format)

Durations use whole seconds, minutes, or hours (`30s`, `10m`, `1h`). The existing
configuration relationships are enforced: High count exceeds Medium count,
High window is at least Medium window, and cooldown is at least High window.
Thresholds accept positive integers up to 10 digits. Replay is limited to 10,000
files and 16 Mi characters of decoded XML input. Oversized or malformed records
are skipped with sanitized diagnostic counts; missing/unreadable inputs and
batches with no valid records fail. Timestamps at the datetime range limits
are rejected if startup-window arithmetic would overflow.

Only alert text or JSONL goes to stdout. Replay status, diagnostics, and errors
go to stderr, so JSONL stdout remains parseable. Console alerts use UTF-8.
No file is saved unless `--save-alerts` is provided. Use a new filename each time;
the parent directory must already exist. An explicitly requested file can remain
empty or partial when input fails or replay is interrupted.

Exit codes: `0` for completed replay or Ctrl+C; `2` for argument/configuration/
input errors; `1` for output failures, unsupported monitoring platforms, or the
currently unimplemented live-monitor command. Offline replay works without
Windows administrator privileges.

## Supported Development Environment

- Windows 11 x64
- Windows 10 22H2 x64 on a best-effort basis
- Standard CPython 3.12, 3.13, or 3.14

Windows Server, Windows on ARM, 32-bit Windows, and older Windows releases are
outside the v0.1 test matrix.

## Development Setup

Clone the repository and open it:

```powershell
git clone https://github.com/edda1011/ThreatLens.git
cd ThreatLens
```

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the exact tested development dependencies:

```powershell
python -m pip install -r requirements.lock
python -m pip install -e . --no-deps
```

If PowerShell blocks virtual-environment activation, the interpreter can be
used directly instead:

```powershell
.\.venv\Scripts\python.exe -m pytest
```

## Development Checks

```powershell
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy src tests
python -m build --no-isolation
python -m threatlens --help
```

To regenerate the dependency lock after intentionally changing
`pyproject.toml`:

```powershell
pip-compile pyproject.toml --extra dev --output-file requirements.lock --strip-extras --no-emit-index-url
```

## Privacy and Safety

The approved v0.1 design requires that ThreatLens:

- does not upload security events or call external intelligence services;
- does not collect passwords;
- does not save raw event XML during normal operation;
- does not persist alerts unless the user explicitly requests it;
- does not change Windows audit policy, registry, firewall, or services;
- does not automatically block, delete, quarantine, or remediate; and
- distinguishes monitoring health from device security.

## License

ThreatLens is available under the [MIT License](LICENSE).
