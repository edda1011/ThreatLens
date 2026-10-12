# ThreatLens

ThreatLens is a local-first personal security monitoring and incident-awareness
tool for Windows users. Its goal is to translate Windows security activity into
clear, cautious alerts that explain what happened, why it may matter, and what
the user can safely do next.

> [!IMPORTANT]
> ThreatLens is currently pre-alpha. The repository contains the approved v0.1
> design, Python project foundation, typed models, a tested 4625 XML parser,
> an in-memory failed-login detection engine, alert formatters, and an optional
> redacted alert-file writer. CLI integration and live Windows monitoring are
> not implemented yet.

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
- reproducible dependency lock
- pytest, Ruff, mypy, coverage, and build configuration
- MIT License

Not yet implemented:

- Windows Security Event Log collection
- CLI integration for monitoring, replay, and output options

Running the CLI currently displays help only.

The human formatter shows severity and confidence separately, explains that
successful access was not evaluated, and places optional technical details last.
JSONL output follows the versioned alert schema.

The file writer is disabled by default. When explicitly enabled, it masks account
names, source IP addresses, and domains; retains timestamps, counts, severity,
and confidence; writes UTF-8 JSONL; and refuses to overwrite an existing file.
Console output includes identifiers so users can investigate local activity.

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
