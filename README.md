# ThreatLens

ThreatLens is a local-first personal security monitoring and incident-awareness
tool for Windows users. Its goal is to translate Windows security activity into
clear, cautious alerts that explain what happened, why it may matter, and what
the user can safely do next.

> [!IMPORTANT]
> ThreatLens is currently pre-alpha. The repository contains the approved v0.1
> design and the Python project foundation; Windows event monitoring and
> detection are not implemented yet.

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
- reproducible dependency lock
- pytest, Ruff, mypy, coverage, and build configuration
- MIT License

Not yet implemented:

- Windows Security Event Log collection
- Event ID 4625 normalization
- failed-login detection and alert output

Running the CLI currently displays help only.

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
