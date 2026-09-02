"""Package-level smoke tests."""

from __future__ import annotations

import subprocess
import sys

import threatlens


def test_package_exposes_version() -> None:
    assert threatlens.__version__ == "0.1.0"


def test_module_help_is_available() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "threatlens", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "ThreatLens" in result.stdout
    assert "personal security monitoring" in result.stdout
