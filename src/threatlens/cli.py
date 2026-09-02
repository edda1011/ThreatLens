"""Command-line entry point for ThreatLens."""

from __future__ import annotations

import argparse
from collections.abc import Sequence


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser without performing system operations."""
    return argparse.ArgumentParser(
        prog="threatlens",
        description="ThreatLens local-first personal security monitoring for Windows.",
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Parse CLI arguments and return a process exit code."""
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0
