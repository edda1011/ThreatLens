"""Command-line entry point for ThreatLens."""

from __future__ import annotations

import argparse
import io
import platform
import re
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from threatlens.config import DetectionConfig
from threatlens.detection.repeated_failed_login import (
    FUTURE_TOLERANCE,
    RepeatedFailedLoginRule,
)
from threatlens.models.event import utc_string
from threatlens.output.sink import AlertFileSink, AlertOutputError
from threatlens.pipeline import run_pipeline
from threatlens.replay import ReplayInputError, load_replay, replay_files


def _duration(value: str) -> timedelta:
    match = re.fullmatch(r"([0-9]{1,6})([smh])", value)
    if match is None:
        raise argparse.ArgumentTypeError("use a duration such as 30s, 10m, or 1h")
    seconds = int(match[1]) * {"s": 1, "m": 60, "h": 3600}[match[2]]
    if not 0 < seconds <= 86_400:
        raise argparse.ArgumentTypeError(
            "duration must be positive and at most 24 hours"
        )
    return timedelta(seconds=seconds)


def _threshold(value: str) -> int:
    if re.fullmatch(r"[0-9]{1,10}", value) is None or int(value) == 0:
        raise argparse.ArgumentTypeError(
            "threshold must be a positive integer (up to 10 digits)"
        )
    return int(value)


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser without performing system operations."""
    parser = argparse.ArgumentParser(
        prog="threatlens",
        description="ThreatLens local-first personal security monitoring for Windows.",
        epilog="Default command: monitor. "
        "Use 'monitor --help' or 'replay --help' for options.",
        allow_abbrev=False,
    )
    common = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    defaults = DetectionConfig()
    common.add_argument(
        "--lookback",
        type=_duration,
        default=defaults.lookback,
        help="startup history duration (default: 10m; maximum: 24h)",
    )
    common.add_argument(
        "--output",
        choices=("human", "jsonl"),
        default="human",
        help="console alert format (default: human)",
    )
    common.add_argument(
        "--save-alerts",
        type=Path,
        metavar="NEW_FILE",
        help="explicitly save redacted JSONL to a new file; never overwrite",
    )
    common.add_argument(
        "--technical",
        action="store_true",
        help="show secondary technical details in human output",
    )
    for name in ("medium", "high"):
        common.add_argument(
            f"--{name}-threshold",
            type=_threshold,
            default=getattr(defaults, f"{name}_threshold"),
            help=f"{name.title()} failure count (default: %(default)s)",
        )
        common.add_argument(
            f"--{name}-window",
            type=_duration,
            default=getattr(defaults, f"{name}_window"),
            help=f"{name.title()} rolling duration "
            f"(default: {2 if name == 'medium' else 5}m)",
        )
    common.add_argument(
        "--cooldown",
        type=_duration,
        default=defaults.cooldown,
        help="inactivity before a fresh alert period (default: 10m)",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "monitor",
        parents=[common],
        allow_abbrev=False,
        help="foreground Windows monitoring (not implemented yet)",
        description="ThreatLens Windows monitoring: not implemented yet.",
    )
    replay = commands.add_parser(
        "replay",
        parents=[common],
        allow_abbrev=False,
        help="developer-only offline XML replay; not live monitoring",
        description="ThreatLens developer-only offline replay; not live monitoring.",
    )
    replay.add_argument(
        "source", type=Path, help="UTF-8 XML file or directory (non-recursive)"
    )
    return parser


def _report(message: str) -> bool:
    """Keep status and safe diagnostics off the alert-only stdout stream."""
    try:
        text = message + "\n"
        complete = sys.stderr.write(text) == len(text)
        sys.stderr.flush()
        return complete
    except (OSError, UnicodeError):
        return False


def main(argv: Sequence[str] | None = None) -> int:
    """Return 0 on success/interrupt, 2 on input errors, 1 on runtime failure."""
    parser = build_parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or (
        arguments[0].startswith("-") and arguments[0] not in {"--help", "-h"}
    ):
        arguments.insert(0, "monitor")
    try:
        options = parser.parse_args(arguments)
        try:
            config = DetectionConfig(
                lookback=options.lookback,
                medium_threshold=options.medium_threshold,
                medium_window=options.medium_window,
                high_threshold=options.high_threshold,
                high_window=options.high_window,
                cooldown=options.cooldown,
            )
            if options.technical and options.output != "human":
                raise ValueError("--technical requires --output human")
        except ValueError as error:
            parser.error(str(error))
    except SystemExit as error:
        return error.code if isinstance(error.code, int) else 2

    if options.command == "monitor":
        if sys.platform != "win32" or platform.machine().lower() not in {
            "amd64",
            "x86_64",
        }:
            _report(
                "Unsupported system: live monitoring requires Windows x64. "
                "Offline replay is available."
            )
        else:
            _report(
                "Live monitoring is not implemented yet. "
                "Use 'threatlens replay' for offline testing."
            )
        return 1

    try:
        if isinstance(sys.stdout, io.TextIOWrapper):
            sys.stdout.reconfigure(encoding="utf-8", errors="strict", newline="\n")
        paths = replay_files(options.source)
        with AlertFileSink(options.save_alerts) as sink:
            batch = load_replay(paths)
            # Avoid datetime arithmetic overflow at the limits of XML timestamps.
            if not (
                datetime.min.replace(tzinfo=UTC) + config.lookback
                <= batch.started_at
                <= datetime.max.replace(tzinfo=UTC) - FUTURE_TOLERANCE
            ):
                raise ReplayInputError(
                    "Replay timestamps are too close to the datetime range limits."
                )
            rule = RepeatedFailedLoginRule(started_at=batch.started_at, config=config)
            if not _report(
                "Offline replay; not live monitoring. Simulated startup (UTC): "
                + utc_string(batch.started_at)
            ):
                return 1
            emitted = run_pipeline(
                batch.events,
                rule=rule,
                stream=sys.stdout,
                sink=sink,
                jsonl=options.output == "jsonl",
                technical=options.technical,
            )
            counts = batch.diagnostic_counts + rule.diagnostic_counts
            diagnostics = ", ".join(
                f"{name}={count}" for name, count in sorted(counts.items())
            )
            summary = (
                f"Replay complete: {len(batch.events)} normalized records; "
                f"{emitted} alert outputs."
            )
            if diagnostics:
                summary += f" Diagnostics: {diagnostics}."
            return 0 if _report(summary) else 1
    except ReplayInputError as error:
        _report(f"Input error: {error}")
        return 2
    except AlertOutputError as error:
        _report(f"Output error: {error}")
        return 1
    except (OSError, UnicodeError):
        _report("Console output could not be configured safely.")
        return 1
    except KeyboardInterrupt:
        _report("Stopped.")
        return 0
