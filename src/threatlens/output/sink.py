"""Explicit creation and flushing of redacted alert files."""

from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path
from types import TracebackType
from typing import TextIO

from threatlens.models.alert import Alert
from threatlens.output.jsonl import format_jsonl


class AlertOutputError(RuntimeError):
    """A safe output error that omits paths and alert contents."""


class AlertFileSink(AbstractContextManager["AlertFileSink"]):
    def __init__(self, path: Path | None = None) -> None:
        self._stream: TextIO | None = None
        self._closed = False
        if path is not None:
            try:
                # This context manager owns the handle until __exit__ or close.
                self._stream = open(path, "x", encoding="utf-8", newline="\n")  # noqa: SIM115
            except (OSError, ValueError):
                raise AlertOutputError(
                    "Could not create the alert file. Choose a new file "
                    "in an existing writable directory."
                ) from None

    def write(self, alert: Alert) -> None:
        if self._closed:
            raise AlertOutputError("Alert file is closed.")
        if self._stream is None:
            return
        line = format_jsonl(alert, redact=True)
        try:
            written = self._stream.write(line)
            self._stream.flush()
        except (OSError, UnicodeError):
            raise AlertOutputError(
                "Alert file write failed; stored data may be incomplete."
            ) from None
        if written != len(line):
            raise AlertOutputError("Alert file write was incomplete.")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._stream is not None:
            try:
                self._stream.close()
            except OSError:
                raise AlertOutputError(
                    "Could not close the alert file safely."
                ) from None
            finally:
                self._stream = None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
