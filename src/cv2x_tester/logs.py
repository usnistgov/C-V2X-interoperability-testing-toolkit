# SPDX-License-Identifier: NIST-Software

"""Per-device and per-run log writers."""

import contextlib
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from .events import DeviceLog, LogLevel
from .util import iso, local_now, time_of_day


def redact(text: str, secrets: list[str]) -> str:
    """Mask secrets (passwords, passphrases) in a message."""
    for s in secrets:
        if s:
            text = text.replace(s, "******")
    return text


class _LogFile:
    def __init__(self, path: Path | None) -> None:
        self._file: TextIO | None = path.open("a", encoding="utf-8") if path else None

    def write(self, line: str) -> None:
        """Write a line. Write errors are ignored, so that they don't interrupt the run."""
        if self._file:
            with contextlib.suppress(OSError):
                self._file.write(line + "\n")
                self._file.flush()

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None


class DeviceLogger:
    """Writes timestamped lines to ``<device>.log`` (if a path is given) and forwards
    them as DeviceLog events. Commands never contain secrets by construction."""

    def __init__(
        self, device: str, sink: Callable[[DeviceLog], None] | None = None, path: Path | None = None
    ) -> None:
        self.device = device
        self._sink = sink
        self._file = _LogFile(path)

    def _emit(self, level: LogLevel, text: str) -> None:
        now = local_now()
        file_time, event_time = iso(now), time_of_day(now)
        for line in text.splitlines() or [""]:
            self._file.write(f"{file_time} [{level}] {line}")
            if self._sink:
                self._sink(DeviceLog(self.device, level, line, event_time))

    def info(self, text: str) -> None:
        self._emit(LogLevel.INFO, text)

    def command(self, command: str) -> None:
        self._emit(LogLevel.COMMAND, f"$ {command}")

    def stdout(self, text: str) -> None:
        self._emit(LogLevel.STDOUT, text.rstrip("\n"))

    def stderr(self, text: str) -> None:
        self._emit(LogLevel.STDERR, text.rstrip("\n"))

    def warning(self, text: str) -> None:
        self._emit(LogLevel.WARNING, text)

    def error(self, text: str) -> None:
        self._emit(LogLevel.ERROR, text)

    def close(self) -> None:
        self._file.close()


class RunLogger:
    """Orchestrator log (``run.log``)."""

    def __init__(self, path: Path | None) -> None:
        self._file = _LogFile(path)

    def __call__(self, message: str) -> None:
        self._file.write(f"{iso(local_now())} {message}")

    def close(self) -> None:
        self._file.close()
