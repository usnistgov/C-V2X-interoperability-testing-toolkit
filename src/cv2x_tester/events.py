# SPDX-License-Identifier: NIST-Software

"""Typed events emitted by the engine and consumed by the GUI and the CLI."""

import enum
from dataclasses import KW_ONLY, dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .clock import ClockResolution

if TYPE_CHECKING:
    from .manifest import RunManifest


class RunState(enum.StrEnum):
    IDLE = "idle"
    PREPARING = "preparing"
    RUNNING = "running"
    STOPPING = "stopping"
    FINISHED = "finished"


class Outcome(enum.StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    ABORTED = "aborted"
    INTERRUPTED = "interrupted"  # force quit: the stop sequence did not finish


class DeviceState(enum.StrEnum):
    IDLE = "idle"
    CONNECTING = "connecting"
    PRECHECK = "precheck"
    CLOCK = "clock"
    STARTING_CAPTURE = "starting_capture"
    STARTING_TEST = "starting_test"
    WAITING = "waiting"  # finished the current phase, waiting for the other devices
    RUNNING = "running"
    STOPPING_TEST = "stopping_test"
    STOPPING_CAPTURE = "stopping_capture"
    COLLECTING = "collecting"
    DONE = "done"
    NOT_READY = "not_ready"  # the pre-check found that the device isn't in a state to run a test
    FAILED = "failed"  # an error occurred; becomes FAILED_CLEAN or FAILED_UNCLEAN once the device is done
    FAILED_CLEAN = "failed_clean"  # failed, but nothing is left running on the device
    FAILED_UNCLEAN = "failed_unclean"  # not stopped cleanly: the test or capture may still be running
    ABORTED = "aborted"

    @property
    def terminal(self) -> bool:
        return self in (
            DeviceState.DONE,
            DeviceState.NOT_READY,
            DeviceState.FAILED_CLEAN,
            DeviceState.FAILED_UNCLEAN,
            DeviceState.ABORTED,
        )


class LogLevel(enum.StrEnum):
    INFO = "info"
    COMMAND = "cmd"
    STDOUT = "stdout"
    STDERR = "stderr"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class RunStateChanged:
    state: RunState
    _: KW_ONLY
    run_dir: Path | None = None
    duration_s: float | None = None


@dataclass(frozen=True)
class RunFinished:
    outcome: Outcome
    _: KW_ONLY
    run_dir: Path | None
    manifest: RunManifest | None = None
    error: str | None = None  # set when the run could not even start (e.g. bad output dir)


@dataclass(frozen=True)
class DeviceStateChanged:
    device: str
    state: DeviceState
    _: KW_ONLY
    phase: str | None = None  # failing phase for NOT_READY and the FAILED states, finished phase for WAITING
    message: str | None = None  # failure message, for NOT_READY and the FAILED states


@dataclass(frozen=True)
class DeviceLog:
    device: str
    level: LogLevel
    line: str
    timestamp: str  # local time, HH:MM:SS.mmm


@dataclass(frozen=True)
class DeviceWarning:
    device: str
    message: str


@dataclass(frozen=True)
class ClockMeasured:
    device: str
    _: KW_ONLY
    offset_s: float
    uncertainty_s: float
    resolution: ClockResolution
    exceeds_threshold: bool


@dataclass(frozen=True)
class StatsUpdated:
    device: str
    _: KW_ONLY
    packets: int | None
    bytes: int


type Event = (
    RunStateChanged
    | RunFinished
    | DeviceStateChanged
    | DeviceLog
    | DeviceWarning
    | ClockMeasured
    | StatsUpdated
)
