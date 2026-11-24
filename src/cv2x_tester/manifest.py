# SPDX-License-Identifier: NIST-Software

"""Run manifest (``run.json``)."""

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .clock import ClockResolution
from .events import DeviceState, Outcome
from .util import atomic_write

MANIFEST_NAME = "run.json"


@dataclass(frozen=True, kw_only=True)
class FileEntry:
    path: str  # relative to the run folder
    size: int
    sha256: str


@dataclass(frozen=True, kw_only=True)
class DeviceFailure:
    phase: str
    message: str


@dataclass(frozen=True, kw_only=True)
class DeviceManifest:
    name: str
    model: str
    role: str
    host: str
    port: int
    state: DeviceState
    failure: DeviceFailure | None
    warnings: list[str]
    clock_offset_secs: float | None
    clock_uncertainty_secs: float | None
    clock_resolution: ClockResolution | None
    start_time: str | None
    stop_time: str | None
    packets: int | None
    bytes: int | None
    pcap: str | None  # file name of the merged pcap
    files: list[FileEntry]


@dataclass(frozen=True, kw_only=True)
class RunManifest:
    tool_version: str
    name: str  # test name
    description: str  # test description
    config_path: str | None
    requested_duration_secs: float
    actual_duration_secs: float | None
    stopped_early: bool
    outcome: Outcome
    timestamps: dict[str, str | None]  # UTC time when the run was created, entered each phase and finished
    start_skew_secs: float | None
    devices: list[DeviceManifest]


def device_raw_dir(run_dir: Path, name: str) -> Path:
    """Return the folder in ``run_dir`` for the raw capture files of device ``name``."""
    return run_dir / f"{name}_raw"


def device_files(run_dir: Path, name: str) -> list[Path]:
    """Return the pcap, log and raw files of device ``name`` that exist in ``run_dir``."""
    files = [run_dir / f"{name}.pcap", run_dir / f"{name}.log"]
    raw = device_raw_dir(run_dir, name)
    if raw.is_dir():
        files += sorted(p for p in raw.rglob("*") if p.is_file())
    return [p for p in files if p.is_file()]


def file_entry(path: Path, run_dir: Path) -> FileEntry:
    """Build the manifest entry of the file at ``path``, with its location relative to
    ``run_dir``, its size and its SHA-256 hash."""
    with path.open("rb") as f:
        digest = hashlib.file_digest(f, "sha256").hexdigest()
    return FileEntry(path=path.relative_to(run_dir).as_posix(), size=path.stat().st_size, sha256=digest)


def write_manifest(run_dir: Path, manifest: RunManifest) -> None:
    text = json.dumps(asdict(manifest), indent=2, ensure_ascii=False) + "\n"
    atomic_write(run_dir / MANIFEST_NAME, text)
