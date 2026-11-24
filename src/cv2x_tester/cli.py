# SPDX-License-Identifier: NIST-Software

"""Command-line interface: launches the GUI, or runs/checks headless."""

import argparse
import asyncio
import collections
import signal
import sys
from pathlib import Path
from types import FrameType

from . import APP_NAME, __version__
from .config import Config, ConfigError, DeviceConfig
from .drivers import CaptureMode, all_drivers
from .events import (
    ClockMeasured,
    DeviceLog,
    DeviceState,
    DeviceStateChanged,
    DeviceWarning,
    LogLevel,
    Outcome,
    RunFinished,
    RunState,
    RunStateChanged,
)
from .manifest import RunManifest
from .util import format_offset, human_bytes, parse_duration, time_of_day

# Lazy, because the engine loads asyncssh and the GUI loads PySide6.
lazy from .engine import Run, check_devices
lazy from .gui.app import main as gui_main

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_ABORTED = 3
EXIT_INTERRUPTED = 130

_CAPTURE_TEXT = {
    CaptureMode.STREAM: "streamed",
    CaptureMode.REMOTE_FILES: "remote files",
}
# The prefix of each device log line in the progress output, by level.
_LOG_PREFIX = {
    LogLevel.STDOUT: "  ",
    LogLevel.STDERR: "  ",
    LogLevel.WARNING: "warning: ",
}
# The status of each device in the pre-check summary, by its final state.
_CHECK_STATUS = {
    DeviceState.DONE: "OK",
    DeviceState.NOT_READY: "NOT READY",
    DeviceState.FAILED_CLEAN: "FAILED",
}


class UsageError(Exception):
    """Invalid arguments or configuration."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description=(
            "Run synchronized tests on C-V2X OBUs/RSUs and collect pcap traces. "
            "If no command is specified, the GUI is launched."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "-c",
        "--config",
        dest="gui_config",
        type=Path,
        help="configuration file to open in the GUI (default: start with an empty configuration)",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", type=Path, required=True, help="configuration file")

    def add_no_timestamps(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "-t",
            "--no-timestamps",
            dest="timestamps",
            action="store_false",
            help="omit the time at the start of each output line",
        )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    run = sub.add_parser(
        "run",
        parents=[common],
        help="run a test without the GUI",
        description=(
            "Run a test without the GUI. Connects to the selected devices, checks them and their "
            "clocks, starts the captures and the test, and stops them after the given duration or "
            "on Ctrl+C. Each device's capture and log are saved in a new run folder inside the "
            "output directory."
        ),
    )
    run.add_argument(
        "--name", metavar="TEST_NAME", default="", help="short test name (used in the run folder name)"
    )
    run.add_argument(
        "--description", metavar="DESC", default="", help="free-text test description stored in the manifest"
    )
    run.add_argument(
        "--duration",
        help=(
            "test duration in seconds (90), M:SS (1:30), H:MM:SS, or with units (1m30s); "
            "default: default_duration from the config"
        ),
    )
    run.add_argument(
        "--device",
        action="extend",
        nargs="+",
        metavar="NAME",
        help="devices to use (default: all enabled devices)",
    )
    run.add_argument("--output-dir", type=Path, help="base directory for run folders")
    add_no_timestamps(run)
    run.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="also print the device logs (each remote command and its output)",
    )

    check = sub.add_parser(
        "check",
        parents=[common],
        help="run pre-checks on the devices",
        description=(
            "Run pre-checks on the selected devices, to make sure they are reachable and ready "
            "for a test. Connects over SSH, runs the device model's checks and measures the "
            "clock offset, then disconnects. Nothing is started on the devices and nothing is "
            "written to disk."
        ),
    )
    check.add_argument(
        "--device",
        action="extend",
        nargs="+",
        metavar="NAME",
        help="devices to check (default: all enabled devices)",
    )
    add_no_timestamps(check)

    sub.add_parser(
        "models",
        help="list the supported device models and their options",
        description=(
            "List the supported device models, with their capture mode and the options they "
            "accept in the configuration file."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command is None:
        return gui_main(args.gui_config)
    try:
        match args.command:
            case "models":
                return cmd_models()
            case "run":
                return cmd_run(args)
            case "check":
                return cmd_check(args)
    except UsageError as e:
        print(f"{APP_NAME}: error: {e}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_USAGE


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def cmd_models() -> int:
    for drv in all_drivers():
        print(f"{drv.model_id}: {drv.display_name}" + (f" ({drv.vendor})" if drv.vendor else ""))
        print(f"    capture mode: {_CAPTURE_TEXT[drv.capture_mode]}" + ("" if drv.uses_ssh else ", no SSH"))
        if drv.default_username:
            print(f"    default user: {drv.default_username}")
        for spec in drv.Options.schema():
            choices = f", one of {', '.join(map(repr, spec.choices))}" if spec.choices else ""
            print(
                f"    option {spec.name} ({spec.kind}, default {spec.default!r}{choices}"
                + (", required)" if spec.required else ")")
                + (f": {spec.help}" if spec.help else "")
            )
    return EXIT_OK


def load_config(path: Path) -> Config:
    if not path.exists():
        raise UsageError(f"configuration file not found: {path}")
    try:
        config = Config.load(path)
    except ConfigError as e:
        raise UsageError("\n".join(f"{e.path}: {p}" for p in e.problems)) from None
    for message in config.skipped:
        print(f"warning: {path}: {message}", file=sys.stderr)
    if config.permission_warning:
        print(f"warning: {path}: {config.permission_warning}", file=sys.stderr)
    return config


def select_devices(config: Config, names: list[str] | None) -> list[DeviceConfig]:
    if names:
        devices = []
        for name in dict.fromkeys(names):
            dev = config.device(name)
            if dev is None:
                raise UsageError(f"unknown device '{name}'")
            devices.append(dev)
        return devices
    devices = [dev for dev in config.devices if dev.enabled]
    if not devices:
        raise UsageError("no devices enabled")
    return devices


class _Reporter:
    def __init__(self, *, show_logs: bool, timestamps: bool = True) -> None:
        # With show_logs, the device log lines are printed too. They already contain the
        # failure, warning and clock offset messages, so these messages are not printed
        # again from the events.
        self.show_logs = show_logs
        self.timestamps = timestamps

    def line(self, text: str, ts: str | None = None) -> None:
        """Print a progress line, prefixed with ``ts`` (default: now) unless timestamps are off."""
        print(f"{ts or time_of_day()} {text}" if self.timestamps else text, flush=True)

    def __call__(self, event: object) -> None:
        match event:
            case DeviceStateChanged(device=dev, state=state, phase=phase, message=msg):
                # Each error message is printed once. With show_logs, it is printed as part of
                # the device log. Otherwise, it is printed with the state that reports the error,
                # FAILED or NOT_READY, and not again with the FAILED_CLEAN or FAILED_UNCLEAN state
                # that follows FAILED.
                if state is DeviceState.FAILED and not self.show_logs:
                    self.line(f"[{dev}] FAILED in {phase}: {msg}")
                elif state is DeviceState.NOT_READY and not self.show_logs:
                    self.line(f"[{dev}] NOT READY in {phase}: {msg}")
                elif state is DeviceState.WAITING:
                    self.line(f"[{dev}] waiting ({phase} successful)")
                else:
                    self.line(f"[{dev}] {state}")
            case RunStateChanged(state=state, run_dir=run_dir, duration_s=duration):
                extra = f" ({duration:g} s)" if state is RunState.RUNNING else ""
                self.line(f"run state: {state}{extra}")
                if state is RunState.RUNNING and run_dir:
                    self.line(f"run folder: {run_dir}")
            case DeviceWarning(device=dev, message=msg):
                if not self.show_logs:
                    self.line(f"[{dev}] warning: {msg}")
            case ClockMeasured(device=dev, offset_s=off, uncertainty_s=unc):
                if not self.show_logs:
                    self.line(f"[{dev}] clock offset {format_offset(off)} (±{unc:.3f} s)")
            case DeviceLog(device=dev, level=level, line=line, timestamp=ts):
                if self.show_logs:
                    self.line(f"[{dev}] {_LOG_PREFIX.get(level, '')}{line}", ts)


def cmd_run(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    devices = select_devices(config, args.device)
    try:
        duration = parse_duration(args.duration) if args.duration else config.settings.default_duration
    except ValueError as e:
        raise UsageError(str(e)) from None
    reporter = _Reporter(show_logs=args.verbose, timestamps=args.timestamps)
    run = Run(
        config,
        devices,
        duration=duration,
        test_name=args.name,
        test_desc=args.description,
        output_dir=args.output_dir,
        on_event=reporter,
    )
    reporter.line(f"devices: {', '.join(d.name for d in devices)}")
    result, interrupted = asyncio.run(_execute_with_sigint(run))
    if result is None:
        _unclean_notice(run)
        print("Run interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    if result.error:
        print(f"error: {result.error}", file=sys.stderr)
    if result.manifest is not None:
        _summary(result.manifest)
    if result.run_dir:
        print(f"Results: {result.run_dir}")
    _unclean_notice(run)
    if interrupted:
        return EXIT_INTERRUPTED
    return {
        Outcome.SUCCESS: EXIT_OK,
        Outcome.PARTIAL: EXIT_FAILED,
        Outcome.FAILED: EXIT_FAILED,
        Outcome.ABORTED: EXIT_ABORTED,
        Outcome.INTERRUPTED: EXIT_INTERRUPTED,
    }[result.outcome]


async def _execute_with_sigint(run: Run) -> tuple[RunFinished | None, bool]:
    loop = asyncio.get_running_loop()
    task = asyncio.create_task(run.execute())
    presses = 0

    def on_sigint(signum: int, frame: FrameType | None) -> None:
        nonlocal presses
        presses += 1
        if presses == 1:
            print("\nStopping (press Ctrl+C again to quit immediately)...", file=sys.stderr, flush=True)
            loop.call_soon_threadsafe(run.request_stop)
        else:
            loop.call_soon_threadsafe(task.cancel)

    previous = signal.signal(signal.SIGINT, on_sigint)
    try:
        return await task, presses > 0
    except asyncio.CancelledError:
        return None, True
    finally:
        signal.signal(signal.SIGINT, previous)


def _unclean_notice(run: Run) -> None:
    if run.unclean_devices:
        names = ", ".join(run.unclean_devices)
        sys.stdout.flush()  # keep the notice after the summary when stdout is piped
        print(
            f"\nWarning: not stopped cleanly; the test or capture may still be running on: {names}",
            file=sys.stderr,
        )


def _summary(manifest: RunManifest) -> None:
    print()
    early = ""
    if manifest.stopped_early and manifest.actual_duration_secs is not None:
        early = f" (stopped early after {manifest.actual_duration_secs:.1f} s)"
    print(f"Outcome: {manifest.outcome}{early}")
    if manifest.start_skew_secs is not None:
        print(f"Start skew: {manifest.start_skew_secs:.3f} s")
    devices = manifest.devices
    name_w = max((len(d.name) for d in devices), default=0)
    state_w = max((len(d.state) for d in devices), default=0)
    for d in devices:
        size = human_bytes(d.bytes) if d.pcap else "no pcap"
        packets = ""
        if d.pcap and d.packets is not None:
            packets = f"{d.packets:,} packet{'' if d.packets == 1 else 's'}"
        print(f"  {d.name:<{name_w}}   {d.state:<{state_w}}   {size:>9}   {packets}".rstrip())
        if d.failure:
            label = "not ready" if d.state is DeviceState.NOT_READY else "error"
            print(f"  {'':<{name_w}}   {label}: {d.failure.phase}: {d.failure.message}")
        for w in d.warnings:
            print(f"  {'':<{name_w}}   warning: {w}")


def cmd_check(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    devices = select_devices(config, args.device)
    try:
        reporter = _Reporter(show_logs=True, timestamps=args.timestamps)
        results = asyncio.run(check_devices(config, devices, reporter))
    except KeyboardInterrupt:
        print("\nPre-checks interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    print()
    statuses = [_CHECK_STATUS[r.state] for r in results]
    name_w = max(len(r.device) for r in results)
    status_w = max(len(s) for s in statuses)
    for r, status in zip(results, statuses, strict=True):
        if r.failure is not None:
            detail = f"{r.failure.phase}: {r.failure.message}"
        else:
            detail = f"clock offset {format_offset(r.clock.offset_s)}" if r.clock else ""
            if r.clock_warning:
                detail += " (exceeds the threshold)"
        print(f"  {r.device:<{name_w}}   {status:<{status_w}}   {detail}".rstrip())
    counts = collections.Counter(r.state for r in results)
    ok = counts[DeviceState.DONE]
    not_ready = counts[DeviceState.NOT_READY]
    failed = counts[DeviceState.FAILED_CLEAN]
    print(f"\nPre-checks: {ok} OK, {not_ready} not ready, {failed} failed")
    return EXIT_OK if ok == len(results) else EXIT_FAILED
