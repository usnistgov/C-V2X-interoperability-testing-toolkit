# SPDX-License-Identifier: NIST-Software

"""Run orchestration (phase barriers, stop sequence, building the manifest) and pre-checks.

Pure asyncio, no Qt. Progress is reported through events (see events.py).
"""

import asyncio
import contextlib
import datetime
import functools
import itertools
import logging
import shutil
import time
import traceback
from collections.abc import Awaitable, Callable
from dataclasses import KW_ONLY, dataclass
from pathlib import Path

from . import APP_NAME, __version__
from .clock import ClockError, ClockSample, measure_clock
from .config import Config, DeviceConfig
from .drivers import CaptureStats, DeviceContext, DeviceNotReady, Driver, DriverError
from .events import (
    ClockMeasured,
    DeviceState,
    DeviceStateChanged,
    DeviceWarning,
    Event,
    Outcome,
    RunFinished,
    RunState,
    RunStateChanged,
    StatsUpdated,
)
from .logs import DeviceLogger, RunLogger, redact
from .manifest import (
    DeviceFailure,
    DeviceManifest,
    RunManifest,
    device_files,
    device_raw_dir,
    file_entry,
    write_manifest,
)
from .pcap import PcapFormatError, merge_pcaps
from .ssh import SshSession
from .util import format_offset, iso, local_now, slugify, utc_now

log = logging.getLogger(__name__)

type EventSink = Callable[[Event], None]

# Seconds between reads of the devices' live capture stats.
STATS_INTERVAL = 0.5

# Stop steps that must succeed for a device to count as cleanly stopped. If one fails,
# the test or capture may still be running on the device (FAILED_UNCLEAN).
_CLEAN_STOP_STEPS = frozenset({"reconnect", "stop_test", "stop_capture"})
# Errors whose message is meant for the user. Any other exception is a bug.
_EXPECTED_ERRORS = (DriverError, ClockError)


# --------------------------------------------------------------------------
# Runs
# --------------------------------------------------------------------------


def create_run_dir(output_dir: Path, test_name: str = "", now: datetime.datetime | None = None) -> Path:
    """Create ``<output_dir>/<YYYY-MM-DD_HH-MM-SS>[_<test_name>]``, adding ``_2``, ``_3``…
    on collision."""
    output_dir.mkdir(parents=True, exist_ok=True)
    base = (now or local_now()).strftime("%Y-%m-%d_%H-%M-%S")
    slug = slugify(test_name)
    if slug:
        base += f"_{slug}"
    for n in itertools.count(1):
        path = output_dir / (base if n == 1 else f"{base}_{n}")
        try:
            path.mkdir()
        except FileExistsError:
            continue
        return path
    raise AssertionError("unreachable")


class _Device:
    """Runtime state of one device during a run or pre-checks."""

    def __init__(
        self,
        config: Config,
        device: DeviceConfig,
        sink: EventSink,
        log_path: Path | None,
        raw_dir: Path | None,
    ) -> None:
        self.device = device
        self.name = device.name

        self.state = DeviceState.IDLE
        # The error that failed the device. A device fails only once: later errors are warnings.
        self.failure: DeviceFailure | None = None
        # First error that left the test or capture possibly running.
        self.unclean: DeviceFailure | None = None
        self.warnings: list[str] = []

        self.clock: ClockSample | None = None
        self.start_time: datetime.datetime | None = None
        self.start_mono: float | None = None
        self.stop_time: datetime.datetime | None = None
        self.stats: CaptureStats | None = None
        self.collected: list[Path] = []
        self.pcap: Path | None = None
        self.packets: int | None = None

        self.capture_attempted = False
        # Whether the engine reads the driver's live stats. True from the start of the capture
        # until the capture stops, or until stats() fails.
        self.polling_stats = False
        self.stop_deadline = 0.0  # loop time by which reconnect and stop_test must be done
        self.unreachable = False  # reconnect failed, so the stop steps that need SSH are skipped
        self.remote_stopped = False  # stop_test and stop_capture succeeded
        self.collect_complete = False  # collect succeeded and every download worked

        driver_cls = device.driver_class
        if driver_cls is None:
            raise ValueError(f"device '{device.name}': unknown model '{device.model}'")
        self.log = DeviceLogger(device.name, sink, log_path)
        self.ctx = DeviceContext(
            device=device,
            settings=config.settings,
            log=self.log,
            raw_files_dir=raw_dir,
            keep_raw_files=config.keep_raw_files(device),
            delete_remote_files=config.delete_remote_files(device),
        )
        self.session: SshSession | None = None
        if driver_cls.uses_ssh:
            self.session = SshSession(
                device, config.settings, self.log, key_path=config.key_file_path(device)
            )
            self.ctx.ssh = self.session
        self.driver: Driver = driver_cls(device, device.driver_options(), self.ctx)

    @property
    def raw_files_dir(self) -> Path:
        """Folder of the raw capture files (set for a run, not for pre-checks)."""
        assert self.ctx.raw_files_dir is not None
        return self.ctx.raw_files_dir


def _message(exc: BaseException, device: DeviceConfig) -> str:
    msg = str(exc)
    if not isinstance(exc, _EXPECTED_ERRORS):
        msg = f"internal error: {type(exc).__name__}: {msg}"
    return redact(msg, device.secrets)


def _is_not_ready(exc: BaseException, phase: str) -> bool:
    """Return whether ``exc``, raised in ``phase``, means that the device isn't ready rather than
    that it failed. Only the pre-check can find that a device isn't ready."""
    return phase == "precheck" and isinstance(exc, DeviceNotReady)


def _has_data(path: Path) -> bool:
    """Return whether ``path`` is a file that isn't empty."""
    return path.is_file() and path.stat().st_size > 0


def _emit_to(sink: EventSink | None, event: Event) -> None:
    """Pass ``event`` to ``sink``, unless ``sink`` is None. An exception raised by the
    handler is caught and logged."""
    if sink is None:
        return
    try:
        sink(event)
    # Deliberately broad: a bug in an event handler (the GUI's or the CLI's) must not stop
    # the run or the pre-checks.
    except Exception:
        log.exception("event handler failed")


def _report_clock(d: _Device, sample: ClockSample, threshold: float, emit: EventSink) -> bool:
    """Log the clock offset of ``d``, emit ClockMeasured, and warn if the offset exceeds
    ``threshold``. Return whether it does, which is never the case when ``threshold`` is 0
    (warning off)."""
    exceeds = threshold > 0 and abs(sample.offset_s) > threshold
    for message in sample.fallbacks:
        d.log.info(message)
    d.log.info(
        f"clock offset {format_offset(sample.offset_s)} (±{sample.uncertainty_s:.3f} s, "
        f"resolution {sample.resolution})"
    )
    emit(
        ClockMeasured(
            d.name,
            offset_s=sample.offset_s,
            uncertainty_s=sample.uncertainty_s,
            resolution=sample.resolution,
            exceeds_threshold=exceeds,
        )
    )
    if exceeds:
        d.ctx.warn(f"clock offset {format_offset(sample.offset_s)} exceeds the threshold ({threshold:g} s)")
    return exceeds


class Run:
    """One synchronized test execution on a set of devices."""

    def __init__(
        self,
        config: Config,
        devices: list[DeviceConfig],
        *,
        duration: float,
        test_name: str = "",
        test_desc: str = "",
        output_dir: Path | None = None,
        on_event: EventSink | None = None,
    ) -> None:
        if not devices:
            raise ValueError("no devices selected")
        self.config = config
        self.device_configs = list(devices)
        self.duration = float(duration)
        self.test_name = test_name.strip()
        self.test_desc = test_desc.strip()
        self.output_dir = output_dir or config.output_dir()
        self._emit = functools.partial(_emit_to, on_event)

        self.state = RunState.IDLE
        self.run_dir: Path | None = None
        self.actual_duration: float | None = None
        self.stopped_early = False
        self.interrupted = False

        self._run_log = RunLogger(None)  # discards messages until _execute() opens run.log
        self._devices: list[_Device] = []
        self._stats_task: asyncio.Task[None] | None = None
        self._phase = "init"
        self._timestamps: dict[str, datetime.datetime | None] = {}
        self._running_since: float | None = None  # time.monotonic() when the running phase began
        self._aborted = False
        self._stop = asyncio.Event()  # set by request_stop(), to stop the run or cancel it while preparing
        self._failed = asyncio.Event()  # set by the first device failure, to wake up a barrier

    # -- public --------------------------------------------------------------

    def request_stop(self) -> None:
        """Stop the run early (during RUNNING) or cancel it (during PREPARING)."""
        if not self._stop.is_set():
            self._run_log("stop requested")
            self._stop.set()

    @property
    def unclean_devices(self) -> list[str]:
        """Devices not stopped cleanly: the test or capture may still be running on them."""
        return [d.name for d in self._devices if d.state is DeviceState.FAILED_UNCLEAN]

    @property
    def elapsed(self) -> float:
        if self._running_since is None:
            return 0.0
        if self.actual_duration is not None:
            return self.actual_duration
        return time.monotonic() - self._running_since

    async def execute(self) -> RunFinished:
        try:
            return await self._execute()
        except asyncio.CancelledError:
            if self.actual_duration is None and self._running_since is not None:
                self.actual_duration = time.monotonic() - self._running_since
            self.interrupted = True
            self._run_log("run interrupted (force quit)")
            for d in self._devices:
                if d.session:
                    d.session.abort()
                if d.state.terminal:
                    continue
                if d.capture_attempted and not d.remote_stopped:
                    interrupted = DeviceFailure(
                        phase="stopping", message="interrupted before the device was stopped"
                    )
                    d.unclean = d.unclean or interrupted
                    if d.failure is None and not self._aborted:
                        d.failure = interrupted
                d.state = self._final_state(d, DeviceState.ABORTED)
            if self.run_dir is not None:
                # Best effort: a failure to write run.json must not stop the force quit.
                with contextlib.suppress(Exception):
                    write_manifest(self.run_dir, self._build_manifest(self._outcome()))
            raise
        finally:
            if self._stats_task is not None:
                self._stats_task.cancel()
            for d in self._devices:
                d.log.close()
            self._run_log.close()

    # -- events ----------------------------------------------------------------

    def _set_run_state(self, state: RunState) -> None:
        self.state = state
        self._run_log(f"run state: {state}")
        self._emit(RunStateChanged(state, run_dir=self.run_dir, duration_s=self.duration))

    def _set_state(self, d: _Device, state: DeviceState, phase: str | None = None) -> None:
        if d.state is state:
            return
        d.state = state
        self._emit(DeviceStateChanged(d.name, state, phase=phase))

    def _fail(self, d: _Device, phase: str, message: str, *, not_ready: bool = False) -> None:
        if d.failure is not None:
            # A device fails only once, so a later error is reported as a warning.
            d.ctx.warn(f"{phase}: {message}")
            return
        d.failure = DeviceFailure(phase=phase, message=message)
        self._failed.set()
        label = "NOT READY" if not_ready else "FAILED"
        d.log.error(f"{label} in {phase}: {message}")
        self._run_log(f"[{d.name}] {label} in {phase}: {message}")
        # Unlike FAILED, which becomes FAILED_CLEAN or FAILED_UNCLEAN later, NOT_READY is final,
        # because nothing was started on the device.
        d.state = DeviceState.NOT_READY if not_ready else DeviceState.FAILED
        self._emit(DeviceStateChanged(d.name, d.state, phase=phase, message=message))

    def _warn(self, d: _Device, message: str) -> None:
        d.warnings.append(message)
        self._run_log(f"[{d.name}] warning: {message}")
        self._emit(DeviceWarning(d.name, message))

    def _error_message(self, d: _Device, phase: str, exc: Exception) -> str:
        """The message of ``exc`` for the user. An unexpected exception (a bug) also gets
        its traceback written to run.log."""
        if not isinstance(exc, _EXPECTED_ERRORS):
            tb = "".join(traceback.format_exception(exc))
            self._run_log(f"[{d.name}] internal error in {phase}:\n{tb}")
        return _message(exc, d.device)

    def _wire(self, d: _Device) -> None:
        d.ctx.on_warning = lambda msg: self._warn(d, msg)
        d.ctx.on_failure = lambda msg: self._on_async_failure(d, msg)
        if d.session is not None:
            d.session.on_lost = lambda msg: self._on_async_failure(d, msg)

    def _on_async_failure(self, d: _Device, message: str) -> None:
        """A device failed outside of a driver call (stream died, SSH dropped)."""
        if self.state in (RunState.STOPPING, RunState.FINISHED) or d.failure is not None:
            # Only log the message: the stop steps report their own errors, and a device that
            # already failed gets follow-up symptoms of the same problem.
            d.log.error(message)
            return
        phase = "running" if self.state is RunState.RUNNING else self._phase
        self._fail(d, phase, message)

    async def _poll_stats(self) -> None:
        """Every ``STATS_INTERVAL``, update the live stats of the devices that are capturing."""
        while True:
            await asyncio.sleep(STATS_INTERVAL)
            for d in self._devices:
                if d.polling_stats:
                    self._update_stats(d)

    def _update_stats(self, d: _Device) -> None:
        """Read the driver's live stats, and report them if they changed. If stats() fails, the
        device gets a warning, and its stats are no longer read."""
        try:
            stats = d.driver.stats()
        # Deliberately broad: a bug in stats() must only disable the live stats of that device.
        except Exception as e:  # noqa: BLE001
            d.polling_stats = False
            d.ctx.warn(f"cannot read live stats: {self._error_message(d, 'stats', e)}")
            return
        if stats is not None and stats != d.stats:
            d.stats = stats
            self._emit(StatsUpdated(d.name, packets=stats.packets, bytes=stats.bytes))

    # -- orchestration -----------------------------------------------------------

    async def _execute(self) -> RunFinished:
        self._timestamps["created"] = utc_now()
        self._set_run_state(RunState.PREPARING)

        # Host checks: create the run folder and its log, which also proves that the folder is writable.
        try:
            self.run_dir = create_run_dir(self.output_dir, self.test_name)
            self._run_log = RunLogger(self.run_dir / "run.log")
        except OSError as e:
            if self.run_dir is None:
                msg = f"cannot create run folder in {self.output_dir}: {e.strerror or e}"
            else:
                msg = f"cannot create {self.run_dir / 'run.log'}: {e.strerror or e}"
                with contextlib.suppress(OSError):
                    self.run_dir.rmdir()
                self.run_dir = None
            for device in self.device_configs:
                self._emit(DeviceStateChanged(device.name, DeviceState.ABORTED, phase="host", message=msg))
            self._set_run_state(RunState.FINISHED)
            result = RunFinished(Outcome.ABORTED, run_dir=None, error=msg)
            self._emit(result)
            return result
        self._run_log(f"{APP_NAME} {__version__}")
        self._run_log(f"run folder: {self.run_dir}")
        self._run_log(f"devices: {', '.join(dev.name for dev in self.device_configs)}")
        self._run_log(f"duration: {self.duration:g} s")
        self._run_log(f"run state: {self.state}")  # set before run.log was created

        for device in self.device_configs:
            d = _Device(
                self.config,
                device,
                self._emit,
                self.run_dir / f"{device.name}.log",
                device_raw_dir(self.run_dir, device.name),
            )
            self._wire(d)
            self._devices.append(d)
        self._stats_task = asyncio.create_task(self._poll_stats(), name="stats")

        self._aborted = not await self._start_phases()
        if self._aborted:
            self._run_log("run aborted before running")
            for d in self._devices:
                if not d.capture_attempted:
                    self._finish_device(d, DeviceState.ABORTED)
            teardown = [d for d in self._devices if d.capture_attempted]
            ok_state = DeviceState.ABORTED
        else:
            self._phase = "running"
            self._timestamps["running"] = utc_now()
            self._running_since = time.monotonic()
            for d in self._devices:
                if d.failure is None:
                    self._set_state(d, DeviceState.RUNNING)
            self._set_run_state(RunState.RUNNING)
            # The timeout can expire early: the GUI's event loop uses Qt's coarse timers, which
            # can fire up to 5% early. Wait again until the duration has really passed.
            deadline = self._running_since + self.duration
            while not self.stopped_early and (remaining := deadline - time.monotonic()) > 0:
                with contextlib.suppress(TimeoutError):
                    async with asyncio.timeout(remaining):
                        await self._stop.wait()
                        self.stopped_early = True
            self.actual_duration = time.monotonic() - self._running_since
            self._run_log(
                f"running phase ended after {self.actual_duration:.1f} s"
                + (" (stopped early)" if self.stopped_early else "")
            )
            teardown, ok_state = self._devices, DeviceState.DONE
        self._timestamps["stopping"] = utc_now()
        self._set_run_state(RunState.STOPPING)
        if teardown:
            await self._stop_sequence(teardown, ok_state)
        await self._close_sessions()

        self._timestamps["finished"] = utc_now()
        outcome = self._outcome()
        manifest = await asyncio.to_thread(self._build_manifest, outcome)
        try:
            write_manifest(self.run_dir, manifest)
        except OSError as e:
            self._run_log(f"cannot write run.json: {e}")
        self._run_log(f"outcome: {outcome}")
        self._set_run_state(RunState.FINISHED)
        result = RunFinished(outcome, run_dir=self.run_dir, manifest=manifest)
        self._emit(result)
        return result

    @staticmethod
    def _final_state(d: _Device, ok_state: DeviceState) -> DeviceState:
        if d.state is DeviceState.NOT_READY:
            return DeviceState.NOT_READY
        if d.unclean is not None:
            return DeviceState.FAILED_UNCLEAN
        if d.failure is not None:
            return DeviceState.FAILED_CLEAN
        return ok_state

    def _finish_device(self, d: _Device, ok_state: DeviceState) -> None:
        state = self._final_state(d, ok_state)
        if state is ok_state:
            self._set_state(d, state)
            return
        if d.state is state:
            # NOT_READY is set as soon as the pre-check fails, so the device may already be in
            # its final state. Don't emit the same state change twice.
            return
        d.state = state
        failure = d.failure or d.unclean
        assert failure is not None
        self._emit(DeviceStateChanged(d.name, state, phase=failure.phase, message=failure.message))

    async def _start_phases(self) -> bool:
        """Run the start phases one after the other. Return False, without running the
        remaining phases, as soon as the run must abort."""
        return (
            await self._barrier("connect", DeviceState.CONNECTING, self._do_connect, cancel_early=True)
            and await self._barrier("precheck", DeviceState.PRECHECK, self._do_precheck, cancel_early=True)
            and await self._barrier("clock", DeviceState.CLOCK, self._do_clock, cancel_early=True)
            and await self._barrier(
                "start_capture", DeviceState.STARTING_CAPTURE, self._do_start_capture, cancel_early=False
            )
            and await self._barrier(
                "start_test", DeviceState.STARTING_TEST, self._do_start_test, cancel_early=False
            )
        )

    async def _barrier(
        self,
        phase: str,
        state: DeviceState,
        fn: Callable[[_Device], Awaitable[None]],
        *,
        cancel_early: bool,
    ) -> bool:
        """Run ``fn`` on all devices concurrently; return False if the run must abort.

        A stop request cancels the phase immediately, or skips it if the request came before
        the phase began. With ``cancel_early``, the first device failure also cancels the
        phase, whether in ``fn`` or while the device waits for the others (when its SSH
        connection drops, for example).
        """
        if self._stop.is_set():
            return False
        self._phase = phase
        self._timestamps[phase] = utc_now()
        self._run_log(f"phase: {phase}")
        for d in self._devices:
            self._set_state(d, state)
        # Once its test has started, a device is running; otherwise it waits for the others.
        done_state = DeviceState.RUNNING if phase == "start_test" else DeviceState.WAITING
        tasks = {
            asyncio.create_task(self._guarded(d, phase, fn), name=f"{d.name}-{phase}"): d
            for d in self._devices
        }
        stop_wait = asyncio.create_task(self._stop.wait())
        waiters = {stop_wait}
        if cancel_early:
            waiters.add(asyncio.create_task(self._failed.wait()))
        pending = set(tasks)
        try:
            while pending:
                await asyncio.wait(pending | waiters, return_when=asyncio.FIRST_COMPLETED)
                done = {t for t in pending if t.done()}
                pending -= done
                for t in done:
                    d = tasks[t]
                    if d.failure is None and (pending or done_state is DeviceState.RUNNING):
                        self._set_state(d, done_state, phase)
                failed = any(d.failure for d in self._devices)
                if stop_wait.done() or (cancel_early and failed):
                    if stop_wait.done():
                        self._run_log(f"canceled during {phase}")
                    for t in pending:
                        t.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
                    return False
        finally:
            for w in waiters:
                w.cancel()
            for t in pending:
                t.cancel()
        return not any(d.failure for d in self._devices)

    async def _guarded(self, d: _Device, phase: str, fn: Callable[[_Device], Awaitable[None]]) -> None:
        try:
            await fn(d)
        except asyncio.CancelledError:
            raise
        # Deliberately broad: a bug in a driver must fail only that device, not the whole run.
        except Exception as e:  # noqa: BLE001
            self._fail(d, phase, self._error_message(d, phase, e), not_ready=_is_not_ready(e, phase))

    # -- start phases ------------------------------------------------------------

    async def _do_connect(self, d: _Device) -> None:
        if d.session is not None:
            await d.session.connect()

    async def _do_precheck(self, d: _Device) -> None:
        await d.driver.precheck()

    async def _do_clock(self, d: _Device) -> None:
        sample = await measure_clock(d.driver.clock_sources())
        d.clock = sample
        _report_clock(d, sample, self.config.settings.clock_skew_warning, self._emit)

    async def _do_start_capture(self, d: _Device) -> None:
        d.capture_attempted = True
        d.polling_stats = True
        d.raw_files_dir.mkdir(exist_ok=True)
        await d.driver.start_capture()
        d.log.info("capture started")

    async def _do_start_test(self, d: _Device) -> None:
        await d.driver.start_test()
        d.start_time = utc_now()
        d.start_mono = time.monotonic()
        d.log.info("test started")

    # -- stop sequence -------------------------------------------------------------

    async def _stop_sequence(self, devices: list[_Device], ok_state: DeviceState) -> None:
        """Stop the tests on all devices, then stop the captures once every test has
        stopped, so each trace covers the whole time any device was transmitting.
        Everything else runs per device, which gets its final state when it is done."""
        loop = asyncio.get_running_loop()
        stop_timeout = self.config.settings.stop_timeout
        for d in devices:
            d.stop_deadline = loop.time() + stop_timeout
            self._set_state(d, DeviceState.STOPPING_TEST)
        self._phase = "stop_test"
        self._run_log(f"phase: {self._phase}")
        tasks = {
            asyncio.create_task(self._stop_test_steps(d), name=f"{d.name}-stop_test"): d for d in devices
        }
        pending = set(tasks)
        try:
            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    d = tasks[t]
                    if pending and d.unclean is None:  # a device whose stop failed stays FAILED
                        self._set_state(d, DeviceState.WAITING, "stop_test")
        finally:
            for t in pending:
                t.cancel()
        self._phase = "collect"
        self._run_log(f"phase: {self._phase}")
        await asyncio.gather(*(self._finish_steps(d, ok_state) for d in devices))

    async def _stop_test_steps(self, d: _Device) -> None:
        # Both steps together must finish within stop_timeout after the stop sequence begins.
        await self._stop_step(d, "reconnect", self._do_reconnect)
        await self._stop_step(d, "stop_test", self._do_stop_test, needs_connection=True)

    async def _finish_steps(self, d: _Device, ok_state: DeviceState) -> None:
        # Only collect has a time limit of its own (collect_timeout). The remote commands of
        # the other steps are limited by command_timeout, as in the start phases.
        await self._stop_step(d, "stop_capture", self._do_stop_capture, DeviceState.STOPPING_CAPTURE)
        d.remote_stopped = d.unclean is None
        if d.polling_stats:
            # The final counts, until the merge replaces them with those of <device>.pcap.
            self._update_stats(d)
            d.polling_stats = False
        await self._stop_step(d, "collect", self._do_collect, DeviceState.COLLECTING, needs_connection=True)
        await self._stop_step(d, "merge", self._do_finalize_capture)
        await self._stop_step(d, "cleanup", self._do_cleanup, needs_connection=True)
        if d.session is not None:
            await d.session.close()
        self._finish_device(d, ok_state)

    async def _stop_step(
        self,
        d: _Device,
        name: str,
        fn: Callable[[_Device], Awaitable[None]],
        state: DeviceState | None = None,
        *,
        needs_connection: bool = False,
    ) -> None:
        if state is not None:
            self._set_state(d, state)
        if needs_connection and d.unreachable:
            d.log.warning(f"{name}: skipped (device unreachable)")
            return
        try:
            await fn(d)
        # Deliberately broad: a failing step must not prevent the remaining stop steps.
        except Exception as e:  # noqa: BLE001
            self._stop_error(d, name, self._error_message(d, name, e))

    def _stop_error(self, d: _Device, step: str, message: str) -> None:
        if step in _CLEAN_STOP_STEPS and d.unclean is None:
            d.unclean = DeviceFailure(phase=step, message=message)
        if self._aborted:
            # While the run is aborting, a stop error doesn't fail the device, so it is
            # reported as a warning.
            d.ctx.warn(f"{step}: {message}")
        else:
            self._fail(d, step, message)

    async def _do_reconnect(self, d: _Device) -> None:
        if d.session is None or d.session.connected:
            return
        d.log.info("reconnecting for the stop sequence")
        try:
            await d.session.reconnect(d.stop_deadline)
        except DriverError:
            d.unreachable = True
            raise

    async def _do_stop_test(self, d: _Device) -> None:
        try:
            async with asyncio.timeout_at(d.stop_deadline):
                await d.driver.stop_test()
            d.log.info("test stopped")
        except TimeoutError:
            raise DriverError(f"stop timeout ({self.config.settings.stop_timeout:g} s) exceeded") from None
        finally:
            d.stop_time = utc_now()

    async def _do_stop_capture(self, d: _Device) -> None:
        await d.driver.stop_capture()
        d.log.info("capture stopped")

    async def _do_collect(self, d: _Device) -> None:
        raw_dir = d.raw_files_dir
        raw_dir.mkdir(exist_ok=True)
        timeout = self.config.settings.collect_timeout
        try:
            async with asyncio.timeout(timeout):
                d.collected = await d.driver.collect(raw_dir)
        except TimeoutError:
            raise DriverError(f"collect timeout ({timeout:g} s) exceeded") from None
        d.collect_complete = not d.ctx.download_failed

    async def _do_finalize_capture(self, d: _Device) -> None:
        """Local step: merge the streamed and collected capture files into <device>.pcap."""
        assert self.run_dir is not None
        out = self.run_dir / f"{d.name}.pcap"
        raw_kept = f"raw files kept in {d.raw_files_dir.name}/"
        # Keep the raw files by default, so that a failed or interrupted merge doesn't lose them.
        # keep_raw_files applies only if they contain no data, or if all of their data was merged
        # into <device>.pcap.
        keep_raw = True
        try:
            inputs = d.driver.pcap_files_to_merge(d.collected)
            if not any(_has_data(p) for p in inputs):
                d.ctx.warn("no capture data")
                keep_raw = d.ctx.keep_raw_files
            else:
                try:
                    merged = await asyncio.to_thread(merge_pcaps, inputs, out)
                except (OSError, PcapFormatError) as e:
                    reason = e.strerror if isinstance(e, OSError) and e.strerror else e
                    d.ctx.warn(f"cannot merge capture files: {reason}; {raw_kept}")
                else:
                    keep_raw = d.ctx.keep_raw_files
                    for path, reason in merged.skipped:
                        if _has_data(path):
                            keep_raw = True
                            d.ctx.warn(f"{path.name} not merged: {reason}; {raw_kept}")
                        else:
                            d.ctx.warn(f"{path.name} not merged: {reason}")
                    for path, size in merged.truncated:
                        d.ctx.warn(f"{path.name}: removed truncated last record ({size} bytes)")
                    if merged.clock_backward_jumps:
                        jump = max(j for _, j in merged.clock_backward_jumps)
                        d.ctx.warn(
                            f"the device clock was set back during the capture (timestamps go back "
                            f"{jump:.3f} s); the measured clock offset does not apply after that point"
                        )
                    d.pcap, d.packets = out, merged.packets
                    used = len(inputs) - len(merged.skipped)
                    pktcount = f"{merged.packets} packet{'' if merged.packets == 1 else 's'}"
                    if used == 1:
                        d.log.info(f"capture saved to {out.name} ({pktcount})")
                    else:
                        d.log.info(f"merged {used} capture files into {out.name} ({pktcount})")
            if d.pcap is not None and d.packets == 0:
                d.ctx.warn("capture is empty")
            if d.pcap is not None:
                d.stats = CaptureStats(packets=d.packets, bytes=d.pcap.stat().st_size)
                self._emit(StatsUpdated(d.name, packets=d.packets, bytes=d.stats.bytes))
        finally:
            raw_dir = d.raw_files_dir
            if raw_dir.exists() and not (keep_raw and any(raw_dir.iterdir())):
                shutil.rmtree(raw_dir, ignore_errors=True)

    async def _do_cleanup(self, d: _Device) -> None:
        # Keep the remote files if the test may still be writing them (they also help to
        # find out what went wrong), or if some of them were not downloaded.
        if d.unclean is not None:
            reason = "the device was not stopped cleanly"
        elif not d.collect_complete:
            reason = "not all files were collected"
        else:
            await d.driver.cleanup()
            return
        # Only a driver that overrides cleanup() deletes anything on the device.
        if d.ctx.delete_remote_files and type(d.driver).cleanup is not Driver.cleanup:
            d.ctx.warn(f"remote files kept: {reason}")
        else:
            d.log.info(f"cleanup skipped: {reason}")

    async def _close_sessions(self) -> None:
        await asyncio.gather(*(d.session.close() for d in self._devices if d.session), return_exceptions=True)

    # -- results -----------------------------------------------------------------

    def _outcome(self) -> Outcome:
        if self.interrupted:
            return Outcome.INTERRUPTED
        if self._aborted or self._running_since is None:
            return Outcome.ABORTED
        with_pcap = [d for d in self._devices if d.pcap is not None]
        if not with_pcap:
            return Outcome.FAILED
        if all(d.failure is None and d.pcap is not None for d in self._devices):
            return Outcome.SUCCESS
        return Outcome.PARTIAL

    def _build_manifest(self, outcome: Outcome) -> RunManifest:
        assert self.run_dir is not None
        starts = [d.start_mono for d in self._devices if d.start_mono is not None]
        skew = (max(starts) - min(starts)) if len(starts) == len(self._devices) and starts else None
        actual = round(self.actual_duration, 3) if self.actual_duration is not None else None
        devices = []
        for d in self._devices:
            files = []
            for p in device_files(self.run_dir, d.name):
                with contextlib.suppress(OSError):
                    files.append(file_entry(p, self.run_dir))
            devices.append(
                DeviceManifest(
                    name=d.name,
                    model=d.device.model,
                    role=d.device.role,
                    host=d.device.host,
                    port=d.device.port,
                    state=d.state,
                    failure=d.failure,
                    warnings=list(d.warnings),
                    clock_offset_secs=round(d.clock.offset_s, 6) if d.clock else None,
                    clock_uncertainty_secs=round(d.clock.uncertainty_s, 6) if d.clock else None,
                    clock_resolution=d.clock.resolution if d.clock else None,
                    start_time=iso(d.start_time),
                    stop_time=iso(d.stop_time),
                    packets=d.packets if d.pcap is not None else (d.stats.packets if d.stats else None),
                    bytes=(
                        d.pcap.stat().st_size
                        if d.pcap is not None and d.pcap.exists()
                        else (d.stats.bytes if d.stats else None)
                    ),
                    pcap=d.pcap.name if d.pcap is not None else None,
                    files=files,
                )
            )
        return RunManifest(
            tool_version=__version__,
            name=self.test_name,
            description=self.test_desc,
            config_path=str(self.config.path.resolve()) if self.config.path else None,
            requested_duration_secs=self.duration,
            actual_duration_secs=actual,
            stopped_early=self.stopped_early,
            outcome=outcome,
            timestamps={k: iso(v) for k, v in self._timestamps.items()},
            start_skew_secs=round(skew, 3) if skew is not None else None,
            devices=devices,
        )


# --------------------------------------------------------------------------
# Pre-checks
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CheckResult:
    """The result of the pre-checks on one device."""

    device: str
    state: DeviceState  # final state: DONE, NOT_READY, or FAILED_CLEAN
    _: KW_ONLY
    failure: DeviceFailure | None = None  # why the device is NOT_READY or FAILED_CLEAN
    clock: ClockSample | None = None  # the clock measurement, for DONE
    clock_warning: bool = False  # whether the clock offset exceeds the threshold


async def check_devices(
    config: Config, devices: list[DeviceConfig], on_event: EventSink | None = None
) -> list[CheckResult]:
    """Connect → pre-check → clock check on each device, then disconnect.

    Nothing is started and nothing is written to disk.
    """
    emit = functools.partial(_emit_to, on_event)
    threshold = config.settings.clock_skew_warning

    async def one(device: DeviceConfig) -> CheckResult:
        phase = "setup"
        d: _Device | None = None
        try:
            d = _Device(config, device, emit, None, None)
            phase = "connect"
            emit(DeviceStateChanged(device.name, DeviceState.CONNECTING))
            if d.session is not None:
                await d.session.connect()
            phase = "precheck"
            emit(DeviceStateChanged(device.name, DeviceState.PRECHECK))
            await d.driver.precheck()
            phase = "clock"
            emit(DeviceStateChanged(device.name, DeviceState.CLOCK))
            sample = await measure_clock(d.driver.clock_sources())
            clock_warning = _report_clock(d, sample, threshold, emit)
            d.log.info("pre-checks passed")
            emit(DeviceStateChanged(device.name, DeviceState.DONE))
            return CheckResult(device.name, DeviceState.DONE, clock=sample, clock_warning=clock_warning)
        # Deliberately broad: any failure, expected or a bug, is reported for this device only.
        except Exception as e:
            if not isinstance(e, _EXPECTED_ERRORS):
                log.error("[%s] internal error in %s", device.name, phase, exc_info=e)
            msg = _message(e, device)
            not_ready = _is_not_ready(e, phase)
            state = DeviceState.NOT_READY if not_ready else DeviceState.FAILED_CLEAN
            # d is None if the device could not be set up.
            device_log = d.log if d is not None else DeviceLogger(device.name, emit)
            device_log.error(f"{'NOT READY' if not_ready else 'FAILED'} in {phase}: {msg}")
            emit(DeviceStateChanged(device.name, state, phase=phase, message=msg))
            return CheckResult(device.name, state, failure=DeviceFailure(phase=phase, message=msg))
        finally:
            if d is not None and d.session is not None:
                await d.session.close()

    return list(await asyncio.gather(*(one(dev) for dev in devices)))
