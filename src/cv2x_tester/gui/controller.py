# SPDX-License-Identifier: NIST-Software

"""QObject bridge between the QML UI, the configuration and the engine."""

import asyncio
import collections
import logging
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PySide6.QtCore import Property, QObject, QTimer, QUrl, Signal, Slot
from PySide6.QtGui import QDesktopServices, QFontDatabase, QGuiApplication
from PySide6.QtQml import QmlElement, QmlSingleton

from ..config import (
    Config,
    ConfigConflictError,
    ConfigError,
    ConfigIssue,
    DeviceConfig,
    Settings,
    resolve_output_dir,
    validate_device,
)
from ..drivers import all_drivers, get_driver
from ..events import (
    ClockMeasured,
    DeviceLog,
    DeviceState,
    DeviceStateChanged,
    DeviceWarning,
    Event,
    LogLevel,
    Outcome,
    RunFinished,
    RunState,
    RunStateChanged,
    StatsUpdated,
)
from ..options import OptionSpec
from ..util import MAX_DURATION, format_duration, human_bytes, parse_duration
from .models import READY_TEXT, STATE_TEXT, DeviceTableModel

# Lazy, so that the engine and asyncssh are loaded only when a run or pre-checks start, not
# at startup.
lazy from ..engine import CheckResult, Run, check_devices

log = logging.getLogger(__name__)

QML_IMPORT_NAME = "CV2XTester"
QML_IMPORT_MAJOR_VERSION = 1

TICK_INTERVAL_MS = 250  # refresh of the elapsed time and progress during a run
LOG_LINES_MAX = 2000  # log lines kept per device for the log drawer
OUTCOME_TEXT = {
    Outcome.SUCCESS: "Success",
    Outcome.PARTIAL: "Partial: some devices failed",
    Outcome.FAILED: "Failed: no usable capture",
    Outcome.ABORTED: "Aborted before the test started",
    Outcome.INTERRUPTED: "Interrupted: the stop sequence did not finish",
}
_LOG_PREFIX = {
    LogLevel.INFO: "",
    LogLevel.COMMAND: "",
    LogLevel.STDOUT: "  ",
    LogLevel.STDERR: "  stderr: ",
    LogLevel.WARNING: "WARNING: ",
    LogLevel.ERROR: "ERROR: ",
}
# The settings dialog's keys and the settings they hold, in the order of the dialog's fields.
_SETTINGS_FIELDS = (
    ("outputDir", "output_dir"),
    ("defaultDuration", "default_duration"),
    ("connectTimeout", "connect_timeout"),
    ("commandTimeout", "command_timeout"),
    ("stopTimeout", "stop_timeout"),
    ("collectTimeout", "collect_timeout"),
    ("clockSkewWarning", "clock_skew_warning"),
)


def _local_path(url_or_path: str) -> Path:
    url = QUrl(url_or_path)
    return Path(url.toLocalFile()) if url.isLocalFile() else Path(url_or_path)


def _format_elapsed(elapsed: float, duration: float) -> str:
    return f"{format_duration(elapsed)} / {format_duration(duration)}"


def _prechecks_status(results: list[CheckResult]) -> str:
    """Return the status bar text that summarizes the pre-check ``results``: the number of
    devices if all of them passed, and otherwise the number of devices with each result,
    except the zeros."""
    counts = collections.Counter(r.state for r in results)
    ready = counts[DeviceState.DONE]
    if ready == len(results):
        return f"Pre-checks passed on {ready} device{'' if ready == 1 else 's'}"
    parts = []
    for state in (DeviceState.DONE, DeviceState.NOT_READY, DeviceState.FAILED_CLEAN):
        if counts[state]:
            # The words of the status column, which shows a device that passed as ready.
            text = READY_TEXT if state is DeviceState.DONE else STATE_TEXT[state]
            parts.append(f"{counts[state]} {text.lower()}")
    return "Pre-checks: " + ", ".join(parts)


def _bullets(issues: list[ConfigIssue]) -> str:
    lines = []
    for issue in issues:
        lines.append(f"• {issue.message}:" if issue.details else f"• {issue.message}")
        # One line per detail, indented by about the width of "• ".
        lines += [f"   – {detail}" for detail in issue.details]  # noqa: RUF001
    return "\n".join(lines)


def _from_qml(schema: list[OptionSpec], raw: dict[str, Any]) -> dict[str, Any]:
    """Convert values coming from QML (JS numbers are doubles) to the schema types."""
    out = dict(raw)
    for spec in schema:
        if spec.name not in out:
            continue
        v = out[spec.name]
        if spec.kind == "int" and isinstance(v, float) and v.is_integer():
            out[spec.name] = int(v)
        elif spec.kind == "float" and isinstance(v, int) and not isinstance(v, bool):
            out[spec.name] = float(v)
        elif spec.kind == "list" and isinstance(v, (list, tuple)):
            out[spec.name] = [str(x) for x in v if str(x).strip()]
    return out


def _coerce_options(model_id: str, raw: dict[str, Any]) -> dict[str, Any]:
    """The options of a driver as they come from QML, converted to their schema types."""
    driver = get_driver(model_id)
    return _from_qml(driver.Options.schema(), raw) if driver else dict(raw)


@QmlElement
@QmlSingleton
class Controller(QObject):
    """The GUI's controller, available to QML as the ``Controller`` singleton. ``main()``
    creates the instance and gives it to the QML engine."""

    # State properties changed (title, dirty, run state, ...).
    appStateChanged = Signal()
    # Elapsed time and progress changed: every TICK_INTERVAL_MS during a run, and when the run state changes.
    progressChanged = Signal()

    # A formatted line was added to a device's log.
    logLine = Signal(str, str, arguments=["device", "line"])
    # A device's log was cleared.
    logCleared = Signal(str, arguments=["device"])

    # A run ended, with the summary for the run summary dialog.
    runFinished = Signal(dict, arguments=["summary"])

    # Show an error or information dialog with a title, a summary, and optional details
    # such as a list of problems.
    message = Signal(str, str, str, arguments=["title", "summary", "details"])

    # Opening another config or quitting with unsaved changes: ask whether to save them.
    confirmUnsavedChanges = Signal()
    # Ask for a config file to open (once any unsaved changes are saved or discarded).
    openRequested = Signal()
    # Save with no file open: ask for a file name.
    saveAsRequested = Signal()
    # The file changed on disk since it was loaded: ask before overwriting it.
    saveConflict = Signal()
    # Saving would drop invalid/unknown keys from the config file: ask for confirmation.
    confirmLossySave = Signal(str, str, arguments=["file", "details"])

    # Quit during a run: ask before stopping it.
    confirmQuitDuringRun = Signal()

    def __init__(self, quit_callback: Callable[[], None] | None = None) -> None:
        super().__init__()
        self._model = DeviceTableModel(self, can_edit=lambda: not self._busy())
        self._model.edited.connect(self._mark_dirty)
        self._config = Config()
        self._duration_text = str(self._config.settings.default_duration)
        self._dirty = False
        self._banner = ""
        self._status = ""
        self._run: Run | None = None
        self._run_task: asyncio.Task | None = None
        self._prechecks_task: asyncio.Task | None = None
        self._run_state = RunState.IDLE
        self._logs: collections.defaultdict[str, collections.deque[str]] = collections.defaultdict(
            lambda: collections.deque(maxlen=LOG_LINES_MAX)
        )
        self._quit_pending = False
        self._quit_callback = quit_callback
        self._pending_messages: list[tuple[str, str, str]] = []
        self._pending_save: tuple[bool, Path | None] = (False, None)
        # What to do once the unsaved changes are saved or discarded (open another config, quit).
        self._pending_action: Callable[[], None] | None = None
        self._timer = QTimer(self)
        self._timer.setInterval(TICK_INTERVAL_MS)
        self._timer.timeout.connect(self.progressChanged)
        self._drivers = [{"id": d.model_id, "name": d.display_name} for d in all_drivers()]

    # -- config loading ----------------------------------------------------------

    def load(self, path: Path) -> None:
        """Load ``path`` (or start empty if it does not exist). Problems are queued
        as messages and shown by :meth:`show_pending_messages`."""
        try:
            config = Config.load_or_empty(path)
        except ConfigError as e:
            # Start with an empty config not tied to any file, so saving can't overwrite
            # the rejected file.
            summary = f"{e.path} could not be loaded. An empty configuration was opened instead."
            self._pending_messages.append(("Cannot load configuration", summary, _bullets(e.problems)))
            config = Config()
        self._set_config(config)

    def _set_config(self, config: Config) -> None:
        self._config = config
        self._duration_text = str(config.settings.default_duration)
        self._dirty = False
        self._model.set_devices(config.devices)
        name = config.path.name if config.path else ""
        self._banner = f"{name}: {config.permission_warning}" if config.permission_warning else ""
        if config.skipped:
            self._pending_messages.append(
                (
                    "Configuration warnings",
                    f"The following problems were found while loading {config.path}:",
                    _bullets(config.skipped),
                )
            )
        if config.path is None:
            self._status = ""
        elif config.path.exists():
            self._status = f"Loaded {config.path}"
        else:
            self._status = f"New file {config.path}"
        self.appStateChanged.emit()

    def show_pending_messages(self) -> None:
        for title, summary, details in self._pending_messages:
            self.message.emit(title, summary, details)
        self._pending_messages.clear()

    # -- properties ----------------------------------------------------------------

    def _title(self) -> str:
        name = self._config_name()
        return f"{name}*" if self._dirty else name

    def _config_name(self) -> str:
        return self._config.path.name if self._config.path else ""

    def _is_dirty(self) -> bool:
        return self._dirty

    def _mark_dirty(self) -> None:
        self._dirty = True
        self.appStateChanged.emit()

    def _devices(self) -> DeviceTableModel:
        return self._model

    def _device_names(self) -> list[str]:
        return [d.name for d in self._config.devices]

    def _device_status_texts(self) -> list[str]:
        return [*STATE_TEXT.values(), READY_TEXT]

    def _get_duration_text(self) -> str:
        return self._duration_text

    def _set_duration_text(self, text: str) -> None:
        self._duration_text = text
        self.appStateChanged.emit()

    def _run_state_text(self) -> str:
        return str(self._run_state)

    def _running(self) -> bool:
        return self._run_task is not None and not self._run_task.done()

    def _prechecks_running(self) -> bool:
        return self._prechecks_task is not None and not self._prechecks_task.done()

    def _busy(self) -> bool:
        return self._running() or self._prechecks_running()

    def _quitting(self) -> bool:
        return self._quit_pending

    def _no_devices_reason(self) -> str:
        if not self._config.devices:
            return "No devices configured"
        if not any(d.enabled for d in self._config.devices):
            return "No devices enabled"
        return ""

    def _can_start(self) -> bool:
        return not self._busy() and not self._cannot_start_reason()

    def _cannot_start_reason(self) -> str:
        if self._busy():
            return ""
        return self._no_devices_reason() or self.durationError(self._duration_text)

    def _can_stop(self) -> bool:
        return self._running() and self._run_state in (RunState.PREPARING, RunState.RUNNING)

    def _can_run_prechecks(self) -> bool:
        return not self._busy() and not self._no_devices_reason()

    def _cannot_run_prechecks_reason(self) -> str:
        return "" if self._busy() else self._no_devices_reason()

    def _elapsed_text(self) -> str:
        if self._run is None or self._run_state not in (RunState.RUNNING, RunState.STOPPING):
            return ""
        return _format_elapsed(self._run.elapsed, self._run.duration)

    def _longest_elapsed_text(self) -> str:
        return _format_elapsed(MAX_DURATION, MAX_DURATION)

    def _elapsed_fraction(self) -> float:
        if self._run is None or self._run.duration <= 0:
            return 0.0
        return min(1.0, self._run.elapsed / self._run.duration)

    def _banner_text(self) -> str:
        return self._banner

    def _status_text(self) -> str:
        return self._status

    def _set_status(self, text: str) -> None:
        self._status = text
        self.appStateChanged.emit()

    def _driver_models(self) -> list[dict[str, str]]:
        return self._drivers

    def _settings_schema(self) -> dict[str, dict[str, Any]]:
        return {s.name: s.as_dict() for s in Settings.schema()}

    def _mono_font(self) -> str:
        # Querying the fixed font makes Qt's GTK theme plugin return monospace for every
        # font read afterwards (likely a plugin bug), so use fontconfig's alias instead.
        # Fontconfig is used everywhere except on Windows and macOS, whatever the platform
        # plugin (xcb, wayland, wayland-egl, ...).
        if sys.platform in ("darwin", "win32"):
            return QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont).family()
        return "monospace"

    title = Property(str, _title, notify=appStateChanged)
    configName = Property(str, _config_name, notify=appStateChanged)
    dirty = Property(bool, _is_dirty, notify=appStateChanged)
    devices = Property(QObject, _devices, constant=True)
    deviceNames = Property(list, _device_names, notify=appStateChanged)
    # Every text the device table's status column can show, so QML can size the column for
    # the longest.
    deviceStatusTexts = Property(list, _device_status_texts, constant=True)
    # The test duration as typed in the main window. It is a string rather than a number, so
    # that the field keeps invalid input, which cannotStartReason then explains.
    durationText = Property(str, _get_duration_text, _set_duration_text, notify=appStateChanged)

    runState = Property(str, _run_state_text, notify=appStateChanged)
    running = Property(bool, _running, notify=appStateChanged)
    prechecksRunning = Property(bool, _prechecks_running, notify=appStateChanged)
    busy = Property(bool, _busy, notify=appStateChanged)
    quitting = Property(bool, _quitting, notify=appStateChanged)

    canStart = Property(bool, _can_start, notify=appStateChanged)
    # The reason why a run can't be started (no usable devices or an invalid test duration).
    # Empty when it can, and while a run or pre-checks are in progress.
    cannotStartReason = Property(str, _cannot_start_reason, notify=appStateChanged)
    canStop = Property(bool, _can_stop, notify=appStateChanged)
    canRunPrechecks = Property(bool, _can_run_prechecks, notify=appStateChanged)
    # The reason why pre-checks of the enabled devices can't be started (no usable devices).
    # Empty when they can, and while a run or pre-checks are in progress.
    cannotRunPrechecksReason = Property(str, _cannot_run_prechecks_reason, notify=appStateChanged)

    elapsedText = Property(str, _elapsed_text, notify=progressChanged)
    # The longest elapsed text a run can show, so QML can reserve its width.
    longestElapsedText = Property(str, _longest_elapsed_text, constant=True)
    progress = Property(float, _elapsed_fraction, notify=progressChanged)

    banner = Property(str, _banner_text, notify=appStateChanged)
    statusText = Property(str, _status_text, notify=appStateChanged)

    driverModels = Property(list, _driver_models, constant=True)
    # The schema of each setting (OptionSpec.as_dict()), keyed by name.
    settingsSchema = Property(dict, _settings_schema, constant=True)
    monoFont = Property(str, _mono_font, constant=True)

    # -- running -------------------------------------------------------------------

    @Slot(str, result=str)
    def durationError(self, text: str) -> str:
        try:
            parse_duration(text)
        except ValueError as e:
            return str(e)
        return ""

    @Slot(str, str)
    def start(self, test_name: str, test_desc: str) -> None:
        """Start a run of the enabled devices, for the duration in durationText."""
        if not self._can_start():
            return
        duration = parse_duration(self._duration_text)
        devices = [d for d in self._config.devices if d.enabled]
        self._model.reset_status()
        self._begin_logs({d.name for d in devices}, f"run started {time.strftime('%Y-%m-%d %H:%M:%S')}")
        self._run = Run(
            self._config,
            devices,
            duration=duration,
            test_name=test_name,
            test_desc=test_desc,
            on_event=self._on_event,
        )
        self._run_state = RunState.PREPARING
        self._run_task = asyncio.create_task(self._execute_run(self._run))
        self._run_task.add_done_callback(self._task_done)
        self._set_status("Run in progress…")
        self._timer.start()

    async def _execute_run(self, run: Run) -> None:
        result: RunFinished | None = None
        try:
            result = await run.execute()
        except asyncio.CancelledError:
            pass
        except Exception as e:  # a bug; keep the UI alive
            log.exception("run failed")
            self._set_status("Run failed: internal error")
            self.message.emit(
                "Run failed",
                f"The run stopped because of an internal error: {e}\n\n"
                "Tests or captures may still be running on the devices.",
                "",
            )
        finally:
            self._timer.stop()
            self._run_state = RunState.FINISHED if result else RunState.IDLE
            self.progressChanged.emit()
            self.appStateChanged.emit()
        if result is not None:
            self._set_status(f"Run finished: {result.outcome}")
            if not self._quit_pending:
                self.runFinished.emit(self._summary(result))

    def _summary(self, result: RunFinished) -> dict[str, Any]:
        m = result.manifest
        manifest_devices = m.devices if m else []
        devices = []
        for d in manifest_devices:
            devices.append(
                {
                    "name": d.name,
                    "stateText": STATE_TEXT[d.state],
                    "stateId": str(d.state),
                    "pcap": d.pcap or "",
                    "pcapPath": str(result.run_dir / d.pcap) if d.pcap and result.run_dir else "",
                    "pcapSize": human_bytes(d.bytes) if d.pcap else "",
                    "packets": "" if d.packets is None or not d.pcap else f"{d.packets:,}",
                    "problems": "\n".join(
                        ([f"{d.failure.phase}: {d.failure.message}"] if d.failure else []) + d.warnings
                    ),
                }
            )
        actual = m.actual_duration_secs if m else None
        skew = m.start_skew_secs if m else None
        return {
            "outcome": str(result.outcome),
            "outcomeText": OUTCOME_TEXT[result.outcome],
            "runDir": str(result.run_dir or ""),
            "error": result.error or "",
            "duration": format_duration(round(actual)) if actual is not None else "—",
            "stoppedEarly": bool(m and m.stopped_early),
            "startSkew": "" if skew is None else f"{skew:.3f} s",
            "devices": devices,
            "uncleanDevices": [d.name for d in manifest_devices if d.state is DeviceState.FAILED_UNCLEAN],
        }

    @Slot()
    def stop(self) -> None:
        if self._run is not None and self._can_stop():
            self._run.request_stop()
            self._set_status("Stopping…")

    # -- pre-checks -------------------------------------------------------------------

    @Slot("QVariantList")
    def runPrechecks(self, names: list[str]) -> None:
        if self._busy():
            return
        wanted = set(names)
        devices = [d for d in self._config.devices if ((d.name in wanted) if wanted else d.enabled)]
        if not devices:
            self.message.emit("Run pre-checks", "No valid devices are selected.", "")
            return
        names_set = {d.name for d in devices}
        self._model.reset_status(names_set, prechecks=True)
        self._begin_logs(names_set, f"pre-checks started {time.strftime('%Y-%m-%d %H:%M:%S')}")
        self._prechecks_task = asyncio.create_task(self._execute_prechecks(devices))
        self._prechecks_task.add_done_callback(self._task_done)
        self._set_status("Pre-checks in progress…")

    async def _execute_prechecks(self, devices: list[DeviceConfig]) -> None:
        try:
            results = await check_devices(self._config, devices, self._on_event)
        except asyncio.CancelledError:
            results = []
        except Exception as e:  # a bug; keep the UI alive
            log.exception("pre-checks failed")
            results = []
            self._set_status("Pre-checks failed: internal error")
            self.message.emit(
                "Pre-checks failed", f"The pre-checks stopped because of an internal error: {e}", ""
            )
        finally:
            self.appStateChanged.emit()
        if results:
            self._set_status(_prechecks_status(results))

    def _task_done(self, _task: asyncio.Task) -> None:
        """Refresh the UI and resume a pending quit once a run or pre-checks task is done.

        The task's coroutine also emits appStateChanged at its end, but the task isn't done yet
        at that point, so the controller still counts as busy. Only here is it no longer busy.
        """
        self.appStateChanged.emit()
        if self._quit_pending:
            self._continue_quit()

    # -- engine events -------------------------------------------------------------------

    def _on_event(self, ev: Event) -> None:
        match ev:
            case DeviceStateChanged(device=name, state=state, phase=phase, message=msg):
                changes: dict[str, Any] = {"state": state, "phase": phase or ""}
                if msg:
                    changes["failure"] = f"{phase}: {msg}" if phase else msg
                self._model.update(name, **changes)
            case DeviceLog(device=name, level=level, line=line, timestamp=ts):
                self._append_log(name, f"{ts}  {_LOG_PREFIX[level]}{line}")
            case DeviceWarning(device=name, message=msg):
                self._model.add_warning(name, msg)
            case StatsUpdated(device=name, packets=packets, bytes=nbytes):
                self._model.update(name, packets=packets, bytes=nbytes)
            case ClockMeasured(
                device=name, offset_s=off, uncertainty_s=unc, resolution=res, exceeds_threshold=warn
            ):
                self._model.update(
                    name, clock_offset=off, clock_uncertainty=unc, clock_resolution=res, clock_warn=warn
                )
            case RunStateChanged(state=state):
                self._run_state = state
                self.appStateChanged.emit()
                self.progressChanged.emit()

    # -- logs ---------------------------------------------------------------------------

    def _begin_logs(self, names: set[str], title: str) -> None:
        for name in names:
            self._append_log(name, f"──── {title} ────")

    def _append_log(self, name: str, line: str) -> None:
        self._logs[name].append(line)
        self.logLine.emit(name, line)

    @Slot(str, result=str)
    def logText(self, name: str) -> str:
        return "\n".join(self._logs.get(name, ()))

    @Slot(str)
    def clearLog(self, name: str) -> None:
        self._logs.pop(name, None)
        self.logCleared.emit(name)

    @Slot(str)
    def copyLog(self, name: str) -> None:
        QGuiApplication.clipboard().setText(self.logText(name))

    # -- device editing -------------------------------------------------------------------

    @Slot(str, result="QVariantMap")
    def driverInfo(self, model_id: str) -> dict[str, Any]:
        driver = get_driver(model_id)
        if driver is None:
            return {
                "known": False,
                "schema": [],
                "options": {},
                "username": "",
                "password": "",
                "usesSsh": True,
            }
        defaults = driver.Options().to_mapping()
        return {
            "known": True,
            "schema": [s.as_dict() for s in driver.Options.schema()],
            "options": defaults,
            "username": driver.default_username or "",
            "password": driver.default_password or "",
            "usesSsh": driver.uses_ssh,
        }

    def _data_of(self, dev: DeviceConfig) -> dict[str, Any]:
        return {
            "name": dev.name,
            "model": dev.model,
            "role": dev.role,
            "host": dev.host,
            "port": dev.port,
            "username": dev.username,
            "password": dev.password or "",
            "keyFile": dev.key_file or "",
            "keyPassphrase": dev.key_passphrase or "",
            "options": dev.driver_options().to_mapping(),
        }

    @Slot(result="QVariantMap")
    def newDeviceData(self) -> dict[str, Any]:
        model_id = self._drivers[0]["id"] if self._drivers else ""
        info = self.driverInfo(model_id)
        return {
            "name": "",
            "model": model_id,
            "role": "obu",
            "host": "",
            "port": 22,
            "username": info["username"],
            "password": info["password"],
            "keyFile": "",
            "keyPassphrase": "",
            "options": info["options"],
        }

    @Slot(int, result="QVariantMap")
    def deviceData(self, row: int) -> dict[str, Any]:
        dev = self._model.device(row)
        return self._data_of(dev) if dev else {}

    @Slot(int, result="QVariantMap")
    def duplicateData(self, row: int) -> dict[str, Any]:
        dev = self._model.device(row)
        if dev is None:
            return {}
        data = self._data_of(dev)
        data["name"] = self._unique_name(f"{dev.name}_copy")
        return data

    def _unique_name(self, base: str) -> str:
        names = {d.name for d in self._config.devices}
        if base not in names:
            return base
        n = 2
        while f"{base}_{n}" in names:
            n += 1
        return f"{base}_{n}"

    def _device_from_data(self, data: dict[str, Any]) -> DeviceConfig:
        model = data["model"]
        return DeviceConfig(
            name=data["name"].strip(),
            model=model,
            role=data["role"],
            host=data["host"].strip(),
            port=data["port"],
            username=data["username"].strip(),
            password=data["password"] or None,
            key_file=data["keyFile"].strip() or None,
            key_passphrase=data["keyPassphrase"] or None,
            options=_coerce_options(model, data["options"]),
        )

    @Slot("QVariantMap", int, result="QVariantMap")
    def validateDevice(self, data: dict[str, Any], row: int) -> dict[str, str]:
        dev = self._device_from_data(data)
        others = [d for i, d in enumerate(self._config.devices) if i != row]
        return validate_device(dev, others)

    @Slot("QVariantMap", int, result=bool)
    def applyDevice(self, data: dict[str, Any], row: int) -> bool:
        if self._busy() or self.validateDevice(data, row):
            return False
        dev = self._device_from_data(data)
        old = self._model.device(row) if row >= 0 else None
        if old is not None:
            # Fields not shown in the dialog are carried over.
            dev.enabled = old.enabled
            dev.keep_raw_files = old.keep_raw_files
            dev.delete_remote_files = old.delete_remote_files
            self._config.devices[row] = dev
            self._model.replace(row, dev)
            if old.name != dev.name and old.name in self._logs:
                self._logs[dev.name] = self._logs.pop(old.name)
        else:
            self._config.devices.append(dev)
            self._model.append(dev)
        self._mark_dirty()
        return True

    @Slot(int)
    def removeDevice(self, row: int) -> None:
        dev = self._model.device(row)
        if dev is None or self._busy():
            return
        del self._config.devices[row]
        self._model.remove(row)
        self._logs.pop(dev.name, None)
        self._mark_dirty()

    # -- settings ---------------------------------------------------------------------

    @Slot(result="QVariantMap")
    def settingsData(self) -> dict[str, Any]:
        s = self._config.settings
        data = {key: getattr(s, name) for key, name in _SETTINGS_FIELDS}
        # The dialog edits the default duration as text.
        data["defaultDuration"] = str(s.default_duration)
        return data

    @Slot(str, result=str)
    def resolveOutputDir(self, text: str) -> str:
        """Return the absolute path that the output directory typed in the settings dialog
        resolves to, or an empty string if the text isn't a valid output directory."""
        try:
            output_dir = Settings.check("output_dir", text.strip())
        except ValueError:
            return ""
        return str(resolve_output_dir(output_dir))

    @staticmethod
    def _parse_settings(data: dict[str, Any]) -> dict[str, Any]:
        """Convert the settings dialog's values to Settings fields. Raises ValueError with a
        message for the user about the first invalid field."""
        specs = {s.name: s for s in Settings.schema()}
        raw = _from_qml(list(specs.values()), {name: data.get(key) for key, name in _SETTINGS_FIELDS})
        values = {}
        for _, name in _SETTINGS_FIELDS:
            value = raw[name]
            try:
                if name == "default_duration":
                    # parse_duration() checks the option's limits.
                    values[name] = parse_duration(str(value or ""))
                elif name == "output_dir":
                    values[name] = Settings.check(name, str(value or "").strip())
                else:
                    values[name] = Settings.check(name, value)
            except ValueError as e:
                raise ValueError(f"{specs[name].label}: {e}") from None
        return values

    @Slot("QVariantMap", result=str)
    def settingsError(self, data: dict[str, Any]) -> str:
        """The first problem with the settings dialog's values, or an empty string if they are valid."""
        try:
            self._parse_settings(data)
        except ValueError as e:
            return str(e)
        return ""

    @Slot("QVariantMap", result=str)
    def applySettings(self, data: dict[str, Any]) -> str:
        if self._busy():
            return "Settings cannot be changed while a test is active."
        try:
            new = self._parse_settings(data)
        except ValueError as e:
            return str(e)
        s = self._config.settings
        if any(getattr(s, k) != v for k, v in new.items()):
            if new["default_duration"] != s.default_duration:
                self._duration_text = str(new["default_duration"])
            for k, v in new.items():
                setattr(s, k, v)
            self._mark_dirty()
        return ""

    # -- files -------------------------------------------------------------------------

    @Slot()
    def requestOpen(self) -> None:
        """File → Open: ask for a file, after handling any unsaved changes."""
        if not self._busy():
            self._confirm_unsaved(self.openRequested.emit)

    @Slot(str)
    def openConfig(self, url: str) -> None:
        if self._busy():
            return
        path = _local_path(url)
        try:
            config = Config.load(path)
        except ConfigError as e:
            summary = f"{e.path} could not be opened. The current configuration was kept."
            self.message.emit("Cannot open configuration", summary, _bullets(e.problems))
            return
        self._logs.clear()
        self._set_config(config)
        self.show_pending_messages()

    @Slot()
    def save(self) -> None:
        self._save(force=False)

    @Slot(str)
    def saveAs(self, url: str) -> None:
        path = _local_path(url)
        if path.suffix == "":
            path = path.with_suffix(".toml")
        self._save(force=True, path=path)

    @Slot()
    def saveOverwrite(self) -> None:
        self._save(force=True)

    @Slot()
    def saveLossy(self) -> None:
        """Save the configuration after the user has confirmed that the entries skipped or ignored
        at load time may be removed from the file. The confirmation remains valid for subsequent
        saves, even if this save fails or is canceled."""
        self._config.skipped = []
        force, path = self._pending_save
        self._save(force=force, path=path)

    def _save(self, *, force: bool, path: Path | None = None) -> bool:
        target = path if path is not None else self._config.path
        if target is None:
            self.saveAsRequested.emit()
            return False
        if self._config.skipped and self._config.is_loaded_file(target):
            self._pending_save = (force, path)
            self.confirmLossySave.emit(str(target), _bullets(self._config.skipped))
            return False
        try:
            self._config.save(target, force=force)
        except ConfigConflictError:
            self.saveConflict.emit()
            return False
        except OSError as e:
            self._pending_action = None
            self.message.emit(
                "Cannot save configuration", f"{target} could not be saved: {e.strerror or e}.", ""
            )
            return False
        self._dirty = False
        self._set_status(f"Saved {target}")
        self._run_pending_action()
        return True

    @Slot(str, result=str)
    def localPath(self, url: str) -> str:
        return str(_local_path(url))

    @Slot(str)
    def openPath(self, path: str) -> None:
        """Open a file or folder with the desktop's default application."""
        if path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    @Slot()
    def dismissBanner(self) -> None:
        self._banner = ""
        self.appStateChanged.emit()

    # -- quitting ----------------------------------------------------------------------

    @Slot()
    def requestQuit(self) -> None:
        """Window close / File → Quit."""
        if self._quit_pending:
            return
        if self._running():
            self.confirmQuitDuringRun.emit()
        else:
            self._confirm_unsaved(self._quit)

    @Slot()
    def quitAfterStop(self) -> None:
        """User confirmed quitting during a run: stop gracefully, then quit."""
        self._quit_pending = True
        self.appStateChanged.emit()
        if self._run is not None and self._running():
            self._run.request_stop()
        elif self._prechecks_task is not None and self._prechecks_running():
            self._prechecks_task.cancel()
        else:
            self._continue_quit()

    @Slot()
    def forceQuit(self) -> None:
        """Skip the remaining stop work."""
        for task in (self._run_task, self._prechecks_task):
            if task is not None and not task.done():
                task.cancel()
        self._quit()

    def _continue_quit(self) -> None:
        if self._busy():
            return
        self._quit_pending = False
        self.appStateChanged.emit()
        self._confirm_unsaved(self._quit)

    # -- unsaved changes ---------------------------------------------------------------

    def _confirm_unsaved(self, action: Callable[[], None]) -> None:
        """Run ``action`` now, or once the user has saved or discarded the unsaved changes."""
        if not self._dirty:
            action()
            return
        self._pending_action = action
        self.confirmUnsavedChanges.emit()

    @Slot()
    def saveAndContinue(self) -> None:
        """Unsaved-changes prompt → Save: the pending action runs once the save succeeds,
        possibly after a Save As or a confirmation (QML calls cancelPending if those are
        canceled)."""
        self._save(force=False)

    @Slot()
    def discardAndContinue(self) -> None:
        self._run_pending_action()

    @Slot()
    def cancelPending(self) -> None:
        self._pending_action = None

    def _run_pending_action(self) -> None:
        action, self._pending_action = self._pending_action, None
        if action is not None:
            action()

    def _quit(self) -> None:
        if self._prechecks_running() and self._prechecks_task is not None:
            self._prechecks_task.cancel()
        if self._quit_callback is not None:
            self._quit_callback()
