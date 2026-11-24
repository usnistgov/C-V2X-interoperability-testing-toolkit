# SPDX-License-Identifier: NIST-Software

from pathlib import Path

import pytest
from conftest import mock_config, mock_device
from PySide6.QtCore import Qt, QUrl

from cv2x_tester.engine import CheckResult, Run
from cv2x_tester.events import DeviceState, Outcome, RunFinished
from cv2x_tester.gui.controller import OUTCOME_TEXT, Controller, _prechecks_status

CONFIG = """\
[[devices]]
name = "obu1"
model = "mock"
role = "obu"
username = "demo"
"""


class Harness:
    """Controller with a modified config, recording the signals of the unsaved-changes flow."""

    def __init__(self, path: Path | None) -> None:
        self.quits = 0
        self.ctl = Controller(quit_callback=self._quit)
        if path is not None:
            path.write_text(CONFIG)
            self.ctl.load(path)
        else:
            self.ctl.applyDevice(
                self.ctl.newDeviceData() | {"name": "obu1", "model": "mock", "host": "x"}, -1
            )
        self.events: list[str] = []
        for name in ("confirmUnsavedChanges", "openRequested", "saveAsRequested", "message"):
            getattr(self.ctl, name).connect(lambda *_, name=name: self.events.append(name))
        devices = self.ctl.property("devices")
        devices.setData(devices.index(0, 0), Qt.CheckState.Unchecked, Qt.ItemDataRole.CheckStateRole)
        assert self.ctl.property("dirty")

    def _quit(self) -> None:
        self.quits += 1


def test_load_shows_the_file_in_the_status_bar(tmp_path):
    existing = tmp_path / "c.toml"
    existing.write_text(CONFIG)
    new = tmp_path / "new.toml"
    ctl = Controller()
    ctl.load(existing)
    assert ctl.property("statusText") == f"Loaded {existing}"
    ctl.load(new)
    assert ctl.property("statusText") == f"New file {new}"
    assert ctl.property("title") == "new.toml"


def test_open_and_quit_do_not_prompt_when_saved(tmp_path):
    h = Harness(tmp_path / "c.toml")
    h.ctl.save()
    h.ctl.requestOpen()
    h.ctl.requestQuit()
    assert h.events == ["openRequested"]
    assert h.quits == 1


def test_discard_runs_the_pending_action(tmp_path):
    h = Harness(tmp_path / "c.toml")
    h.ctl.requestQuit()
    assert (h.events, h.quits) == (["confirmUnsavedChanges"], 0)
    h.ctl.discardAndContinue()
    assert h.quits == 1
    assert "enabled" not in (tmp_path / "c.toml").read_text()  # not saved


def test_save_then_open(tmp_path):
    h = Harness(tmp_path / "c.toml")
    h.ctl.requestOpen()
    h.ctl.saveAndContinue()
    assert h.events == ["confirmUnsavedChanges", "openRequested"]
    assert "enabled = false" in (tmp_path / "c.toml").read_text()


def test_save_as_then_quit(tmp_path):
    h = Harness(None)  # not bound to a file: saving asks for a name first
    h.ctl.requestQuit()
    h.ctl.saveAndContinue()
    assert (h.events, h.quits) == (["confirmUnsavedChanges", "saveAsRequested"], 0)
    h.ctl.saveAs(QUrl.fromLocalFile(str(tmp_path / "new.toml")).toString())
    assert h.quits == 1
    assert (tmp_path / "new.toml").exists()


def test_cancel_forgets_the_pending_action(tmp_path):
    h = Harness(None)
    h.ctl.requestQuit()
    h.ctl.saveAndContinue()
    h.ctl.cancelPending()  # Save As dialog canceled
    h.ctl.saveAs(QUrl.fromLocalFile(str(tmp_path / "new.toml")).toString())  # a later, unrelated save
    assert h.quits == 0


def test_failed_save_forgets_the_pending_action(tmp_path):
    h = Harness(None)
    h.ctl.requestQuit()
    h.ctl.saveAndContinue()
    (tmp_path / "file").write_text("")
    h.ctl.saveAs(QUrl.fromLocalFile(str(tmp_path / "file" / "new.toml")).toString())  # not a directory
    assert h.events[-1] == "message"  # "Cannot save configuration"
    h.ctl.saveAs(QUrl.fromLocalFile(str(tmp_path / "new.toml")).toString())
    assert h.quits == 0


def test_save_error_names_the_configuration_file(tmp_path):
    target = tmp_path / "cfg.toml"
    target.mkdir()  # the final rename of the temporary file fails
    ctl = Controller(quit_callback=lambda: None)
    summaries = []
    ctl.message.connect(lambda _title, summary, _details: summaries.append(summary))
    ctl.saveAs(QUrl.fromLocalFile(str(target)).toString())
    assert len(summaries) == 1
    assert summaries[0].startswith(f"{target} could not be saved: ")
    assert ".tmp" not in summaries[0]


def test_config_warnings_list_each_problem_of_a_device(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text(CONFIG + '\n[[devices]]\nname = "bad"\nmodel = "mock"\nrole = "car"\nport = 0\n')
    ctl = Controller(quit_callback=lambda: None)
    messages = []
    ctl.message.connect(lambda *args: messages.append(args))
    ctl.load(path)
    ctl.show_pending_messages()
    assert messages[0][2] == (
        "• device 'bad' skipped:\n"
        "   – field 'role': expected 'obu' or 'rsu'\n"  # noqa: RUF001
        "   – field 'port': expected an integer between 1 and 65535"  # noqa: RUF001
    )


def test_device_dialog_reports_a_missing_required_option():
    ctl = Controller(quit_callback=lambda: None)
    data = ctl.newDeviceData() | {"name": "pi", "model": "generic-linux", "host": "x", "username": "u"}
    assert ctl.validateDevice(data | {"options": {"interface": "", "filter": "udp"}}, -1) == {
        "options.interface": "required"
    }
    assert ctl.validateDevice(data | {"options": {"filter": "udp"}}, -1) == {"options.interface": "required"}
    assert ctl.validateDevice(data | {"options": {"interface": "eth0"}}, -1) == {}


def test_settings_dialog_sets_the_collect_timeout():
    ctl = Controller(quit_callback=lambda: None)
    data = ctl.settingsData()
    assert data["collectTimeout"] == 300
    assert ctl.settingsError(data | {"collectTimeout": 0}) == (
        "Collect timeout: expected an integer between 1 and 86400"
    )
    assert ctl.applySettings(data | {"collectTimeout": 120}) == ""
    assert ctl._config.settings.collect_timeout == 120
    assert ctl.dirty


def test_test_duration_is_reset_to_a_new_default(tmp_path):
    ctl = Controller(quit_callback=lambda: None)
    ctl.setProperty("durationText", "5")
    data = ctl.settingsData()
    assert ctl.applySettings(data | {"collectTimeout": 120}) == ""
    assert ctl.property("durationText") == "5"
    assert ctl.applySettings(data | {"defaultDuration": "1m30s"}) == ""
    assert ctl.property("durationText") == "90"
    ctl.setProperty("durationText", "5")
    path = tmp_path / "c.toml"
    path.write_text(CONFIG)
    ctl.load(path)
    assert ctl.property("durationText") == "60"


def test_start_and_prechecks_say_why_they_are_disabled():
    ctl = Controller(quit_callback=lambda: None)

    def state() -> tuple[object, ...]:
        names = ("canStart", "cannotStartReason", "canRunPrechecks", "cannotRunPrechecksReason")
        return tuple(ctl.property(name) for name in names)

    assert state() == (False, "No devices configured", False, "No devices configured")
    ctl.applyDevice(ctl.newDeviceData() | {"name": "obu1", "model": "mock", "host": "x"}, -1)
    assert state() == (True, "", True, "")
    ctl.setProperty("durationText", "0")
    assert state() == (False, ctl.durationError("0"), True, "")
    devices = ctl.property("devices")
    devices.setData(devices.index(0, 0), Qt.CheckState.Unchecked, Qt.ItemDataRole.CheckStateRole)
    assert state() == (False, "No devices enabled", False, "No devices enabled")


async def test_start_uses_the_test_duration_and_stop_cancels(tmp_path):
    ctl = Controller(quit_callback=lambda: None)
    ctl.start("", "")
    assert not ctl.property("running")  # no devices
    ctl._set_config(mock_config(tmp_path, mock_device("obu1")))
    ctl.setProperty("durationText", "1:30")
    ctl.start("", "")
    assert ctl._run is not None
    assert ctl._run.duration == 90
    assert ctl.property("canStop")
    assert not ctl.property("canStart")
    assert ctl.property("cannotStartReason") == ""  # nothing to explain during a run
    ctl.stop()
    assert ctl._run_task is not None
    await ctl._run_task
    assert not ctl.property("running")
    assert not ctl.property("canStop")
    assert ctl.property("canStart")


async def test_run_reports_an_internal_error(tmp_path, monkeypatch):
    async def broken(self):
        raise RuntimeError("engine bug")

    monkeypatch.setattr(Run, "execute", broken)
    ctl = Controller(quit_callback=lambda: None)
    messages = []
    ctl.message.connect(lambda *args: messages.append(args))
    ctl._set_config(mock_config(tmp_path, mock_device("obu1")))
    ctl.start("", "")
    assert ctl._run_task is not None
    await ctl._run_task
    [(title, summary, details)] = messages
    assert title == "Run failed"
    assert summary == (
        "The run stopped because of an internal error: engine bug\n\n"
        "Tests or captures may still be running on the devices."
    )
    assert details == ""
    assert ctl.property("statusText") == "Run failed: internal error"
    assert not ctl.property("running")
    assert ctl.property("canStart")


async def test_prechecks_report_an_internal_error(tmp_path, monkeypatch):
    async def broken(*args):
        raise RuntimeError("engine bug")

    monkeypatch.setattr("cv2x_tester.gui.controller.check_devices", broken)
    ctl = Controller(quit_callback=lambda: None)
    messages = []
    ctl.message.connect(lambda *args: messages.append(args))
    ctl._set_config(mock_config(tmp_path, mock_device("obu1")))
    ctl.runPrechecks([])
    assert ctl._prechecks_task is not None
    await ctl._prechecks_task
    [(title, summary, details)] = messages
    assert title == "Pre-checks failed"
    assert summary == "The pre-checks stopped because of an internal error: engine bug"
    assert details == ""
    assert ctl.property("statusText") == "Pre-checks failed: internal error"
    assert ctl.property("canRunPrechecks")


async def test_prechecks_status_counts_each_result(tmp_path):
    ctl = Controller(quit_callback=lambda: None)
    devices = [mock_device("a"), mock_device("b", not_ready=True), mock_device("c", fail_phase="precheck")]
    ctl._set_config(mock_config(tmp_path, *devices))
    ctl.runPrechecks([])
    assert ctl._prechecks_task is not None
    await ctl._prechecks_task
    assert ctl.property("statusText") == "Pre-checks: 1 ready, 1 not ready, 1 failed"


@pytest.mark.parametrize(
    ("results", "text"),
    [
        ("+", "Pre-checks passed on 1 device"),
        ("+++", "Pre-checks passed on 3 devices"),
        ("++~", "Pre-checks: 2 ready, 1 not ready"),
        ("+--", "Pre-checks: 1 ready, 2 failed"),
        ("~-", "Pre-checks: 1 not ready, 1 failed"),
        ("~", "Pre-checks: 1 not ready"),
    ],
)
def test_prechecks_status_leaves_out_zero_counts(results, text):
    states = {"+": DeviceState.DONE, "~": DeviceState.NOT_READY, "-": DeviceState.FAILED_CLEAN}
    checks = [CheckResult(f"d{i}", states[r]) for i, r in enumerate(results)]
    assert _prechecks_status(checks) == text


def test_settings_dialog_resolves_the_output_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ctl = Controller(quit_callback=lambda: None)
    assert ctl.resolveOutputDir(" runs ") == str(tmp_path / "runs")
    assert ctl.resolveOutputDir("~/runs") == str(Path.home() / "runs")
    assert ctl.resolveOutputDir(str(tmp_path / "abs")) == str(tmp_path / "abs")
    assert ctl.resolveOutputDir(" ") == ""
    assert ctl.resolveOutputDir("~no-such-user/runs") == ""
    data = ctl.settingsData()
    assert ctl.settingsError(data | {"outputDir": "~no-such-user/runs"}) == (
        "Output directory: home directory '~no-such-user' not found"
    )


def test_settings_dialog_reports_the_first_invalid_field():
    ctl = Controller(quit_callback=lambda: None)
    data = ctl.settingsData()
    error = ctl.settingsError
    assert error(data | {"clockSkewWarning": 0.0001}) == "Clock skew warning: expected at most 3 decimals"
    assert error(data | {"clockSkewWarning": 0.001}) == ""
    assert error(data | {"outputDir": " ", "defaultDuration": "0"}) == "Output directory: required"
    assert (
        error(data | {"defaultDuration": "0"})
        == "Default test duration: duration must be between 1 s and 24 h"
    )
    schema = ctl.property("settingsSchema")
    assert (schema["connect_timeout"]["min"], schema["connect_timeout"]["max"]) == (1, 86400)
    assert schema["clock_skew_warning"]["decimals"] == 3


async def test_run_summary(tmp_path):
    ok, bad = mock_device("ok"), mock_device("bad", fail_phase="stop_test")
    result = await Run(mock_config(tmp_path, ok, bad), [ok, bad], duration=0.3).execute()
    assert result.run_dir is not None
    summary = Controller(quit_callback=lambda: None)._summary(result)
    assert summary["outcome"] == "partial"
    assert summary["outcomeText"] == OUTCOME_TEXT[Outcome.PARTIAL]
    assert summary["runDir"] == str(result.run_dir)
    assert summary["error"] == ""
    assert summary["duration"] == "00:00"
    assert not summary["stoppedEarly"]
    assert summary["startSkew"].endswith(" s")
    assert summary["uncleanDevices"] == ["bad"]
    ok_s, bad_s = summary["devices"]
    assert (ok_s["name"], ok_s["stateText"], ok_s["stateId"], ok_s["problems"]) == ("ok", "Done", "done", "")
    assert (ok_s["pcap"], ok_s["pcapPath"]) == ("ok.pcap", str(result.run_dir / "ok.pcap"))
    assert ok_s["pcapSize"].endswith("B")
    assert ok_s["packets"].isdigit()
    assert (bad_s["stateText"], bad_s["stateId"]) == ("Failed (unclean)", "failed_unclean")
    assert bad_s["problems"] == "stop_test: simulated failure in stop_test"


def test_run_summary_when_the_run_could_not_start():
    result = RunFinished(Outcome.ABORTED, run_dir=None, error="cannot create run folder")
    assert Controller(quit_callback=lambda: None)._summary(result) == {
        "outcome": "aborted",
        "outcomeText": OUTCOME_TEXT[Outcome.ABORTED],
        "runDir": "",
        "error": "cannot create run folder",
        "duration": "—",
        "stoppedEarly": False,
        "startSkew": "",
        "devices": [],
        "uncleanDevices": [],
    }
