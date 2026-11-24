# SPDX-License-Identifier: NIST-Software

import json
import os
import re
import signal
from pathlib import Path
from typing import Any

import pytest

from cv2x_tester import cli
from cv2x_tester.cli import _Reporter, main
from cv2x_tester.drivers import all_drivers
from cv2x_tester.events import (
    ClockMeasured,
    DeviceLog,
    DeviceState,
    DeviceStateChanged,
    LogLevel,
    RunState,
    RunStateChanged,
)

TIMESTAMP = r"\d{2}:\d{2}:\d{2}\.\d{3}"


def config_file(tmp_path: Path, devices: dict[str, dict[str, object]]) -> Path:
    """Write a config with mock devices; ``devices`` maps each name to its options."""
    lines = [f"output_dir = {json.dumps(str(tmp_path / 'results'))}"]
    for name, options in devices.items():
        lines += ["", "[[devices]]", f'name = "{name}"', 'model = "mock"', "", "[devices.options]"]
        lines += [f"{key} = {json.dumps(value)}" for key, value in {"step_delay_ms": 10, **options}.items()]
    path = tmp_path / "config.toml"
    path.write_text("\n".join(lines) + "\n")
    return path


def normalize(text: str, tmp_path: Path) -> str:
    """Replace the parts of the output that change from run to run."""
    text = text.replace(str(tmp_path), "<tmp>")
    text = re.sub(r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}", "<run>", text)
    text = re.sub(r"±\d+\.\d{3} s", "±<unc>", text)
    text = re.sub(r" +\d+(?:\.\d)? (?:B|kB|MB|GB)   \d[\d,]* packets?", " <size>   <n> packets", text)
    return text


def run_cli(capsys: pytest.CaptureFixture[str], tmp_path: Path, *args: str) -> tuple[int, str, str]:
    code = main(list(args))
    out, err = capsys.readouterr()
    return code, normalize(out, tmp_path), normalize(err, tmp_path)


# ---------------------------------------------------------------------------
# Progress lines
# ---------------------------------------------------------------------------


def test_reporter_without_device_log(capsys):
    report = _Reporter(show_logs=False, timestamps=False)
    report(DeviceStateChanged("a", DeviceState.PRECHECK))
    report(DeviceStateChanged("a", DeviceState.WAITING, phase="precheck"))
    report(DeviceStateChanged("a", DeviceState.FAILED, phase="running", message="stream ended"))
    report(DeviceStateChanged("a", DeviceState.FAILED_CLEAN, phase="running", message="stream ended"))
    report(
        ClockMeasured("a", offset_s=-0.00004, uncertainty_s=0.01, resolution="ns", exceeds_threshold=False)
    )
    report(DeviceLog("a", LogLevel.INFO, "not shown", "12:34:56.789"))
    assert capsys.readouterr().out.splitlines() == [
        "[a] precheck",
        "[a] waiting (precheck successful)",
        "[a] FAILED in running: stream ended",
        "[a] failed_clean",  # the message was already printed
        "[a] clock offset +0.000 s (±0.010 s)",
    ]


def test_reporter_with_device_log(capsys):
    report = _Reporter(show_logs=True, timestamps=False)
    report(DeviceLog("a", LogLevel.COMMAND, "$ commsignia-device-info", "12:34:56.789"))
    report(DeviceLog("a", LogLevel.STDOUT, "Firmware: 1.2.3", "12:34:56.789"))
    report(DeviceLog("a", LogLevel.STDERR, "a warning", "12:34:56.789"))
    report(DeviceLog("a", LogLevel.ERROR, "FAILED in precheck: boom", "12:34:56.789"))
    report(DeviceStateChanged("a", DeviceState.FAILED, phase="precheck", message="boom"))
    report(
        ClockMeasured("a", offset_s=0.5, uncertainty_s=0.01, resolution="ns", exceeds_threshold=False)
    )  # the device log has it
    assert capsys.readouterr().out.splitlines() == [
        "[a] $ commsignia-device-info",
        "[a]   Firmware: 1.2.3",
        "[a]   a warning",
        "[a] FAILED in precheck: boom",
        "[a] failed",
    ]


def test_reporter_timestamps(capsys):
    report = _Reporter(show_logs=True, timestamps=True)
    report(DeviceLog("a", LogLevel.INFO, "logged", "12:34:56.789"))
    report(DeviceStateChanged("a", DeviceState.DONE))
    log_line, state_line = capsys.readouterr().out.splitlines()
    assert log_line == "12:34:56.789 [a] logged"  # the time the line was logged
    assert re.fullmatch(rf"{TIMESTAMP} \[a\] done", state_line)


# ---------------------------------------------------------------------------
# models, usage errors, config warnings
# ---------------------------------------------------------------------------


def test_models(capsys):
    code = main(["models"])
    out = capsys.readouterr().out
    assert code == 0
    headers = [line for line in out.splitlines() if not line.startswith(" ")]
    assert [h.split(":")[0] for h in headers] == [d.model_id for d in all_drivers()]
    assert (
        "kapsch: Kapsch (Kapsch)\n"
        "    capture mode: streamed\n"
        "    default user: admin\n"
        "    option interface (str, default 'rmnet_data1', required): Capture interface\n"
        "    option filter (str, default ''): tcpdump/pcap filter expression\n"
    ) in out
    assert "mock: Mock device (Simulated)\n    capture mode: streamed, no SSH\n" in out
    assert (
        "cohda-mk6: Cohda MK6 (Cohda Wireless)\n    capture mode: remote files\n    default user: user\n"
        in out
    )
    assert "option fail_phase (choice, default 'none', one of 'none', 'precheck'," in out


@pytest.mark.parametrize(
    ("args", "config", "error"),
    [
        (["check"], None, "configuration file not found: <tmp>/config.toml"),
        (["check"], "x = [", "<tmp>/config.toml: invalid TOML"),
        (
            ["check"],
            'default_duration = "soon"',
            "<tmp>/config.toml: setting 'default_duration': expected an integer",
        ),
        (["check"], '[[devices]]\nname = "a"\nmodel = "mock"\nenabled = false', "no devices enabled"),
        (["run", "--duration", "0"], "mock", "duration must be between 1 s and 24 h"),
        (["run", "--duration", "soon"], "mock", "invalid duration 'soon'"),
    ],
)
def test_usage_errors(capsys, tmp_path, args, config, error):
    """``config`` is the config file's text, "mock" for one mock device, or None for no file."""
    path = tmp_path / "config.toml"
    if config == "mock":
        config_file(tmp_path, {"a": {}})
    elif config is not None:
        path.write_text(config + "\n")
    code, out, err = run_cli(capsys, tmp_path, *args, "--config", str(path))
    assert code == 2
    assert out == ""
    assert err.startswith(f"cv2x-tester: error: {error}")


@pytest.mark.parametrize(
    "args",
    [
        ["run"],
        ["check"],
        ["--config", "cfg.toml", "check"],  # before the command, --config is the GUI's
    ],
)
def test_config_is_required(capsys, args):
    with pytest.raises(SystemExit) as exit_info:
        main(args)
    assert exit_info.value.code == 2
    assert "error: the following arguments are required: -c/--config" in capsys.readouterr().err


def test_config_warnings(capsys, tmp_path):
    path = config_file(tmp_path, {"a": {}})
    text = path.read_text().replace("\n", '\ncolor = "blue"\n', 1)
    path.write_text(text + '\n[[devices]]\nname = "b"\nmodel = "nope"\nhost = "h"\nusername = "u"\n')
    code, out, err = run_cli(capsys, tmp_path, "check", "-t", "--config", str(path))
    assert code == 0  # the warnings do not stop the pre-checks
    assert err == (
        "warning: <tmp>/config.toml: unknown key 'color' ignored\n"
        "warning: <tmp>/config.toml: device 'b' skipped: field 'model': unknown model 'nope'\n"
    )
    assert out.endswith("Pre-checks: 1 OK, 0 not ready, 0 failed\n")


@pytest.mark.skipif(os.name != "posix", reason="file permissions are POSIX-only")
def test_config_permission_warning(capsys, tmp_path):
    path = config_file(tmp_path, {"a": {}})
    path.write_text(path.read_text().replace('model = "mock"', 'model = "mock"\npassword = "secret"'))
    path.chmod(0o644)
    code, _, err = run_cli(capsys, tmp_path, "check", "-t", "--config", str(path))
    assert code == 0
    assert err == (
        "warning: <tmp>/config.toml: config file is readable by group/others and contains plaintext "
        "passwords or passphrases; consider 'chmod 600'\n"
    )


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


def test_check_ok(capsys, tmp_path):
    config = config_file(tmp_path, {"a": {}})
    code, out, err = run_cli(capsys, tmp_path, "check", "-t", "-c", str(config))
    assert code == 0
    assert err == ""
    assert out == (
        "[a] connecting\n"
        "[a] precheck\n"
        "[a] [mock] running pre-checks\n"
        "[a] clock\n"
        "[a] clock offset +0.000 s (±<unc>, resolution ns)\n"
        "[a] pre-checks passed\n"
        "[a] done\n"
        "\n"
        "  a   OK   clock offset +0.000 s\n"
        "\n"
        "Pre-checks: 1 OK, 0 not ready, 0 failed\n"
    )
    assert not (tmp_path / "results").exists()


def test_check_failure(capsys, tmp_path):
    config = config_file(tmp_path, {"a": {"fail_phase": "precheck"}})
    code, out, err = run_cli(capsys, tmp_path, "check", "-t", "--config", str(config))
    assert code == 1
    assert err == ""
    assert out == (
        "[a] connecting\n"
        "[a] precheck\n"
        "[a] [mock] running pre-checks\n"
        "[a] FAILED in precheck: simulated failure in precheck\n"
        "[a] failed_clean\n"
        "\n"
        "  a   FAILED   precheck: simulated failure in precheck\n"
        "\n"
        "Pre-checks: 0 OK, 0 not ready, 1 failed\n"
    )


def test_check_not_ready(capsys, tmp_path):
    config = config_file(tmp_path, {"a": {"not_ready": True}})
    code, out, err = run_cli(capsys, tmp_path, "check", "-t", "--config", str(config))
    assert code == 1
    assert err == ""
    assert out == (
        "[a] connecting\n"
        "[a] precheck\n"
        "[a] [mock] running pre-checks\n"
        "[a] NOT READY in precheck: simulated device not ready\n"
        "[a] not_ready\n"
        "\n"
        "  a   NOT READY   precheck: simulated device not ready\n"
        "\n"
        "Pre-checks: 0 OK, 1 not ready, 0 failed\n"
    )


def test_check_clock_warning(capsys, tmp_path):
    config = config_file(tmp_path, {"a": {"clock_offset_ms": 3000}})
    code, out, _ = run_cli(capsys, tmp_path, "check", "-t", "-c", str(config))
    assert code == 0
    progress, summary = out.split("\n\n", 1)
    warnings = [line for line in progress.splitlines() if "threshold" in line]
    assert warnings == ["[a] warning: clock offset +3.000 s exceeds the threshold (2 s)"]
    assert summary.startswith("  a   OK   clock offset +3.000 s (exceeds the threshold)\n")


def test_check_summary_aligns_columns(capsys, tmp_path):
    config = config_file(
        tmp_path, {"obu": {}, "very-slow-rsu": {"fail_phase": "precheck"}, "rsu": {"not_ready": True}}
    )
    code, out, _ = run_cli(capsys, tmp_path, "check", "-t", "--config", str(config))
    assert code == 1
    assert out.split("\n\n", 1)[1] == (
        "  obu             OK          clock offset +0.000 s\n"
        "  very-slow-rsu   FAILED      precheck: simulated failure in precheck\n"
        "  rsu             NOT READY   precheck: simulated device not ready\n"
        "\n"
        "Pre-checks: 1 OK, 1 not ready, 1 failed\n"
    )


def test_check_timestamps(capsys, tmp_path):
    config = config_file(tmp_path, {"a": {}})
    code, out, _ = run_cli(capsys, tmp_path, "check", "--config", str(config))
    assert code == 0
    progress, summary = out.split("\n\n", 1)
    assert all(re.match(rf"{TIMESTAMP} \[a\] ", line) for line in progress.splitlines())
    assert not re.search(TIMESTAMP, summary)


def test_check_interrupted(capsys, tmp_path, monkeypatch):
    async def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "check_devices", interrupted)
    config = config_file(tmp_path, {"a": {}})
    code, _, err = run_cli(capsys, tmp_path, "check", "-t", "--config", str(config))
    assert code == 130
    assert err == "\nPre-checks interrupted\n"


def test_check_unknown_device(capsys, tmp_path):
    config = config_file(tmp_path, {"a": {}})
    code, out, err = run_cli(capsys, tmp_path, "check", "--config", str(config), "--device", "nope")
    assert code == 2
    assert out == ""
    assert "unknown device 'nope'" in err


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def test_run_success(capsys, tmp_path):
    config = config_file(tmp_path, {"a": {}})
    code, out, err = run_cli(capsys, tmp_path, "run", "-t", "--duration", "1", "--config", str(config))
    assert code == 0
    assert err == ""
    assert out == (
        "devices: a\n"
        "run state: preparing\n"
        "[a] connecting\n"
        "[a] precheck\n"
        "[a] clock\n"
        "[a] clock offset +0.000 s (±<unc>)\n"
        "[a] starting_capture\n"
        "[a] starting_test\n"
        "[a] running\n"
        "run state: running (1 s)\n"
        "run folder: <tmp>/results/<run>\n"
        "run state: stopping\n"
        "[a] stopping_test\n"
        "[a] stopping_capture\n"
        "[a] collecting\n"
        "[a] done\n"
        "run state: finished\n"
        "\n"
        "Outcome: success\n"
        "Start skew: 0.000 s\n"
        "  a   done <size>   <n> packets\n"
        "Results: <tmp>/results/<run>\n"
    )


def test_run_not_stopped_cleanly(capsys, tmp_path):
    config = config_file(tmp_path, {"a": {"fail_phase": "stop_test"}})
    code, out, err = run_cli(capsys, tmp_path, "run", "-t", "--duration", "1", "--config", str(config))
    assert code == 1
    assert out.split("run state: stopping\n", 1)[1] == (
        "[a] stopping_test\n"
        "[a] FAILED in stop_test: simulated failure in stop_test\n"
        "[a] stopping_capture\n"
        "[a] collecting\n"
        "[a] failed_unclean\n"
        "run state: finished\n"
        "\n"
        "Outcome: partial\n"
        "Start skew: 0.000 s\n"
        "  a   failed_unclean <size>   <n> packets\n"
        "      error: stop_test: simulated failure in stop_test\n"
        "Results: <tmp>/results/<run>\n"
    )
    assert err == "\nWarning: not stopped cleanly; the test or capture may still be running on: a\n"


def test_run_aborted(capsys, tmp_path):
    config = config_file(tmp_path, {"a": {"fail_phase": "precheck"}})
    code, out, err = run_cli(capsys, tmp_path, "run", "-t", "--duration", "1", "--config", str(config))
    assert code == 3
    assert err == ""
    assert out == (
        "devices: a\n"
        "run state: preparing\n"
        "[a] connecting\n"
        "[a] precheck\n"
        "[a] FAILED in precheck: simulated failure in precheck\n"
        "[a] failed_clean\n"
        "run state: stopping\n"
        "run state: finished\n"
        "\n"
        "Outcome: aborted\n"
        "  a   failed_clean     no pcap\n"
        "      error: precheck: simulated failure in precheck\n"
        "Results: <tmp>/results/<run>\n"
    )


def test_run_not_ready(capsys, tmp_path):
    config = config_file(tmp_path, {"a": {"not_ready": True}})
    code, out, err = run_cli(capsys, tmp_path, "run", "-t", "--duration", "1", "--config", str(config))
    assert code == 3
    assert err == ""
    assert out.split("run state: preparing\n", 1)[1] == (
        "[a] connecting\n"
        "[a] precheck\n"
        "[a] NOT READY in precheck: simulated device not ready\n"
        "run state: stopping\n"
        "run state: finished\n"
        "\n"
        "Outcome: aborted\n"
        "  a   not_ready     no pcap\n"
        "      not ready: precheck: simulated device not ready\n"
        "Results: <tmp>/results/<run>\n"
    )


STOPPING_MESSAGE = "\nStopping (press Ctrl+C again to quit immediately)...\n"


def press_ctrl_c_when(monkeypatch: pytest.MonkeyPatch, state: RunState, presses: int = 1) -> None:
    """Make the progress reporter of ``run`` send SIGINT ``presses`` times when the run enters
    ``state``, as if the user pressed Ctrl+C."""
    report = _Reporter.__call__

    def report_and_press(self, event):
        report(self, event)
        if isinstance(event, RunStateChanged) and event.state is state:
            # Another handler, such as asyncio's or Python's default, could turn the signal into a
            # KeyboardInterrupt, which would abort the whole test session.
            handler = signal.getsignal(signal.SIGINT)
            assert getattr(handler, "__module__", None) == cli.__name__, "the CLI's handler isn't installed"
            for _ in range(presses):
                signal.raise_signal(signal.SIGINT)

    monkeypatch.setattr(_Reporter, "__call__", report_and_press)


def run_manifest(tmp_path: Path) -> dict[str, Any]:
    """Return the contents of the run.json of the only run in ``tmp_path``."""
    (path,) = (tmp_path / "results").glob("*/run.json")
    manifest: dict[str, Any] = json.loads(path.read_text())
    return manifest


@pytest.mark.parametrize(
    ("state", "outcome", "stopped_early"),
    [
        (RunState.PREPARING, "aborted", False),
        (RunState.RUNNING, "success", True),
        # Once the run is stopping, Ctrl+C no longer affects it, but still sets the exit code.
        (RunState.STOPPING, "success", False),
    ],
)
def test_run_ctrl_c_exits_with_130(capsys, tmp_path, monkeypatch, state, outcome, stopped_early):
    press_ctrl_c_when(monkeypatch, state)
    config = config_file(tmp_path, {"a": {}})
    code, _, err = run_cli(capsys, tmp_path, "run", "-t", "--duration", "1", "--config", str(config))
    assert code == 130
    assert err == STOPPING_MESSAGE
    manifest = run_manifest(tmp_path)
    assert (manifest["outcome"], manifest["stopped_early"]) == (outcome, stopped_early)


def test_run_second_ctrl_c_exits_immediately(capsys, tmp_path, monkeypatch):
    press_ctrl_c_when(monkeypatch, RunState.RUNNING, presses=2)
    config = config_file(tmp_path, {"a": {}})
    code, _, err = run_cli(capsys, tmp_path, "run", "-t", "--duration", "30", "--config", str(config))
    assert code == 130
    assert err == (
        STOPPING_MESSAGE
        + "\nWarning: not stopped cleanly; the test or capture may still be running on: a\n"
        + "Run interrupted\n"
    )
    assert run_manifest(tmp_path)["outcome"] == "interrupted"


def test_run_verbose(capsys, tmp_path):
    config = config_file(tmp_path, {"a": {}})
    code, out, _ = run_cli(capsys, tmp_path, "run", "-t", "-v", "--duration", "1", "--config", str(config))
    assert code == 0
    progress = out.split("\n\n", 1)[0].splitlines()
    assert "[a] [mock] running pre-checks" in progress
    assert "[a] test started" in progress
    # The clock offset comes from the device log only, not again from the event.
    assert [line for line in progress if "clock offset" in line] == [
        "[a] clock offset +0.000 s (±<unc>, resolution ns)"
    ]


def test_run_verbose_prints_warnings_once(capsys, tmp_path):
    config = config_file(tmp_path, {"a": {"truncate_capture": True}})
    code, out, _ = run_cli(capsys, tmp_path, "run", "-t", "-v", "--duration", "1", "--config", str(config))
    assert code == 0
    progress = out.split("\n\n", 1)[0].splitlines()
    # The warning comes from the device log only, not again from the event.
    [line] = [line for line in progress if "truncated" in line]
    assert line.startswith("[a] warning: stream1.pcap: removed truncated last record (")


def test_run_unwritable_output_dir(capsys, tmp_path):
    config = config_file(tmp_path, {"a": {}})
    blocker = tmp_path / "file"
    blocker.write_text("x")
    code, out, err = run_cli(
        capsys,
        tmp_path,
        "run",
        "-t",
        "--duration",
        "1",
        "--config",
        str(config),
        "--output-dir",
        str(blocker),
    )
    assert code == 3
    assert "error: cannot create run folder in <tmp>/file" in err
    assert "Results:" not in out


@pytest.mark.parametrize("flag", ["-t", "--no-timestamps"])
def test_run_without_timestamps(capsys, tmp_path, flag):
    config = config_file(tmp_path, {"a": {}})
    code, out, _ = run_cli(capsys, tmp_path, "run", flag, "--duration", "1", "--config", str(config))
    assert code == 0
    assert not re.search(TIMESTAMP, out)
