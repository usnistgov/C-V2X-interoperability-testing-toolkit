# SPDX-License-Identifier: NIST-Software

import asyncio
import dataclasses
import datetime
import errno
import itertools
import json
import re
import time
from collections.abc import Callable
from contextvars import Context
from pathlib import Path
from typing import Any

import pytest
from conftest import mock_config, mock_device, pcap_bytes, pcap_packets
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether

from cv2x_tester.clock import date_sources
from cv2x_tester.config import DeviceConfig
from cv2x_tester.drivers import CaptureStats, DeviceNotReady
from cv2x_tester.drivers.mock import Mock
from cv2x_tester.engine import Run, check_devices, create_run_dir
from cv2x_tester.events import (
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
from cv2x_tester.manifest import DeviceFailure
from cv2x_tester.pcap import PcapFormatError
from cv2x_tester.ssh import CommandResult


@pytest.fixture(autouse=True)
def fast_mock_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("cv2x_tester.drivers.mock.RUNNING_FAILURE_DELAY", 0.1)


def make_run(
    tmp_path: Path, *devices: DeviceConfig, duration: float = 0.3, **kw: Any
) -> tuple[Run, list[Event]]:
    cfg = mock_config(tmp_path, *devices)
    events: list[Event] = []
    run = Run(cfg, list(devices), duration=duration, on_event=events.append, **kw)
    return run, events


async def start_run(tmp_path: Path, *devices: DeviceConfig) -> tuple[Run, asyncio.Task[RunFinished]]:
    """Start a 30 s run of ``devices`` in a task, and return once the run is running."""
    running = asyncio.Event()

    def on_event(e: Event) -> None:
        if isinstance(e, RunStateChanged) and e.state is RunState.RUNNING:
            running.set()

    run = Run(mock_config(tmp_path, *devices), list(devices), duration=30, on_event=on_event)
    task = asyncio.create_task(run.execute())
    await asyncio.wait_for(running.wait(), 5)
    return run, task


def final_states(events: list[Event]) -> dict[str, DeviceState]:
    states: dict[str, DeviceState] = {}
    for e in events:
        if isinstance(e, DeviceStateChanged):
            states[e.device] = e.state
    return states


def device_log(run: Run, name: str) -> str:
    assert run.run_dir is not None
    return (run.run_dir / f"{name}.log").read_text()


def state_events(events: list[Event], device: str) -> list[tuple[DeviceState, str | None]]:
    return [(e.state, e.phase) for e in events if isinstance(e, DeviceStateChanged) and e.device == device]


async def test_success(tmp_path):
    a, b = mock_device("obu1"), mock_device("rsu1", role="rsu", password="hunter2-secret")
    run, events = make_run(tmp_path, a, b, test_name=" my test ", test_desc="bench 3\nline 2\n")
    result = await run.execute()
    assert result.outcome is Outcome.SUCCESS
    assert result.run_dir is not None
    assert result.manifest is not None
    assert result.run_dir.parent == tmp_path / "results"
    assert result.run_dir.name.endswith("_my-test")
    run_states = [e.state for e in events if isinstance(e, RunStateChanged)]
    assert run_states == [RunState.PREPARING, RunState.RUNNING, RunState.STOPPING, RunState.FINISHED]
    assert isinstance(events[-1], RunFinished)
    assert final_states(events) == {"obu1": DeviceState.DONE, "rsu1": DeviceState.DONE}
    files = sorted(p.name for p in result.run_dir.iterdir())
    assert files == ["obu1.log", "obu1.pcap", "rsu1.log", "rsu1.pcap", "run.json", "run.log"]
    run_log = (result.run_dir / "run.log").read_text()
    for line in ("run state: preparing", "phase: stop_test", "phase: collect", "outcome: success"):
        assert f" {line}\n" in run_log
    for name in ("obu1", "rsu1"):
        assert pcap_packets(result.run_dir / f"{name}.pcap")
        log = device_log(run, name)
        for line in ("capture started", "test started", "test stopped", "capture stopped"):
            assert f"[info] {line}\n" in log
        assert f"capture saved to {name}.pcap (" in log

    text = (result.run_dir / "run.json").read_text()
    assert "hunter2-secret" not in text
    m = json.loads(text)
    assert m == dataclasses.asdict(result.manifest)
    assert m["outcome"] == "success"
    assert m["name"] == "my test"
    assert m["description"] == "bench 3\nline 2"
    assert m["requested_duration_secs"] == 0.3
    assert not m["stopped_early"]
    assert m["actual_duration_secs"] == pytest.approx(0.3, abs=0.1)
    assert m["start_skew_secs"] is not None
    assert m["start_skew_secs"] < 0.5
    assert list(m["timestamps"]) == [
        "created",
        "connect",
        "precheck",
        "clock",
        "start_capture",
        "start_test",
        "running",
        "stopping",
        "finished",
    ]
    d = m["devices"][0]
    assert d["name"] == "obu1"
    assert d["state"] == "done"
    assert d["failure"] is None
    assert d["clock_offset_secs"] == pytest.approx(0, abs=0.05)
    assert d["clock_resolution"] == "ns"
    assert d["packets"] > 0
    assert d["pcap"] == "obu1.pcap"
    assert {f["path"] for f in d["files"]} == {"obu1.pcap", "obu1.log"}
    assert all(len(f["sha256"]) == 64 and f["size"] > 0 for f in d["files"])
    assert d["start_time"]
    assert d["stop_time"]


async def test_streams_are_merged(tmp_path):
    run, _ = make_run(tmp_path, mock_device("obu1", streams=2))
    result = await run.execute()
    assert result.outcome is Outcome.SUCCESS
    assert result.run_dir is not None
    assert result.manifest is not None
    assert not (result.run_dir / "obu1_raw").exists()
    # The UDP payload of each mock packet starts with its sequence number.
    packets = pcap_packets(result.run_dir / "obu1.pcap")
    seqs = [int.from_bytes(bytes(Ether(p)[UDP].payload)[:4]) for p in packets]
    # The merged capture has the packets of both streams, in order.
    assert len(seqs) > 1
    assert seqs == list(range(1, len(seqs) + 1))
    assert result.manifest.devices[0].packets == len(seqs)
    assert f"merged 2 capture files into obu1.pcap ({len(seqs)} packets)" in device_log(run, "obu1")


async def test_raw_files_kept_with_keep_raw_files(tmp_path):
    dev = mock_device("obu1", streams=2)
    dev.keep_raw_files = True
    run, _ = make_run(tmp_path, dev)
    result = await run.execute()
    assert result.run_dir is not None
    assert result.manifest is not None
    assert sorted(p.name for p in (result.run_dir / "obu1_raw").iterdir()) == ["stream1.pcap", "stream2.pcap"]
    files = {f.path for f in result.manifest.devices[0].files}
    assert files == {"obu1.pcap", "obu1.log", "obu1_raw/stream1.pcap", "obu1_raw/stream2.pcap"}


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (PcapFormatError("not a pcap file (bad magic)"), "not a pcap file (bad magic)"),
        (OSError(errno.ENOSPC, "No space left on device"), "No space left on device"),
    ],
)
async def test_merge_failure_keeps_the_raw_files(tmp_path, monkeypatch, error, reason):
    def fail(inputs, output):
        raise error

    monkeypatch.setattr("cv2x_tester.engine.merge_pcaps", fail)
    run, _ = make_run(tmp_path, mock_device("obu1", streams=2))
    result = await run.execute()
    assert result.run_dir is not None
    assert result.manifest is not None
    d = result.manifest.devices[0]
    assert d.state is DeviceState.DONE
    assert d.warnings == [f"cannot merge capture files: {reason}; raw files kept in obu1_raw/"]
    assert d.pcap is None
    assert sorted(p.name for p in (result.run_dir / "obu1_raw").iterdir()) == ["stream1.pcap", "stream2.pcap"]


@pytest.mark.parametrize(
    ("content", "warning", "raw_files"),
    [
        (
            b"not a pcap at all, really",
            "junk.pcap not merged: not a pcap file; raw files kept in obu1_raw/",
            ["junk.pcap", "stream1.pcap"],
        ),
        (b"", "junk.pcap not merged: empty file", []),
    ],
)
async def test_unmerged_input_keeps_the_raw_files_if_it_has_data(
    tmp_path, monkeypatch, content, warning, raw_files
):
    def pcap_files_to_merge(self, collected):
        junk = self.ctx.raw_files_dir / "junk.pcap"
        junk.write_bytes(content)
        return [*self._paths, junk]

    monkeypatch.setattr(Mock, "pcap_files_to_merge", pcap_files_to_merge)
    run, _ = make_run(tmp_path, mock_device("obu1"))
    result = await run.execute()
    assert result.run_dir is not None
    assert result.manifest is not None
    d = result.manifest.devices[0]
    assert d.warnings == [warning]
    assert d.pcap == "obu1.pcap"
    raw = result.run_dir / "obu1_raw"
    assert (sorted(p.name for p in raw.iterdir()) if raw.exists() else []) == raw_files


async def test_live_stats_are_read_every_interval(tmp_path, monkeypatch):
    reads = itertools.count()
    monkeypatch.setattr("cv2x_tester.engine.STATS_INTERVAL", 0.02)
    monkeypatch.setattr(Mock, "stats", lambda self: CaptureStats(packets=None, bytes=next(reads)))
    run, events = make_run(tmp_path, mock_device("obu1"))
    await run.execute()
    # Each read returns new counts, and the capture lasts about 0.35 s, so about 15 reads.
    assert sum(isinstance(e, StatsUpdated) for e in events) >= 10


async def test_live_stats_report_only_changes(tmp_path, monkeypatch):
    monkeypatch.setattr("cv2x_tester.engine.STATS_INTERVAL", 0.05)
    monkeypatch.setattr(Mock, "stats", lambda self: CaptureStats(packets=1, bytes=100))
    run, events = make_run(tmp_path, mock_device("obu1"))
    result = await run.execute()
    assert result.manifest is not None
    device = result.manifest.devices[0]
    stats = [(e.packets, e.bytes) for e in events if isinstance(e, StatsUpdated)]
    # One update from the polls, and one from the merge.
    assert stats == [(1, 100), (device.packets, device.bytes)]


async def test_failing_stats_disable_only_the_live_stats(tmp_path, monkeypatch):
    def broken(self):
        raise RuntimeError("driver bug")

    monkeypatch.setattr("cv2x_tester.engine.STATS_INTERVAL", 0.05)
    monkeypatch.setattr(Mock, "stats", broken)
    run, _ = make_run(tmp_path, mock_device("obu1"))
    result = await run.execute()
    assert result.outcome is Outcome.SUCCESS
    assert result.manifest is not None
    [warning] = result.manifest.devices[0].warnings
    assert warning == "cannot read live stats: internal error: RuntimeError: driver bug"


async def test_backward_clock_jump_is_reported(tmp_path, monkeypatch):
    def pcap_files_to_merge(self, collected):
        stepped = self.ctx.raw_files_dir / "stepped.pcap"
        stepped.write_bytes(pcap_bytes([(10, 0, b"a"), (7, 0, b"b")]))
        return [*self._paths, stepped]

    monkeypatch.setattr(Mock, "pcap_files_to_merge", pcap_files_to_merge)
    run, _ = make_run(tmp_path, mock_device("obu1"))
    result = await run.execute()
    assert result.manifest is not None
    [warning] = result.manifest.devices[0].warnings
    assert warning == (
        "the device clock was set back during the capture (timestamps go back 3.000 s); "
        "the measured clock offset does not apply after that point"
    )


async def test_truncated_capture_is_reported(tmp_path):
    run, _ = make_run(tmp_path, mock_device("obu1", truncate_capture=True))
    result = await run.execute()
    assert result.run_dir is not None
    assert result.manifest is not None
    d = result.manifest.devices[0]
    # The record header (16 bytes) and the half of the 50-byte packet left in the file.
    assert d.warnings == ["stream1.pcap: removed truncated last record (41 bytes)"]
    assert f"[warning] {d.warnings[0]}\n" in device_log(run, "obu1")
    assert d.packets == len(pcap_packets(result.run_dir / "obu1.pcap")) > 0


async def test_no_capture_data(tmp_path):
    run, _ = make_run(tmp_path, mock_device("bad", fail_phase="start_capture"))
    result = await run.execute()
    assert result.run_dir is not None
    assert result.manifest is not None
    d = result.manifest.devices[0]
    assert "no capture data" in d.warnings
    assert d.pcap is None
    assert not (result.run_dir / "bad_raw").exists()


@pytest.mark.parametrize(
    ("phase", "teardown"),
    [
        ("precheck", False),
        ("clock", False),
        ("start_capture", True),
        ("start_test", True),
    ],
)
async def test_abort_at_start_phase(tmp_path, phase, teardown):
    bad, good = mock_device("bad", fail_phase=phase), mock_device("good")
    run, events = make_run(tmp_path, bad, good)
    result = await run.execute()
    assert result.outcome is Outcome.ABORTED
    assert result.run_dir is not None
    states = final_states(events)
    assert states["bad"] is DeviceState.FAILED_CLEAN  # nothing left running
    assert states["good"] is DeviceState.ABORTED
    assert run.unclean_devices == []
    failed = next(e for e in events if isinstance(e, DeviceStateChanged) and e.state is DeviceState.FAILED)
    assert failed.phase == phase
    assert failed.message is not None
    assert "simulated failure" in failed.message
    assert RunState.RUNNING not in [e.state for e in events if isinstance(e, RunStateChanged)]
    # Devices that started capturing are torn down by the stop sequence.
    assert ("stopping test" in device_log(run, "good")) is teardown
    m = json.loads((result.run_dir / "run.json").read_text())
    assert m["outcome"] == "aborted"
    assert m["devices"][0]["failure"]["phase"] == phase


async def test_not_ready_device_aborts_the_run(tmp_path):
    bad, good = mock_device("bad", not_ready=True), mock_device("good")
    run, events = make_run(tmp_path, bad, good)
    result = await run.execute()
    assert result.outcome is Outcome.ABORTED
    assert result.run_dir is not None
    # The device gets its final state right away, and only once.
    assert state_events(events, "bad")[-2:] == [
        (DeviceState.PRECHECK, None),
        (DeviceState.NOT_READY, "precheck"),
    ]
    assert final_states(events) == {"bad": DeviceState.NOT_READY, "good": DeviceState.ABORTED}
    not_ready = next(
        e for e in events if isinstance(e, DeviceStateChanged) and e.state is DeviceState.NOT_READY
    )
    assert not_ready.message == "simulated device not ready"
    assert "NOT READY in precheck: simulated device not ready" in device_log(run, "bad")
    m = json.loads((result.run_dir / "run.json").read_text())
    assert m["outcome"] == "aborted"
    assert m["devices"][0]["state"] == "not_ready"
    assert m["devices"][0]["failure"] == {"phase": "precheck", "message": "simulated device not ready"}


async def test_device_not_ready_outside_the_precheck_is_a_failure(tmp_path, monkeypatch):
    async def start_test(self):
        raise DeviceNotReady("not ready")

    monkeypatch.setattr(Mock, "start_test", start_test)
    run, events = make_run(tmp_path, mock_device("a"))
    result = await run.execute()
    assert result.outcome is Outcome.ABORTED
    assert DeviceState.NOT_READY not in [state for state, _ in state_events(events, "a")]
    assert final_states(events) == {"a": DeviceState.FAILED_CLEAN}


async def test_failure_while_waiting_cancels_the_phase(tmp_path, monkeypatch):
    # A device can fail while it waits for the others, e.g. when its SSH connection drops.
    # Like a failure in the step itself, that must cancel the step on the other devices.
    canceled = []

    async def precheck(self):
        if self.device.name == "fast":
            asyncio.get_running_loop().call_later(0.05, self.ctx.report_failure, "connection lost")
            return
        try:
            await asyncio.sleep(2)
        except asyncio.CancelledError:
            canceled.append(self.device.name)
            raise

    monkeypatch.setattr(Mock, "precheck", precheck)
    run, events = make_run(tmp_path, mock_device("fast"), mock_device("slow"))
    result = await run.execute()
    assert canceled == ["slow"]
    assert result.outcome is Outcome.ABORTED
    assert state_events(events, "fast")[-3:] == [
        (DeviceState.WAITING, "precheck"),
        (DeviceState.FAILED, "precheck"),
        (DeviceState.FAILED_CLEAN, "precheck"),
    ]
    assert final_states(events)["slow"] is DeviceState.ABORTED


async def test_mid_run_failure_is_partial(tmp_path):
    bad, good = mock_device("bad", fail_phase="running"), mock_device("good")
    run, _events = make_run(tmp_path, bad, good, duration=0.5)
    result = await run.execute()
    assert result.outcome is Outcome.PARTIAL
    assert result.manifest is not None
    bad_m, good_m = result.manifest.devices
    assert bad_m.failure is not None
    assert bad_m.state == "failed_clean"
    assert bad_m.failure.phase == "running"
    assert device_log(run, "bad").count("simulated failure while running") == 1  # logged once
    assert bad_m.pcap == "bad.pcap"  # partial capture kept
    assert good_m.state == "done"
    assert "stopping test" in device_log(run, "bad")  # stop sequence still ran


async def test_all_failed_without_pcap(tmp_path):
    dev = mock_device("x", packet_rate_hz=0.0, fail_phase="collect")
    run, _ = make_run(tmp_path, dev)
    result = await run.execute()
    # The stream file has only a header, so the merged pcap is empty: the run is partial, with
    # an empty-capture warning.
    assert result.outcome is Outcome.PARTIAL
    assert result.manifest is not None
    assert "capture is empty" in result.manifest.devices[0].warnings


@pytest.mark.parametrize("hook", ["precheck", "cleanup"])
async def test_driver_bug_is_logged_with_its_traceback(tmp_path, monkeypatch, hook):
    async def broken(self):
        raise RuntimeError("driver bug")

    monkeypatch.setattr(Mock, hook, broken)
    run, _ = make_run(tmp_path, mock_device("a"))
    result = await run.execute()
    assert result.run_dir is not None
    assert result.manifest is not None
    failure = result.manifest.devices[0].failure
    assert failure == DeviceFailure(phase=hook, message="internal error: RuntimeError: driver bug")
    run_log = (result.run_dir / "run.log").read_text()
    assert f"[a] internal error in {hook}:\nTraceback (most recent call last):" in run_log


async def test_early_stop(tmp_path):
    run, task = await start_run(tmp_path, mock_device("a"))
    await asyncio.sleep(0.2)
    run.request_stop()
    result = await task
    assert result.outcome is Outcome.SUCCESS
    assert result.manifest is not None
    assert result.manifest.stopped_early is True
    duration = result.manifest.actual_duration_secs
    assert duration is not None
    assert duration < 2


class EarlyTimersLoop(asyncio.SelectorEventLoop):
    """Event loop whose timers fire after 80% of their delay, like an extreme Qt coarse timer."""

    def call_at[*Ts](
        self, when: float, callback: Callable[[*Ts], object], *args: *Ts, context: Context | None = None
    ) -> asyncio.TimerHandle:
        early = when - (when - self.time()) * 0.2
        return super().call_at(early, callback, *args, context=context)


def test_run_lasts_its_duration_when_timers_fire_early(tmp_path):
    run, _ = make_run(tmp_path, mock_device("a"), duration=0.5)
    result = asyncio.run(run.execute(), loop_factory=EarlyTimersLoop)
    assert result.outcome is Outcome.SUCCESS
    assert result.manifest is not None
    assert not result.manifest.stopped_early
    duration = result.manifest.actual_duration_secs
    assert duration is not None
    assert duration >= 0.5


async def test_cancel_during_preparing(tmp_path):
    a, b = mock_device("a", step_delay_ms=300), mock_device("b", step_delay_ms=300)
    run, events = make_run(tmp_path, a, b, duration=30)
    task = asyncio.create_task(run.execute())
    await asyncio.sleep(0.1)
    run.request_stop()
    result = await asyncio.wait_for(task, 5)
    assert result.outcome is Outcome.ABORTED
    assert set(final_states(events).values()) == {DeviceState.ABORTED}


async def test_force_quit_writes_interrupted_manifest(tmp_path):
    run, task = await start_run(tmp_path, mock_device("a"))
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert run.run_dir is not None
    m = json.loads((run.run_dir / "run.json").read_text())
    assert m["outcome"] == "interrupted"
    assert "interrupted" not in m
    assert m["devices"][0]["state"] == "failed_unclean"
    assert run.unclean_devices == ["a"]


async def test_clock_skew_warning_does_not_fail(tmp_path):
    run, _ = make_run(tmp_path, mock_device("a", clock_offset_ms=5000))
    result = await run.execute()
    assert result.outcome is Outcome.SUCCESS
    assert result.manifest is not None
    d = result.manifest.devices[0]
    assert d.clock_offset_secs == pytest.approx(5.0, abs=0.05)
    assert any("clock offset" in w for w in d.warnings)


async def test_clock_skew_warning_off(tmp_path):
    dev = mock_device("a", clock_offset_ms=5000)
    result = await Run(mock_config(tmp_path, dev, clock_skew_warning=0.0), [dev], duration=0.3).execute()
    assert result.manifest is not None
    d = result.manifest.devices[0]
    assert d.clock_offset_secs == pytest.approx(5.0, abs=0.05)
    assert d.warnings == []


async def test_fast_device_waits_for_slow_one(tmp_path):
    fast, slow = mock_device("fast", step_delay_ms=10), mock_device("slow", step_delay_ms=100)
    run, events = make_run(tmp_path, fast, slow)
    await run.execute()
    fast_states, slow_states = state_events(events, "fast"), state_events(events, "slow")
    assert (DeviceState.WAITING, "precheck") in fast_states
    assert (DeviceState.WAITING, "start_capture") in fast_states
    assert (DeviceState.WAITING, "precheck") not in slow_states  # the last device never waits
    assert [s for s, _ in fast_states if s is not DeviceState.WAITING][:6] == [
        DeviceState.CONNECTING,
        DeviceState.PRECHECK,
        DeviceState.CLOCK,
        DeviceState.STARTING_CAPTURE,
        DeviceState.STARTING_TEST,
        DeviceState.RUNNING,
    ]
    # The fast device is running as soon as its own test has started, before the run is.
    fast_running = events.index(DeviceStateChanged("fast", DeviceState.RUNNING, phase="start_test"))
    run_running = next(
        i for i, e in enumerate(events) if isinstance(e, RunStateChanged) and e.state is RunState.RUNNING
    )
    assert fast_running < run_running


async def test_captures_stop_after_all_tests_and_devices_finish_independently(tmp_path, monkeypatch):
    calls = []
    stop_test, stop_capture = Mock.stop_test, Mock.stop_capture

    async def recording_stop_test(self):
        await stop_test(self)
        calls.append((self.device.name, "stop_test"))

    async def recording_stop_capture(self):
        calls.append((self.device.name, "stop_capture"))
        await stop_capture(self)

    monkeypatch.setattr(Mock, "stop_test", recording_stop_test)
    monkeypatch.setattr(Mock, "stop_capture", recording_stop_capture)
    fast, slow = mock_device("fast", step_delay_ms=10), mock_device("slow", step_delay_ms=100)
    run, events = make_run(tmp_path, fast, slow)
    result = await run.execute()
    assert result.outcome is Outcome.SUCCESS
    steps = [step for _, step in calls]
    assert steps == ["stop_test", "stop_test", "stop_capture", "stop_capture"]
    assert (DeviceState.WAITING, "stop_test") in state_events(events, "fast")
    fast_states = [s for s, _ in state_events(events, "fast")]
    assert fast_states[fast_states.index(DeviceState.STOPPING_TEST) :] == [
        DeviceState.STOPPING_TEST,
        DeviceState.WAITING,
        DeviceState.STOPPING_CAPTURE,
        DeviceState.COLLECTING,
        DeviceState.DONE,
    ]
    done = [e.device for e in events if isinstance(e, DeviceStateChanged) and e.state is DeviceState.DONE]
    assert done == ["fast", "slow"]  # fast finished collecting first


@pytest.mark.parametrize("phase", ["stop_test", "stop_capture"])
async def test_failed_stop_is_unclean(tmp_path, phase):
    bad, good = mock_device("bad", fail_phase=phase), mock_device("good")
    run, events = make_run(tmp_path, bad, good)
    result = await run.execute()
    assert result.outcome is Outcome.PARTIAL
    assert result.manifest is not None
    assert final_states(events) == {"bad": DeviceState.FAILED_UNCLEAN, "good": DeviceState.DONE}
    last = [e for e in events if isinstance(e, DeviceStateChanged) and e.device == "bad"][-1]
    assert last.phase == phase
    assert last.message is not None
    assert "simulated failure" in last.message
    bad_m = result.manifest.devices[0]
    assert bad_m.failure is not None
    assert (bad_m.state, bad_m.failure.phase) == ("failed_unclean", phase)
    assert bad_m.pcap == "bad.pcap"  # its capture is kept
    assert run.unclean_devices == ["bad"]


async def test_unclean_device_keeps_remote_files(tmp_path, monkeypatch):
    cleaned = []

    async def cleanup(self):
        cleaned.append(self.device.name)

    monkeypatch.setattr(Mock, "cleanup", cleanup)
    run, _ = make_run(tmp_path, mock_device("bad", fail_phase="stop_test"), mock_device("good"))
    result = await run.execute()
    assert result.manifest is not None
    assert cleaned == ["good"]
    assert "remote files kept: the device was not stopped cleanly" in result.manifest.devices[0].warnings
    assert "[warning] remote files kept: the device was not stopped cleanly" in device_log(run, "bad")


async def test_device_whose_stop_failed_does_not_wait(tmp_path):
    bad = mock_device("bad", step_delay_ms=10, fail_phase="stop_test")
    slow = mock_device("slow", step_delay_ms=100)
    run, events = make_run(tmp_path, bad, slow)
    await run.execute()
    bad_states = [s for s, _ in state_events(events, "bad")]
    stop_part = bad_states[bad_states.index(DeviceState.STOPPING_TEST) :]
    assert DeviceState.WAITING not in stop_part
    assert stop_part[:2] == [DeviceState.STOPPING_TEST, DeviceState.FAILED]
    assert bad_states[-1] is DeviceState.FAILED_UNCLEAN


async def test_slow_stop_does_not_fail_the_other_devices(tmp_path, monkeypatch):
    stop_test = Mock.stop_test

    async def hanging_stop_test(self):
        if self.device.name == "slow":
            await asyncio.sleep(10)
        await stop_test(self)

    monkeypatch.setattr(Mock, "stop_test", hanging_stop_test)
    slow, ok = mock_device("slow"), mock_device("ok")
    run = Run(mock_config(tmp_path, slow, ok, stop_timeout=0.3), [slow, ok], duration=0.3)
    result = await run.execute()
    assert result.manifest is not None
    slow_m, ok_m = result.manifest.devices
    assert slow_m.state is DeviceState.FAILED_UNCLEAN
    assert slow_m.failure == DeviceFailure(phase="stop_test", message="stop timeout (0.3 s) exceeded")
    assert slow_m.pcap == "slow.pcap"  # its capture was still stopped and merged
    assert (ok_m.state, ok_m.failure, ok_m.warnings) == (DeviceState.DONE, None, [])


async def test_collect_timeout_keeps_remote_files(tmp_path, monkeypatch):
    cleaned = []

    async def hanging_collect(self, directory):
        await asyncio.sleep(10)
        return []

    async def cleanup(self):
        cleaned.append(self.device.name)

    monkeypatch.setattr(Mock, "collect", hanging_collect)
    monkeypatch.setattr(Mock, "cleanup", cleanup)
    dev = mock_device("a")
    run = Run(mock_config(tmp_path, dev, collect_timeout=0.2), [dev], duration=0.3)
    result = await run.execute()
    assert result.manifest is not None
    d = result.manifest.devices[0]
    assert d.state is DeviceState.FAILED_CLEAN
    assert d.failure == DeviceFailure(phase="collect", message="collect timeout (0.2 s) exceeded")
    assert cleaned == []
    assert "remote files kept: not all files were collected" in d.warnings


async def test_failed_download_keeps_remote_files(tmp_path, monkeypatch):
    cleaned = []

    async def collect(self, directory):
        local = await self.download("/remote/rx.pcap", directory)  # fails: the mock has no SSH
        return [local] if local else []

    async def cleanup(self):
        cleaned.append(self.device.name)

    monkeypatch.setattr(Mock, "collect", collect)
    monkeypatch.setattr(Mock, "cleanup", cleanup)
    run, _ = make_run(tmp_path, mock_device("a"))
    result = await run.execute()
    assert result.manifest is not None
    d = result.manifest.devices[0]
    assert d.state is DeviceState.DONE
    assert cleaned == []
    assert d.warnings == ["this device has no SSH session", "remote files kept: not all files were collected"]


async def test_failed_collect_is_clean(tmp_path):
    run, events = make_run(tmp_path, mock_device("a", fail_phase="collect"))
    result = await run.execute()
    assert result.manifest is not None
    assert final_states(events) == {"a": DeviceState.FAILED_CLEAN}  # stopped before collect failed
    failure = result.manifest.devices[0].failure
    assert failure is not None
    assert failure.phase == "collect"
    assert run.unclean_devices == []


async def test_abort_teardown_that_cannot_stop_is_unclean(tmp_path):
    bad, other = mock_device("bad", fail_phase="start_test"), mock_device("other", fail_phase="stop_test")
    run, events = make_run(tmp_path, bad, other)
    result = await run.execute()
    assert result.outcome is Outcome.ABORTED
    assert result.manifest is not None
    assert final_states(events) == {"bad": DeviceState.FAILED_CLEAN, "other": DeviceState.FAILED_UNCLEAN}
    other_m = result.manifest.devices[1]
    assert other_m.failure is None  # "other" did not cause the abort
    assert any("stop_test" in w for w in other_m.warnings)
    assert run.unclean_devices == ["other"]


def test_run_requires_devices(tmp_path):
    with pytest.raises(ValueError, match="no devices selected"):
        Run(mock_config(tmp_path), [], duration=1)


def test_run_dir_collision(tmp_path):
    now = datetime.datetime(2026, 10, 12, 10, 0, 0, tzinfo=datetime.UTC)
    first = create_run_dir(tmp_path, "bsm", now)
    second = create_run_dir(tmp_path, "bsm", now)
    third = create_run_dir(tmp_path, "", now)
    assert first.name == "2026-10-12_10-00-00_bsm"
    assert second.name == "2026-10-12_10-00-00_bsm_2"
    assert third.name == "2026-10-12_10-00-00"


async def test_unwritable_output_dir(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    run, events = make_run(tmp_path, mock_device("a"), output_dir=blocker / "sub")
    result = await run.execute()
    assert result.outcome is Outcome.ABORTED
    assert result.run_dir is None
    assert result.error
    assert "cannot create run folder" in result.error
    assert final_states(events) == {"a": DeviceState.ABORTED}


async def test_unwritable_run_log(tmp_path, monkeypatch):
    def unwritable(path):
        raise PermissionError(13, "Permission denied", str(path))

    run, events = make_run(tmp_path, mock_device("a"))
    monkeypatch.setattr("cv2x_tester.engine.RunLogger", unwritable)
    result = await run.execute()
    assert result.outcome is Outcome.ABORTED
    assert result.run_dir is None
    assert run.run_dir is None
    assert result.error
    assert result.error.endswith("run.log: Permission denied")
    assert list((tmp_path / "results").iterdir()) == []  # the empty run folder was removed
    assert final_states(events) == {"a": DeviceState.ABORTED}


async def test_check_devices(tmp_path):
    ok, bad = mock_device("ok", clock_offset_ms=1000), mock_device("bad", fail_phase="precheck")
    events: list[Event] = []
    results = await check_devices(mock_config(tmp_path, ok, bad), [ok, bad], events.append)
    assert [r.state for r in results] == [DeviceState.DONE, DeviceState.FAILED_CLEAN]
    assert results[0].failure is None
    clock = results[0].clock
    assert clock is not None
    assert clock.offset_s == pytest.approx(1.0, abs=0.05)
    assert results[1].failure == DeviceFailure(phase="precheck", message="simulated failure in precheck")
    assert results[1].clock is None
    assert final_states(events) == {r.device: r.state for r in results}
    assert not (tmp_path / "results").exists()  # nothing written


async def test_check_devices_not_ready(tmp_path):
    ok, bad = mock_device("ok"), mock_device("bad", not_ready=True)
    events: list[Event] = []
    results = await check_devices(mock_config(tmp_path, ok, bad), [ok, bad], events.append)
    assert [r.state for r in results] == [DeviceState.DONE, DeviceState.NOT_READY]
    assert results[1].failure == DeviceFailure(phase="precheck", message="simulated device not ready")
    assert final_states(events) == {r.device: r.state for r in results}


async def test_check_devices_reports_the_clock(tmp_path, monkeypatch):
    async def busybox_date(command):
        out = "1700000000.N" if "%N" in command else str(int(time.time()) + 5)
        return CommandResult(command, exit_status=0, stdout=out, stderr="")

    monkeypatch.setattr(Mock, "clock_sources", lambda self: date_sources(busybox_date))
    dev = mock_device("a")
    events: list[Event] = []
    [result] = await check_devices(mock_config(tmp_path, dev), [dev], events.append)
    assert result.state is DeviceState.DONE
    assert result.clock is not None
    assert result.clock.resolution == "s"
    lines = [(e.level, e.line) for e in events if isinstance(e, DeviceLog)]
    fallback = "unexpected 'date +%s.%N' output: '1700000000.N'; falling back to date (s)"
    assert (LogLevel.INFO, fallback) in lines
    [warning] = [line for level, line in lines if level is LogLevel.WARNING]
    assert re.fullmatch(r"clock offset \+\d\.\d{3} s exceeds the threshold \(2 s\)", warning)
    assert result.clock_warning
    assert not any(isinstance(e, DeviceWarning) for e in events)


async def test_check_devices_logs_driver_bugs(tmp_path, monkeypatch, caplog):
    async def broken(self):
        raise RuntimeError("driver bug")

    monkeypatch.setattr(Mock, "precheck", broken)
    dev = mock_device("a")
    [result] = await check_devices(mock_config(tmp_path, dev), [dev])
    assert result.state is DeviceState.FAILED_CLEAN
    assert result.failure == DeviceFailure(
        phase="precheck", message="internal error: RuntimeError: driver bug"
    )
    [record] = caplog.records
    assert record.getMessage() == "[a] internal error in precheck"
    assert record.exc_info


async def test_check_devices_reports_setup_errors(tmp_path):
    dev = dataclasses.replace(mock_device("a"), model="nonexistent")
    events: list[Event] = []
    [result] = await check_devices(mock_config(tmp_path, dev), [dev], events.append)
    assert result.state is DeviceState.FAILED_CLEAN
    assert result.failure is not None
    assert result.failure.phase == "setup"
    lines = [(e.device, e.level, e.line) for e in events if isinstance(e, DeviceLog)]
    assert lines == [("a", LogLevel.ERROR, f"FAILED in setup: {result.failure.message}")]
