# SPDX-License-Identifier: NIST-Software

from dataclasses import asdict, fields, replace
from typing import Any

from PySide6.QtCore import Qt

from cv2x_tester.config import DeviceConfig
from cv2x_tester.events import DeviceState
from cv2x_tester.gui.models import Column, DeviceStatus, DeviceTableModel, ItemRole


def make_model(*devices: DeviceConfig) -> DeviceTableModel:
    model = DeviceTableModel()
    model.set_devices(list(devices or [DeviceConfig(name="obu1", model="cohda-mk6", host="10.0.0.3")]))
    return model


def cell(model: DeviceTableModel, column: Column, role: int = ItemRole.display, row: int = 0) -> Any:
    return model.data(model.index(row, column), role)


def signaled(model: DeviceTableModel) -> list[tuple[Column, set[ItemRole]]]:
    """Record the dataChanged() signals of a model: (column, roles) for each column."""
    changes: list[tuple[Column, set[ItemRole]]] = []

    def record(first, last, roles):
        for c in range(first.column(), last.column() + 1):
            changes.append((Column(c), {ItemRole(r) for r in roles}))

    model.dataChanged.connect(record)
    return changes


def test_headers():
    model = make_model()
    headers = [model.headerData(i, Qt.Orientation.Horizontal) for i in range(model.columnCount())]
    assert headers == [
        "",
        "Name",
        "Model",
        "Role",
        "Address",
        "Status",
        "Clock",
        "Capture size",
        "Packets",
        "Problems",
    ]
    assert model.headerData(0, Qt.Orientation.Vertical) is None
    alignment = ItemRole.textAlignment
    right = [
        i
        for i in range(model.columnCount())
        if model.headerData(i, Qt.Orientation.Horizontal, alignment) == Qt.AlignmentFlag.AlignRight
    ]
    assert right == [Column.SIZE, Column.PACKETS]


def test_idle_row():
    model = make_model()
    texts = [cell(model, c) for c in Column]
    assert texts == ["", "obu1", "Cohda MK6", "OBU", "10.0.0.3:22", "Idle", "", "", "", ""]
    assert cell(model, Column.ENABLED, ItemRole.checkState) == Qt.CheckState.Checked
    assert cell(model, Column.NAME, ItemRole.checkState) is None
    assert cell(model, Column.ENABLED, ItemRole.toolTip) == "Include this device in runs"
    assert cell(model, Column.STATUS, ItemRole.toolTip) == ""
    assert (
        cell(model, Column.STATUS, ItemRole.deviceState)
        == cell(model, Column.PROBLEMS, ItemRole.deviceState)
        == "idle"
    )
    assert cell(model, Column.NAME, ItemRole.deviceState) is None
    assert cell(model, Column.STATUS, ItemRole.active) is False
    assert cell(model, Column.CLOCK, ItemRole.clockWarn) is False


def test_simulated_address():
    model = make_model(DeviceConfig(name="m", model="mock"))
    assert cell(model, Column.ADDRESS) == "—"


def test_status_tooltips():
    model = make_model()
    model.update("obu1", state=DeviceState.WAITING, phase="clock")
    assert cell(model, Column.STATUS) == "Waiting"
    assert cell(model, Column.STATUS, ItemRole.toolTip) == "Clock check done; waiting for the other devices"
    assert cell(model, Column.STATUS, ItemRole.active) is False

    model.update("obu1", state=DeviceState.FAILED_UNCLEAN, failure="stop_test: timed out")
    assert cell(model, Column.STATUS) == "Failed (unclean)"
    assert cell(model, Column.STATUS, ItemRole.toolTip) == (
        "Not stopped cleanly: the test or capture may still be running on the device.\nstop_test: timed out"
    )

    model.update("obu1", state=DeviceState.FAILED_CLEAN)
    assert cell(model, Column.STATUS) == "Failed"
    assert cell(model, Column.STATUS, ItemRole.toolTip) == "stop_test: timed out"

    model.update("obu1", state=DeviceState.RUNNING)
    assert cell(model, Column.STATUS, ItemRole.deviceState) == "running"
    assert cell(model, Column.STATUS, ItemRole.active) is True


def test_prechecks_done():
    model = make_model()
    model.reset_status(prechecks=True)
    model.update("obu1", state=DeviceState.DONE)
    assert cell(model, Column.STATUS) == "Ready"


def test_not_ready():
    model = make_model()
    failure = "precheck: C-V2X radio not active (RX Suspended)"
    model.update("obu1", state=DeviceState.NOT_READY, failure=failure)
    assert cell(model, Column.STATUS) == "Not ready"
    assert cell(model, Column.STATUS, ItemRole.toolTip) == failure
    assert cell(model, Column.STATUS, ItemRole.active) is False
    assert cell(model, Column.PROBLEMS) == failure
    assert cell(model, Column.PROBLEMS, ItemRole.toolTip) == f"Not ready:\n{failure}"


def test_clock():
    model = make_model()
    model.update("obu1", clock_offset=4.2, clock_uncertainty=0.004, clock_resolution="ns")
    assert cell(model, Column.CLOCK) == "Δ+4.2 s"
    assert (
        cell(model, Column.CLOCK, ItemRole.toolTip)
        == "Device clock offset +4.200 s (±0.004 s, resolution ns)"
    )
    assert cell(model, Column.CLOCK, ItemRole.clockWarn) is False

    model.update("obu1", clock_warn=True)
    assert cell(model, Column.CLOCK, ItemRole.toolTip).endswith("\nExceeds the clock skew threshold")
    assert cell(model, Column.CLOCK, ItemRole.clockWarn) is True


def test_capture():
    model = make_model()
    model.update("obu1", bytes=310_000)
    assert (cell(model, Column.SIZE), cell(model, Column.PACKETS)) == ("310.0 kB", "")
    model.update("obu1", packets=1204)
    assert (cell(model, Column.SIZE), cell(model, Column.PACKETS)) == ("310.0 kB", "1,204")
    alignment = ItemRole.textAlignment
    assert (
        cell(model, Column.SIZE, alignment)
        == cell(model, Column.PACKETS, alignment)
        == Qt.AlignmentFlag.AlignRight
    )
    assert cell(model, Column.NAME, alignment) is None


def test_problems():
    model = make_model()
    changes = signaled(model)
    model.add_warning("obu1", "clock offset +4.200 s exceeds the threshold (3 s)")
    model.add_warning("obu1", "empty capture")
    assert cell(model, Column.PROBLEMS) == "clock offset +4.200 s exceeds the threshold (3 s) • empty capture"
    assert (
        cell(model, Column.PROBLEMS, ItemRole.toolTip)
        == "Warnings:\nclock offset +4.200 s exceeds the threshold (3 s)\nempty capture"
    )
    assert changes == [(Column.PROBLEMS, {ItemRole.display, ItemRole.toolTip})] * 2

    model.update("obu1", state=DeviceState.FAILED_CLEAN, failure="collect: download of a.pcap failed")
    assert cell(model, Column.PROBLEMS) == "collect: download of a.pcap failed"
    assert cell(model, Column.PROBLEMS, ItemRole.toolTip) == (
        "Error:\ncollect: download of a.pcap failed\n\n"
        "Warnings:\nclock offset +4.200 s exceeds the threshold (3 s)\nempty capture"
    )


def test_set_enabled():
    allowed = True
    model = DeviceTableModel(can_edit=lambda: allowed)
    model.set_devices([DeviceConfig(name="obu1", model="cohda-mk6", host="10.0.0.3")])
    edits = []
    model.edited.connect(lambda: edits.append(True))
    changes = []
    model.dataChanged.connect(lambda first, last, roles: changes.append((first, last, list(roles))))
    enabled = model.index(0, Column.ENABLED)
    check = ItemRole.checkState
    assert model.flags(enabled) & Qt.ItemFlag.ItemIsUserCheckable
    assert not model.flags(model.index(0, Column.NAME)) & Qt.ItemFlag.ItemIsUserCheckable

    assert model.setData(enabled, Qt.CheckState.Unchecked, check)
    assert cell(model, Column.ENABLED, check) == Qt.CheckState.Unchecked
    assert model.setData(enabled, Qt.CheckState.Checked.value, check)  # QML passes an int
    assert cell(model, Column.ENABLED, check) == Qt.CheckState.Checked
    assert len(edits) == 2
    assert changes == [(enabled, enabled, [check])] * 2

    assert not model.setData(enabled, Qt.CheckState.Checked, check)  # no change
    assert not model.setData(enabled, Qt.CheckState.PartiallyChecked, check)
    assert not model.setData(enabled, "x", check)
    assert not model.setData(enabled, Qt.CheckState.Unchecked, Qt.ItemDataRole.EditRole)
    assert not model.setData(model.index(0, Column.NAME), Qt.CheckState.Unchecked, check)
    allowed = False
    assert not model.setData(enabled, Qt.CheckState.Unchecked, check)
    assert cell(model, Column.ENABLED, check) == Qt.CheckState.Checked
    assert len(edits) == 2
    assert len(changes) == 2


def test_signaled_cells():
    model = make_model()
    changes = signaled(model)
    model.setData(model.index(0, Column.ENABLED), Qt.CheckState.Unchecked, ItemRole.checkState)
    assert cell(model, Column.ENABLED, ItemRole.checkState) == Qt.CheckState.Unchecked
    model.update("obu1", packets=10, bytes=1000)
    model.update("obu1", clock_warn=True)
    model.update("obu1", state=DeviceState.FAILED, failure="start_test: exit code 1")
    assert changes == [
        (Column.ENABLED, {ItemRole.checkState}),
        (Column.PACKETS, {ItemRole.display}),
        (Column.SIZE, {ItemRole.display}),
        (Column.CLOCK, {ItemRole.toolTip, ItemRole.clockWarn}),
        (Column.STATUS, {ItemRole.display, ItemRole.toolTip, ItemRole.deviceState, ItemRole.active}),
        (Column.PROBLEMS, {ItemRole.display, ItemRole.toolTip, ItemRole.deviceState}),
    ]

    # Every status change names its roles, and none names the chooser role: otherwise
    # TableView reloads every visible cell (see DeviceTable.qml).
    model.reset_status()
    model.add_warning("obu1", "empty capture")
    assert all(roles and ItemRole.chooser not in roles for _, roles in changes)


def test_update_signals_every_change():
    """update() emits dataChanged() for every cell and role whose data a change of a status
    field affects."""

    def snapshot() -> dict[tuple[Column, ItemRole], Any]:
        return {(c, r): model.data(model.index(0, c), r) for c in Column for r in ItemRole}

    # The clock tooltip needs an uncertainty and a resolution once there is an offset.
    idle = DeviceStatus(clock_uncertainty=0.004, clock_resolution="ns")
    bases = [
        idle,
        replace(idle, state=DeviceState.WAITING, phase="connect", clock_offset=0.5, packets=1, bytes=100),
        replace(idle, state=DeviceState.DONE, prechecks=True),
        replace(
            idle,
            state=DeviceState.FAILED_UNCLEAN,
            failure="stop_test: timed out",
            warnings=["empty capture"],
            clock_offset=4.2,
            clock_warn=True,
        ),
        replace(idle, state=DeviceState.NOT_READY, failure="precheck: C-V2X radio not active (RX Suspended)"),
    ]
    # Two values for each field, so that one differs from the base's.
    values: dict[str, tuple[Any, Any]] = {
        "state": (DeviceState.RUNNING, DeviceState.DONE),
        "prechecks": (True, False),
        "failure": ("start_test: exit code 1", ""),
        "phase": ("precheck", ""),
        "warnings": (["empty capture", "truncated capture"], []),
        "clock_offset": (1.5, None),
        "clock_uncertainty": (0.002, 0.004),
        "clock_resolution": ("us", "ns"),
        "clock_warn": (True, False),
        "packets": (5, None),
        "bytes": (5000, None),
    }
    assert set(values) == {f.name for f in fields(DeviceStatus)}

    model = make_model()
    changes = signaled(model)
    for base in bases:
        for name, (a, b) in values.items():
            model.update("obu1", **asdict(base))
            before = snapshot()
            changes.clear()
            model.update("obu1", **{name: a if getattr(base, name) != a else b})
            after = snapshot()
            changed = {key for key, value in before.items() if after[key] != value}
            assert changed <= {(c, r) for c, roles in changes for r in roles}, (base, name)
