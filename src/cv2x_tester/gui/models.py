# SPDX-License-Identifier: NIST-Software

"""Qt item model for the device table."""

import enum
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QByteArray,
    QModelIndex,
    QPersistentModelIndex,
    Qt,
    Signal,
)

from ..config import DeviceConfig
from ..events import DeviceState
from ..util import format_offset, human_bytes

STATE_TEXT = {
    DeviceState.IDLE: "Idle",
    DeviceState.CONNECTING: "Connecting",
    DeviceState.PRECHECK: "Pre-check",
    DeviceState.CLOCK: "Clock check",
    DeviceState.STARTING_CAPTURE: "Starting capture",
    DeviceState.STARTING_TEST: "Starting test",
    DeviceState.WAITING: "Waiting",
    DeviceState.RUNNING: "Running",
    DeviceState.STOPPING_TEST: "Stopping test",
    DeviceState.STOPPING_CAPTURE: "Stopping capture",
    DeviceState.COLLECTING: "Collecting",
    DeviceState.DONE: "Done",
    DeviceState.NOT_READY: "Not ready",
    DeviceState.FAILED: "Failed",
    DeviceState.FAILED_CLEAN: "Failed",  # only unclean failures get a suffix
    DeviceState.FAILED_UNCLEAN: "Failed (unclean)",
    DeviceState.ABORTED: "Aborted",
}
READY_TEXT = "Ready"  # instead of "Done" after pre-checks

# What a WAITING device has finished, by phase.
PHASE_DONE_TEXT = {
    "connect": "Connected",
    "precheck": "Pre-check done",
    "clock": "Clock check done",
    "start_capture": "Capture started",
    "stop_test": "Test stopped",
}


@dataclass
class DeviceStatus:
    """Runtime status of a device in the current/last run or pre-checks."""

    state: DeviceState = DeviceState.IDLE
    prechecks: bool = False  # status comes from pre-checks, not a run
    failure: str = ""
    phase: str = ""  # for WAITING: the phase the device has finished
    warnings: list[str] = field(default_factory=list)
    clock_offset: float | None = None
    clock_uncertainty: float | None = None
    clock_resolution: str = ""
    clock_warn: bool = False
    packets: int | None = None
    bytes: int | None = None


@dataclass
class Row:
    cfg: DeviceConfig
    status: DeviceStatus = field(default_factory=DeviceStatus)


@enum.unique
class Column(enum.IntEnum):
    """Columns of the device table. Keep them in sync with the Column enum in DeviceTable.qml."""

    ENABLED = 0
    NAME = 1
    MODEL = 2
    ROLE = 3
    ADDRESS = 4
    STATUS = 5
    CLOCK = 6
    SIZE = 7
    PACKETS = 8
    PROBLEMS = 9


_HEADERS = {
    Column.ENABLED: "",
    Column.NAME: "Name",
    Column.MODEL: "Model",
    Column.ROLE: "Role",
    Column.ADDRESS: "Address",
    Column.STATUS: "Status",
    Column.CLOCK: "Clock",
    Column.SIZE: "Capture size",
    Column.PACKETS: "Packets",
    Column.PROBLEMS: "Problems",
}
_NUMERIC_COLUMNS = (Column.SIZE, Column.PACKETS)


@enum.unique
class ItemRole(enum.IntEnum):
    """The model's roles. The names of the custom ones, for the cells styled in QML, must not
    conflict with properties that QML delegates already have, such as "state", "row" or
    "column"."""

    display = Qt.ItemDataRole.DisplayRole
    toolTip = Qt.ItemDataRole.ToolTipRole
    checkState = Qt.ItemDataRole.CheckStateRole
    textAlignment = Qt.ItemDataRole.TextAlignmentRole
    chooser = Qt.ItemDataRole.UserRole  # for DeviceTable's DelegateChooser, never changes
    deviceState = enum.auto()
    active = enum.auto()
    clockWarn = enum.auto()


# For each DeviceStatus field, the columns that show it and the roles they show it in. When
# the field changes, dataChanged() is emitted for only these columns and roles. A
# dataChanged() without roles would mean that all of them changed, including the chooser
# role, and TableView would reload every visible cell (see DeviceTable.qml).
_FIELD_CELLS: dict[str, dict[Column, tuple[ItemRole, ...]]] = {
    "state": {
        Column.STATUS: (ItemRole.display, ItemRole.toolTip, ItemRole.deviceState, ItemRole.active),
        Column.PROBLEMS: (ItemRole.toolTip, ItemRole.deviceState),
    },
    "prechecks": {Column.STATUS: (ItemRole.display,)},
    "failure": {Column.STATUS: (ItemRole.toolTip,), Column.PROBLEMS: (ItemRole.display, ItemRole.toolTip)},
    "phase": {Column.STATUS: (ItemRole.toolTip,)},
    "warnings": {Column.PROBLEMS: (ItemRole.display, ItemRole.toolTip)},
    "clock_offset": {Column.CLOCK: (ItemRole.display, ItemRole.toolTip)},
    "clock_uncertainty": {Column.CLOCK: (ItemRole.toolTip,)},
    "clock_resolution": {Column.CLOCK: (ItemRole.toolTip,)},
    "clock_warn": {Column.CLOCK: (ItemRole.toolTip, ItemRole.clockWarn)},
    "packets": {Column.PACKETS: (ItemRole.display,)},
    "bytes": {Column.SIZE: (ItemRole.display,)},
}

_INACTIVE_STATES = (
    DeviceState.IDLE,
    DeviceState.WAITING,
    DeviceState.DONE,
    DeviceState.NOT_READY,
    DeviceState.FAILED,
    DeviceState.FAILED_CLEAN,
    DeviceState.FAILED_UNCLEAN,
    DeviceState.ABORTED,
)


class DeviceTableModel(QAbstractTableModel):
    # A device was enabled or disabled through setData().
    edited = Signal()

    def __init__(self, parent: Any = None, can_edit: Callable[[], bool] = lambda: True) -> None:
        super().__init__(parent)
        self._rows: list[Row] = []
        # Whether setData() may change devices right now.
        self._can_edit = can_edit

    # -- Qt API -----------------------------------------------------------------

    def roleNames(self) -> dict[int, QByteArray]:
        return {r: QByteArray(r.name.encode()) for r in ItemRole}

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(Column)

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if orientation is not Qt.Orientation.Horizontal:
            return None
        column = Column(section)
        match role:
            case ItemRole.display:
                return _HEADERS[column]
            case ItemRole.textAlignment:
                return (
                    Qt.AlignmentFlag.AlignRight if column in _NUMERIC_COLUMNS else Qt.AlignmentFlag.AlignLeft
                )
        return None

    def data(
        self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if not index.isValid() or not 0 <= index.row() < len(self._rows):
            return None
        row = self._rows[index.row()]
        column = Column(index.column())
        match role, column:
            case ItemRole.display, _:
                return self._text(row, column)
            case ItemRole.toolTip, _:
                return self._tooltip(row, column)
            case ItemRole.checkState, Column.ENABLED:
                return Qt.CheckState.Checked if row.cfg.enabled else Qt.CheckState.Unchecked
            case ItemRole.textAlignment, _ if column in _NUMERIC_COLUMNS:
                return Qt.AlignmentFlag.AlignRight
            case ItemRole.deviceState, Column.STATUS | Column.PROBLEMS:
                return str(row.status.state)
            case ItemRole.active, Column.STATUS:
                return row.status.state not in _INACTIVE_STATES
            case ItemRole.clockWarn, Column.CLOCK:
                return row.status.clock_warn
        return None

    def flags(self, index: QModelIndex | QPersistentModelIndex) -> Qt.ItemFlag:
        flags = super().flags(index)
        if index.isValid() and index.column() == Column.ENABLED:
            flags |= Qt.ItemFlag.ItemIsUserCheckable
        return flags

    def setData(
        self, index: QModelIndex | QPersistentModelIndex, value: Any, role: int = Qt.ItemDataRole.EditRole
    ) -> bool:
        """Enable or disable a device through the check state of the enabled column. Return False
        for other columns, roles and values, when nothing changes, or when editing isn't allowed."""
        if role != ItemRole.checkState or not self.flags(index) & Qt.ItemFlag.ItemIsUserCheckable:
            return False
        try:
            # QML passes the state as an int, Python as a Qt.CheckState.
            enabled = {Qt.CheckState.Unchecked: False, Qt.CheckState.Checked: True}[Qt.CheckState(value)]
        except ValueError, KeyError:
            return False
        cfg = self._rows[index.row()].cfg
        if enabled == cfg.enabled or not self._can_edit():
            return False
        cfg.enabled = enabled
        self.dataChanged.emit(index, index, [role])
        self.edited.emit()
        return True

    def _text(self, row: Row, column: Column) -> str:
        cfg, st = row.cfg, row.status
        driver = cfg.driver_class
        match column:
            case Column.NAME:
                return cfg.name
            case Column.MODEL:
                return driver.display_name if driver else cfg.model
            case Column.ROLE:
                return cfg.role.upper()
            case Column.ADDRESS:
                if driver is not None and not driver.uses_ssh:
                    return "—"
                return cfg.address if cfg.host else ""
            case Column.STATUS:
                if st.state is DeviceState.DONE and st.prechecks:
                    return READY_TEXT
                return STATE_TEXT[st.state]
            case Column.CLOCK:
                if st.clock_offset is None:
                    return ""
                return f"Δ{format_offset(st.clock_offset, 1)}"
            case Column.SIZE:
                return human_bytes(st.bytes)
            case Column.PACKETS:
                return "" if st.packets is None else f"{st.packets:,}"
            case Column.PROBLEMS:
                # Only the error if there is one. Joined with the warnings, it could be read as one message.
                return st.failure or " • ".join(st.warnings)
        return ""

    def _tooltip(self, row: Row, column: Column) -> str:
        st = row.status
        match column:
            case Column.ENABLED:
                return "Include this device in runs"
            case Column.STATUS:
                if st.state is DeviceState.WAITING:
                    note = f"{PHASE_DONE_TEXT.get(st.phase, st.phase)}; waiting for the other devices"
                elif st.state is DeviceState.FAILED_UNCLEAN:
                    note = "Not stopped cleanly: the test or capture may still be running on the device."
                else:
                    return st.failure
                return f"{note}\n{st.failure}" if st.failure else note
            case Column.CLOCK:
                if st.clock_offset is None:
                    return ""
                tip = (
                    f"Device clock offset {format_offset(st.clock_offset)} "
                    f"(±{st.clock_uncertainty:.3f} s, resolution {st.clock_resolution})"
                )
                return f"{tip}\nExceeds the clock skew threshold" if st.clock_warn else tip
            case Column.PROBLEMS:
                label = "Not ready" if st.state is DeviceState.NOT_READY else "Error"
                sections = [f"{label}:\n{st.failure}"] if st.failure else []
                if st.warnings:
                    sections.append("Warnings:\n" + "\n".join(st.warnings))
                return "\n\n".join(sections)
        return ""

    def _status_changed(self, row: int, fields: Iterable[str]) -> None:
        """Emit dataChanged() for the cells and roles that show the given fields of a row's status."""
        cells: dict[Column, set[ItemRole]] = {}
        for f in fields:
            for column, roles in _FIELD_CELLS[f].items():
                cells.setdefault(column, set()).update(roles)
        for column, changed in cells.items():
            index = self.index(row, column)
            self.dataChanged.emit(index, index, list(changed))

    # -- devices ----------------------------------------------------------------

    def device(self, row: int) -> DeviceConfig | None:
        return self._rows[row].cfg if 0 <= row < len(self._rows) else None

    def row_of(self, name: str) -> int:
        return next((i for i, r in enumerate(self._rows) if r.cfg.name == name), -1)

    def set_devices(self, devices: list[DeviceConfig]) -> None:
        self.beginResetModel()
        self._rows = [Row(d) for d in devices]
        self.endResetModel()

    def append(self, cfg: DeviceConfig) -> int:
        n = len(self._rows)
        self.beginInsertRows(QModelIndex(), n, n)
        self._rows.append(Row(cfg))
        self.endInsertRows()
        return n

    def replace(self, row: int, cfg: DeviceConfig) -> None:
        self._rows[row] = Row(cfg)
        self.dataChanged.emit(self.index(row, 0), self.index(row, len(Column) - 1))

    def remove(self, row: int) -> None:
        self.beginRemoveRows(QModelIndex(), row, row)
        del self._rows[row]
        self.endRemoveRows()

    # -- runtime status ---------------------------------------------------------

    def status(self, name: str) -> DeviceStatus | None:
        row = self.row_of(name)
        return self._rows[row].status if row >= 0 else None

    def reset_status(self, names: set[str] | None = None, *, prechecks: bool = False) -> None:
        """Clear the status of the named devices (by default all of them) before a run or
        pre-checks. Pass ``prechecks=True`` for pre-checks, so that the devices that pass them
        get the right status label."""
        for i, r in enumerate(self._rows):
            if names is None or r.cfg.name in names:
                r.status = DeviceStatus(prechecks=prechecks)
                self._status_changed(i, _FIELD_CELLS)

    def update(self, name: str, **changes: Any) -> None:
        """Set fields of a device's status, and refresh only the cells that show them."""
        row = self.row_of(name)
        if row < 0:
            return
        st = self._rows[row].status
        for k, v in changes.items():
            setattr(st, k, v)
        self._status_changed(row, changes)

    def add_warning(self, name: str, message: str) -> None:
        st = self.status(name)
        if st is not None:
            st.warnings.append(message)
            self._status_changed(self.row_of(name), ["warnings"])
