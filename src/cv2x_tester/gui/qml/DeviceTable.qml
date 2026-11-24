// SPDX-License-Identifier: NIST-Software

pragma ComponentBehavior: Bound

import CV2XTester
import QtQml.Models
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "colors.js" as Colors

Control {
    id: deviceTable

    // Columns of the device table. Keep them in sync with the Column enum in models.py.
    enum Column {
        Enabled,
        Name,
        Model,
        Role,
        Address,
        Status,
        Clock,
        Size,
        Packets,
        Problems
    }
    // Padding of the table's cells. It's an enum rather than a property of the table so
    // that Cell, an inline component, can read it as a typed value.
    enum Metrics {
        CellPadding = 8
    }

    readonly property alias currentRow: table.currentRow
    readonly property alias count: table.rows
    property Menu contextMenu

    // Columns that share the leftover width, unless the user resized them.
    readonly property list<int> stretchColumns: [DeviceTable.Name, DeviceTable.Address, DeviceTable.Problems]

    // Status cell: size of the dot and space between the dot and the text.
    readonly property int statusDotSize: 12
    readonly property int statusSpacing: 6

    // Minimum widths of the columns whose text changes during a run, so they don't jump:
    // wide enough for their longest text (see models.py).
    readonly property var minimumWidths: {
        const padding = 2 * DeviceTable.CellPadding
        const widest = (metrics, texts) => Math.ceil(Math.max(...texts.map(t => metrics.advanceWidth(t))))
        return {
            [DeviceTable.Status]: widest(textMetrics, Controller.deviceStatusTexts) + statusDotSize + statusSpacing + padding,
            [DeviceTable.Clock]: widest(textMetrics, ["Δ+00.0 s"]) + padding,
            [DeviceTable.Size]: widest(monoMetrics, ["999.9 MB"]) + padding,
            [DeviceTable.Packets]: widest(monoMetrics, ["999,999"]) + padding
        }
    }

    // Natural widths of the columns at the last refit().
    property list<real> naturalWidths: []

    signal editRequested(int row)
    signal removeRequested(int row)

    // Width of a column without its share of the leftover width: the width the user
    // dragged it to, otherwise the widest of its cells, its header and its minimum.
    // -1 while the column's cells aren't loaded yet: TableView then measures it itself.
    function naturalWidth(column: int): real {
        const explicit = table.explicitColumnWidth(column)
        if (explicit >= 0)
            return explicit
        const content = table.implicitColumnWidth(column)
        if (content < 0)
            return -1
        return Math.max(content, header.implicitColumnWidth(column), minimumWidths[column] ?? 0)
    }

    function columnWidth(column: int): real {
        const width = naturalWidth(column)
        const stretch = stretchColumns.filter(c => table.explicitColumnWidth(c) < 0)
        if (width < 0 || !stretch.includes(column))
            return width
        let used = table.columnSpacing * (table.columns - 1)
        for (let c = 0; c < table.columns; ++c) {
            const w = naturalWidth(c)
            if (w < 0)
                return width
            used += w
        }
        return width + Math.max(0, table.width - used) / stretch.length
    }

    // Refit the columns when a change in the cells changes their natural widths (e.g. a
    // longer name, a new warning), not on every stats update during a run.
    function refit(): void {
        const widths = []
        for (let c = 0; c < table.columns; ++c)
            widths.push(naturalWidth(c))
        if (widths.join() !== naturalWidths.join()) {
            naturalWidths = widths
            table.forceLayout()
        }
    }

    FontMetrics {
        id: textMetrics

        font: deviceTable.font
    }
    FontMetrics {
        id: monoMetrics

        font.family: Controller.monoFont
        font.pointSize: deviceTable.font.pointSize
    }
    Connections {
        function onDataChanged() {
            Qt.callLater(deviceTable.refit)
        }

        target: Controller.devices
    }
    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        HorizontalHeaderView {
            id: header

            visible: table.rows > 0
            syncView: table
            resizableColumns: true
            clip: true
            Layout.fillWidth: true

            // The style's header label ignores the model's text alignment.
            delegate: HorizontalHeaderViewDelegate {
                id: headerCell

                required property int textAlignment

                font.bold: true

                Binding {
                    target: headerCell.contentItem
                    property: "horizontalAlignment"
                    value: headerCell.textAlignment
                }
            }
        }
        TableView {
            id: table

            clip: true
            focus: true
            model: Controller.devices
            selectionBehavior: TableView.SelectRows
            selectionMode: TableView.SingleSelection
            // TableViewDelegate has an inline editor.
            editTriggers: TableView.NoEditTriggers
            alternatingRows: false
            columnWidthProvider: column => deviceTable.columnWidth(column)
            Layout.fillWidth: true
            Layout.fillHeight: true

            ScrollBar.vertical: ScrollBar {}
            ScrollBar.horizontal: ScrollBar {}
            // Clicks and arrow keys only move the current cell: select its row.
            selectionModel: ItemSelectionModel {
                onCurrentChanged: current => {
                    if (current.valid)
                        select(current, ItemSelectionModel.ClearAndSelect | ItemSelectionModel.Rows)
                }
            }
            delegate: DelegateChooser {
                // Workaround for QTBUG-151942 (seen with Qt 6.12): without a role, TableView
                // reloads every visible cell whenever the text of any cell changes. The
                // delegate choices depend only on the column, so the chooser gets a role that
                // never changes.
                role: "chooser"

                DelegateChoice {
                    column: DeviceTable.Enabled

                    Cell {
                        id: enabledCell

                        contentItem: Item {
                            implicitWidth: box.implicitWidth
                            implicitHeight: box.implicitHeight

                            CheckBox {
                                id: box

                                anchors.centerIn: parent
                                // Not taller than the text cells, which set the row height.
                                padding: 0
                                // The box only shows the model's state. Clicking asks the model to change it.
                                checkable: false
                                checked: enabledCell.model.checkState === Qt.Checked
                                enabled: !Controller.busy

                                // Don't use a required checkState property here. Writing to one needs
                                // the view's delegateModelAccess set to ReadWrite, and it keeps the new
                                // value even when the model refuses it, leaving the box out of sync.
                                onClicked: enabledCell.model.checkState = checked ? Qt.Unchecked : Qt.Checked
                            }
                        }
                    }
                }
                DelegateChoice {
                    column: DeviceTable.Name

                    Cell {
                        font.bold: true
                    }
                }
                DelegateChoice {
                    column: DeviceTable.Address

                    Cell {
                        font.family: Controller.monoFont
                    }
                }
                DelegateChoice {
                    column: DeviceTable.Status

                    Cell {
                        id: statusCell

                        required property string deviceState
                        required property bool active
                        property bool pooled: false

                        contentItem: RowLayout {
                            spacing: deviceTable.statusSpacing

                            Rectangle {
                                readonly property string deviceState: statusCell.deviceState

                                implicitWidth: deviceTable.statusDotSize
                                implicitHeight: deviceTable.statusDotSize
                                radius: deviceTable.statusDotSize / 2
                                color: deviceState === "idle" ? "transparent" : Colors.stateColor(deviceState)
                                border.width: 2
                                border.color: Colors.stateColor(deviceState)

                                NumberAnimation on opacity {
                                    from: 1.0
                                    to: 0.3
                                    easing.type: Easing.SineCurve
                                    duration: 1000
                                    loops: Animation.Infinite
                                    running: statusCell.active && !statusCell.pooled
                                    alwaysRunToEnd: true
                                }
                            }
                            Label {
                                text: statusCell.model.display
                                elide: Text.ElideRight
                                color: {
                                    if (statusCell.highlighted)
                                        return statusCell.palette.highlightedText
                                    // The text is colored only for the states that need the user's attention: not ready and failed.
                                    const deviceState = statusCell.deviceState
                                    if (deviceState === "not_ready" || deviceState.startsWith("failed"))
                                        return Colors.stateColor(deviceState)
                                    return statusCell.palette.buttonText
                                }
                                Layout.fillWidth: true
                            }
                        }

                        TableView.onPooled: pooled = true
                        TableView.onReused: pooled = false
                    }
                }
                DelegateChoice {
                    column: DeviceTable.Clock

                    Cell {
                        required property bool clockWarn

                        palette.buttonText: clockWarn ? Colors.current().warning : deviceTable.palette.buttonText
                    }
                }
                DelegateChoice {
                    column: DeviceTable.Size

                    Cell {
                        font.family: Controller.monoFont
                    }
                }
                DelegateChoice {
                    column: DeviceTable.Packets

                    Cell {
                        font.family: Controller.monoFont
                    }
                }
                DelegateChoice {
                    column: DeviceTable.Problems

                    Cell {
                        required property string deviceState

                        palette.buttonText: deviceState.startsWith("failed") ? Colors.stateColor(deviceState) : Colors.current().warning
                    }
                }
                DelegateChoice {
                    Cell {}
                }
            }

            onWidthChanged: forceLayout()
            onRowsChanged: Qt.callLater(forceLayout)
            Keys.onReturnPressed: {
                if (currentRow >= 0)
                    deviceTable.editRequested(currentRow)
            }
            Keys.onDeletePressed: {
                if (currentRow >= 0)
                    deviceTable.removeRequested(currentRow)
            }

            // Not ContextMenu.menu: that would also open the menu below the last row.
            ContextMenu.onRequested: position => {
                const cell = table.cellAtPosition(table.mapToItem(table.contentItem, position))
                if (cell.y < 0)
                    return
                table.selectionModel.setCurrentIndex(table.index(cell.y, cell.x), ItemSelectionModel.NoUpdate)
                table.forceActiveFocus()
                deviceTable.contextMenu?.popup(table, position)
            }

            TapHandler {
                onDoubleTapped: eventPoint => {
                    const cell = table.cellAtPosition(eventPoint.position)
                    if (cell.y >= 0)
                        deviceTable.editRequested(cell.y)
                }
            }
        }
    }
    Label {
        anchors.centerIn: parent
        visible: table.rows === 0
        text: "No devices configured.\nClick \"Add\" to create one."
        horizontalAlignment: Text.AlignHCenter
        color: palette.placeholderText
    }

    // Base delegate of all columns: Qt's TableViewDelegate with fixed padding and the
    // model's tooltip.
    component Cell: TableViewDelegate {
        id: cell

        required property string toolTip
        // Undefined except in the numeric columns.
        required property var textAlignment

        padding: DeviceTable.CellPadding
        ToolTip.text: cell.toolTip

        // Qt's label ignores the model's text alignment.
        Binding {
            target: cell.contentItem
            property: "horizontalAlignment"
            value: cell.textAlignment
            when: cell.textAlignment !== undefined
        }
    }
}
