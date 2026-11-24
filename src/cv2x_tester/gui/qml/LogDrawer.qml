// SPDX-License-Identifier: NIST-Software

import CV2XTester
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Drawer {
    id: drawer

    property string device: ""

    function showDevice(name: string): void {
        device = name || (Controller.deviceNames[0] ?? "")
        deviceCombo.currentIndex = deviceCombo.indexOfValue(device)
        reload()
        open()
    }

    function reload(): void {
        logArea.text = device ? Controller.logText(device) : ""
        Qt.callLater(scrollToEnd)
    }

    function atEnd(): bool {
        const bar = scroll.ScrollBar.vertical
        return bar.position + bar.size >= 0.999
    }

    function scrollToEnd(): void {
        const bar = scroll.ScrollBar.vertical
        bar.position = Math.max(0, 1.0 - bar.size)
    }

    edge: Qt.RightEdge
    modal: false
    interactive: false
    closePolicy: Popup.CloseOnEscape

    Connections {
        function onLogLine(device, line) {
            if (device !== drawer.device || !drawer.opened)
                return
            const follow = drawer.atEnd()
            logArea.append(line)
            if (follow)
                Qt.callLater(drawer.scrollToEnd)
        }

        function onLogCleared(device) {
            if (device === drawer.device)
                logArea.text = ""
        }

        target: Controller
    }
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 8

        RowLayout {
            Layout.fillWidth: true

            Label {
                text: "Log"
                font.bold: true
            }
            ComboBox {
                id: deviceCombo

                model: Controller.deviceNames
                Layout.fillWidth: true
                Layout.maximumWidth: 250

                onActivated: {
                    drawer.device = currentText
                    drawer.reload()
                }
            }
            Item {
                Layout.fillWidth: true
            }
            Button {
                text: "Copy"
                icon.source: "icons/edit-copy.svg"
                enabled: logArea.length > 0

                onClicked: Controller.copyLog(drawer.device)
            }
            Button {
                text: "Clear"
                icon.source: "icons/edit-clear.svg"
                enabled: logArea.length > 0

                onClicked: Controller.clearLog(drawer.device)
            }
            IconToolButton {
                text: "Close"
                icon.source: "icons/window-close.svg"
                display: AbstractButton.IconOnly
                ToolTip.text: text

                onClicked: drawer.close()
            }
        }
        ScrollView {
            id: scroll

            Layout.fillWidth: true
            Layout.fillHeight: true

            TextArea {
                id: logArea

                readOnly: true
                wrapMode: TextArea.NoWrap
                font.family: Controller.monoFont
                font.pointSize: Application.font.pointSize * 0.9
                placeholderText: drawer.device ? "No output yet for %1.".arg(drawer.device) : "No devices."
            }
        }
    }
}
