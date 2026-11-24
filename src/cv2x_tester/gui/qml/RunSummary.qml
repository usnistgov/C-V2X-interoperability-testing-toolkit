// SPDX-License-Identifier: NIST-Software

pragma ComponentBehavior: Bound

import CV2XTester
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "colors.js" as Colors

Dialog {
    id: dlg

    property var summary: ({
                               devices: [],
                               uncleanDevices: []
                           })
    // Size that fits the content, within the main window's height. The device table is the
    // widest content that doesn't wrap. Taking the dialog's implicitWidth instead prints a
    // binding loop warning when the dialog is wider than 80% of the main window (seen with
    // Qt 6.12 on Wayland).
    readonly property real fitWidth: Math.min(800, Math.max(tableHeader.implicitWidth + leftPadding + rightPadding, Overlay.overlay.width * 0.8))
    readonly property real fitHeight: Math.min(implicitHeight, Overlay.overlay.height * 0.8)

    function show(s: var): void {
        summary = s
        width = fitWidth
        // Follow the content until the dialog is on screen (see onOpened).
        height = Qt.binding(() => fitHeight)
        open()
    }

    title: "Run finished"
    popupType: Popup.Window
    modal: true
    anchors.centerIn: Overlay.overlay
    standardButtons: Dialog.Close

    Component.onCompleted: (footer as DialogButtonBox).defaultStandardButton = Dialog.Close
    // Unbind the height after the first frame, when the content has been laid out, so that
    // it doesn't snap back when a resize rewraps the text. Use fitHeight, as height can
    // still lag behind the window.
    onOpened: {
        const window = contentItem.Window.window
        const unbind = () => {
            window.frameSwapped.disconnect(unbind)
            dlg.height = dlg.fitHeight
        }
        window.frameSwapped.connect(unbind)
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 10

        Label {
            text: dlg.summary.outcomeText || ""
            font.bold: true
            font.pointSize: Application.font.pointSize * 1.25
            color: Colors.outcomeColor(dlg.summary.outcome)
        }
        Label {
            visible: dlg.summary.uncleanDevices.length > 0
            text: "Not stopped cleanly; the test or capture may still be running on: %1".arg(dlg.summary.uncleanDevices.join(", "))
            color: Colors.current().unclean
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        GridLayout {
            columns: 2
            columnSpacing: 12
            rowSpacing: 6

            Label {
                text: "Test duration:"
                color: palette.placeholderText
            }
            Label {
                text: (dlg.summary.duration || "") + (dlg.summary.stoppedEarly ? " (stopped early)" : "")
            }
            Label {
                text: "Start skew:"
                color: palette.placeholderText
                visible: !!dlg.summary.startSkew
            }
            Label {
                text: dlg.summary.startSkew || ""
                visible: !!dlg.summary.startSkew
            }
            Label {
                text: "Run folder:"
                color: palette.placeholderText
                visible: dlg.summary.runDir !== ""
            }
            RowLayout {
                visible: dlg.summary.runDir !== ""
                Layout.fillWidth: true

                TextField {
                    text: dlg.summary.runDir || ""
                    readOnly: true
                    Layout.fillWidth: true
                    Layout.minimumWidth: 400
                }
                Button {
                    text: "Open"
                    icon.source: "icons/folder-open.svg"

                    onClicked: Controller.openPath(dlg.summary.runDir)
                }
            }
        }
        Label {
            visible: !!dlg.summary.error
            text: dlg.summary.error || ""
            color: Colors.current().failed
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        // Device table. It takes the height left by the rest of the dialog, and its rows
        // scroll under the header.
        ColumnLayout {
            visible: dlg.summary.devices.length > 0
            spacing: 0
            Layout.fillWidth: true
            Layout.fillHeight: true

            Rectangle {
                id: tableHeader

                implicitWidth: headerRow.implicitWidth + 16
                implicitHeight: 26
                color: palette.button
                Layout.fillWidth: true

                RowLayout {
                    id: headerRow

                    anchors.fill: parent
                    anchors.leftMargin: 8
                    anchors.rightMargin: 8
                    spacing: 10

                    Label {
                        text: "Device"
                        font.bold: true
                        Layout.preferredWidth: 110
                    }
                    Label {
                        text: "State"
                        font.bold: true
                        Layout.preferredWidth: 110
                    }
                    Label {
                        text: "Capture"
                        font.bold: true
                        Layout.preferredWidth: 180
                    }
                    Label {
                        text: "Packets"
                        font.bold: true
                        Layout.preferredWidth: 70
                    }
                    Label {
                        text: "Problems"
                        font.bold: true
                        Layout.fillWidth: true
                        Layout.minimumWidth: 200
                    }
                }
            }
            ScrollView {
                id: rowsView

                contentWidth: availableWidth
                Layout.fillWidth: true
                Layout.fillHeight: true

                background: Rectangle {
                    color: palette.base
                }

                ColumnLayout {
                    width: rowsView.availableWidth
                    spacing: 0

                    Repeater {
                        model: dlg.summary.devices

                        delegate: Item {
                            id: deviceRow

                            required property string name
                            required property string stateText
                            required property string stateId
                            required property string pcap
                            required property string pcapPath
                            required property string pcapSize
                            required property string packets
                            required property string problems

                            implicitHeight: Math.max(28, problemsLabel.implicitHeight + 10)
                            Layout.fillWidth: true

                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: 8
                                anchors.rightMargin: 8
                                spacing: 10

                                Label {
                                    text: deviceRow.name
                                    font.bold: true
                                    elide: Text.ElideRight
                                    Layout.preferredWidth: 110
                                }
                                Label {
                                    text: deviceRow.stateText
                                    color: Colors.stateColor(deviceRow.stateId)
                                    Layout.preferredWidth: 110
                                }
                                // The file name is a link that opens the pcap with the default application.
                                Label {
                                    id: pcapLabel

                                    text: deviceRow.pcap !== "" ? `<a href="pcap">${deviceRow.pcap}</a> (${deviceRow.pcapSize})` : "—"
                                    textFormat: Text.StyledText
                                    linkColor: Colors.linkColor(palette.link)
                                    elide: Text.ElideMiddle
                                    Layout.preferredWidth: 180

                                    onLinkActivated: Controller.openPath(deviceRow.pcapPath)

                                    HoverHandler {
                                        cursorShape: pcapLabel.hoveredLink !== "" ? Qt.PointingHandCursor : Qt.ArrowCursor
                                    }
                                }
                                Label {
                                    text: deviceRow.packets
                                    Layout.preferredWidth: 70
                                }
                                Label {
                                    id: problemsLabel

                                    text: deviceRow.problems
                                    color: palette.placeholderText
                                    wrapMode: Text.Wrap
                                    Layout.fillWidth: true
                                    Layout.minimumWidth: 200
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
