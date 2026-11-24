// SPDX-License-Identifier: NIST-Software

import CV2XTester
import QtQuick
import QtQuick.Controls
import QtQuick.Dialogs
import QtQuick.Layouts
import "colors.js" as Colors

FormDialog {
    id: dlg

    property string errorText: ""
    readonly property var schema: Controller.settingsSchema

    function openWith(data: var): void {
        outputField.text = data.outputDir
        durationField.text = data.defaultDuration
        connectBox.value = data.connectTimeout
        commandBox.value = data.commandTimeout
        stopBox.value = data.stopTimeout
        collectBox.value = data.collectTimeout
        skewBox.value = data.clockSkewWarning
        validate()
        open()
    }

    function collect(): var {
        return {
            outputDir: outputField.text,
            defaultDuration: durationField.text,
            connectTimeout: connectBox.value,
            commandTimeout: commandBox.value,
            stopTimeout: stopBox.value,
            collectTimeout: collectBox.value,
            clockSkewWarning: skewBox.value
        }
    }

    function validate(): void {
        errorText = Controller.settingsError(collect())
        standardButton(Dialog.Ok).enabled = errorText === ""
    }

    title: "Run settings"
    width: Math.min(560, Overlay.overlay.width * 0.8)

    onSubmitted: Controller.applySettings(collect())

    ColumnLayout {
        anchors.fill: parent
        spacing: 8

        GridLayout {
            columns: 2
            columnSpacing: 12
            rowSpacing: 8
            Layout.fillWidth: true

            Label {
                text: "Output directory"
            }
            RowLayout {
                Layout.fillWidth: true

                TextField {
                    id: outputField

                    Layout.fillWidth: true
                    ToolTip.text: "Absolute, or relative to the current directory; a leading ~ is expanded"

                    onTextChanged: dlg.validate()
                }
                Button {
                    text: "Browse…"

                    onClicked: folderDialog.open()
                }
            }
            Item {}
            Label {
                text: Controller.resolveOutputDir(outputField.text)
                color: palette.placeholderText
                font.pointSize: Application.font.pointSize * 0.9
                elide: Text.ElideMiddle
                Layout.fillWidth: true
            }
            Label {
                text: "Default test duration"
            }
            TextField {
                id: durationField

                color: Controller.durationError(text) === "" ? palette.text : Colors.validationError
                Layout.preferredWidth: 140
                ToolTip.text: "Seconds (90), M:SS (1:30), H:MM:SS, or with units (1m30s)"

                onTextChanged: dlg.validate()
            }
            Label {
                text: "Connect timeout (s)"
            }
            SpinBox {
                id: connectBox

                editable: true
                from: dlg.schema.connect_timeout.min
                to: dlg.schema.connect_timeout.max
            }
            Label {
                text: "Command timeout (s)"
            }
            SpinBox {
                id: commandBox

                editable: true
                from: dlg.schema.command_timeout.min
                to: dlg.schema.command_timeout.max
            }
            Label {
                text: "Stop timeout (s)"
            }
            SpinBox {
                id: stopBox

                editable: true
                from: dlg.schema.stop_timeout.min
                to: dlg.schema.stop_timeout.max
            }
            Label {
                text: "Collect timeout (s)"
            }
            SpinBox {
                id: collectBox

                editable: true
                from: dlg.schema.collect_timeout.min
                to: dlg.schema.collect_timeout.max
            }
            Label {
                text: "Clock skew warning (s)"
            }
            DoubleSpinBox {
                id: skewBox

                editable: true
                decimals: dlg.schema.clock_skew_warning.decimals
                from: dlg.schema.clock_skew_warning.min
                to: dlg.schema.clock_skew_warning.max
                ToolTip.text: "Device clock offsets above this produce a warning (0 turns the warning off)"
            }
        }
        ErrorLabel {
            text: dlg.errorText
        }
    }
    FolderDialog {
        id: folderDialog

        title: "Select output directory"

        onAccepted: outputField.text = Controller.localPath(selectedFolder.toString())
    }
}
