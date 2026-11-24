// SPDX-License-Identifier: NIST-Software

import CV2XTester
import QtQuick
import QtQuick.Controls
import QtQuick.Dialogs
import QtQuick.Layouts
import "colors.js" as Colors

ApplicationWindow {
    id: win

    function selectedName(): string {
        const row = table.currentRow
        return row >= 0 && row < table.count ? Controller.deviceNames[row] : ""
    }

    // Call `openFunc`, which opens a dialog, once the main window is exposed (on screen).
    // This is a workaround for QTBUG-152296 (a dialog that opens while the main window
    // isn't exposed keeps reopening). A window draws frames only while it is exposed, so
    // this function waits for the main window's next frame.
    function whenExposed(openFunc: var): void {
        const run = () => {
            win.frameSwapped.disconnect(run)
            openFunc()
        }
        win.frameSwapped.connect(run)
        win.update()
    }

    width: 1200
    height: 640
    minimumWidth: 700
    minimumHeight: 400
    title: Controller.title
    visible: true

    // ------------------------------------------------------------------ menu

    menuBar: MenuBar {
        Menu {
            title: "&File"
            popupType: Popup.Native

            Action {
                text: "&Open…"
                shortcut: StandardKey.Open
                enabled: !Controller.busy

                onTriggered: Controller.requestOpen()
            }
            Action {
                text: "&Save"
                shortcut: StandardKey.Save

                onTriggered: Controller.save()
            }
            Action {
                text: "Save &As…"
                shortcut: StandardKey.SaveAs

                onTriggered: saveAsDialog.open()
            }
            MenuSeparator {}
            Action {
                text: "&Quit"
                shortcut: StandardKey.Quit

                onTriggered: Controller.requestQuit()
            }
        }
        Menu {
            title: "S&ettings"
            popupType: Popup.Native

            Action {
                text: "&Run settings…"
                enabled: !Controller.busy

                onTriggered: settingsDialog.openWith(Controller.settingsData())
            }
        }
    }

    // ------------------------------------------------------------------ header

    header: ColumnLayout {
        spacing: 0

        WarningBanner {
            text: Controller.banner
            Layout.fillWidth: true

            onDismissed: Controller.dismissBanner()
        }
        Pane {
            padding: 10
            Layout.fillWidth: true

            GridLayout {
                anchors.fill: parent
                columns: 5
                columnSpacing: 10
                rowSpacing: 6

                Label {
                    text: "Test name"
                }
                TextField {
                    id: testNameField

                    placeholderText: "optional short suffix added to the results folder name"
                    enabled: !Controller.busy
                    Layout.fillWidth: true
                }
                Label {
                    text: "Test duration"
                }
                TextField {
                    text: Controller.durationText
                    enabled: !Controller.busy
                    color: Controller.durationError(text) === "" ? palette.text : Colors.validationError
                    Layout.preferredWidth: 100
                    ToolTip.text: "Seconds (90), M:SS (1:30), H:MM:SS, or with units (1m30s)"

                    onTextEdited: Controller.durationText = text
                }
                Button {
                    id: startButton

                    readonly property string mode: !Controller.running ? "start" : Controller.runState === "preparing" ? "cancel" : "stop"

                    // Returns the argument that matches the current mode.
                    function pickForMode(start: var, cancel: var, stop: var): var {
                        return mode === "start" ? start : mode === "cancel" ? cancel : stop
                    }

                    highlighted: !Controller.running
                    text: pickForMode("Start", "Cancel", "Stop")
                    icon.source: pickForMode("icons/media-playback-start.svg", "icons/window-close.svg", "icons/media-playback-stop.svg")
                    // Like the label (Fusion tints highlighted icons differently).
                    icon.color: palette.buttonText
                    enabled: Controller.running ? Controller.canStop : Controller.canStart
                    Layout.preferredWidth: 120
                    Layout.alignment: Qt.AlignRight
                    ToolTip.text: Controller.cannotStartReason

                    onClicked: Controller.running ? Controller.stop() : Controller.start(testNameField.text, testDescField.text)
                }
                Label {
                    text: "Test description"
                }
                TextField {
                    id: testDescField

                    placeholderText: "optional free text stored with the results"
                    enabled: !Controller.busy
                    Layout.fillWidth: true
                }
                Label {
                    text: Controller.runState === "preparing" ? "Preparing…" : Controller.runState === "stopping" ? "Stopping…" : ""
                    color: palette.placeholderText
                }
                ProgressBar {
                    from: 0
                    to: 1
                    value: Controller.progress
                    indeterminate: Controller.runState === "preparing" || Controller.runState === "stopping"
                    visible: Controller.running
                    Layout.fillWidth: true
                }
                Label {
                    id: elapsedLabel

                    horizontalAlignment: Text.AlignRight
                    font.family: Controller.monoFont
                    text: Controller.elapsedText
                    // Wide enough for the longest text, so the progress bar doesn't shrink during a run.
                    Layout.preferredWidth: Math.ceil(elapsedMetrics.advanceWidth)
                    Layout.alignment: Qt.AlignRight

                    TextMetrics {
                        id: elapsedMetrics

                        font: elapsedLabel.font
                        text: Controller.longestElapsedText
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------ footer

    footer: ToolBar {
        topPadding: 4
        bottomPadding: 4

        RowLayout {
            anchors.fill: parent

            // Icons are set on the buttons, not the actions: the actions also feed the
            // native row menu, which does not tint icons.
            IconToolButton {
                action: addAction
                icon.source: "icons/list-add.svg"
            }
            IconToolButton {
                action: editAction
                icon.source: "icons/document-edit.svg"
            }
            IconToolButton {
                action: duplicateAction
                icon.source: "icons/edit-copy.svg"
            }
            IconToolButton {
                action: removeAction
                icon.source: "icons/edit-delete.svg"
            }
            ToolSeparator {}
            IconToolButton {
                text: Controller.prechecksRunning ? "Checking…" : "Run pre-checks"
                icon.source: "icons/network-connect.svg"
                enabled: Controller.canRunPrechecks
                ToolTip.text: {
                    if (Controller.cannotRunPrechecksReason !== "")
                        return Controller.cannotRunPrechecksReason
                    return "Connect to the enabled devices, run the model's checks and measure the clock offsets, without starting anything"
                }

                onClicked: Controller.runPrechecks([])
            }
            ToolSeparator {}
            Label {
                text: Controller.statusText
                elide: Text.ElideMiddle
                color: palette.placeholderText
                Layout.fillWidth: true
            }
            IconToolButton {
                text: "Log"
                icon.source: "icons/view-log.svg"
                // Shown pressed while the drawer is open.
                checked: logDrawer.opened

                onClicked: logDrawer.opened ? logDrawer.close() : logDrawer.showDevice(win.selectedName())
            }
        }
    }

    onClosing: close => {
        close.accepted = false
        Controller.requestQuit()
    }

    // ------------------------------------------------------------------ table

    DeviceTable {
        id: table

        anchors.fill: parent
        anchors.margins: 8
        anchors.topMargin: 0
        contextMenu: rowMenu

        onEditRequested: row => editAction.trigger()
        onRemoveRequested: row => removeAction.trigger()
    }
    Menu {
        id: rowMenu

        // Drawn inside the window: as a native or window popup it opens in the wrong
        // place on Wayland.
        popupType: Popup.Item

        MenuItem {
            action: editAction
        }
        MenuItem {
            action: duplicateAction
        }
        MenuItem {
            action: removeAction
        }
        MenuSeparator {}
        MenuItem {
            text: "Run pre-checks"
            enabled: !Controller.busy && table.currentRow >= 0

            onTriggered: Controller.runPrechecks([win.selectedName()])
        }
        MenuItem {
            text: "Show log"

            onTriggered: logDrawer.showDevice(win.selectedName())
        }
    }
    Action {
        id: addAction

        text: "Add"
        enabled: !Controller.busy

        onTriggered: deviceDialog.openFor(-1, Controller.newDeviceData())
    }
    Action {
        id: editAction

        text: "Edit…"
        enabled: !Controller.busy && table.currentRow >= 0

        onTriggered: deviceDialog.openFor(table.currentRow, Controller.deviceData(table.currentRow))
    }
    Action {
        id: duplicateAction

        text: "Duplicate"
        enabled: !Controller.busy && table.currentRow >= 0

        onTriggered: deviceDialog.openFor(-1, Controller.duplicateData(table.currentRow))
    }
    Action {
        id: removeAction

        text: "Remove"
        enabled: !Controller.busy && table.currentRow >= 0

        onTriggered: {
            removeDialog.row = table.currentRow
            removeDialog.name = win.selectedName()
            removeDialog.open()
        }
    }
    LogDrawer {
        id: logDrawer

        width: Math.max(420, win.width * 0.55)
        // Between the header and the toolbar, so Stop, the progress and the Log button stay visible.
        y: win.menuBar.height + win.header.height
        height: win.height - y - win.footer.height
    }

    // ------------------------------------------------------------------ dialogs

    DeviceDialog {
        id: deviceDialog
    }
    RunSummary {
        id: runSummary
    }
    SettingsDialog {
        id: settingsDialog
    }
    // Each message dialog is made application modal, instead of the default window modal:
    // on macOS 26 and later, Qt replaces a window-modal native alert with its own non-native
    // dialog, which also makes the macOS style print a customization warning (QTBUG-148841).
    MessageDialog {
        id: removeDialog

        property int row: -1
        property string name

        modality: Qt.ApplicationModal
        title: "Remove device"
        text: "Do you want to remove the device \"%1\" from the configuration?".arg(name)
        buttons: MessageDialog.Yes | MessageDialog.No

        onAccepted: Controller.removeDevice(row)
    }
    Dialog {
        id: alertDialog

        property string summary
        property string details

        popupType: Popup.Window
        modal: true
        anchors.centerIn: Overlay.overlay
        width: Math.min(640, Overlay.overlay.width * 0.8)
        standardButtons: Dialog.Ok

        Component.onCompleted: (footer as DialogButtonBox).defaultStandardButton = Dialog.Ok

        ColumnLayout {
            anchors.fill: parent
            spacing: 8

            Label {
                text: alertDialog.summary
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            ScrollView {
                implicitHeight: Math.min(detailsText.implicitHeight, win.height * 0.6)
                visible: alertDialog.details !== ""
                Layout.fillWidth: true
                Layout.fillHeight: true

                TextArea {
                    id: detailsText

                    text: alertDialog.details
                    readOnly: true
                    wrapMode: TextArea.Wrap
                }
            }
        }
    }
    MessageDialog {
        id: unsavedDialog

        modality: Qt.ApplicationModal
        title: "Unsaved changes"
        text: "Do you want to save the changes to %1?".arg(Controller.configName || "the configuration")
        buttons: MessageDialog.Save | MessageDialog.Discard | MessageDialog.Cancel

        onButtonClicked: button => {
            switch (button) {
            case MessageDialog.Save:
                Controller.saveAndContinue()
                break
            case MessageDialog.Discard:
                Controller.discardAndContinue()
                break
            }
        }
        onRejected: Controller.cancelPending()
    }
    FileDialog {
        id: openDialog

        title: "Open configuration"
        nameFilters: ["TOML files (*.toml)", "All files (*)"]

        onAccepted: Controller.openConfig(selectedFile.toString())
    }
    FileDialog {
        id: saveAsDialog

        title: "Save configuration as"
        fileMode: FileDialog.SaveFile
        defaultSuffix: "toml"
        nameFilters: ["TOML files (*.toml)", "All files (*)"]

        onAccepted: Controller.saveAs(selectedFile.toString())
        onRejected: Controller.cancelPending()
    }
    MessageDialog {
        id: conflictDialog

        modality: Qt.ApplicationModal
        title: "File changed on disk"
        text: "The file %1 has been modified by another program.\n\nDo you want to overwrite it with your changes?".arg(Controller.configName)
        buttons: MessageDialog.Save | MessageDialog.Cancel

        onAccepted: Controller.saveOverwrite()
        onRejected: Controller.cancelPending()
    }
    Dialog {
        id: lossySaveDialog

        property string file
        property string details

        title: "Remove skipped entries?"
        popupType: Popup.Window
        modal: true
        anchors.centerIn: Overlay.overlay
        width: Math.min(640, Overlay.overlay.width * 0.8)
        standardButtons: Dialog.Save | Dialog.Cancel

        Component.onCompleted: (footer as DialogButtonBox).defaultStandardButton = Dialog.Cancel
        onAccepted: Controller.saveLossy()
        onRejected: Controller.cancelPending()

        ColumnLayout {
            anchors.fill: parent
            spacing: 8

            Label {
                text: "Saving rewrites %1 without these entries, which were skipped or ignored when it was loaded:".arg(lossySaveDialog.file)
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            ScrollView {
                implicitHeight: Math.min(lossyText.implicitHeight, win.height * 0.4)
                Layout.fillWidth: true
                Layout.fillHeight: true

                TextArea {
                    id: lossyText

                    text: lossySaveDialog.details
                    readOnly: true
                    wrapMode: TextArea.Wrap
                }
            }
        }
    }
    MessageDialog {
        id: quitRunningDialog

        modality: Qt.ApplicationModal
        title: "Test in progress"
        text: "A test is running.\n\nDo you want to stop it on all devices, collect the captures, and quit?"
        buttons: MessageDialog.Yes | MessageDialog.No

        onAccepted: Controller.quitAfterStop()
    }
    Dialog {
        id: stoppingDialog

        title: "Stopping"
        popupType: Popup.Window
        modal: true
        closePolicy: Popup.NoAutoClose
        anchors.centerIn: Overlay.overlay
        visible: Controller.quitting && Controller.busy

        footer: DialogButtonBox {
            Button {
                text: "Force quit"
                DialogButtonBox.buttonRole: DialogButtonBox.DestructiveRole

                onClicked: Controller.forceQuit()
            }
        }

        RowLayout {
            spacing: 12

            BusyIndicator {
                running: stoppingDialog.visible
            }
            Label {
                text: "Stopping the test and collecting captures before quitting…"
            }
        }
    }
    // The controller can request a dialog while the main window is in the background, e.g. at
    // the end of a run, so the handlers below use whenExposed() to open their dialogs.
    Connections {
        function onRunFinished(summary) {
            win.whenExposed(() => runSummary.show(summary))
        }

        function onMessage(title, summary, details) {
            win.whenExposed(() => {
                alertDialog.title = title
                alertDialog.summary = summary
                alertDialog.details = details
                alertDialog.open()
            })
        }

        function onConfirmUnsavedChanges() {
            win.whenExposed(() => unsavedDialog.open())
        }

        function onOpenRequested() {
            win.whenExposed(() => openDialog.open())
        }

        function onSaveAsRequested() {
            win.whenExposed(() => saveAsDialog.open())
        }

        function onSaveConflict() {
            win.whenExposed(() => conflictDialog.open())
        }

        function onConfirmLossySave(file, details) {
            win.whenExposed(() => {
                lossySaveDialog.file = file
                lossySaveDialog.details = details
                lossySaveDialog.open()
            })
        }

        function onConfirmQuitDuringRun() {
            win.whenExposed(() => quitRunningDialog.open())
        }

        target: Controller
    }
}
