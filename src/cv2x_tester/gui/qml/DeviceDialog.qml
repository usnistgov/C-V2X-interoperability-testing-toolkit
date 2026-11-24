// SPDX-License-Identifier: NIST-Software

import CV2XTester
import QtQuick
import QtQuick.Controls
import QtQuick.Dialogs
import QtQuick.Layouts

FormDialog {
    id: dlg

    // -1: add a new device.
    property int row: -1
    property string modelId: ""
    property var schema: []
    property var options: ({})
    property bool usesSsh: true
    property bool optionsEdited: false
    property string pendingModel: ""
    property var errors: ({})

    function openFor(row: int, data: var): void {
        dlg.row = row
        nameField.text = data.name
        if (data.role === "rsu")
            rsuRadio.checked = true
        else
            obuRadio.checked = true
        hostField.text = data.host
        portBox.value = data.port
        userField.text = data.username
        passwordField.text = data.password
        passwordField.revealed = false
        keyFileField.text = data.keyFile
        passphraseField.text = data.keyPassphrase
        passphraseField.revealed = false
        loadModel(data.model, data.options)
        optionsEdited = false
        validate()
        // Scroll back to the top.
        scroller.ScrollBar.vertical.position = 0
        open()
    }

    function loadModel(id: string, opts: var): void {
        const info = Controller.driverInfo(id)
        modelId = id
        modelCombo.currentIndex = modelCombo.indexOfValue(id)
        schema = info.schema
        options = Object.assign({}, opts)
        usesSsh = info.usesSsh
    }

    function switchModel(id: string): void {
        const info = Controller.driverInfo(id)
        loadModel(id, info.options)
        optionsEdited = false
        if (userField.text === "")
            userField.text = info.username
        if (passwordField.text === "")
            passwordField.text = info.password
        validate()
    }

    function collect(): var {
        return {
            name: nameField.text,
            model: modelId,
            role: rsuRadio.checked ? "rsu" : "obu",
            host: hostField.text,
            port: portBox.value,
            username: userField.text,
            password: passwordField.text,
            keyFile: keyFileField.text,
            keyPassphrase: passphraseField.text,
            options: options
        }
    }

    function validate(): void {
        errors = Controller.validateDevice(collect(), row)
        standardButton(Dialog.Ok).enabled = Object.keys(errors).length === 0
    }

    title: row < 0 ? "Add device" : "Edit device"
    width: Math.min(640, Overlay.overlay.width * 0.8)
    height: Math.min(implicitHeight, Overlay.overlay.height * 0.8)

    contentItem: ScrollView {
        id: scroller

        // Space around the content, so that focus frames drawn outside the fields (as in
        // the macOS style) aren't clipped at the edges of the scroll area.
        readonly property int margin: 6

        contentWidth: availableWidth
        contentHeight: content.implicitHeight + 2 * margin

        ColumnLayout {
            id: content

            x: scroller.margin
            y: scroller.margin
            width: scroller.availableWidth - 2 * scroller.margin

            GridLayout {
                columns: 2
                columnSpacing: 12
                rowSpacing: 8
                Layout.fillWidth: true

                FieldLabel {
                    text: "Name"
                    field: nameField
                }
                ColumnLayout {
                    spacing: 2
                    Layout.fillWidth: true

                    TextField {
                        id: nameField

                        placeholderText: "letters, digits, '.', '_' and '-'"
                        Layout.fillWidth: true

                        onTextEdited: dlg.validate()
                    }
                    ErrorLabel {
                        text: dlg.errors.name || ""
                    }
                }
                FieldLabel {
                    text: "Model"
                    field: modelCombo
                }
                ColumnLayout {
                    spacing: 2
                    Layout.fillWidth: true

                    ComboBox {
                        id: modelCombo

                        model: Controller.driverModels
                        textRole: "name"
                        valueRole: "id"
                        Layout.fillWidth: true

                        onActivated: {
                            const id = currentValue
                            if (id === dlg.modelId)
                                return
                            if (dlg.optionsEdited) {
                                dlg.pendingModel = id
                                currentIndex = indexOfValue(dlg.modelId)
                                resetDialog.open()
                            } else {
                                dlg.switchModel(id)
                            }
                        }
                    }
                    ErrorLabel {
                        text: dlg.errors.model || ""
                    }
                }
                Label {
                    text: "Role"
                }
                RowLayout {
                    spacing: 16

                    RadioButton {
                        id: obuRadio

                        text: "OBU"
                        checked: true
                    }
                    RadioButton {
                        id: rsuRadio

                        text: "RSU"
                    }
                }
            }
            GroupBox {
                title: "Connection settings"
                enabled: dlg.usesSsh
                Layout.fillWidth: true
                Layout.topMargin: 8

                GridLayout {
                    width: parent.width
                    columns: 2
                    columnSpacing: 12
                    rowSpacing: 8

                    FieldLabel {
                        text: "Host"
                        field: hostField
                    }
                    ColumnLayout {
                        spacing: 2
                        Layout.fillWidth: true

                        TextField {
                            id: hostField

                            placeholderText: "hostname, IPv4 or IPv6 address"
                            Layout.fillWidth: true

                            onTextEdited: dlg.validate()
                        }
                        ErrorLabel {
                            text: dlg.errors.host || ""
                        }
                    }
                    FieldLabel {
                        text: "Port"
                        field: portBox
                    }
                    ColumnLayout {
                        spacing: 2
                        Layout.fillWidth: true

                        SpinBox {
                            id: portBox

                            editable: true
                            from: 1
                            to: 65535
                            textFromValue: (value, locale) => String(value)
                            valueFromText: (text, locale) => parseInt(text)

                            onValueModified: dlg.validate()
                        }
                        ErrorLabel {
                            text: dlg.errors.port || ""
                        }
                    }
                    FieldLabel {
                        text: "Username"
                        field: userField
                    }
                    ColumnLayout {
                        spacing: 2
                        Layout.fillWidth: true

                        TextField {
                            id: userField

                            Layout.fillWidth: true

                            onTextEdited: dlg.validate()
                        }
                        ErrorLabel {
                            text: dlg.errors.username || ""
                        }
                    }
                    Label {
                        text: "Password"
                    }
                    SecretField {
                        id: passwordField

                        secretName: "password"
                        placeholderText: "stored in plaintext in the configuration file"
                    }
                    FieldLabel {
                        text: "Key file"
                        field: keyFileRow
                    }
                    ColumnLayout {
                        spacing: 2
                        Layout.fillWidth: true

                        RowLayout {
                            id: keyFileRow

                            Layout.fillWidth: true

                            TextField {
                                id: keyFileField

                                placeholderText: "optional private key, e.g. ~/.ssh/id_ed25519"
                                Layout.fillWidth: true

                                onTextEdited: dlg.validate()
                            }
                            Button {
                                text: "Browse…"

                                onClicked: keyDialog.open()
                            }
                        }
                        ErrorLabel {
                            text: dlg.errors.key_file || ""
                        }
                    }
                    Label {
                        text: "Key passphrase"
                    }
                    SecretField {
                        id: passphraseField

                        secretName: "passphrase"
                        placeholderText: "only if the key file is encrypted; stored in plaintext"
                    }
                }
            }
            GroupBox {
                title: "Advanced driver options"
                visible: dlg.schema.length > 0
                Layout.fillWidth: true
                Layout.topMargin: 8

                OptionsForm {
                    width: parent.width
                    schema: dlg.schema
                    values: dlg.options
                    errors: dlg.errors

                    onEdited: (name, value) => {
                        dlg.options[name] = value
                        dlg.optionsEdited = true
                        dlg.validate()
                    }
                }
            }
        }
    }

    onSubmitted: Controller.applyDevice(collect(), row)

    MessageDialog {
        id: resetDialog

        modality: Qt.ApplicationModal
        title: "Change model"
        text: "Changing the model resets the driver options to the new model's defaults.\n\nDo you want to continue?"
        buttons: MessageDialog.Yes | MessageDialog.No

        onAccepted: dlg.switchModel(dlg.pendingModel)
    }
    FileDialog {
        id: keyDialog

        title: "Select private key"

        onAccepted: {
            keyFileField.text = Controller.localPath(selectedFile.toString())
            dlg.validate()
        }
    }

    // Label of a field that has an error label below it. It is aligned with the field
    // alone, so its position doesn't change when the error is shown.
    component FieldLabel: Label {
        required property Item field

        verticalAlignment: Text.AlignVCenter
        Layout.alignment: Qt.AlignTop
        Layout.preferredHeight: field.height
    }

    // Masked text field with a button that shows or hides the secret.
    component SecretField: RowLayout {
        property alias text: secretInput.text
        property alias placeholderText: secretInput.placeholderText
        property alias revealed: secretReveal.checked
        property string secretName

        Layout.fillWidth: true

        TextField {
            id: secretInput

            echoMode: secretReveal.checked ? TextInput.Normal : TextInput.Password
            Layout.fillWidth: true
        }
        IconToolButton {
            id: secretReveal

            checkable: true
            display: AbstractButton.IconOnly
            text: (checked ? "Hide %1" : "Show %1").arg(parent.secretName)
            icon.source: checked ? "icons/view-hidden.svg" : "icons/view-visible.svg"
            ToolTip.text: text
        }
    }
}
