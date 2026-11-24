// SPDX-License-Identifier: NIST-Software

pragma ComponentBehavior: Bound

import CV2XTester
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "colors.js" as Colors

// Form generated from a driver's option schema (see OptionSpec.as_dict()).
// Each option uses two grid rows: label and editor, then the help or error text
// under the editor.
GridLayout {
    id: form

    property var schema: []
    property var values: ({})
    property var errors: ({})

    signal edited(string name, var value)

    columns: 2
    columnSpacing: 12
    rowSpacing: 2

    Repeater {
        model: form.schema

        delegate: Label {
            required property var modelData
            required property int index

            text: modelData.label
            Layout.row: 2 * index
            Layout.column: 0
            Layout.alignment: modelData.kind === "list" ? Qt.AlignTop : Qt.AlignVCenter
            Layout.topMargin: (index > 0 ? 6 : 0) + (modelData.kind === "list" ? 6 : 0)
        }
    }
    Repeater {
        model: form.schema

        delegate: Loader {
            id: opt

            required property var modelData
            required property int index
            readonly property var spec: modelData
            readonly property var current: form.values[spec.name]

            sourceComponent: {
                switch (spec.kind) {
                case "bool":
                    return boolEditor
                case "int":
                    return intEditor
                case "float":
                    return floatEditor
                case "choice":
                    return choiceEditor
                case "list":
                    return listEditor
                default:
                    return strEditor
                }
            }
            Layout.row: 2 * index
            Layout.column: 1
            Layout.topMargin: index > 0 ? 6 : 0
            Layout.fillWidth: spec.kind !== "bool"

            Component {
                id: strEditor

                TextField {
                    text: opt.current ?? ""

                    onTextEdited: form.edited(opt.spec.name, text)
                }
            }
            Component {
                id: boolEditor

                CheckBox {
                    // No label: drop the padding and spacing so the box lines up with the other editors.
                    leftPadding: 0
                    spacing: 0
                    checked: !!opt.current

                    onToggled: form.edited(opt.spec.name, checked)
                }
            }
            Component {
                id: intEditor

                SpinBox {
                    editable: true
                    from: opt.spec.min ?? -2147483647
                    to: opt.spec.max ?? 2147483647
                    value: opt.current ?? 0

                    onValueModified: form.edited(opt.spec.name, value)
                }
            }
            Component {
                id: floatEditor

                DoubleSpinBox {
                    editable: true
                    decimals: opt.spec.decimals ?? 2
                    from: opt.spec.min ?? -1e6
                    to: opt.spec.max ?? 1e6
                    value: opt.current ?? 0

                    onValueModified: form.edited(opt.spec.name, value)
                }
            }
            Component {
                id: choiceEditor

                ComboBox {
                    model: opt.spec.choices
                    currentIndex: Math.max(0, opt.spec.choices.indexOf(opt.current))

                    onActivated: form.edited(opt.spec.name, currentText)
                }
            }
            Component {
                id: listEditor

                ScrollView {
                    implicitHeight: 84

                    TextArea {
                        text: opt.current ? opt.current.join("\n") : ""
                        placeholderText: "one entry per line"
                        font.family: Controller.monoFont

                        onTextChanged: {
                            if (activeFocus)
                                form.edited(opt.spec.name, text.split("\n").filter(s => s.trim() !== ""))
                        }
                    }
                }
            }
        }
    }
    Repeater {
        model: form.schema

        delegate: Label {
            required property var modelData
            required property int index
            readonly property string error: form.errors["options." + modelData.name] || ""

            visible: text !== ""
            text: error !== "" ? error : modelData.help
            color: error !== "" ? Colors.validationError : palette.placeholderText
            font.pointSize: Application.font.pointSize * 0.9
            wrapMode: Text.Wrap
            Layout.row: 2 * index + 1
            Layout.column: 1
            Layout.fillWidth: true
        }
    }
}
