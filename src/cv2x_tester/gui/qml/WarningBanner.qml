// SPDX-License-Identifier: NIST-Software

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "colors.js" as Colors

// Full-width warning message with a dismiss button.
Rectangle {
    id: banner

    property alias text: message.text

    signal dismissed

    visible: text !== ""
    implicitHeight: row.implicitHeight + 12
    color: Qt.alpha(Colors.current().warning, 0.1)

    Rectangle {
        width: 4
        height: parent.height
        color: Colors.current().warning
    }
    RowLayout {
        id: row

        anchors.fill: parent
        anchors.leftMargin: 12
        anchors.rightMargin: 6
        spacing: 8

        Label {
            text: "⚠"
            color: Colors.current().warning
            font.pointSize: Application.font.pointSize * 1.5
        }
        Label {
            id: message

            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        IconToolButton {
            text: "Dismiss"
            icon.source: "icons/window-close.svg"
            display: AbstractButton.IconOnly
            ToolTip.text: text

            onClicked: banner.dismissed()
        }
    }
}
