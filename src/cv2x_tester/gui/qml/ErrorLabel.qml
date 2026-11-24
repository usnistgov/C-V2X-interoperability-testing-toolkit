// SPDX-License-Identifier: NIST-Software

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "colors.js" as Colors

// Validation message shown below a field or a form, hidden while empty.
Label {
    visible: text !== ""
    color: Colors.validationError
    font.pointSize: Application.font.pointSize * 0.9
    wrapMode: Text.Wrap
    Layout.fillWidth: true
}
