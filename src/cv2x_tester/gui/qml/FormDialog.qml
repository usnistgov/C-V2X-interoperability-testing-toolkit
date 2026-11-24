// SPDX-License-Identifier: NIST-Software

import QtQuick
import QtQuick.Controls

// Dialog for editing values, shown in its own window, with OK and Cancel buttons. Dialogs based
// on it must read the values in a submitted() handler, not in an accepted() handler.
Dialog {
    id: dlg

    // Emitted when the dialog is accepted, after any pending edit in its fields has been committed.
    signal submitted

    popupType: Popup.Window
    modal: true
    anchors.centerIn: Overlay.overlay
    standardButtons: Dialog.Ok | Dialog.Cancel

    Component.onCompleted: (footer as DialogButtonBox).defaultStandardButton = Dialog.Ok
    onAccepted: {
        // A spin box commits an edit only when it loses focus, and clicking OK doesn't take the
        // focus when the button's focus policy lacks Qt.ClickFocus (the default on macOS).
        // Focusing the footer, which is outside the content, takes the focus from any field and
        // so commits a pending edit.
        footer.forceActiveFocus()
        submitted()
    }
}
