// SPDX-License-Identifier: NIST-Software

import QtQuick
import QtQuick.Controls

// ToolButton that tints its icon like its text, so the single-color icons in
// icons/ follow the disabled state and dark mode (Fusion does not tint ToolButton icons).
ToolButton {
    icon.color: palette.buttonText
}
