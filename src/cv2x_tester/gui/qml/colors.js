// SPDX-License-Identifier: NIST-Software

.pragma library

var light = {
    idle: "#808080",
    preparing: "#008b8b",
    starting: "#4169e1",
    waiting: "#708090",
    ok: "#099209",
    stopping: "#4682b4",
    failed: "#e0202a",
    unclean: "#b0155a",
    warning: "#d2691e",
}
var dark = {
    idle: "#808080",
    preparing: "#008b8b",
    starting: "#3a90e3",
    waiting: "#778899",
    ok: "#099209",
    stopping: "#4682b4",
    failed: "#ee3030",
    unclean: "#e3366b",
    warning: "#f2a10d",
}

// Validation errors: same color for both schemes.
var validationError = "#ff1a24"

// The palette for the current color scheme.
function current() {
    if (Qt.styleHints.colorScheme === Qt.Dark)
        return dark
    return light
}

// Color of a device state (a DeviceState value).
function stateColor(state) {
    const colors = current()
    switch (state) {
    case "connecting":
    case "precheck":
    case "clock":
        return colors.preparing
    case "starting_capture":
    case "starting_test":
        return colors.starting
    case "waiting":
        return colors.waiting
    case "running":
    case "done":
        return colors.ok
    case "stopping_test":
    case "stopping_capture":
    case "collecting":
        return colors.stopping
    case "not_ready":
        return colors.warning
    case "failed":
    case "failed_clean":
        return colors.failed
    case "failed_unclean":
        return colors.unclean
    default:  // idle, aborted
        return colors.idle
    }
}

// Color of a run outcome (an Outcome value).
function outcomeColor(outcome) {
    const colors = current()
    switch (outcome) {
    case "success":
        return colors.ok
    case "partial":
        return colors.warning
    default:  // failed, aborted
        return colors.failed
    }
}

// Color of links. Returns the palette's link color unchanged, except for Qt's default blue
// in the dark scheme, which is unreadable on a dark background. Qt uses that blue when the
// platform doesn't provide a link color, as on Linux with the GTK theme.
function linkColor(paletteLink) {
    if (Qt.styleHints.colorScheme === Qt.Dark && Qt.colorEqual(paletteLink, "#0000ff"))
        return "#78aeed"
    return paletteLink
}
