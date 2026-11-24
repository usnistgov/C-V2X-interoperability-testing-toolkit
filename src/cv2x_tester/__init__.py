# SPDX-License-Identifier: NIST-Software

"""cv2x-tester: run synchronized tests on C-V2X OBUs/RSUs and collect pcap traces."""

import importlib.metadata

APP_NAME = "cv2x-tester"  # command name, used in the CLI and logs
APP_DISPLAY_NAME = "C-V2X Interoperability Tester"  # name shown in the GUI

try:
    __version__ = importlib.metadata.version("cv2x-tester")
except importlib.metadata.PackageNotFoundError:  # running from a bare checkout
    __version__ = "0.0.0"
