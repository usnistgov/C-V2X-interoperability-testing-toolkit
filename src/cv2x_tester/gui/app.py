# SPDX-License-Identifier: NIST-Software

"""GUI entry point: QGuiApplication + qasync event loop + QML engine."""

import asyncio
import contextlib
import functools
import signal
import socket
import sys
from collections.abc import Generator
from pathlib import Path

import qasync
from PySide6.QtCore import QSocketNotifier
from PySide6.QtGui import QGuiApplication, QIcon
from PySide6.QtQml import QQmlApplicationEngine

from .. import APP_DISPLAY_NAME, APP_NAME, __version__
from .controller import QML_IMPORT_NAME, Controller

QML_DIR = Path(__file__).resolve().parent / "qml"


class EventLoop(qasync.QEventLoop):
    """qasync loop that accepts the ``context`` argument Python 3.15's selector
    transports pass to ``_add_reader``/``_add_writer`` (qasync 0.28 does not)."""

    def _add_reader(self, fd, callback, *args, context=None):
        if context is not None:
            callback = functools.partial(context.run, callback)
        return super()._add_reader(fd, callback, *args)

    def _add_writer(self, fd, callback, *args, context=None):
        if context is not None:
            callback = functools.partial(context.run, callback)
        return super()._add_writer(fd, callback, *args)


@contextlib.contextmanager
def _wake_on_signals() -> Generator[None]:
    """Wake up Qt's event loop whenever a signal arrives, so that Ctrl+C works while the GUI
    is idle.

    Python doesn't run a signal handler, such as the one that ``asyncio.run()`` installs for
    Ctrl+C, as soon as the signal arrives, but the next time the interpreter executes Python
    code. An idle Qt event loop waits in C++ code, so without this wakeup the handler runs
    only when an event that calls into Python arrives, e.g. when the window is activated."""
    read_sock, write_sock = socket.socketpair()
    with read_sock, write_sock:
        write_sock.setblocking(False)
        notifier = QSocketNotifier(read_sock.fileno(), QSocketNotifier.Type.Read)
        notifier.activated.connect(lambda: read_sock.recv(64))
        old_fd = signal.set_wakeup_fd(write_sock.fileno())
        try:
            yield
        finally:
            signal.set_wakeup_fd(old_fd)
            notifier.setEnabled(False)


def main(config_path: Path | None = None) -> int:
    app = QGuiApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_DISPLAY_NAME)
    app.setApplicationVersion(__version__)
    app.setQuitOnLastWindowClosed(False)  # quitting is decided by the controller
    icon = QML_DIR / "icons" / "cv2x-tester.svg"
    if icon.exists():
        app.setWindowIcon(QIcon(str(icon)))

    async def run_ui() -> int:
        done: asyncio.Future[None] = asyncio.get_running_loop().create_future()

        def quit_app() -> None:
            if not done.done():
                done.set_result(None)

        controller = Controller(quit_callback=quit_app)
        if config_path is not None:
            controller.load(config_path)
        engine = QQmlApplicationEngine()
        if not engine.setExternalSingletonInstance(QML_IMPORT_NAME, "Controller", controller):
            return 1
        engine.load(QML_DIR / "Main.qml")
        if not engine.rootObjects():
            return 1
        # Main.qml opens the dialogs of these messages once the main window is on screen.
        controller.show_pending_messages()
        await done
        # Qt requires the controller to outlive the engine.
        del engine
        return 0

    try:
        with _wake_on_signals():
            return asyncio.run(run_ui(), loop_factory=lambda: EventLoop(app))
    except KeyboardInterrupt:
        return 130
