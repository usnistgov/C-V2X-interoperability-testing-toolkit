# SPDX-License-Identifier: NIST-Software

"""Driver base class, options base class and registry."""

import enum
import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from ..clock import ClockSource, date_sources
from ..options import Options
from ..util import last_line

if TYPE_CHECKING:
    from ..config import DeviceConfig, Settings
    from ..logs import DeviceLogger
    from ..ssh import CommandResult, SshSession

# Prints the state of the C-V2X radio, on devices that provide it.
CV2X_STATUS_COMMAND = "cv2x_get_status"

# A line of CV2X_STATUS_COMMAND's output that reports the state of RX or TX, e.g. "  RX : Active".
# The state is the remainder of the line.
_CV2X_STATUS_RE = re.compile(r"\s*(RX|TX)\s*:\s*(\S.*?)\s*")
# A radio state (RX or TX) counts as active if it starts with the word "Active" (case-insensitive).
_CV2X_ACTIVE_RE = re.compile(r"active\b", re.IGNORECASE)


class DriverError(Exception):
    """A driver operation failed. The message is shown to the user as is."""


class DeviceNotReady(DriverError):
    """The device works, but isn't in a state to run a test, for example because its C-V2X radio
    isn't active. Raise it from :meth:`Driver.precheck`. The message is shown to the user as is."""


class DriverRegistrationError(Exception):
    """Two drivers declare the same ``model_id``."""


class CaptureMode(enum.Enum):
    STREAM = "stream"  # pcap bytes streamed over SSH to local files while the test runs
    REMOTE_FILES = "remote"  # device writes files, downloaded after stop


@dataclass(kw_only=True)
class CaptureStats:
    packets: int | None
    bytes: int


@dataclass
class DriverOptions(Options):
    """Base class for a driver's options. Subclass it as a dataclass and declare each option
    with :func:`~cv2x_tester.options.option`."""


# --------------------------------------------------------------------------
# Per-device context
# --------------------------------------------------------------------------


@dataclass(eq=False, kw_only=True)
class DeviceContext:
    """What the engine provides to the driver of one device, such as its configuration, SSH session,
    logger and callbacks to report progress."""

    device: DeviceConfig
    settings: Settings
    log: DeviceLogger
    ssh: SshSession | None = None
    raw_files_dir: Path | None = None
    keep_raw_files: bool = False
    delete_remote_files: bool = True
    on_warning: Callable[[str], None] = lambda message: None
    on_failure: Callable[[str], None] | None = None
    # Set by Driver.download when a download fails, so that the remote files are kept.
    download_failed: bool = False

    @property
    def role(self) -> str:
        return self.device.role

    @property
    def name(self) -> str:
        return self.device.name

    def require_ssh(self) -> SshSession:
        if self.ssh is None:
            raise DriverError("this device has no SSH session")
        return self.ssh

    def warn(self, message: str) -> None:
        self.log.warning(message)
        self.on_warning(message)

    def report_failure(self, message: str) -> None:
        """Report that the device failed asynchronously (e.g. the capture stream died). The
        message goes to ``on_failure``, which logs it itself, or to the device log if there is
        no handler."""
        if self.on_failure is not None:
            self.on_failure(message)
        else:
            self.log.error(message)


# --------------------------------------------------------------------------
# Driver base class and registry
# --------------------------------------------------------------------------

_REGISTRY: dict[str, type[Driver[Any]]] = {}


class Driver[O: DriverOptions]:
    """Base class for device drivers, generic over the driver's options class.

    To add a device model, subclass ``Driver[MyOptions]``, where ``MyOptions`` is the driver's
    options dataclass, and set the ``Options`` class attribute to the same class. Set ``model_id``
    to the name used as ``model`` in the config file.

    Every hook has a default. A driver should override only the hooks it needs.
    """

    model_id: ClassVar[str]
    display_name: ClassVar[str]
    vendor: ClassVar[str] = ""
    capture_mode: ClassVar[CaptureMode] = CaptureMode.STREAM
    Options: ClassVar[type[DriverOptions]] = DriverOptions
    default_username: ClassVar[str | None] = None
    default_password: ClassVar[str | None] = None
    uses_ssh: ClassVar[bool] = True

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        model_id = cls.__dict__.get("model_id")
        if model_id is None:
            return
        if model_id in _REGISTRY and _REGISTRY[model_id] is not cls:
            other = _REGISTRY[model_id]
            raise DriverRegistrationError(
                f"duplicate driver model_id {model_id!r}: "
                f"{other.__module__}.{other.__qualname__} and {cls.__module__}.{cls.__qualname__}"
            )
        _REGISTRY[model_id] = cls

    def __init__(self, device: DeviceConfig, options: O, ctx: DeviceContext) -> None:
        self.device = device
        self.options = options
        self.ctx = ctx

    # -- convenience -------------------------------------------------------

    @property
    def ssh(self) -> SshSession:
        """The device's SSH session. Raises DriverError for a driver that uses no SSH."""
        return self.ctx.require_ssh()

    async def run(self, command: str, *, check: bool = True, timeout: float | None = None) -> CommandResult:
        """Run a command on the device. The command and its output go to the device log.

        With ``check``, a non-zero exit status raises CommandError. ``timeout`` defaults to the
        ``command_timeout`` setting.
        """
        return await self.ssh.run(command, check=check, timeout=timeout)

    async def run_as_root(self, command: str) -> CommandResult:
        """Run a command as root on the device and raise DriverError if it fails.

        The command runs as is when the login user is root, and as ``sudo -n COMMAND`` otherwise.
        """
        if self.ssh.is_root:
            return await self.run(command)
        result = await self.run(f"sudo -n {command}", check=False)
        if result.ok:
            return result
        if "password is required" in result.stderr:
            raise DriverError("passwordless sudo required")
        detail = last_line(result.stderr)
        raise DriverError(
            f"'sudo -n {command}' failed with exit status {result.exit_status}"
            + (f": {detail}" if detail else "")
        )

    async def check_root_privileges(self) -> None:
        """Check that the login user is able to run commands as root, either by being root or
        through passwordless sudo, and raise DriverError otherwise. Call it at the start of
        :meth:`precheck` in a driver that needs root privileges."""
        if not self.ssh.is_root:
            await self.run_as_root("true")

    async def check_cv2x_status(self, *, as_root: bool = False) -> None:
        """Check that the device's C-V2X radio is active by running the ``cv2x_get_status`` command
        on the device. Call it from :meth:`precheck` in a driver whose devices provide the command.

        Raises DeviceNotReady unless every line that reports the state of RX or TX says it is
        active, and DriverError if the command fails or its output reports no state for RX or for
        TX. Other lines of output are ignored. With ``as_root``, the command runs with root
        privileges (see :meth:`run_as_root`). By default, it runs as the login user.
        """
        if as_root:
            result = await self.run_as_root(CV2X_STATUS_COMMAND)
        else:
            result = await self.run(CV2X_STATUS_COMMAND)
        # The command exits with status 0 whatever the state of the radio, so only its output
        # tells whether the radio is active.
        states = [m.groups() for line in result.stdout.splitlines() if (m := _CV2X_STATUS_RE.fullmatch(line))]
        labels = {label for label, _ in states}
        missing = [label for label in ("RX", "TX") if label not in labels]
        if missing:
            raise DriverError(f"unexpected '{CV2X_STATUS_COMMAND}' output: no {' or '.join(missing)} state")
        not_active = [f"{label} {state}" for label, state in states if not _CV2X_ACTIVE_RE.match(state)]
        if not_active:
            raise DeviceNotReady(f"C-V2X radio not active ({', '.join(not_active)})")

    async def download(
        self, remote_path: str, local_dir: Path, *, as_root: bool = False, name: str | None = None
    ) -> Path | None:
        """Download ``remote_path`` into ``local_dir``. With ``as_root``, the file is read with root
        privileges (see :meth:`run_as_root`). Missing or unreadable files produce a device warning
        and return None, and the remote files are then not deleted by the cleanup."""
        local = local_dir / (name or Path(remote_path).name)
        try:
            await self.ssh.read_file_via_cat(remote_path, local, sudo=as_root and not self.ssh.is_root)
        except DriverError as e:
            self.ctx.download_failed = True
            self.ctx.warn(str(e))
            return None
        return local

    # -- hooks ---------------------------------------------------------------

    async def precheck(self) -> None:
        """Verify the device is ready for a test; raise DriverError otherwise."""

    def clock_sources(self) -> list[ClockSource]:
        """Return the methods of reading the device clock for the clock check, best first. The check
        falls back to the next source when one fails. By default, these are ``date +%s.%N``, then
        ``date +%s``. To add a better source, put it before ``super().clock_sources()``, so that
        ``date`` remains the fallback."""
        return date_sources(partial(self.run, check=False))

    async def start_capture(self) -> None:
        """Start capturing; return only once the capture is ready."""

    async def start_test(self) -> None:
        """Start the test; must return promptly (the test runs in the background)."""

    async def stop_test(self) -> None:
        """Stop the test."""

    async def stop_capture(self) -> None:
        """Stop capturing. STREAM drivers must leave finalized local files."""

    async def collect(self, directory: Path) -> list[Path]:
        """Download device files into ``directory`` and return their local paths. By default,
        nothing is downloaded."""
        return []

    def pcap_files_to_merge(self, collected: list[Path]) -> list[Path]:
        """Return the files to merge into ``<device>.pcap``. By default, these are all the collected
        ``.pcap`` files."""
        return [p for p in collected if p.suffix == ".pcap"]

    async def cleanup(self) -> None:
        """Remove leftovers from the device (honoring ``ctx.delete_remote_files``)."""

    def stats(self) -> CaptureStats | None:
        """Return the live capture statistics, or None if the driver has none (the default).

        The engine calls this method every ``STATS_INTERVAL`` while the capture runs, and once
        more after the capture stops. The method must therefore be cheap: it should only read
        counters that the driver updates during the capture, without any I/O such as running a
        command on the device.
        """
        return None
