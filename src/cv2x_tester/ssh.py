# SPDX-License-Identifier: NIST-Software

"""Thin asyncssh wrapper. Every command and its output goes through the device log."""

import asyncio
import contextlib
import logging
import shlex
from collections.abc import Callable
from dataclasses import KW_ONLY, dataclass
from pathlib import Path
from typing import Any

import asyncssh

from .config import DeviceConfig, Settings
from .drivers import DriverError
from .logs import DeviceLogger, redact
from .util import last_line, strip_brackets

logging.getLogger("asyncssh").setLevel(logging.WARNING)

KEEPALIVE_INTERVAL = 5  # seconds between SSH keepalive messages
KEEPALIVE_COUNT_MAX = 3  # unanswered keepalives before the connection is considered lost
READ_SIZE = 64 * 1024  # bytes read from a download at a time
CLOSE_TIMEOUT = 5.0  # seconds to wait for a closed connection to shut down


class SshError(DriverError):
    """Connection-level failure (cannot connect, connection lost, ...)."""


class CommandError(DriverError):
    """A remote command failed or timed out."""

    def __init__(self, message: str, result: CommandResult | None = None) -> None:
        super().__init__(message)
        self.result = result


@dataclass
class CommandResult:
    command: str
    _: KW_ONLY
    exit_status: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_status == 0


class _Client(asyncssh.SSHClient):
    def __init__(self, session: SshSession) -> None:
        self._session = session

    def connection_lost(self, exc: Exception | None) -> None:
        self._session._connection_lost(self, exc)


class SshSession:
    def __init__(
        self,
        device: DeviceConfig,
        settings: Settings,
        log: DeviceLogger,
        *,
        key_path: Path | None = None,
        on_lost: Callable[[str], None] | None = None,
    ) -> None:
        self.device = device
        self.settings = settings
        self.log = log
        self.key_path = key_path
        self.on_lost = on_lost
        # Whether the login user is root (uid 0). Updated on every connect.
        self.is_root = False
        self._conn: asyncssh.SSHClientConnection | None = None
        self._client: _Client | None = None

    @property
    def connected(self) -> bool:
        """Whether the session has an open connection."""
        return self._conn is not None

    def _describe(self, exc: BaseException) -> str:
        if isinstance(exc, asyncssh.PermissionDenied):
            msg = "authentication failed"
        elif isinstance(exc, TimeoutError):
            msg = "timed out"
        elif isinstance(exc, OSError) and exc.strerror:
            msg = exc.strerror
        else:
            msg = str(exc) or type(exc).__name__
        return redact(msg, self.device.secrets)

    async def connect(self, timeout: float | None = None) -> None:
        """Connect to the device, then find out whether the login user is root (``is_root``).
        ``timeout`` defaults to the ``connect_timeout`` setting.

        Host keys are not verified. Raises SshError if the connection fails.
        """
        dev = self.device
        kwargs: dict[str, Any] = {
            "host": strip_brackets(dev.host),
            "port": dev.port,
            "username": dev.username,
            "known_hosts": None,  # not verified
            "connect_timeout": self.settings.connect_timeout if timeout is None else timeout,
            "keepalive_interval": KEEPALIVE_INTERVAL,
            "keepalive_count_max": KEEPALIVE_COUNT_MAX,
        }
        if dev.password:
            kwargs["password"] = dev.password
        if self.key_path:
            kwargs["client_keys"] = [str(self.key_path)]
            if dev.key_passphrase:
                kwargs["passphrase"] = dev.key_passphrase
        self.log.info(f"connecting to {dev.username}@{dev.address}")
        client = None

        def factory() -> _Client:
            nonlocal client
            client = _Client(self)
            return client

        try:
            conn = await asyncssh.connect(client_factory=factory, **kwargs)
        except (OSError, asyncssh.Error, asyncssh.KeyImportError, ValueError) as e:
            raise SshError(f"cannot connect to {dev.address}: {self._describe(e)}") from None
        self._conn, self._client = conn, client
        self.log.info("connected")
        await self._check_root()

    async def _check_root(self) -> None:
        """Set ``is_root`` from the output of ``id -u``. If the command fails, assume
        that the login user isn't root, so that commands that need root privileges still
        run with sudo. A connection error is left to the next command to report."""
        self.is_root = False
        try:
            result = await self.run("id -u", check=False)
        except CommandError, SshError:
            return
        self.is_root = result.ok and result.stdout.strip() == "0"

    def _connection_lost(self, client: _Client, exc: Exception | None) -> None:
        if client is not self._client:
            return  # an old or deliberately closed connection
        self._conn = self._client = None
        reason = self._describe(exc) if exc else "closed by remote host"
        message = f"SSH connection lost: {reason}"
        # The on_lost callback logs the message itself.
        if self.on_lost is not None:
            self.on_lost(message)
        else:
            self.log.error(message)

    async def reconnect(self, deadline: float) -> None:
        """Reconnect, retrying with backoff until the loop time ``deadline``."""
        loop = asyncio.get_running_loop()
        self.abort()
        delay = 1.0
        last_error = "timed out"
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise SshError(f"reconnect failed: {last_error}")
            try:
                await self.connect(timeout=min(self.settings.connect_timeout, remaining))
                return
            except SshError as e:
                last_error = str(e)
                self.log.warning(f"reconnect attempt failed: {last_error}")
            await asyncio.sleep(min(delay, max(0.0, deadline - loop.time())))
            delay = min(delay * 2, 5.0)

    def _require(self) -> asyncssh.SSHClientConnection:
        if self._conn is None:
            raise SshError("not connected")
        return self._conn

    async def run(self, command: str, *, check: bool = True, timeout: float | None = None) -> CommandResult:
        """Run a command and log it with its output and exit status.

        With ``check``, a non-zero exit status raises CommandError. So does a timeout, which
        defaults to the ``command_timeout`` setting. A connection error raises SshError.
        """
        conn = self._require()
        if timeout is None:
            timeout = self.settings.command_timeout
        self.log.command(command)
        try:
            res = await conn.run(
                command,
                check=False,
                timeout=timeout,
                stdin=asyncssh.DEVNULL,
                encoding="utf-8",
                errors="replace",
            )
        except asyncssh.TimeoutError as e:
            if e.stdout:
                self.log.stdout(str(e.stdout))
            if e.stderr:
                self.log.stderr(str(e.stderr))
            self.log.error(f"command timed out after {timeout:g} s")
            raise CommandError(f"'{command}' timed out after {timeout:g} s") from None
        except (OSError, asyncssh.Error) as e:
            msg = self._describe(e)
            self.log.error(f"command failed: {msg}")
            raise SshError(f"'{command}' failed: {msg}") from None
        stdout = str(res.stdout or "")
        stderr = str(res.stderr or "")
        if stdout:
            self.log.stdout(stdout)
        if stderr:
            self.log.stderr(stderr)
        status = res.exit_status if res.exit_status is not None else -1
        result = CommandResult(command, exit_status=status, stdout=stdout, stderr=stderr)
        if status != 0:
            signal_text = f" (signal {res.exit_signal[0]})" if res.exit_signal else ""
            if check:
                self.log.error(f"exit status {status}{signal_text}")
                reason = last_line(stderr)
                raise CommandError(
                    f"'{command}' failed with exit status {status}" + (f": {reason}" if reason else ""),
                    result,
                )
            self.log.info(f"exit status {status}{signal_text}")
        return result

    async def start_process(self, command: str) -> asyncssh.SSHClientProcess[bytes]:
        """Start a long-running binary-mode process (e.g. tcpdump streaming).

        Raises SshError if the session is not connected or the process cannot be started.
        The command's exit status is not checked, since the process is still running.
        """
        conn = self._require()
        self.log.command(command)
        try:
            return await conn.create_process(command, stdin=asyncssh.DEVNULL, encoding=None)
        except (OSError, asyncssh.Error) as e:
            raise SshError(f"'{command}' failed: {self._describe(e)}") from None

    async def read_file_via_cat(
        self, remote_path: str, local_path: Path, *, sudo: bool = False, timeout: float | None = None
    ) -> int:
        """Download a file with ``[sudo -n] cat``; returns the number of bytes.

        On failure the partial local file is removed and CommandError is raised.
        """
        command = f"{'sudo -n ' if sudo else ''}cat {shlex.quote(remote_path)}"
        proc = await self.start_process(command)
        size = 0
        # The local file operations are quick enough to run on the event loop.
        try:
            async with asyncio.timeout(timeout):
                with local_path.open("wb") as f:
                    while chunk := await proc.stdout.read(READ_SIZE):
                        f.write(chunk)
                        size += len(chunk)
                stderr = (await proc.stderr.read()).decode("utf-8", "replace")
                await proc.wait_closed()
        except TimeoutError:
            proc.close()
            local_path.unlink(missing_ok=True)  # noqa: ASYNC240
            raise CommandError(f"download of {remote_path} timed out") from None
        except (OSError, asyncssh.Error) as e:
            proc.close()
            local_path.unlink(missing_ok=True)  # noqa: ASYNC240
            raise CommandError(f"download of {remote_path} failed: {self._describe(e)}") from None
        status = proc.exit_status if proc.exit_status is not None else -1
        if status != 0:
            local_path.unlink(missing_ok=True)  # noqa: ASYNC240
            if stderr:
                self.log.stderr(stderr)
            detail = last_line(stderr, f"exit status {status}")
            detail = detail.removeprefix(f"cat: {remote_path}: ")
            raise CommandError(f"cannot read {remote_path}: {detail}")
        self.log.info(f"downloaded {remote_path} ({size} bytes)")
        return size

    def abort(self) -> None:
        """Drop the connection immediately without reporting it as lost."""
        conn, self._conn, self._client = self._conn, None, None
        if conn is not None:
            conn.abort()

    async def close(self) -> None:
        """Close the connection, waiting up to ``CLOSE_TIMEOUT`` seconds for it to shut down."""
        conn, self._conn, self._client = self._conn, None, None
        if conn is not None:
            conn.close()
            # Best effort: the connection is already closing, so an error while waiting for the
            # close to complete can be ignored.
            with contextlib.suppress(Exception):
                async with asyncio.timeout(CLOSE_TIMEOUT):
                    await conn.wait_closed()
            self.log.info("disconnected")
