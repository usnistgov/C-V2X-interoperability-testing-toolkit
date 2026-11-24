# SPDX-License-Identifier: NIST-Software

"""The base class of drivers that capture by streaming tcpdump output over SSH."""

import asyncio
import contextlib
import re
import shlex
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

# Lazy, so that loading the drivers does not load asyncssh.
lazy import asyncssh
lazy from asyncssh import SSHClientProcess

from ..options import option
from ..pcap import PcapFormatError, PcapStreamCounter
from .base import CaptureMode, CaptureStats, DeviceContext, Driver, DriverError, DriverOptions

STDERR_DRAIN_DELAY = 0.2  # seconds to wait for the last error output of a tcpdump that exited
READ_SIZE = 64 * 1024  # bytes read from the capture stream at a time
FLUSH_INTERVAL = 1.0  # seconds between flushes of a stream's file, while data arrives
STOP_EOF_TIMEOUT = 5.0  # seconds to wait for tcpdump to exit after SIGINT
_PID_RE = re.compile(rb"^CV2X_PID (\d+)\s*$")


@dataclass(frozen=True, kw_only=True)
class StreamSpec:
    """One tcpdump capture of a device. It is written to ``<name>.pcap`` in the raw files
    folder."""

    name: str
    interface: str
    filter: str = ""
    promiscuous: bool = False


@dataclass
class SingleInterfaceOptions(DriverOptions):
    """Options of a TcpdumpDriver that captures on a single interface. Redeclare a field
    in a subclass to change its default."""

    interface: str = option("", help="Capture interface", required=True)
    filter: str = option("", label="Capture filter", help="tcpdump/pcap filter expression")
    promiscuous: bool = option(False, label="Promiscuous mode", help="Put the interface in promiscuous mode")

    def stream(self) -> StreamSpec:
        """A stream on these options, named after the interface."""
        return StreamSpec(
            name=self.interface, interface=self.interface, filter=self.filter, promiscuous=self.promiscuous
        )


def tcpdump_command(
    interface: str,
    pcap_filter: str = "",
    *,
    sudo: bool = False,
    promiscuous: bool = False,
    ssh_port: int = 22,
) -> str:
    """Build the remote command that streams pcap data on stdout.

    The wrapper shell prints its PID on stderr before exec'ing tcpdump, so the
    capture can later be stopped with ``kill -INT``.

    The filter leaves out the SSH connection that carries the capture. Otherwise every
    captured packet would add SSH traffic, which would be captured too. The shell finds
    the connection in ``$SSH_CONNECTION``. If the SSH server doesn't set it, all TCP
    traffic on ``ssh_port`` is left out instead.
    """
    # "${1%%[%]*}" drops the zone of an IPv6 link-local address (fe80::1%eth0).
    wrapper = (
        "echo CV2X_PID $$ >&2; "
        "ssh_filter() { "
        'if [ $# -eq 4 ]; then echo "tcp and host ${1%%[%]*} and port $2 and host ${3%%[%]*} and port $4"; '
        f'else echo "tcp port {ssh_port}"; fi; '
        "}; "
        'exec "$@" "not ($(ssh_filter $SSH_CONNECTION))"'
    )
    args = ["sudo", "-n"] if sudo else []
    args += ["tcpdump", "-i", interface, *([] if promiscuous else ["-p"]), "-U", "-w", "-"]
    if user_filter := pcap_filter.strip():
        args += [f"({user_filter})", "and"]
    # The "sh" after the wrapper becomes its $0 argument, the following arguments start at $1.
    return shlex.join(["sh", "-c", wrapper, "sh", *args])


class TcpdumpStream:
    """Runs tcpdump on the device and streams its pcap output into a local file."""

    def __init__(
        self,
        ctx: DeviceContext,
        spec: StreamSpec,
        *,
        sudo: bool = False,
    ) -> None:
        if ctx.raw_files_dir is None:
            raise DriverError("no raw files folder")
        self.ctx = ctx
        self.name = spec.name
        self.command = tcpdump_command(
            spec.interface, spec.filter, sudo=sudo, promiscuous=spec.promiscuous, ssh_port=ctx.device.port
        )
        self.sudo = sudo
        self.path: Path = ctx.raw_files_dir / f"{spec.name}.pcap"
        self.counter = PcapStreamCounter()
        self.pid: int | None = None
        self._proc: SSHClientProcess[bytes] | None = None
        self._file: BinaryIO | None = None
        self._ready = asyncio.Event()
        self._stdout_done = asyncio.Event()
        self._stderr_lines: list[str] = []
        self._tasks: list[asyncio.Task[None]] = []
        # Whether start() has returned successfully. The stream's first error, in _error, is
        # raised by start() if it occurs before, and reported as a failure if it occurs after.
        self._started = False
        self._error: str | None = None
        self._stopping = False

    async def start(self) -> None:
        """Start tcpdump and return once it reports it is listening."""
        f = self._file = self.path.open("wb")
        proc = self._proc = await self.ctx.require_ssh().start_process(self.command)
        self._tasks = [
            asyncio.create_task(self._read_stdout(proc, f), name=f"{self.ctx.name}-{self.name}-stdout"),
            asyncio.create_task(self._read_stderr(proc), name=f"{self.ctx.name}-{self.name}-stderr"),
            asyncio.create_task(self._flush_periodically(proc, f), name=f"{self.ctx.name}-{self.name}-flush"),
        ]
        timeout = self.ctx.settings.command_timeout
        ready = asyncio.create_task(self._ready.wait())
        exited = asyncio.create_task(self._stdout_done.wait())
        try:
            done, _ = await asyncio.wait(
                {ready, exited}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            ready.cancel()
            exited.cancel()
        if self._error is None and self._ready.is_set() and not self._stdout_done.is_set():
            self._started = True
            self.ctx.log.info(f"{self.name}: capture ready (pid {self.pid})")
            return
        # The stream failed, tcpdump exited early, or it never reported listening.
        await asyncio.sleep(STDERR_DRAIN_DELAY)
        await self._finalize()
        if self._error is not None:
            raise DriverError(self._error)
        stderr = "; ".join(self._stderr_lines)
        if exited in done or self._stdout_done.is_set():
            raise DriverError(
                f"{self.name}: tcpdump exited before capture was ready: {stderr or 'no error output'}"
            )
        raise DriverError(
            f"{self.name}: tcpdump did not become ready within {timeout:g} s"
            + (f": {stderr}" if stderr else "")
        )

    async def _read_stdout(self, proc: SSHClientProcess[bytes], f: BinaryIO) -> None:
        """Write tcpdump's pcap output to the local file and count its packets. A write error, a
        connection error, or the end of the output before :meth:`stop` fails the stream."""
        try:
            while chunk := await proc.stdout.read(READ_SIZE):
                try:
                    f.write(chunk)
                except OSError as e:
                    self._write_failed(e, proc)
                    return
                try:
                    self.counter.feed(chunk)
                except PcapFormatError as e:
                    self.ctx.warn(f"{self.name}: cannot count packets: {e}")
        except (OSError, asyncssh.Error) as e:  # connection errors surface here
            if not self._stopping:
                self._fail(f"{self.name}: capture stream error: {e}")
            return
        finally:
            self._stdout_done.set()
        # If tcpdump exits before start() has returned, start() reports the exit, together with
        # tcpdump's error output.
        if self._started and not self._stopping:
            status = proc.exit_status
            self._fail(
                f"{self.name}: capture stream ended unexpectedly"
                + (f" (tcpdump exit status {status})" if status is not None else "")
            )

    async def _read_stderr(self, proc: SSHClientProcess[bytes]) -> None:
        """Read tcpdump's error output. The PID line of the wrapper shell sets ``pid``, the other
        lines go to the device log, and tcpdump's "listening on" message marks the stream ready.
        A connection error ends the reading silently, because :meth:`_read_stdout` reports it."""
        with contextlib.suppress(OSError, asyncssh.Error):
            while line := await proc.stderr.readline():
                if m := _PID_RE.match(line):
                    self.pid = int(m.group(1))
                    continue
                text = line.decode("utf-8", "replace").rstrip()
                self._stderr_lines.append(text)
                self.ctx.log.stderr(text)
                if "listening on" in text:
                    self._ready.set()

    async def _flush_periodically(self, proc: SSHClientProcess[bytes], f: BinaryIO) -> None:
        """Every ``FLUSH_INTERVAL``, flush the file if data has arrived since the previous flush.
        A write error fails the stream."""
        flushed = 0
        while True:
            await asyncio.sleep(FLUSH_INTERVAL)
            if self.counter.bytes == flushed:
                continue
            flushed = self.counter.bytes
            try:
                f.flush()
            except OSError as e:
                self._write_failed(e, proc)
                return

    def _write_failed(self, error: OSError, proc: SSHClientProcess[bytes]) -> None:
        """Fail the stream after an error writing its file, and close tcpdump's channel."""
        self._fail(f"cannot write {self.path.name}: {error.strerror or error}")
        proc.close()

    def _fail(self, message: str) -> None:
        """Record the stream's first error, and report it as a failure if start() has returned.
        Otherwise, start() raises it."""
        if self._error is None:
            self._error = message
            if self._started:
                self.ctx.report_failure(message)

    async def stop(self) -> None:
        """Send SIGINT to tcpdump, wait for its output to end, finalize the file."""
        self._stopping = True
        try:
            ssh = self.ctx.ssh
            if self.pid and ssh is not None and ssh.connected:
                # Also sent after a dropped connection (possibly on a new session),
                # in case tcpdump survived on the device. It is harmless if tcpdump is gone.
                kill = f"{'sudo -n ' if self.sudo else ''}kill -INT {self.pid}"
                await ssh.run(kill, check=False)
            if self._proc is not None and not self._stdout_done.is_set():
                with contextlib.suppress(TimeoutError):
                    async with asyncio.timeout(STOP_EOF_TIMEOUT):
                        await self._stdout_done.wait()
                if not self._stdout_done.is_set():
                    self.ctx.log.warning(
                        f"{self.name}: tcpdump did not exit after SIGINT; closing the channel"
                    )
        finally:
            await self._finalize()

    async def _finalize(self) -> None:
        self._stopping = True
        if self._proc is not None:
            self._proc.close()
        tasks, self._tasks = self._tasks, []
        for t in tasks:
            if not t.done():
                t.cancel()
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            self._close_file()

    def _close_file(self) -> None:
        if self._file is not None:
            try:
                self._file.close()
            except OSError as e:
                # Closing the file flushes its buffer, so it can fail like a write.
                # This failure is not reported if the stream has already failed, because
                # its cause is most likely the same.
                if self._error is None:
                    self.ctx.warn(f"cannot write {self.path.name}: {e.strerror or e}")
            self._file = None


class TcpdumpDriver[O: DriverOptions](Driver[O], ABC):
    """Base class for drivers that capture by streaming tcpdump output over SSH.

    A subclass must list in :meth:`streams` the interfaces to capture on. Each stream
    runs its own tcpdump and is written to its own file. After the capture stops, the
    engine merges the files into ``<device>.pcap``.

    The pre-check makes sure tcpdump is installed and, if tcpdump needs root privileges,
    that it can run as root (:meth:`check_root_privileges`). Override :meth:`needs_root`
    when tcpdump can capture packets without root privileges on the device.
    """

    capture_mode = CaptureMode.STREAM

    _streams: tuple[TcpdumpStream, ...] = ()

    @abstractmethod
    def streams(self) -> list[StreamSpec]:
        """The streams to capture."""

    def needs_root(self) -> bool:
        """Return whether tcpdump needs root privileges (True by default)."""
        return True

    async def precheck(self) -> None:
        await self.run("command -v tcpdump")
        if self.needs_root():
            await self.check_root_privileges()

    async def start_capture(self) -> None:
        specs = self.streams()
        if len({s.name for s in specs}) < len(specs):
            raise DriverError("stream names must be unique")
        sudo = self.needs_root() and not self.ssh.is_root
        self._streams = tuple(TcpdumpStream(self.ctx, s, sudo=sudo) for s in specs)
        _raise_first(await asyncio.gather(*(s.start() for s in self._streams), return_exceptions=True))

    async def stop_capture(self) -> None:
        _raise_first(await asyncio.gather(*(s.stop() for s in self._streams), return_exceptions=True))

    def pcap_files_to_merge(self, collected: list[Path]) -> list[Path]:
        return [s.path for s in self._streams] + super().pcap_files_to_merge(collected)

    def stats(self) -> CaptureStats | None:
        if not self._streams:
            return None
        return CaptureStats(
            packets=sum(s.counter.packets for s in self._streams),
            bytes=sum(s.counter.bytes for s in self._streams),
        )


def _raise_first(results: list[object]) -> None:
    """Raise the first exception among the results of ``asyncio.gather(...,
    return_exceptions=True)``."""
    errors = [r for r in results if isinstance(r, BaseException)]
    if errors:
        raise errors[0]
