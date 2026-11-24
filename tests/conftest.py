# SPDX-License-Identifier: NIST-Software

import asyncio
import concurrent.futures
import io
import re
from collections.abc import Callable
from pathlib import Path

import pytest
from scapy.utils import RawPcapReader, RawPcapWriter

from cv2x_tester import pcap
from cv2x_tester.config import Config, DeviceConfig, Settings
from cv2x_tester.drivers import DeviceContext
from cv2x_tester.logs import DeviceLogger
from cv2x_tester.ssh import CommandError, CommandResult

# Once PySide6 is imported (test_controller.py, test_models.py), reading a lazily imported
# name as a module attribute returns the lazy object instead of resolving it, because PySide6
# 6.12.0 replaces the attribute lookup of all modules (PYSIDE-3471). asyncio.to_thread()
# would then get a lazy object instead of the standard library's ThreadPoolExecutor, so the
# line below resolves ThreadPoolExecutor before the tests import PySide6. The GUI is
# unaffected: qasync has its own executor. Commit c04f621cde46 in the 6.12 branch of
# pyside-setup fixes the bug. Remove this workaround once the project requires a PySide6
# release with that commit (expected to be 6.12.1).
concurrent.futures.ThreadPoolExecutor  # noqa: B018

# The exit status, stdout and stderr of a command.
type Response = tuple[int, str, str]


def pcap_bytes(
    records: list[tuple[int, int, bytes]], *, linktype: int = 1, nano: bool = False, endianness: str = "<"
) -> bytes:
    """Return a classic pcap file with the given (sec, frac, data) records.

    ``frac`` is the fractional part of the timestamp, in microseconds, or in nanoseconds if
    ``nano`` is set. ``linktype`` and ``endianness`` are passed to scapy's ``RawPcapWriter``.
    """
    out = io.BytesIO()
    writer = RawPcapWriter(out, linktype=linktype, nano=nano, endianness=endianness)
    writer.write_header(None)
    for sec, frac, data in records:
        writer.write_packet(data, sec=sec, usec=frac)
    return out.getvalue()


def pcap_packets(path: Path) -> list[bytes]:
    """Return the data of each packet in the classic pcap file ``path``."""
    with RawPcapReader(str(path)) as reader:
        return [data for data, _ in reader]


class FakeStream:
    """In-memory byte stream that replaces the stdout or stderr of an asyncssh process.

    The test adds data with ``feed()`` and ends the stream with ``close()``.
    """

    def __init__(self) -> None:
        self._buf = bytearray()
        self._eof = False
        self._cond = asyncio.Condition()

    async def feed(self, data: bytes) -> None:
        """Append ``data`` to the stream and wake up the waiting readers."""
        async with self._cond:
            self._buf += data
            self._cond.notify_all()

    async def close(self) -> None:
        """End the stream. Readers get the remaining data, then an empty bytes object."""
        async with self._cond:
            self._eof = True
            self._cond.notify_all()

    async def read(self, n: int = -1) -> bytes:
        """Wait for data and return up to ``n`` bytes, or all the available bytes if ``n`` is
        negative. Once the stream is closed and all its data has been read, return an empty bytes
        object."""
        async with self._cond:
            await self._cond.wait_for(lambda: self._buf or self._eof)
            n = len(self._buf) if n < 0 else n
            data = bytes(self._buf[:n])
            del self._buf[:n]
            return data

    async def readline(self) -> bytes:
        """Wait for a complete line and return it, including its newline. Once the stream
        is closed and no complete line is left, return the remaining data, which may be empty."""
        async with self._cond:
            await self._cond.wait_for(lambda: b"\n" in self._buf or self._eof)
            idx = self._buf.find(b"\n")
            end = idx + 1 if idx >= 0 else len(self._buf)
            data = bytes(self._buf[:end])
            del self._buf[:end]
            return data


class FakeTcpdump:
    """Fake remote ``tcpdump -w -`` process, as returned by ``FakeSsh.start_process()``.

    The process writes the pcap stream to ``stdout`` and its messages to ``stderr``. To make the
    process fail at startup, set ``fail`` to the error message that tcpdump should print.
    """

    def __init__(self, pid: int = 4242, fail: str | None = None) -> None:
        self.pid = pid
        self.stdout = FakeStream()
        self.stderr = FakeStream()
        self.exit_status: int | None = None
        self.closed = False
        self.fail = fail

    async def boot(self) -> None:
        """Write what the remote command prints at startup.

        The process prints the PID line of the wrapper shell, then the pcap global header and
        tcpdump's "listening on" message. If ``fail`` is set, the process prints the error message
        in ``fail`` instead of the header and the "listening on" message, and exits with status 1.
        """
        await self.stderr.feed(f"CV2X_PID {self.pid}\n".encode())
        if self.fail:
            await self.stderr.feed(f"tcpdump: {self.fail}\n".encode())
            self.exit_status = 1
            await self.stdout.close()
            await self.stderr.close()
            return
        await self.stdout.feed(pcap_bytes([]))
        await self.stderr.feed(b"tcpdump: listening on lo, link-type EN10MB (Ethernet)\n")

    async def packet(self, data: bytes, ts: float = 1.0) -> None:
        """Write a packet to stdout, as a pcap record with the timestamp ``ts`` in seconds."""
        record = pcap_bytes([(int(ts), int((ts % 1) * 1e6), data)])[pcap.GLOBAL_HEADER_LEN :]
        await self.stdout.feed(record)

    async def interrupt(self) -> None:
        """Exit with status 0, as tcpdump does on SIGINT, and end both output streams."""
        self.exit_status = 0
        await self.stdout.close()
        await self.stderr.close()

    def close(self) -> None:
        """Record that the driver closed the process."""
        self.closed = True


class FakeSsh:
    """Fake SSH session that records the commands it gets and answers them with canned responses.

    ``responses`` maps regular expressions, which must match the whole command, to a ``Response``
    or to a function that returns a response for the command. ``files`` maps remote paths to the
    contents that ``read_file_via_cat()`` downloads. ``is_root`` says whether the login user is
    root. To make the tcpdump processes started afterward fail, set ``tcpdump_fail`` to the
    error message that tcpdump should print.
    """

    def __init__(
        self,
        responses: dict[str, Response | Callable[[str], Response]] | None = None,
        files: dict[str, bytes] | None = None,
        *,
        is_root: bool = False,
    ) -> None:
        self.responses = responses or {}
        self.files = files or {}
        self.is_root = is_root
        self.tcpdump_fail: str | None = None
        self.connected = True
        self.commands: list[str] = []
        self.processes: list[FakeTcpdump] = []

    @property
    def process(self) -> FakeTcpdump | None:
        """The last tcpdump process started, or None if there is none."""
        return self.processes[-1] if self.processes else None

    def _lookup(self, command: str) -> Response:
        for pattern, resp in self.responses.items():
            if re.fullmatch(pattern, command):
                return resp(command) if callable(resp) else resp
        return 0, "", ""

    async def run(self, command: str, *, check: bool = True, timeout: float | None = None) -> CommandResult:
        """Record the command and return the response of the first pattern that matches it, or
        success with no output if none matches.

        Like the real session, raise ``CommandError`` for a nonzero exit status if ``check`` is
        set. A ``kill -INT <pid>`` command also interrupts the fake tcpdump process with that PID.
        ``timeout`` is ignored.
        """
        self.commands.append(command)
        if m := re.search(r"kill -INT (\d+)", command):
            for process in self.processes:
                if process.pid == int(m.group(1)):
                    await process.interrupt()
        status, out, err = self._lookup(command)
        result = CommandResult(command, exit_status=status, stdout=out, stderr=err)
        if check and status != 0:
            raise CommandError(f"'{command}' failed with exit status {status}", result)
        return result

    async def start_process(self, command: str) -> FakeTcpdump:
        """Record the command and start a fake tcpdump process, which fails if ``tcpdump_fail``
        is set."""
        self.commands.append(command)
        process = FakeTcpdump(pid=4242 + len(self.processes), fail=self.tcpdump_fail)
        self.processes.append(process)
        await process.boot()
        return process

    async def read_file_via_cat(
        self, remote_path: str, local_path: Path, *, sudo: bool = False, timeout: float | None = None
    ) -> int:
        """Record the ``cat`` command and write the contents of ``remote_path`` in ``files`` to
        ``local_path``.

        Return the number of bytes written, or raise ``CommandError`` if ``files`` has no such
        path. ``timeout`` is ignored.
        """
        self.commands.append(f"{'sudo -n ' if sudo else ''}cat {remote_path}")
        if remote_path not in self.files:
            raise CommandError(f"cannot read {remote_path}: No such file or directory")
        local_path.write_bytes(self.files[remote_path])  # noqa: ASYNC240
        return len(self.files[remote_path])


# The factory that the make_ctx fixture returns.
type DeviceContextFactory = Callable[..., tuple[DeviceContext, FakeSsh, list[str]]]


@pytest.fixture
def make_ctx(tmp_path: Path) -> DeviceContextFactory:
    """Return a factory that builds the ``DeviceContext`` of a driver.

    The factory takes the device's config and returns the context, its SSH session and the
    warnings that the driver reports. The session is a new ``FakeSsh`` unless one is given. The
    failures that the driver reports go to the context's ``failures`` list, and raw files go to
    ``<device>_raw/`` in ``tmp_path``.
    """

    def factory(
        device: DeviceConfig,
        ssh: FakeSsh | None = None,
        *,
        keep_raw: bool = False,
        delete_remote: bool = True,
    ) -> tuple[DeviceContext, FakeSsh, list[str]]:
        ssh = ssh or FakeSsh()
        raw_dir = tmp_path / f"{device.name}_raw"
        raw_dir.mkdir(exist_ok=True)
        warnings: list[str] = []
        failures: list[str] = []
        ctx = DeviceContext(
            device=device,
            settings=Settings(command_timeout=2),
            log=DeviceLogger(device.name),
            ssh=ssh,  # type: ignore[arg-type]
            raw_files_dir=raw_dir,
            keep_raw_files=keep_raw,
            delete_remote_files=delete_remote,
            on_warning=warnings.append,
            on_failure=failures.append,
        )
        ctx.failures = failures  # type: ignore[attr-defined]
        return ctx, ssh, warnings

    return factory


def mock_device(name: str, role: str = "obu", **options: object) -> DeviceConfig:
    """Return the config of a mock device.

    ``options`` sets driver options. By default, the device takes 10 ms per step and generates
    50 packets per second, so that short tests run fast and still capture packets.
    """
    opts: dict[str, object] = {"step_delay_ms": 10, "packet_rate_hz": 50.0}
    opts.update(options)
    return DeviceConfig(name=name, model="mock", role=role, host="127.0.0.1", username="demo", options=opts)


def mock_config(tmp_path: Path, *devices: DeviceConfig, **settings: object) -> Config:
    """Return a config with the given devices that writes its results to ``results/`` in
    ``tmp_path``.

    ``settings`` sets global settings. The stop timeout is 5 seconds by default.
    """
    cfg = Config(tmp_path / "config.toml")
    cfg.settings.output_dir = str(tmp_path / "results")
    cfg.settings.stop_timeout = 5
    for k, v in settings.items():
        setattr(cfg.settings, k, v)
    cfg.devices = list(devices)
    return cfg
