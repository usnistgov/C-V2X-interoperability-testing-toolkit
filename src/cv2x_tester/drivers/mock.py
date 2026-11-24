# SPDX-License-Identifier: NIST-Software

"""Simulated device for GUI development, demos and tests.

It needs no SSH connection and writes synthetic UDP packets to its capture files.
"""

import asyncio
import contextlib
import hashlib
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

# Lazy, so that loading the drivers does not load scapy.
lazy from scapy.data import DLT_EN10MB
lazy from scapy.layers.inet import IP, UDP
lazy from scapy.layers.l2 import Ether
lazy from scapy.utils import RawPcapWriter

from .. import pcap
from ..clock import ClockSource
from ..options import option
from .base import CaptureMode, CaptureStats, DeviceNotReady, Driver, DriverError, DriverOptions

FailPhase = Literal[
    "none",
    "precheck",
    "clock",
    "start_capture",
    "start_test",
    "running",
    "stop_test",
    "stop_capture",
    "collect",
]
RUNNING_FAILURE_DELAY = 1.0  # seconds after start_test when fail_phase = "running" triggers


@dataclass
class MockOptions(DriverOptions):
    packet_rate_hz: float = option(
        10.0, label="Packet rate (Hz)", help="Synthetic packets per second", min=0.0, max=10000.0
    )
    streams: int = option(
        1,
        help="Number of capture streams, each written to its own file; packets are spread across them",
        min=1,
        max=8,
    )
    truncate_capture: bool = option(
        False,
        help="Simulate an interrupted stream by cutting the last captured packet in half",
    )
    clock_offset_ms: int = option(0, label="Clock offset (ms)", help="Simulated device clock offset")
    not_ready: bool = option(False, help="Make the pre-check report that the device is not ready")
    fail_phase: FailPhase = option("none", label="Fail in phase", help="Inject a failure in this phase")
    step_delay_ms: int = option(
        200,
        label="Step delay (ms)",
        help="Simulated duration of each step, such as the pre-check or stopping the test",
        min=0,
        max=60000,
    )


def synthetic_packet(device: str, seq: int) -> bytes:
    """Ethernet/IPv4/UDP broadcast packet to port 50000 carrying a sequence number and
    the device name in its payload."""
    tag = hashlib.sha256(device.encode()).digest()[:3]
    payload = struct.pack("!I", seq) + device.encode()[:32]
    packet = (
        Ether(src=f"02:00:00:{tag.hex(':')}", dst="ff:ff:ff:ff:ff:ff")
        / IP(src=f"10.{tag[0]}.{tag[1]}.{tag[2]}", dst="255.255.255.255", id=seq & 0xFFFF)
        / UDP(sport=50000, dport=50000)
        / payload
    )
    return bytes(packet)


class Mock(Driver[MockOptions]):
    model_id = "mock"
    display_name = "Mock device"
    vendor = "Simulated"
    capture_mode = CaptureMode.STREAM
    Options = MockOptions
    uses_ssh = False

    _task: asyncio.Task[None] | None = None
    _fail_task: asyncio.Task[None] | None = None
    _paths: tuple[Path, ...] = ()
    _writers: tuple[RawPcapWriter, ...] = ()
    _last: tuple[int, int] | None = None  # stream index and length of the last packet written
    _packets = 0
    _bytes = 0

    async def _step(self, phase: str, description: str) -> None:
        self.ctx.log.info(f"[mock] {description}")
        await asyncio.sleep(self.options.step_delay_ms / 1000)
        if self.options.fail_phase == phase:
            raise DriverError(f"simulated failure in {phase}")

    async def precheck(self) -> None:
        await self._step("precheck", "running pre-checks")
        if self.options.not_ready:
            raise DeviceNotReady("simulated device not ready")

    def clock_sources(self) -> list[ClockSource]:
        return [ClockSource("simulated clock", resolution="ns", read=self._read_clock)]

    async def _read_clock(self) -> float:
        if self.options.fail_phase == "clock":
            raise DriverError("simulated failure in clock")
        # Sample the clock halfway through a simulated round trip, like a real device.
        half_rtt = min(self.options.step_delay_ms / 1000, 0.05) / 2
        await asyncio.sleep(half_rtt)
        now = time.time() + self.options.clock_offset_ms / 1000
        await asyncio.sleep(half_rtt)
        return now

    async def start_capture(self) -> None:
        await self._step("start_capture", "starting capture")
        if self.ctx.raw_files_dir is None:
            raise DriverError("no raw files folder")
        self._paths = tuple(
            self.ctx.raw_files_dir / f"stream{i}.pcap" for i in range(1, self.options.streams + 1)
        )
        self._writers = tuple(RawPcapWriter(str(p), linktype=DLT_EN10MB, endianness="<") for p in self._paths)
        for writer in self._writers:
            writer.write_header(None)
        self._bytes = len(self._writers) * pcap.GLOBAL_HEADER_LEN
        self._task = asyncio.create_task(self._generate(), name=f"{self.device.name}-mock")

    async def _generate(self) -> None:
        rate = self.options.packet_rate_hz
        if rate <= 0:
            return
        interval = 1.0 / rate
        start = time.monotonic()
        seq = 0
        while True:
            seq += 1
            now = time.time()
            sec = int(now)
            packet = synthetic_packet(self.device.name, seq)
            index = (seq - 1) % len(self._writers)  # each stream in turn
            self._writers[index].write_packet(packet, sec=sec, usec=int((now - sec) * 1e6))
            self._last = (index, len(packet))
            self._packets += 1
            self._bytes += pcap.RECORD_HEADER_LEN + len(packet)
            if seq % max(1, int(rate / 2)) == 0:
                for writer in self._writers:
                    writer.flush()
            await asyncio.sleep(max(0.0, start + seq * interval - time.monotonic()))

    async def start_test(self) -> None:
        await self._step("start_test", "starting test")
        if self.options.fail_phase == "running":
            self._fail_task = asyncio.create_task(self._fail_later())

    async def _fail_later(self) -> None:
        await asyncio.sleep(RUNNING_FAILURE_DELAY)
        await self._stop_generator()
        self.ctx.report_failure("simulated failure while running")

    async def _stop_generator(self) -> None:
        """Stop generating packets, and wait until the generator has finished."""
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            await asyncio.wait([task])

    async def stop_test(self) -> None:
        if self._fail_task is not None:
            self._fail_task.cancel()
        await self._step("stop_test", "stopping test")

    async def stop_capture(self) -> None:
        self.ctx.log.info("[mock] stopping capture")
        await asyncio.sleep(self.options.step_delay_ms / 1000)
        await self._stop_generator()
        for writer in self._writers:
            with contextlib.suppress(OSError):
                writer.close()
        self._writers = ()
        if self.options.truncate_capture and self._last is not None:
            # Cut the last packet in half, in the file it was written to.
            index, length = self._last
            self._last = None
            path = self._paths[index]
            with contextlib.suppress(OSError), path.open("r+b") as f:
                f.truncate(path.stat().st_size - length // 2)
                self._bytes -= length // 2
        # Fail only once the capture has stopped, so that nothing writes to its files after the run.
        if self.options.fail_phase == "stop_capture":
            raise DriverError("simulated failure in stop_capture")

    async def collect(self, directory: Path) -> list[Path]:
        await self._step("collect", "collecting files")
        return []

    def pcap_files_to_merge(self, collected: list[Path]) -> list[Path]:
        return list(self._paths)

    def stats(self) -> CaptureStats:
        return CaptureStats(packets=self._packets, bytes=self._bytes)
