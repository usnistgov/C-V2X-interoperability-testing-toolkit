# SPDX-License-Identifier: NIST-Software

"""pcap utilities: a streaming record counter, and a scapy-based merge."""

import contextlib
import heapq
import logging
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

# Lazy, so that only reading or writing pcap files loads scapy.
lazy from scapy.error import Scapy_Exception
lazy from scapy.utils import RawPcapNgReader, RawPcapReader, RawPcapWriter

# merge_pcaps reports truncated records itself.
logging.getLogger("scapy.runtime").addFilter(
    lambda record: record.getMessage() != "Pcap: packet has been truncated"
)

# The size in bytes of the header at the start of a classic pcap file.
GLOBAL_HEADER_LEN = 24
# The size in bytes of the header that precedes each packet in the file.
RECORD_HEADER_LEN = 16
# The smallest backward jump of the timestamps in a capture, in seconds, that is reported as the
# clock being set back. Smaller jumps come from packets received on different CPU cores, which
# can be written in a slightly different order than they were timestamped.
CLOCK_BACKWARD_JUMP_MIN = 0.01

# magic (as read little-endian) -> byte order
_MAGICS = {
    0xA1B2C3D4: "<",
    0xA1B23C4D: "<",  # nanosecond timestamps
    0xD4C3B2A1: ">",
    0x4D3CB2A1: ">",  # nanosecond timestamps
}
_PCAPNG_MAGIC = 0x0A0D0D0A


class PcapFormatError(Exception):
    pass


class LinkTypeMismatchError(PcapFormatError):
    pass


def parse_global_header(header: bytes) -> str:
    """Check a classic pcap global header and return its byte order ("<" or ">")."""
    if len(header) < GLOBAL_HEADER_LEN:
        raise PcapFormatError("file is too short to be a pcap file")
    (magic,) = struct.unpack("<I", header[:4])
    if magic == _PCAPNG_MAGIC:
        raise PcapFormatError("pcapng files are not supported")
    if magic not in _MAGICS:
        raise PcapFormatError("not a pcap file (bad magic)")
    return _MAGICS[magic]


class PcapStreamCounter:
    """Counts complete packets in a pcap byte stream fed in arbitrary chunks."""

    def __init__(self) -> None:
        self.packets = 0
        self.bytes = 0
        self._buf = bytearray()
        self._endian: str | None = None
        # Bytes of the current record's body (its packet data) still expected.
        self._remaining = 0
        self._in_body = False
        self._invalid = False

    def feed(self, data: bytes) -> None:
        """Count the bytes and packets in ``data``. If the stream is not pcap data, raise
        :class:`PcapFormatError` once, then count only bytes."""
        self.bytes += len(data)
        if self._invalid:
            return
        i, n = 0, len(data)
        while i < n:
            if self._endian is None:
                take = min(GLOBAL_HEADER_LEN - len(self._buf), n - i)
                self._buf += data[i : i + take]
                i += take
                if len(self._buf) == GLOBAL_HEADER_LEN:
                    try:
                        self._endian = parse_global_header(bytes(self._buf))
                    except PcapFormatError:
                        self._invalid = True
                        raise
                    self._buf.clear()
            elif self._in_body:
                take = min(self._remaining, n - i)
                self._remaining -= take
                i += take
                if self._remaining == 0:
                    self._in_body = False
                    self.packets += 1
            else:
                take = min(RECORD_HEADER_LEN - len(self._buf), n - i)
                self._buf += data[i : i + take]
                i += take
                if len(self._buf) == RECORD_HEADER_LEN:
                    caplen = struct.unpack(self._endian + "I", self._buf[8:12])[0]
                    self._buf.clear()
                    if caplen == 0:
                        self.packets += 1
                    else:
                        self._remaining = caplen
                        self._in_body = True


class _PcapFile:
    """A classic pcap file read with scapy's raw reader, so packets are never dissected."""

    def __init__(self, path: Path) -> None:
        self.size = path.stat().st_size
        # Open the file here so it gets closed if scapy rejects it, which scapy doesn't do
        # for files it opens itself. File objects work despite scapy's type annotation.
        f = path.open("rb")
        try:
            self._reader = RawPcapReader(f)  # type: ignore[arg-type]
        except Scapy_Exception as e:
            f.close()
            raise PcapFormatError("not a pcap file") from e
        if isinstance(self._reader, RawPcapNgReader):
            self._reader.close()
            raise PcapFormatError("pcapng files are not supported")
        self.linktype: int = self._reader.linktype
        self.nano: bool = self._reader.nano
        self.valid_size = GLOBAL_HEADER_LEN  # where the last complete record read ends

    @property
    def truncated(self) -> bool:
        return self.valid_size < self.size

    def records(self) -> Iterator[tuple[bytes, RawPcapReader.PacketMetadata]]:
        """Yield the data and metadata of each complete record.

        Stops at the first record cut off by the end of the file, judging by the length in
        its header (scapy returns at most 65535 bytes of data).
        """
        for data, meta in self._reader:
            end = self.valid_size + RECORD_HEADER_LEN + meta.caplen
            if end > self.size:
                return
            self.valid_size = end
            yield data, meta

    def close(self) -> None:
        self._reader.close()


@dataclass
class MergeResult:
    packets: int
    linktype: int
    nano: bool
    # The inputs that were not merged, each with the reason, such as "missing" or "empty file".
    skipped: list[tuple[Path, str]] = field(default_factory=list)
    # The merged inputs whose last record was cut off, each with the number of bytes left out.
    truncated: list[tuple[Path, int]] = field(default_factory=list)
    # The merged inputs whose timestamps go back by more than CLOCK_BACKWARD_JUMP_MIN, each with its
    # largest backward jump in seconds.
    clock_backward_jumps: list[tuple[Path, float]] = field(default_factory=list)


def merge_pcaps(inputs: list[Path], output: Path) -> MergeResult:
    """Merge classic pcap files into ``output`` in timestamp order.

    The records of each input keep their order. If the clock was set back during the capture,
    the timestamps go back at that point, and the output is not in timestamp order around it.
    Backward jumps larger than ``CLOCK_BACKWARD_JUMP_MIN`` are reported in ``clock_backward_jumps``.

    Inputs that are missing, empty or unreadable are skipped (reported in
    ``skipped``). A last record cut off by the end of its input is left out
    (reported in ``truncated``). Raises LinkTypeMismatchError if the remaining
    inputs have different link types, and PcapFormatError if no input is usable.
    If writing ``output`` fails, the partial file is removed.
    """
    files: list[tuple[Path, _PcapFile]] = []
    skipped: list[tuple[Path, str]] = []
    try:
        for path in inputs:
            if not path.exists():
                skipped.append((path, "missing"))
                continue
            if path.stat().st_size == 0:
                skipped.append((path, "empty file"))
                continue
            try:
                files.append((path, _PcapFile(path)))
            except PcapFormatError as e:
                skipped.append((path, str(e)))
            except OSError as e:
                skipped.append((path, e.strerror or str(e)))
        if not files:
            reasons = "; ".join(f"{p.name}: {reason}" for p, reason in skipped)
            raise PcapFormatError("no usable input files" + (f" ({reasons})" if reasons else ""))
        linktypes = {f.linktype for _, f in files}
        if len(linktypes) > 1:
            detail = ", ".join(f"{p.name}={f.linktype}" for p, f in files)
            raise LinkTypeMismatchError(f"input files have different link types ({detail})")
        linktype = files[0][1].linktype
        nano = any(f.nano for _, f in files)
        # The largest backward jump of the timestamps of each input, in seconds.
        jumps = dict.fromkeys((p for p, _ in files), 0.0)

        def packets(index: int, path: Path, f: _PcapFile) -> Iterator[tuple[int, int, bytes, int]]:
            scale = 1 if f.nano else 1000
            last = 0
            for data, meta in f.records():
                ts = meta.sec * 1_000_000_000 + meta.usec * scale
                if ts < last:
                    jumps[path] = max(jumps[path], (last - ts) / 1e9)
                last = ts
                yield (ts, index, data, meta.wirelen)

        count = 0
        streams = [packets(i, p, f) for i, (p, f) in enumerate(files)]
        writer = RawPcapWriter(str(output), linktype=linktype, nano=nano, endianness="<")
        try:
            with contextlib.closing(writer):
                writer.write_header(None)
                for ts, _, data, wirelen in heapq.merge(*streams, key=lambda p: (p[0], p[1])):
                    sec, frac_ns = divmod(ts, 1_000_000_000)
                    writer.write_packet(
                        data,
                        sec=sec,
                        usec=frac_ns if nano else frac_ns // 1000,
                        caplen=len(data),
                        wirelen=wirelen,
                    )
                    count += 1
        except BaseException:
            output.unlink(missing_ok=True)
            raise
        truncated = [(p, f.size - f.valid_size) for p, f in files if f.truncated]
        clock_backward_jumps = [(p, j) for p, j in jumps.items() if j > CLOCK_BACKWARD_JUMP_MIN]
        return MergeResult(count, linktype, nano, skipped, truncated, clock_backward_jumps)
    finally:
        for _, f in files:
            # Best effort: an error closing an input must not replace the merge's result or error.
            with contextlib.suppress(Exception):
                f.close()
