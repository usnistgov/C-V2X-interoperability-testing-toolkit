# SPDX-License-Identifier: NIST-Software

import errno
from pathlib import Path

import pytest
from conftest import pcap_bytes
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapReader, RawPcapWriter, wrpcapng

from cv2x_tester.pcap import (
    LinkTypeMismatchError,
    PcapFormatError,
    PcapStreamCounter,
    merge_pcaps,
)


def write_pcap(
    path: Path, records: list[tuple[int, int, bytes]], *, linktype: int = 1, nano: bool = False
) -> Path:
    """records: list of (sec, frac, payload)."""
    path.write_bytes(pcap_bytes(records, linktype=linktype, nano=nano))
    return path


def read_records(path: Path) -> tuple[bool, list[tuple[int, int, bytes]]]:
    with RawPcapReader(str(path)) as r:
        return r.nano, [(m.sec, m.usec, d) for d, m in r]


def test_merge_orders_by_timestamp(tmp_path):
    rx = write_pcap(tmp_path / "rx.pcap", [(10, 0, b"r1"), (10, 500, b"r2"), (12, 0, b"r3")])
    tx = write_pcap(tmp_path / "tx.pcap", [(10, 250, b"t1"), (11, 999_999, b"t2")])
    out = tmp_path / "out.pcap"
    res = merge_pcaps([rx, tx], out)
    assert res.packets == 5
    assert res.linktype == 1
    assert not res.nano
    assert res.skipped == []
    nano, recs = read_records(out)
    assert not nano
    assert [d for _, _, d in recs] == [b"r1", b"t1", b"r2", b"t2", b"r3"]
    assert recs[1][:2] == (10, 250)


def test_merge_ties_keep_input_order(tmp_path):
    a = write_pcap(tmp_path / "a.pcap", [(5, 0, b"a")])
    b = write_pcap(tmp_path / "b.pcap", [(5, 0, b"b")])
    merge_pcaps([a, b], tmp_path / "o.pcap")
    assert [d for *_, d in read_records(tmp_path / "o.pcap")[1]] == [b"a", b"b"]


def test_merge_nanosecond_precision(tmp_path):
    us = write_pcap(tmp_path / "us.pcap", [(1, 2, b"us")])  # 1.000002 s
    ns = write_pcap(tmp_path / "ns.pcap", [(1, 1_500, b"ns1"), (1, 2_500, b"ns2")], nano=True)
    res = merge_pcaps([us, ns], tmp_path / "o.pcap")
    assert res.nano
    nano, recs = read_records(tmp_path / "o.pcap")
    assert nano
    assert recs == [(1, 1_500, b"ns1"), (1, 2_000, b"us"), (1, 2_500, b"ns2")]


def test_merge_keeps_link_type_and_original_lengths(tmp_path):
    # Link type 147, with the P bit set and an FCS length of 2 words in the upper bits.
    linktype = 0x24000000 | 147
    a = write_pcap(tmp_path / "a.pcap", [(1, 0, b"a")], linktype=linktype)
    b = tmp_path / "b.pcap"
    writer = RawPcapWriter(str(b), linktype=linktype, endianness="<")
    writer.write_header(None)
    writer.write_packet(b"cut", sec=2, usec=0, wirelen=1500)  # cut short by the device's snaplen
    writer.close()
    merge_pcaps([a, b], tmp_path / "o.pcap")
    with RawPcapReader(str(tmp_path / "o.pcap")) as r:
        assert r.linktype == linktype
        assert [(d, m.caplen, m.wirelen) for d, m in r] == [(b"a", 1, 1), (b"cut", 3, 1500)]


def test_merge_big_endian_input(tmp_path):
    p = tmp_path / "be.pcap"
    p.write_bytes(pcap_bytes([(1, 0, b"abc")], endianness=">"))
    assert p.read_bytes()[:4] == b"\xa1\xb2\xc3\xd4"  # big-endian magic
    merge_pcaps([p], tmp_path / "o.pcap")
    assert read_records(tmp_path / "o.pcap")[1] == [(1, 0, b"abc")]


def test_merge_link_type_mismatch(tmp_path):
    a = write_pcap(tmp_path / "a.pcap", [(1, 0, b"a")], linktype=1)
    b = write_pcap(tmp_path / "b.pcap", [(1, 0, b"b")], linktype=147)
    with pytest.raises(LinkTypeMismatchError):
        merge_pcaps([a, b], tmp_path / "o.pcap")


def test_merge_skips_missing_and_empty(tmp_path):
    a = write_pcap(tmp_path / "a.pcap", [(1, 0, b"a")])
    (tmp_path / "empty.pcap").write_bytes(b"")
    (tmp_path / "junk.pcap").write_bytes(b"not a pcap at all, really")
    res = merge_pcaps(
        [a, tmp_path / "missing.pcap", tmp_path / "empty.pcap", tmp_path / "junk.pcap"], tmp_path / "o.pcap"
    )
    assert res.packets == 1
    assert {p.name for p, _ in res.skipped} == {"missing.pcap", "empty.pcap", "junk.pcap"}


def test_merge_skips_pcapng_and_short_files(tmp_path):
    a = write_pcap(tmp_path / "a.pcap", [(1, 0, b"a")])
    ng = tmp_path / "x.pcapng"
    wrpcapng(str(ng), [Ether()])
    short = tmp_path / "short.pcap"
    short.write_bytes(b"short")
    res = merge_pcaps([a, ng, short], tmp_path / "o.pcap")
    assert res.packets == 1
    assert res.skipped == [(ng, "pcapng files are not supported"), (short, "not a pcap file")]


def test_merge_no_usable_inputs(tmp_path):
    with pytest.raises(PcapFormatError, match=r"no usable input files \(missing.pcap: missing\)"):
        merge_pcaps([tmp_path / "missing.pcap"], tmp_path / "o.pcap")


def test_merge_removes_partial_output(tmp_path, monkeypatch):
    def fail(self, *args, **kwargs):
        raise OSError(errno.ENOSPC, "No space left on device")

    a = write_pcap(tmp_path / "a.pcap", [(1, 0, b"a")])
    out = tmp_path / "o.pcap"
    monkeypatch.setattr(RawPcapWriter, "write_packet", fail)
    with pytest.raises(OSError, match="No space left on device"):
        merge_pcaps([a], out)
    assert not out.exists()


def test_merge_empty_inputs_writes_header_only(tmp_path):
    a = write_pcap(tmp_path / "a.pcap", [])
    res = merge_pcaps([a], tmp_path / "o.pcap")
    assert res.packets == 0
    assert read_records(tmp_path / "o.pcap")[1] == []


def test_merge_leaves_out_truncated_last_record(tmp_path, capfd):
    a = write_pcap(tmp_path / "a.pcap", [(1, 0, b"a1"), (3, 0, b"a2")])
    with a.open("ab") as f:
        # A record header that announces 100 bytes, followed by only 7.
        RawPcapWriter(f, linktype=1, endianness="<").write_packet(b"partial", sec=4, usec=0, caplen=100)
    b = write_pcap(tmp_path / "b.pcap", [(2, 0, b"b1")])
    res = merge_pcaps([a, b], tmp_path / "o.pcap")
    assert res.packets == 3
    assert res.truncated == [(a, 23)]
    assert [d for *_, d in read_records(tmp_path / "o.pcap")[1]] == [b"a1", b"b1", b"a2"]
    assert "truncated" not in capfd.readouterr().err  # reported by the result, not by scapy


def test_merge_leaves_out_truncated_record_header(tmp_path):
    a = write_pcap(tmp_path / "a.pcap", [(1, 0, b"a1")])
    with a.open("ab") as f:
        f.write(b"\x01\x02\x03")
    b = write_pcap(tmp_path / "b.pcap", [(2, 0, b"b1")])
    res = merge_pcaps([a, b], tmp_path / "o.pcap")
    assert res.packets == 2
    assert res.truncated == [(a, 3)]
    assert [d for *_, d in read_records(tmp_path / "o.pcap")[1]] == [b"a1", b"b1"]


def test_merge_packets_larger_than_scapy_limit(tmp_path):
    # scapy returns at most 65535 bytes of a packet, which must not look like a cut-off record.
    a = write_pcap(tmp_path / "big.pcap", [(1, 0, b"x" * 70000), (2, 0, b"y")])
    res = merge_pcaps([a], tmp_path / "o.pcap")
    assert res.packets == 2
    assert res.truncated == []
    assert read_records(tmp_path / "o.pcap")[1][1] == (2, 0, b"y")


def test_merge_reports_backward_clock_jumps(tmp_path):
    # The clock jumps back 2.5 s in rx. The backward jump of 5 ms in tx is packet reordering.
    rx = write_pcap(tmp_path / "rx.pcap", [(10, 0, b"r1"), (11, 0, b"r2"), (8, 500_000, b"r3")])
    tx = write_pcap(tmp_path / "tx.pcap", [(10, 10_000, b"t1"), (10, 5_000, b"t2")])
    out = tmp_path / "out.pcap"
    res = merge_pcaps([rx, tx], out)
    assert res.clock_backward_jumps == [(rx, 2.5)]
    # Each input keeps its order.
    assert [d for _, _, d in read_records(out)[1]] == [b"r1", b"t1", b"t2", b"r2", b"r3"]


@pytest.mark.parametrize("chunk", [1, 3, 7, 16, 1000])
def test_stream_counter(chunk):
    data = pcap_bytes([(1, 0, bytes(n)) for n in (0, 5, 60, 1)])
    counter = PcapStreamCounter()
    for i in range(0, len(data), chunk):
        counter.feed(data[i : i + chunk])
    assert counter.packets == 4
    assert counter.bytes == len(data)


def test_stream_counter_partial_record():
    data = pcap_bytes([(1, 0, b"abcdef")])
    counter = PcapStreamCounter()
    counter.feed(data[:-2])
    assert counter.packets == 0
    counter.feed(data[-2:])
    assert counter.packets == 1


def test_stream_counter_bad_magic():
    counter = PcapStreamCounter()
    with pytest.raises(PcapFormatError, match="bad magic"):
        counter.feed(b"x" * 40)
    counter.feed(b"x" * 10)  # no second error
    assert counter.packets == 0
    assert counter.bytes == 50
