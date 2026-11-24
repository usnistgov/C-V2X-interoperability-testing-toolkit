# SPDX-License-Identifier: NIST-Software

import datetime
import os

import pytest

from cv2x_tester.util import (
    atomic_write,
    format_address,
    format_duration,
    format_offset,
    human_bytes,
    last_line,
    parse_duration,
    slugify,
    time_of_day,
)


@pytest.mark.parametrize(
    ("text", "seconds"),
    [
        ("90", 90),
        ("1:30", 90),
        ("01:02:03", 3723),
        ("1m30s", 90),
        ("2h", 7200),
        ("45s", 45),
        ("1h1s", 3601),
        (" 10 m ", 600),
        ("24h", 86400),
    ],
)
def test_parse_duration(text, seconds):
    assert parse_duration(text) == seconds


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("", "duration is empty"),
        ("0", "must be between 1 s and 24 h"),
        ("25h", "must be between 1 s and 24 h"),
        ("abc", "invalid duration"),
        ("1:60", "invalid duration"),
        ("1:2:3:4", "invalid duration"),
        ("1.5", "invalid duration"),
        ("m", "invalid duration"),
        ("-5", "invalid duration"),
    ],
)
def test_parse_duration_invalid(text, error):
    with pytest.raises(ValueError, match=error):
        parse_duration(text)


def test_formatting():
    assert format_duration(83) == "01:23"
    assert format_duration(3723) == "1:02:03"
    assert slugify("  BSM range test #2 ") == "BSM-range-test-2"
    assert slugify("///") == ""
    assert format_address("fe80::1%eth0", 22) == "[fe80::1%eth0]:22"
    assert format_address("[fe80::1]", 2222) == "[fe80::1]:2222"
    assert format_address("10.0.0.1", 22) == "10.0.0.1:22"
    assert last_line("a\nb\n\n") == "b"
    assert last_line("", "dflt") == "dflt"


def test_human_bytes():
    assert human_bytes(None) == ""
    assert human_bytes(0) == "0 B"
    assert human_bytes(512) == "512 B"
    assert human_bytes(999) == "999 B"
    assert human_bytes(1000) == "1.0 kB"
    assert human_bytes(310_000) == "310.0 kB"
    assert human_bytes(999_949) == "999.9 kB"
    assert human_bytes(999_999) == "1.0 MB"  # not 1000.0 kB
    assert human_bytes(1_000_000) == "1.0 MB"
    assert human_bytes(2_500_000) == "2.5 MB"
    assert human_bytes(999_999_999) == "1.0 GB"  # not 1000.0 MB
    assert human_bytes(2_000_000_000) == "2.0 GB"
    assert human_bytes(5 * 10**12) == "5000.0 GB"  # GB is the largest unit


def test_format_offset():
    assert format_offset(0.1204) == "+0.120 s"
    assert format_offset(-1.5) == "-1.500 s"
    assert format_offset(-0.00004) == "+0.000 s"  # no "-0.000"
    assert format_offset(-0.0) == "+0.000 s"
    assert format_offset(-0.04, 1) == "+0.0 s"
    assert format_offset(2.26, 1) == "+2.3 s"


def test_time_of_day():
    ts = datetime.datetime(2026, 10, 18, 9, 5, 7, 123456, tzinfo=datetime.UTC)
    assert time_of_day(ts) == "09:05:07.123"
    assert len(time_of_day()) == len("HH:MM:SS.mmm")


@pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX only")
def test_atomic_write_modes(tmp_path):
    umask = os.umask(0o022)
    try:
        default, private = tmp_path / "default.txt", tmp_path / "sub" / "private.txt"
        atomic_write(default, "a\n")
        atomic_write(private, "b\n", new_file_mode=0o600)
        assert default.read_text() == "a\n"
        assert private.read_text() == "b\n"
        assert default.stat().st_mode & 0o777 == 0o644  # set by the umask
        assert private.stat().st_mode & 0o777 == 0o600
        default.chmod(0o640)
        atomic_write(default, "c\n", new_file_mode=0o600)
        assert default.read_text() == "c\n"
        assert default.stat().st_mode & 0o777 == 0o640
    finally:
        os.umask(umask)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["default.txt", "sub"]  # no temporary files left


def test_atomic_write_failure_keeps_the_old_file(tmp_path, monkeypatch):
    target = tmp_path / "f.txt"
    target.write_text("old\n")

    def fail(*args):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError, match="disk full"):
        atomic_write(target, "new\n")
    assert target.read_text() == "old\n"
    assert [p.name for p in tmp_path.iterdir()] == ["f.txt"]  # the temporary file is removed
