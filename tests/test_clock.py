# SPDX-License-Identifier: NIST-Software

import time
from collections.abc import Awaitable, Callable

import pytest

from cv2x_tester.clock import (
    SAMPLES,
    ClockError,
    ClockResolution,
    ClockSource,
    compute_offset,
    date_sources,
    measure_clock,
)
from cv2x_tester.ssh import CommandResult


def test_compute_offset():
    offset, unc = compute_offset(100.0, 100.2, 105.1)
    assert offset == pytest.approx(5.0)
    assert unc == pytest.approx(0.1)
    offset, _ = compute_offset(100.0, 100.0, 99.5)
    assert offset == pytest.approx(-0.5)


# ---------------------------------------------------------------------------
# measure_clock
# ---------------------------------------------------------------------------


def source(name: str, resolution: ClockResolution, results: list[float | None]) -> ClockSource:
    """A clock source that returns the host time plus each of ``results`` in turn, or raises
    ClockError for a None, and then keeps failing."""
    remaining = iter(results)

    async def read() -> float:
        offset = next(remaining, None)
        if offset is None:
            raise ClockError(f"{name} failed")
        return time.time() + offset

    return ClockSource(name, resolution=resolution, read=read)


async def test_measure_clock_resolution():
    sample = await measure_clock([source("a", "ms", [1.25] * SAMPLES)])
    assert sample.resolution == "ms"
    assert sample.offset_s == pytest.approx(1.2505, abs=0.05)
    assert sample.uncertainty_s >= 0.0005
    assert sample.fallbacks == ()


async def test_measure_clock_falls_back():
    sample = await measure_clock([source("a", "ms", [None]), source("b", "s", [3, 3, 3])])
    assert sample.resolution == "s"
    assert sample.offset_s == pytest.approx(3.5, abs=0.05)
    assert sample.fallbacks == ("a failed; falling back to b",)


async def test_measure_clock_keeps_the_finer_sample_after_a_fallback():
    # The first source fails on the second sample, after one good sample. The coarser
    # samples that follow have a larger uncertainty, so the first one is kept.
    sample = await measure_clock([source("a", "ms", [1]), source("b", "s", [5, 5, 5])])
    assert sample.resolution == "ms"
    assert sample.offset_s == pytest.approx(1, abs=0.05)
    assert sample.fallbacks == ("a failed; falling back to b",)


async def test_measure_clock_last_source_fails():
    with pytest.raises(ClockError, match="b failed"):
        await measure_clock([source("a", "ms", [None]), source("b", "s", [None])])


async def test_measure_clock_other_errors_propagate():
    async def broken() -> float:
        raise OSError("connection lost")

    sources = [ClockSource("a", resolution="ms", read=broken), source("b", "s", [0, 0, 0])]
    with pytest.raises(OSError, match="connection lost"):
        await measure_clock(sources)


# ---------------------------------------------------------------------------
# date_sources
# ---------------------------------------------------------------------------


def fake_date(output: Callable[[str], str], calls: list[str]) -> Callable[[str], Awaitable[CommandResult]]:
    """A fake ``Driver.run()`` with ``check=False``, for ``date_sources()``: records each
    command in ``calls`` and answers with ``output(command)``."""

    async def run(command: str) -> CommandResult:
        calls.append(command)
        return CommandResult(command, exit_status=0, stdout=output(command), stderr="")

    return run


async def test_date_sources_ns():
    calls: list[str] = []
    sample = await measure_clock(date_sources(fake_date(lambda _: f"{time.time() + 2.5:.9f}\n", calls)))
    assert sample.resolution == "ns"
    assert sample.offset_s == pytest.approx(2.5, abs=0.05)
    assert sample.fallbacks == ()
    assert calls == ["date +%s.%N"] * SAMPLES


async def test_date_sources_busybox_fallback():
    def busybox(command: str) -> str:
        return "1700000000.N" if command == "date +%s.%N" else str(int(time.time()) - 10)

    calls: list[str] = []
    sample = await measure_clock(date_sources(fake_date(busybox, calls)), samples=2)
    assert sample.resolution == "s"
    assert sample.offset_s == pytest.approx(-10, abs=1.1)
    assert sample.uncertainty_s >= 0.5
    assert sample.fallbacks == ("unexpected 'date +%s.%N' output: '1700000000.N'; falling back to date (s)",)
    assert calls == ["date +%s.%N", "date +%s", "date +%s"]


async def test_date_sources_garbage():
    sources = date_sources(fake_date(lambda _: "date: invalid", []))
    with pytest.raises(ClockError, match=r"unexpected 'date \+%s' output: 'date: invalid'"):
        await measure_clock(sources)
