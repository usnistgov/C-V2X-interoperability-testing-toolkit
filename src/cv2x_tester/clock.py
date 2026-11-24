# SPDX-License-Identifier: NIST-Software

"""Device clock offset measurement. The device clock is read through the driver's clock
sources, falling back from one to the next, and the offset is computed from the midpoint
of each round trip, as NTP does."""

import re
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import KW_ONLY, dataclass, replace
from functools import partial
from typing import TYPE_CHECKING, Literal

from .util import last_line

if TYPE_CHECKING:
    from .ssh import CommandResult

type ClockResolution = Literal["ns", "ms", "s"]

SAMPLES = 3  # measurements per clock check (the one with the smallest uncertainty is kept)
_FRAC_SECS_RE = re.compile(r"\d+\.\d+")
_WHOLE_SECS_RE = re.compile(r"\d+")
_RESOLUTION_SECS: dict[ClockResolution, float] = {"ns": 1e-9, "ms": 1e-3, "s": 1.0}


class ClockError(Exception):
    """A clock source could not read the device clock (unexpected output or a failed
    command)."""


@dataclass(frozen=True)
class ClockSource:
    """A method of reading the device clock.

    ``read`` returns the device time in seconds since the epoch, truncated to
    ``resolution``, and raises ClockError on failure. ``name`` is a short label for the
    device log.
    """

    name: str
    _: KW_ONLY
    resolution: ClockResolution
    read: Callable[[], Awaitable[float]]


@dataclass(frozen=True, kw_only=True)
class ClockSample:
    offset_s: float  # device clock minus host clock
    uncertainty_s: float
    resolution: ClockResolution
    # Why each preferred source was abandoned, one message per source, for the device log.
    fallbacks: tuple[str, ...] = ()


def compute_offset(t_send: float, t_recv: float, remote: float) -> tuple[float, float]:
    """Offset of the remote clock vs. the host, assuming symmetric delays.

    Returns (offset, uncertainty) where uncertainty is half the round-trip time.
    """
    rtt = t_recv - t_send
    return remote - (t_send + t_recv) / 2, rtt / 2


def date_sources(run: Callable[[str], Awaitable[CommandResult]]) -> list[ClockSource]:
    """Return the clock sources that use ``date``: ``date +%s.%N``, then ``date +%s`` for
    devices whose ``date`` does not support ``%N`` (BusyBox).

    ``run`` runs a command on the device and returns its result regardless of the exit status,
    like ``Driver.run()`` with ``check=False``. A command that fails or prints unexpected output
    raises ClockError, so that the clock check falls back to the next source.
    """

    async def read(command: str, pattern: re.Pattern[str]) -> float:
        result = await run(command)
        if not result.ok:
            reason = last_line(result.stderr)
            raise ClockError(
                f"'{command}' failed with exit status {result.exit_status}"
                + (f": {reason}" if reason else "")
            )
        out = result.stdout.strip()
        if not pattern.fullmatch(out):
            raise ClockError(f"unexpected '{command}' output: {out[:60]!r}")
        return float(out)

    return [
        ClockSource("date (ns)", resolution="ns", read=partial(read, "date +%s.%N", _FRAC_SECS_RE)),
        ClockSource("date (s)", resolution="s", read=partial(read, "date +%s", _WHOLE_SECS_RE)),
    ]


async def measure_clock(sources: Sequence[ClockSource], samples: int = SAMPLES) -> ClockSample:
    """Measure the offset of the device clock from the host clock.

    Reads the clock with the first of ``sources``. When a source raises ClockError, the
    measurement falls back to the next one, for the current sample and all the remaining
    ones. ClockError from the last source propagates, as do all other errors. Takes
    ``samples`` samples and keeps the one with the smallest uncertainty.

    Sources truncate their readings to their resolution, so half the resolution is added
    to both the reading and the uncertainty (0.5 s with ``date +%s``).
    """
    if not sources:
        raise ValueError("no clock sources")
    index = 0
    fallbacks: list[str] = []
    best: ClockSample | None = None
    for _ in range(samples):
        while True:
            source = sources[index]
            wall0, perf0 = time.time(), time.perf_counter()
            try:
                remote = await source.read()
            except ClockError as e:
                if index == len(sources) - 1:
                    raise
                index += 1
                fallbacks.append(f"{e}; falling back to {sources[index].name}")
                continue
            rtt = time.perf_counter() - perf0
            break
        half_step = _RESOLUTION_SECS[source.resolution] / 2
        offset, half_rtt = compute_offset(wall0, wall0 + rtt, remote + half_step)
        sample = ClockSample(
            offset_s=offset, uncertainty_s=half_rtt + half_step, resolution=source.resolution
        )
        if best is None or sample.uncertainty_s < best.uncertainty_s:
            best = sample
    assert best is not None
    return replace(best, fallbacks=tuple(fallbacks))
