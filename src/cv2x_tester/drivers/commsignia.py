# SPDX-License-Identifier: NIST-Software

"""Commsignia OBU/RSU."""

import re
from dataclasses import dataclass
from datetime import UTC, datetime

from ..clock import ClockError, ClockSource
from ..options import option
from .base import DriverError
from .tcpdump import SingleInterfaceOptions, StreamSpec, TcpdumpDriver

# Prints the device time in milliseconds since the epoch, which is finer than BusyBox's
# date (whole seconds).
MUCI_CLOCK_COMMAND = "muci stats deviceStatus.miscData.timeStampMs"
# The range of plausible muci times, in seconds since the epoch. Outside it, such as with
# a value in the wrong unit, the clock check falls back to date.
MUCI_CLOCK_EARLIEST = datetime(2020, 1, 1, tzinfo=UTC).timestamp()
MUCI_CLOCK_LATEST = datetime(2100, 1, 1, tzinfo=UTC).timestamp()
# The number of digits is limited so that int() never exceeds Python's limit on the
# length of integer strings, which would raise ValueError.
_MUCI_CLOCK_RE = re.compile(r"deviceStatus\.miscData\.timeStampMs\s*=\s*(\d{1,20})")


@dataclass
class CommsigniaOptions(SingleInterfaceOptions):
    interface: str = option("lo", help="Capture interface", required=True)
    filter: str = option("port 7943", label="Capture filter", help="tcpdump/pcap filter expression")
    check_gps: bool = option(
        True,
        label="Check GPS",
        help="Run kinematics-sample-client during the pre-check and fail if it reports an error",
    )


class Commsignia(TcpdumpDriver[CommsigniaOptions]):
    model_id = "commsignia"
    display_name = "Commsignia"
    vendor = "Commsignia"
    Options = CommsigniaOptions
    default_username = "root"

    def streams(self) -> list[StreamSpec]:
        return [self.options.stream()]

    async def precheck(self) -> None:
        await self.run("commsignia-device-info")
        await self.check_cv2x_status(as_root=True)
        if self.options.check_gps:
            await self.run("kinematics-sample-client -a -n 1")
        await super().precheck()

    def clock_sources(self) -> list[ClockSource]:
        muci = ClockSource("muci", resolution="ms", read=self._read_muci_clock)
        return [muci, *super().clock_sources()]

    async def _read_muci_clock(self) -> float:
        """Return the device time from muci. Any failure raises ClockError, so that the
        clock check falls back to date."""
        try:
            # muci exits with status 1 even when it succeeds, so only its output shows
            # whether it worked.
            result = await self.run(MUCI_CLOCK_COMMAND, check=False)
        except DriverError as e:
            raise ClockError(str(e)) from e
        out = result.stdout.strip()
        m = _MUCI_CLOCK_RE.fullmatch(out)
        if m is None:
            raise ClockError(f"unexpected '{MUCI_CLOCK_COMMAND}' output: {out[:60]!r}")
        ms = int(m[1])
        if not MUCI_CLOCK_EARLIEST <= ms / 1000 < MUCI_CLOCK_LATEST:
            raise ClockError(f"'{MUCI_CLOCK_COMMAND}' returned an implausible timestamp: {ms}")
        return ms / 1000
