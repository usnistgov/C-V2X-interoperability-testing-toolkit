# SPDX-License-Identifier: NIST-Software

"""Yunex Traffic OBU/RSU."""

import shlex
from dataclasses import dataclass

from ..options import option
from .base import DriverOptions
from .tcpdump import StreamSpec, TcpdumpDriver


@dataclass
class YunexOptions(DriverOptions):
    rx_interface: str = option(
        "atk-cv2x-rx", label="RX interface", help="Capture interface for received packets", required=True
    )
    rx_filter: str = option(
        "", label="RX capture filter", help="tcpdump/pcap filter expression for the RX interface"
    )
    tx_interface: str = option(
        "atk-cv2x-tx", label="TX interface", help="Capture interface for transmitted packets", required=True
    )
    tx_filter: str = option(
        "", label="TX capture filter", help="tcpdump/pcap filter expression for the TX interface"
    )
    promiscuous: bool = option(False, label="Promiscuous mode", help="Put the interfaces in promiscuous mode")


class Yunex(TcpdumpDriver[YunexOptions]):
    model_id = "yunex"
    display_name = "Yunex"
    vendor = "Yunex Traffic"
    Options = YunexOptions
    default_username = "admin"

    def streams(self) -> list[StreamSpec]:
        opts = self.options
        return [
            StreamSpec(
                name="rx", interface=opts.rx_interface, filter=opts.rx_filter, promiscuous=opts.promiscuous
            ),
            StreamSpec(
                name="tx", interface=opts.tx_interface, filter=opts.tx_filter, promiscuous=opts.promiscuous
            ),
        ]

    async def start_capture(self) -> None:
        # The interfaces may be down. They are left up after the run.
        for interface in (self.options.rx_interface, self.options.tx_interface):
            await self.run_as_root(f"ip link set {shlex.quote(interface)} up")
        await super().start_capture()
