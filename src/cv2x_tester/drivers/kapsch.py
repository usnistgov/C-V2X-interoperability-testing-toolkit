# SPDX-License-Identifier: NIST-Software

"""Kapsch OBU/RSU."""

from dataclasses import dataclass

from ..options import option
from .tcpdump import SingleInterfaceOptions, StreamSpec, TcpdumpDriver


@dataclass
class KapschOptions(SingleInterfaceOptions):
    interface: str = option("rmnet_data1", help="Capture interface", required=True)


class Kapsch(TcpdumpDriver[KapschOptions]):
    model_id = "kapsch"
    display_name = "Kapsch"
    vendor = "Kapsch"
    Options = KapschOptions
    default_username = "admin"

    def streams(self) -> list[StreamSpec]:
        return [self.options.stream()]
