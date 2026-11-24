# SPDX-License-Identifier: NIST-Software

"""Ettifos OBU/RSU."""

from dataclasses import dataclass

from ..options import option
from .tcpdump import SingleInterfaceOptions, StreamSpec, TcpdumpDriver


@dataclass
class EttifosOptions(SingleInterfaceOptions):
    interface: str = option("rmnet_data1", help="Capture interface", required=True)


class Ettifos(TcpdumpDriver[EttifosOptions]):
    model_id = "ettifos"
    display_name = "Ettifos"
    vendor = "Ettifos"
    Options = EttifosOptions
    default_username = "user"

    def streams(self) -> list[StreamSpec]:
        return [self.options.stream()]
