# SPDX-License-Identifier: NIST-Software

"""Generic Linux host: tcpdump streamed over SSH plus optional start/stop commands."""

from dataclasses import dataclass

from ..options import option
from .tcpdump import SingleInterfaceOptions, StreamSpec, TcpdumpDriver


@dataclass
class GenericLinuxOptions(SingleInterfaceOptions):
    use_sudo: bool = option(
        True,
        label="Run tcpdump with sudo",
        help=(
            "When enabled, the SSH user must be able to run sudo without a password; "
            "this option has no effect when logging in as root and should be disabled "
            "only if tcpdump can capture packets on the interface without root privileges"
        ),
    )
    start_commands: list[str] = option(
        [],
        help="Commands run in order to start the test; {role} and {name} are substituted",
    )
    stop_commands: list[str] = option(
        [],
        help="Commands run in order to stop the test; {role} and {name} are substituted",
    )


class GenericLinux(TcpdumpDriver[GenericLinuxOptions]):
    model_id = "generic-linux"
    display_name = "Generic Linux"
    Options = GenericLinuxOptions

    def streams(self) -> list[StreamSpec]:
        return [self.options.stream()]

    def needs_root(self) -> bool:
        return self.options.use_sudo

    def _expand(self, command: str) -> str:
        return command.replace("{role}", self.device.role).replace("{name}", self.device.name)

    async def start_test(self) -> None:
        for command in self.options.start_commands:
            await self.run(self._expand(command))

    async def stop_test(self) -> None:
        for command in self.options.stop_commands:
            await self.run(self._expand(command))
