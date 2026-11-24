# SPDX-License-Identifier: NIST-Software

"""Cohda Wireless MK6 OBU/RSU."""

import asyncio
import shlex
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ..options import option
from .base import CaptureMode, Driver, DriverError, DriverOptions

RC_SCRIPT = "/mnt/rw/example1609/rc.example1609"
LOG_DIR = "/tmp/log/current"
MERGE_FILES = ("rx_pc5.pcap", "tx_pc5.pcap")
RAW_FILES = (
    "cfg",
    "conf.all",
    "conf.diff",
    "config.gz",
    "gps.pcap",
    "info",
    "rx.pcap",
    "rx_pc5.pcap",
    "stderr",
    "stdout",
    "tx.pcap",
    "tx_pc5.pcap",
)
LOG_DIR_RESOLVE_ATTEMPTS = 5


@dataclass
class CohdaMk6Options(DriverOptions):
    check_gps: bool = option(
        True,
        label="Check GPS",
        help="Run kinematics-sample-client during the pre-check and fail if it reports an error",
    )


class CohdaMk6(Driver[CohdaMk6Options]):
    model_id = "cohda-mk6"
    display_name = "Cohda MK6"
    vendor = "Cohda Wireless"
    capture_mode = CaptureMode.REMOTE_FILES
    Options = CohdaMk6Options
    default_username = "user"
    default_password = "user"

    remote_dir: str | None = None

    async def precheck(self) -> None:
        await self.check_root_privileges()
        await self.check_cv2x_status(as_root=True)
        if self.options.check_gps:
            await self.run_as_root("kinematics-sample-client -a -n 1")

    async def start_test(self) -> None:
        await self.run_as_root(f"{RC_SCRIPT} start {shlex.quote(self.device.role)}")
        # Resolve the per-run log directory now, so a later run cannot change it.
        for attempt in range(LOG_DIR_RESOLVE_ATTEMPTS):
            result = await self.run(f"readlink -en {LOG_DIR}", check=False)
            path = result.stdout.strip()
            if result.ok and path.startswith("/"):
                self.remote_dir = path
                self.ctx.log.info(f"remote log directory: {path}")
                return
            if attempt < LOG_DIR_RESOLVE_ATTEMPTS - 1:
                await asyncio.sleep(1)
        raise DriverError(f"could not resolve {LOG_DIR} after starting the test")

    async def stop_test(self) -> None:
        await self.run_as_root(f"{RC_SCRIPT} stop {shlex.quote(self.device.role)}")

    async def collect(self, directory: Path) -> list[Path]:
        if not self.remote_dir:
            self.ctx.warn("remote log directory unknown; nothing to collect")
            return []
        names = RAW_FILES if self.ctx.keep_raw_files else MERGE_FILES
        collected = []
        for name in names:
            local = await self.download(f"{self.remote_dir}/{name}", directory, as_root=True)
            if local is not None:
                collected.append(local)
        return collected

    def pcap_files_to_merge(self, collected: list[Path]) -> list[Path]:
        return [p for p in collected if p.name in MERGE_FILES]

    async def cleanup(self) -> None:
        if not self.ctx.delete_remote_files or not self.remote_dir:
            return
        # Safety net: only ever delete per-run directories next to the log symlink.
        allowed = f"{PurePosixPath(LOG_DIR).parent}/"
        if not self.remote_dir.startswith(allowed) or ".." in self.remote_dir:
            self.ctx.warn(f"refusing to delete unexpected remote directory {self.remote_dir}")
            return
        await self.run_as_root(f"rm -fr {shlex.quote(self.remote_dir)}")
