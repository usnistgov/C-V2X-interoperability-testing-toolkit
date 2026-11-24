# SPDX-License-Identifier: NIST-Software

import asyncio
import os
import re
import shlex
import shutil
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import DeviceContextFactory, FakeSsh, FakeTcpdump, Response, pcap_bytes, pcap_packets
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from cv2x_tester import pcap
from cv2x_tester.clock import SAMPLES, measure_clock
from cv2x_tester.config import DeviceConfig
from cv2x_tester.drivers import (
    CaptureMode,
    DeviceContext,
    DeviceNotReady,
    Driver,
    DriverError,
    DriverOptions,
    DriverRegistrationError,
    all_drivers,
    get_driver,
)
from cv2x_tester.drivers.cohda_mk6 import LOG_DIR, RC_SCRIPT, CohdaMk6
from cv2x_tester.drivers.commsignia import (
    MUCI_CLOCK_COMMAND,
    MUCI_CLOCK_EARLIEST,
    MUCI_CLOCK_LATEST,
    Commsignia,
)
from cv2x_tester.drivers.ettifos import Ettifos
from cv2x_tester.drivers.generic_linux import GenericLinux
from cv2x_tester.drivers.kapsch import Kapsch
from cv2x_tester.drivers.mock import Mock, synthetic_packet
from cv2x_tester.drivers.tcpdump import StreamSpec, tcpdump_command
from cv2x_tester.drivers.yunex import Yunex
from cv2x_tester.events import DeviceLog
from cv2x_tester.logs import DeviceLogger
from cv2x_tester.ssh import CommandError, SshError


def make_driver[D: Driver](cls: type[D], dev: DeviceConfig, ctx: DeviceContext) -> D:
    """Create a driver of class ``cls`` for the device ``dev``, with the options in its config."""
    return cls(dev, dev.driver_options(), ctx)


# ---------------------------------------------------------------------------
# Registry and options
# ---------------------------------------------------------------------------


def test_builtin_drivers_discovered():
    ids = {d.model_id for d in all_drivers()}
    assert {"cohda-mk6", "commsignia", "ettifos", "generic-linux", "kapsch", "mock"} <= ids
    assert get_driver("cohda-mk6") is CohdaMk6
    assert get_driver("mock") is Mock
    assert get_driver("nope") is None
    assert CohdaMk6.capture_mode is CaptureMode.REMOTE_FILES
    assert Mock.uses_ssh is False


def test_duplicate_model_id_rejected():
    with pytest.raises(DriverRegistrationError):

        class Clash(Driver):
            model_id = "mock"
            display_name = "Clash"


def test_base_classes_without_model_id_not_registered():
    class Intermediate(Driver):
        display_name = "x"

    assert Intermediate not in all_drivers()


def test_required_option_must_not_be_empty():
    assert GenericLinux.Options.from_mapping({})[1] == {"interface": "required"}
    assert GenericLinux.Options.from_mapping({"interface": "  "})[1] == {"interface": "required"}
    assert Kapsch.Options.from_mapping({})[1] == {}  # its default is used
    assert Kapsch.Options.from_mapping({"interface": ""})[1] == {"interface": "required"}


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------


class Plain(Driver):
    """A driver that adds nothing to the base class, for testing the base class itself."""

    display_name = "Plain"


def plain(make_ctx: DeviceContextFactory, ssh: FakeSsh | None = None) -> tuple[Plain, FakeSsh, list[str]]:
    """Return a Plain driver on ``ssh`` (a new FakeSsh by default), the FakeSsh, and the list that
    collects the driver's warnings."""
    dev = DeviceConfig(name="dev", model="plain", host="h", username="u")
    ctx, ssh, warnings = make_ctx(dev, ssh)
    return Plain(dev, DriverOptions(), ctx), ssh, warnings


@pytest.mark.parametrize(("is_root", "command"), [(False, "sudo -n id -un"), (True, "id -un")])
async def test_run_as_root(make_ctx, is_root, command):
    drv, ssh, _ = plain(make_ctx, FakeSsh({r"(sudo -n )?id -un": (0, "root\n", "")}, is_root=is_root))
    result = await drv.run_as_root("id -un")
    assert result.stdout == "root\n"
    assert ssh.commands == [command]


@pytest.mark.parametrize(
    ("is_root", "stderr", "error"),
    [
        pytest.param(
            False, "sudo: a password is required\n", "passwordless sudo required", id="no-passwordless-sudo"
        ),
        pytest.param(
            False, "line1\ncmd failed\n", "'sudo -n cmd' failed with exit status 2: cmd failed", id="sudo"
        ),
        pytest.param(True, "cmd failed\n", "'cmd' failed with exit status 2", id="root"),
    ],
)
async def test_run_as_root_failure(make_ctx, is_root, stderr, error):
    drv, _, _ = plain(make_ctx, FakeSsh({r"(sudo -n )?cmd": (2, "", stderr)}, is_root=is_root))
    with pytest.raises(DriverError, match=re.escape(error)):
        await drv.run_as_root("cmd")


@pytest.mark.parametrize(("is_root", "commands"), [(False, ["sudo -n true"]), (True, [])])
async def test_check_root_privileges(make_ctx, is_root, commands):
    drv, ssh, _ = plain(make_ctx, FakeSsh(is_root=is_root))
    await drv.check_root_privileges()
    assert ssh.commands == commands


async def test_check_root_privileges_requires_passwordless_sudo(make_ctx):
    drv, _, _ = plain(make_ctx, FakeSsh({r"sudo -n true": (1, "", "sudo: a password is required\n")}))
    with pytest.raises(DriverError, match="passwordless sudo required"):
        await drv.check_root_privileges()


# Matches cv2x_get_status, with or without sudo.
CV2X_STATUS = r"(sudo -n )?cv2x_get_status"


def cv2x_status(rx: str = "Active", tx: str = "Active") -> Response:
    """Return a successful cv2x_get_status response with the given RX and TX states,
    formatted as seen on Cohda and Commsignia devices."""
    return 0, f"C-V2X Status:\n  RX : {rx}\n  TX : {tx}\n", ""


@pytest.mark.parametrize(
    "out",
    [
        pytest.param("C-V2X Status:\n  RX : Active\n  TX : Active\n", id="sample"),
        pytest.param("C-V2X Status:\r\n  RX : ACTIVE\r\n  TX : active\r\n", id="case-crlf"),
        pytest.param("TX:Active\nRX:Active", id="no-spaces"),
        pytest.param("\n \n\tRX\t:\tActive   \r\r TX :Active \t\n\n", id="whitespace-blank-lines"),
        pytest.param("C-V2X Status:\n  RX : Active (since boot)\n  TX : ACTIVE.\n", id="text-after-active"),
        pytest.param("RX : Active\nTX : Active\nRX : Active\nTX: active\n", id="repeated-lines"),
        pytest.param(
            "Starting\nRX status: SUSPENDED\nC-V2X Status:\n  RX : Active\n  TX : Active\nDone\n",
            id="unrelated-lines",
        ),
    ],
)
async def test_check_cv2x_status_active(make_ctx, out):
    drv, ssh, _ = plain(make_ctx, FakeSsh({CV2X_STATUS: (0, out, "")}))
    await drv.check_cv2x_status()
    assert ssh.commands == ["cv2x_get_status"]


@pytest.mark.parametrize(
    ("rx", "tx", "listed"),
    [
        ("SUSPENDED", "SUSPENDED", "RX SUSPENDED, TX SUSPENDED"),
        ("Active", "Suspended", "TX Suspended"),
        ("Inactive", "Active", "RX Inactive"),
        ("Unknown", "Unknown", "RX Unknown, TX Unknown"),
    ],
)
async def test_check_cv2x_status_not_active(make_ctx, rx, tx, listed):
    drv, _, _ = plain(make_ctx, FakeSsh({CV2X_STATUS: cv2x_status(rx, tx)}))
    with pytest.raises(DeviceNotReady) as excinfo:
        await drv.check_cv2x_status()
    assert str(excinfo.value) == f"C-V2X radio not active ({listed})"


@pytest.mark.parametrize(
    ("out", "listed"),
    [
        pytest.param(
            "RX : Active\nTX : Active\nRX : Suspended\n", "RX Suspended", id="repeated-one-not-active"
        ),
        pytest.param(
            "RX : Not available\nTX : Active (since boot)\n", "RX Not available", id="several-words"
        ),
        pytest.param("RX : Activated\nTX : Active\n", "RX Activated", id="longer-word"),
        pytest.param(
            "RX: 1234 packets\nC-V2X Status:\n  RX : Active\n  TX : Active\n",
            "RX 1234 packets",
            id="unrelated-rx-line",
        ),
    ],
)
async def test_check_cv2x_status_not_active_lines(make_ctx, out, listed):
    drv, _, _ = plain(make_ctx, FakeSsh({CV2X_STATUS: (0, out, "")}))
    with pytest.raises(DeviceNotReady) as excinfo:
        await drv.check_cv2x_status()
    assert str(excinfo.value) == f"C-V2X radio not active ({listed})"


@pytest.mark.parametrize(
    ("response", "detail"),
    [
        pytest.param((0, "", ""), "no RX or TX state", id="empty"),
        pytest.param((0, "C-V2X Status:\n  RX : Active\n", ""), "no TX state", id="no-tx"),
        pytest.param((0, "C-V2X Status:\n  RX :\n  TX : Active\n", ""), "no RX state", id="empty-state"),
        pytest.param(
            (0, "C-V2X Status:\n  rx : Active\n  tx : Active\n", ""),
            "no RX or TX state",
            id="lowercase-labels",
        ),
        pytest.param(
            (0, "", "C-V2X Status:\n  RX : Active\n  TX : Active\n"), "no RX or TX state", id="stderr-only"
        ),
    ],
)
async def test_check_cv2x_status_unexpected_output(make_ctx, response, detail):
    drv, _, _ = plain(make_ctx, FakeSsh({CV2X_STATUS: response}))
    with pytest.raises(DriverError) as excinfo:
        await drv.check_cv2x_status()
    assert excinfo.type is DriverError
    assert str(excinfo.value) == f"unexpected 'cv2x_get_status' output: {detail}"


async def test_check_cv2x_status_command_failure(make_ctx):
    drv, _, _ = plain(make_ctx, FakeSsh({CV2X_STATUS: (2, "", "radio down\n")}))
    with pytest.raises(DriverError, match="'cv2x_get_status' failed with exit status 2"):
        await drv.check_cv2x_status()


@pytest.mark.parametrize(
    ("is_root", "command"), [(False, "sudo -n cv2x_get_status"), (True, "cv2x_get_status")]
)
async def test_check_cv2x_status_as_root(make_ctx, is_root, command):
    drv, ssh, _ = plain(make_ctx, FakeSsh({CV2X_STATUS: cv2x_status()}, is_root=is_root))
    await drv.check_cv2x_status(as_root=True)
    assert ssh.commands == [command]


@pytest.mark.parametrize(
    ("as_root", "is_root", "command"),
    [
        (False, False, "cat /logs/rx.pcap"),
        (False, True, "cat /logs/rx.pcap"),
        (True, False, "sudo -n cat /logs/rx.pcap"),
        (True, True, "cat /logs/rx.pcap"),
    ],
)
async def test_download(make_ctx, tmp_path, as_root, is_root, command):
    drv, ssh, warnings = plain(make_ctx, FakeSsh(files={"/logs/rx.pcap": b"rx"}, is_root=is_root))
    path = await drv.download("/logs/rx.pcap", tmp_path, as_root=as_root)
    assert path == tmp_path / "rx.pcap"
    assert (tmp_path / "rx.pcap").read_bytes() == b"rx"
    assert ssh.commands == [command]
    assert warnings == []
    assert not drv.ctx.download_failed


async def test_download_with_name(make_ctx, tmp_path):
    drv, _, _ = plain(make_ctx, FakeSsh(files={"/logs/rx.pcap": b"rx"}))
    path = await drv.download("/logs/rx.pcap", tmp_path, name="obu1-rx.pcap")
    assert path == tmp_path / "obu1-rx.pcap"
    assert (tmp_path / "obu1-rx.pcap").read_bytes() == b"rx"


async def test_download_missing_file(make_ctx, tmp_path):
    drv, _, warnings = plain(make_ctx)
    assert await drv.download("/logs/rx.pcap", tmp_path) is None
    assert warnings == ["cannot read /logs/rx.pcap: No such file or directory"]
    assert drv.ctx.download_failed
    assert not (tmp_path / "rx.pcap").exists()


async def test_clock_sources_default(make_ctx):
    drv, ssh, _ = plain(make_ctx, FakeSsh({r"date \+%s\.%N": (0, "1700000000.123456789\n", "")}))
    sources = drv.clock_sources()
    assert [(s.name, s.resolution) for s in sources] == [("date (ns)", "ns"), ("date (s)", "s")]
    assert await sources[0].read() == pytest.approx(1700000000.123456789)
    assert ssh.commands == ["date +%s.%N"]


async def test_clock_falls_back_to_date_s_if_date_ns_fails(make_ctx):
    ssh = FakeSsh(
        {
            r"date \+%s\.%N": (1, "", "date: invalid format\n"),
            r"date \+%s": (0, f"{int(time.time())}\n", ""),
        }
    )
    drv, _, _ = plain(make_ctx, ssh)
    sample = await measure_clock(drv.clock_sources(), samples=1)
    assert sample.resolution == "s"
    assert sample.fallbacks == (
        "'date +%s.%N' failed with exit status 1: date: invalid format; falling back to date (s)",
    )


# ---------------------------------------------------------------------------
# Cohda MK6
# ---------------------------------------------------------------------------


def cohda(
    make_ctx: DeviceContextFactory,
    ssh: FakeSsh | None = None,
    *,
    role: str = "obu",
    check_gps: bool = True,
    **kw: bool,
) -> tuple[CohdaMk6, FakeSsh, list[str]]:
    """Return a Cohda MK6 driver on ``ssh`` (a new FakeSsh by default), the FakeSsh, and the list
    that collects the driver's warnings. The C-V2X radio is active unless ``ssh`` answers
    cv2x_get_status itself."""
    dev = DeviceConfig(
        name="obu1", model="cohda-mk6", role=role, host="h", username="user", options={"check_gps": check_gps}
    )
    ctx, ssh, warnings = make_ctx(dev, ssh, **kw)
    ssh.responses.setdefault(CV2X_STATUS, cv2x_status())
    return make_driver(CohdaMk6, dev, ctx), ssh, warnings


async def test_cohda_precheck(make_ctx):
    drv, ssh, _ = cohda(make_ctx)
    await drv.precheck()
    assert ssh.commands == [
        "sudo -n true",
        "sudo -n cv2x_get_status",
        "sudo -n kinematics-sample-client -a -n 1",
    ]
    drv, ssh, _ = cohda(make_ctx, check_gps=False)
    await drv.precheck()
    assert "sudo -n kinematics-sample-client -a -n 1" not in ssh.commands


async def test_cohda_precheck_radio_not_active(make_ctx):
    drv, ssh, _ = cohda(make_ctx, FakeSsh({CV2X_STATUS: cv2x_status("SUSPENDED", "Active")}))
    with pytest.raises(DeviceNotReady, match=re.escape("C-V2X radio not active (RX SUSPENDED)")):
        await drv.precheck()
    assert ssh.commands == ["sudo -n true", "sudo -n cv2x_get_status"]


async def test_cohda_full_cycle(make_ctx, tmp_path):
    remote = "/tmp/log/2026-10-12_10-00-00"
    rx = pcap_bytes([(10, 0, b"rx")])
    tx = pcap_bytes([(11, 0, b"tx")])
    ssh = FakeSsh(
        {rf"readlink -en {LOG_DIR}": (0, remote + "\n", "")},
        files={f"{remote}/rx_pc5.pcap": rx, f"{remote}/tx_pc5.pcap": tx},
    )
    drv, ssh, warnings = cohda(make_ctx, ssh, role="rsu")
    await drv.start_capture()
    await drv.start_test()
    await drv.stop_test()
    raw = tmp_path / "raw"
    raw.mkdir()
    collected = await drv.collect(raw)
    await drv.cleanup()
    assert ssh.commands == [
        f"sudo -n {RC_SCRIPT} start rsu",
        f"readlink -en {LOG_DIR}",
        f"sudo -n {RC_SCRIPT} stop rsu",
        f"sudo -n cat {remote}/rx_pc5.pcap",
        f"sudo -n cat {remote}/tx_pc5.pcap",
        f"sudo -n rm -fr {remote}",
    ]
    assert [p.name for p in drv.pcap_files_to_merge(collected)] == ["rx_pc5.pcap", "tx_pc5.pcap"]
    assert warnings == []
    assert not drv.ctx.download_failed


async def test_cohda_keep_raw_and_no_delete(make_ctx, tmp_path):
    remote = "/tmp/log/run1"
    ssh = FakeSsh(
        {rf"readlink -en {LOG_DIR}": (0, remote, "")},
        files={f"{remote}/rx_pc5.pcap": b"x", f"{remote}/stdout": b"out"},
    )
    drv, ssh, warnings = cohda(make_ctx, ssh, keep_raw=True, delete_remote=False)
    await drv.start_test()
    collected = await drv.collect(tmp_path)
    await drv.cleanup()
    assert {p.name for p in collected} == {"rx_pc5.pcap", "stdout"}
    assert sum(c.startswith("sudo -n cat") for c in ssh.commands) == 12
    assert not any("rm -fr" in c for c in ssh.commands)
    assert len(warnings) == 10  # every missing file produces a warning
    assert drv.ctx.download_failed
    assert drv.pcap_files_to_merge(collected) == [tmp_path / "rx_pc5.pcap"]


async def test_cohda_unresolvable_log_dir(make_ctx, monkeypatch):
    monkeypatch.setattr("cv2x_tester.drivers.cohda_mk6.LOG_DIR_RESOLVE_ATTEMPTS", 1)
    ssh = FakeSsh({rf"readlink -en {LOG_DIR}": (1, "", "")})
    drv, _, _ = cohda(make_ctx, ssh)
    with pytest.raises(DriverError, match="could not resolve"):
        await drv.start_test()


async def test_cohda_refuses_unexpected_cleanup_dir(make_ctx):
    drv, ssh, warnings = cohda(make_ctx)
    drv.remote_dir = "/"
    await drv.cleanup()
    assert ssh.commands == []
    assert warnings


# ---------------------------------------------------------------------------
# tcpdump streams
# ---------------------------------------------------------------------------


needs_sh = pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")


def run_tcpdump_command(tmp_path: Path, command: str, ssh_connection: str | None = None) -> list[str]:
    """Run a tcpdump command locally, with fake tcpdump and sudo that record the
    arguments, and return the arguments tcpdump got."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    args_file = tmp_path / "args"
    (bin_dir / "tcpdump").write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > {shlex.quote(str(args_file))}\n')
    (bin_dir / "sudo").write_text('#!/bin/sh\n[ "$1" = -n ] && shift\nexec "$@"\n')
    for script in bin_dir.iterdir():
        script.chmod(0o755)
    env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    if ssh_connection is not None:
        env["SSH_CONNECTION"] = ssh_connection
    result = subprocess.run(command, shell=True, env=env, capture_output=True, text=True, check=True)
    assert result.stderr.startswith("CV2X_PID ")
    return args_file.read_text().splitlines()


@needs_sh
def test_tcpdump_command_leaves_out_its_ssh_connection(tmp_path):
    args = run_tcpdump_command(tmp_path, tcpdump_command("lo", "port 7943"), "10.0.0.5 50000 10.0.0.9 22")
    assert args == [
        "-i",
        "lo",
        "-p",
        "-U",
        "-w",
        "-",
        "(port 7943)",
        "and",
        "not (tcp and host 10.0.0.5 and port 50000 and host 10.0.0.9 and port 22)",
    ]
    # Without $SSH_CONNECTION, all TCP traffic on the SSH port is left out.
    args = run_tcpdump_command(tmp_path, tcpdump_command("any", sudo=True, promiscuous=True, ssh_port=2222))
    assert args == ["-i", "any", "-U", "-w", "-", "not (tcp port 2222)"]
    # The zone of an IPv6 link-local address is dropped.
    args = run_tcpdump_command(tmp_path, tcpdump_command("eth0"), "fe80::1%eth0 50000 fe80::2%eth0 22")
    assert args[-1] == "not (tcp and host fe80::1 and port 50000 and host fe80::2 and port 22)"
    assert tcpdump_command("any", sudo=True).endswith(" sh sudo -n tcpdump -i any -p -U -w -")


@needs_sh
@pytest.mark.skipif(shutil.which("tcpdump") is None, reason="needs tcpdump")
def test_ssh_exclusion_filter_with_tcpdump(tmp_path):
    packets = {
        "ssh out": Ether() / IP(src="10.0.0.9", dst="10.0.0.5") / TCP(sport=22, dport=50000),
        "ssh in": Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=50000, dport=22),
        "other ssh": Ether() / IP(src="10.0.0.7", dst="10.0.0.9") / TCP(sport=40000, dport=22),
        "v2x": Ether() / IP(src="10.0.0.9", dst="255.255.255.255") / UDP(sport=7943, dport=7943),
    }
    capture = tmp_path / "in.pcap"
    capture.write_bytes(pcap_bytes([(i, 0, bytes(p)) for i, p in enumerate(packets.values())]))

    def kept(command, ssh_connection=None):
        """The packets kept by the filter that the command passes to tcpdump."""
        args = run_tcpdump_command(tmp_path, command, ssh_connection)
        pcap_filter = args[args.index("-w") + 2 :]
        out = tmp_path / "out.pcap"
        subprocess.run(["tcpdump", "-r", capture, "-w", out, *pcap_filter], check=True, capture_output=True)
        data = pcap_packets(out)
        return [name for name, p in packets.items() if bytes(p) in data]

    connection = "10.0.0.5 50000 10.0.0.9 22"
    assert kept(tcpdump_command("eth0"), connection) == ["other ssh", "v2x"]
    assert kept(tcpdump_command("eth0")) == ["v2x"]
    assert kept(tcpdump_command("eth0", "tcp"), connection) == ["other ssh"]


async def test_promiscuous_option_drops_the_p_flag(make_ctx):
    dev = DeviceConfig(
        name="pi",
        model="generic-linux",
        host="h",
        username="u",
        options={"interface": "eth0", "promiscuous": True},
    )
    ctx, ssh, _ = make_ctx(dev)
    drv = make_driver(GenericLinux, dev, ctx)
    await drv.start_capture()
    await drv.stop_capture()
    assert ssh.commands[0] == tcpdump_command("eth0", sudo=True, promiscuous=True)


async def test_stream_tcpdump_exits_early(make_ctx):
    dev = DeviceConfig(name="rsu4", model="commsignia", role="rsu", host="h", username="root")
    ssh = FakeSsh()
    ssh.tcpdump_fail = "lo0: No such device exists"
    ctx, _, _ = make_ctx(dev, ssh)
    drv = make_driver(Commsignia, dev, ctx)
    with pytest.raises(DriverError, match="No such device exists"):
        await drv.start_capture()


async def test_stream_unexpected_end_reports_failure(make_ctx, tmp_path):
    dev = DeviceConfig(
        name="lin", model="generic-linux", host="h", username="u", options={"interface": "eth0"}
    )
    ctx, ssh, _ = make_ctx(dev)
    drv = make_driver(GenericLinux, dev, ctx)
    await drv.start_capture()
    await ssh.process.packet(b"abc")
    await ssh.process.stdout.feed(b"\x00" * 7)  # half a record header
    await ssh.process.stdout.close()  # stream dies
    await asyncio.sleep(0.05)
    assert ctx.failures == ["eth0: capture stream ended unexpectedly"]
    await drv.stop_capture()
    path = tmp_path / "lin_raw" / "eth0.pcap"
    result = pcap.merge_pcaps([path], tmp_path / "lin.pcap")
    assert result.packets == 1
    assert result.truncated == [(path, 7)]


async def test_stream_warns_on_non_pcap_output(make_ctx, tmp_path):
    class NoisyShell(FakeSsh):
        """Prints a line on stdout before tcpdump starts, as a shell startup file can."""

        async def start_process(self, command):
            self.commands.append(command)
            process = FakeTcpdump()
            self.processes.append(process)
            await process.stdout.feed(b"Welcome!\n")
            await process.boot()
            return process

    dev = DeviceConfig(
        name="lin", model="generic-linux", host="h", username="u", options={"interface": "eth0"}
    )
    ctx, ssh, warnings = make_ctx(dev, NoisyShell())
    drv = make_driver(GenericLinux, dev, ctx)
    await drv.start_capture()
    assert ssh.process is not None
    await ssh.process.packet(b"abc")
    await ssh.process.packet(b"def")
    await asyncio.sleep(0.05)
    await drv.stop_capture()
    assert warnings == ["eth0: cannot count packets: not a pcap file (bad magic)"]
    assert ctx.failures == []
    assert (tmp_path / "lin_raw" / "eth0.pcap").read_bytes().startswith(b"Welcome!\n")


class TwoStreams(GenericLinux):
    def streams(self) -> list[StreamSpec]:
        return [StreamSpec(name="rx", interface="rx0"), StreamSpec(name="tx", interface="tx0", filter="udp")]


async def test_tcpdump_driver_runs_several_streams(make_ctx, tmp_path):
    dev = DeviceConfig(name="yx", model="generic-linux", host="h", username="u")
    ctx, ssh, warnings = make_ctx(dev)
    drv = make_driver(TwoStreams, dev, ctx)
    await drv.start_capture()
    assert ssh.commands == [tcpdump_command("rx0", sudo=True), tcpdump_command("tx0", "udp", sudo=True)]
    rx, tx = ssh.processes
    await rx.packet(b"r1", ts=1)
    await tx.packet(b"t1", ts=2)
    await rx.packet(b"r2", ts=3)
    await asyncio.sleep(0.05)
    await drv.stop_capture()
    assert sorted(ssh.commands[2:]) == ["sudo -n kill -INT 4242", "sudo -n kill -INT 4243"]
    raw = tmp_path / "yx_raw"
    assert drv.pcap_files_to_merge([]) == [raw / "rx.pcap", raw / "tx.pcap"]
    assert pcap_packets(raw / "rx.pcap") == [b"r1", b"r2"]
    assert pcap_packets(raw / "tx.pcap") == [b"t1"]
    stats = drv.stats()
    assert stats is not None
    assert stats.packets == 3  # the totals of both streams
    assert ctx.failures == []
    assert warnings == []


async def test_failed_stream_is_named_and_the_others_keep_running(make_ctx, tmp_path):
    dev = DeviceConfig(name="yx", model="generic-linux", host="h", username="u")
    ctx, ssh, _ = make_ctx(dev)
    drv = make_driver(TwoStreams, dev, ctx)
    await drv.start_capture()
    rx, tx = ssh.processes
    await tx.stdout.close()  # the tx stream dies
    await rx.packet(b"r1")
    await asyncio.sleep(0.05)
    assert ctx.failures == ["tx: capture stream ended unexpectedly"]
    await drv.stop_capture()
    assert pcap_packets(tmp_path / "yx_raw" / "rx.pcap") == [b"r1"]


async def test_stream_start_failure_fails_the_capture(make_ctx):
    class TxFails(FakeSsh):
        async def start_process(self, command):
            self.tcpdump_fail = "tx0: No such device exists" if "tx0" in command else None
            return await super().start_process(command)

    dev = DeviceConfig(name="yx", model="generic-linux", host="h", username="u")
    ctx, ssh, _ = make_ctx(dev, TxFails())
    drv = make_driver(TwoStreams, dev, ctx)
    with pytest.raises(
        DriverError, match=r"^tx: tcpdump exited before capture was ready: tcpdump: tx0: No such"
    ):
        await drv.start_capture()
    await drv.stop_capture()  # the rx stream is still running until the stop sequence
    assert "sudo -n kill -INT 4242" in ssh.commands


# Writing to /dev/full fails with ENOSPC, like writing to a full disk.
needs_dev_full = pytest.mark.skipif(not Path("/dev/full").exists(), reason="needs /dev/full")


@needs_dev_full
async def test_stream_write_error_fails_the_start(make_ctx, tmp_path, monkeypatch):
    monkeypatch.setattr("cv2x_tester.drivers.tcpdump.FLUSH_INTERVAL", 0.05)

    class SlowToListen(FakeSsh):
        """Starts a tcpdump that writes the pcap header at once, and reports that it is
        listening only after the stream's first flush."""

        async def start_process(self, command):
            self.commands.append(command)
            process = FakeTcpdump()
            self.processes.append(process)
            await process.stderr.feed(f"CV2X_PID {process.pid}\n".encode())
            await process.stdout.feed(pcap_bytes([]))

            async def listen_later():
                await asyncio.sleep(0.2)
                await process.stderr.feed(b"tcpdump: listening on eth0, link-type EN10MB (Ethernet)\n")

            self.listening = asyncio.create_task(listen_later())
            return process

    dev = DeviceConfig(
        name="lin", model="generic-linux", host="h", username="u", options={"interface": "eth0"}
    )
    ctx, _, warnings = make_ctx(dev, SlowToListen())
    (tmp_path / "lin_raw" / "eth0.pcap").symlink_to("/dev/full")
    drv = make_driver(GenericLinux, dev, ctx)
    with pytest.raises(DriverError, match=r"^cannot write eth0.pcap: No space left on device$"):
        await drv.start_capture()
    await drv.stop_capture()
    assert ctx.failures == []
    assert warnings == []  # closing the file fails too, but the error was already raised


@needs_dev_full
async def test_stream_write_error_after_start_is_reported(make_ctx, tmp_path, monkeypatch):
    monkeypatch.setattr("cv2x_tester.drivers.tcpdump.FLUSH_INTERVAL", 0.05)
    dev = DeviceConfig(
        name="lin", model="generic-linux", host="h", username="u", options={"interface": "eth0"}
    )
    ctx, ssh, warnings = make_ctx(dev)
    (tmp_path / "lin_raw" / "eth0.pcap").symlink_to("/dev/full")
    drv = make_driver(GenericLinux, dev, ctx)
    # The pcap header is still in the file's buffer when the stream is ready.
    await drv.start_capture()
    assert ssh.process is not None
    await asyncio.sleep(0.15)
    assert ctx.failures == ["cannot write eth0.pcap: No space left on device"]
    assert ssh.process.closed
    await drv.stop_capture()
    assert warnings == []  # closing the file fails too, but the error was already reported


async def test_stream_is_flushed_after_traffic_stops(make_ctx, tmp_path, monkeypatch):
    monkeypatch.setattr("cv2x_tester.drivers.tcpdump.FLUSH_INTERVAL", 0.05)
    dev = DeviceConfig(
        name="lin", model="generic-linux", host="h", username="u", options={"interface": "eth0"}
    )
    ctx, ssh, _ = make_ctx(dev)
    drv = make_driver(GenericLinux, dev, ctx)
    await drv.start_capture()
    assert ssh.process is not None
    await ssh.process.packet(b"abc")
    # No packet follows, yet the packet reaches the file.
    await asyncio.sleep(0.15)
    assert pcap_packets(tmp_path / "lin_raw" / "eth0.pcap") == [b"abc"]
    await drv.stop_capture()


@needs_dev_full
async def test_stream_warns_on_write_error_at_close(make_ctx, tmp_path, monkeypatch):
    # Without the periodic flush, the data stays in the file's buffer until it is closed.
    monkeypatch.setattr("cv2x_tester.drivers.tcpdump.FLUSH_INTERVAL", 1e12)
    dev = DeviceConfig(
        name="lin", model="generic-linux", host="h", username="u", options={"interface": "eth0"}
    )
    ctx, ssh, warnings = make_ctx(dev)
    (tmp_path / "lin_raw" / "eth0.pcap").symlink_to("/dev/full")
    drv = make_driver(GenericLinux, dev, ctx)
    await drv.start_capture()
    assert ssh.process is not None
    await ssh.process.packet(b"abc")
    await asyncio.sleep(0.05)
    assert warnings == []
    await drv.stop_capture()
    assert warnings == ["cannot write eth0.pcap: No space left on device"]
    assert ctx.failures == []


async def test_stream_that_never_started_stops_at_once(make_ctx):
    class TxCannotStart(FakeSsh):
        async def start_process(self, command):
            if "tx0" in command:
                raise SshError("connection lost")
            return await super().start_process(command)

    dev = DeviceConfig(name="yx", model="generic-linux", host="h", username="u")
    ctx, _, _ = make_ctx(dev, TxCannotStart())
    logs: list[DeviceLog] = []
    ctx.log = DeviceLogger(dev.name, logs.append)
    drv = make_driver(TwoStreams, dev, ctx)
    with pytest.raises(SshError, match="connection lost"):
        await drv.start_capture()
    # No tcpdump ran for the tx stream, so stopping it doesn't wait for one to exit.
    await asyncio.wait_for(drv.stop_capture(), 1)
    assert not [log.line for log in logs if "did not exit" in log.line]


async def test_stream_names_must_be_unique(make_ctx):
    class SameName(GenericLinux):
        def streams(self) -> list[StreamSpec]:
            return [StreamSpec(name="cap", interface="rx0"), StreamSpec(name="cap", interface="tx0")]

    dev = DeviceConfig(name="yx", model="generic-linux", host="h", username="u")
    ctx, ssh, _ = make_ctx(dev)
    drv = make_driver(SameName, dev, ctx)
    with pytest.raises(DriverError, match="stream names must be unique"):
        await drv.start_capture()
    assert ssh.commands == []  # nothing was started


# ---------------------------------------------------------------------------
# Streaming drivers
# ---------------------------------------------------------------------------


async def test_commsignia_stream_cycle(make_ctx, tmp_path):
    dev = DeviceConfig(name="rsu4", model="commsignia", role="rsu", host="h", username="root")
    ctx, ssh, warnings = make_ctx(dev, FakeSsh({CV2X_STATUS: cv2x_status()}, is_root=True))
    drv = make_driver(Commsignia, dev, ctx)
    await drv.precheck()
    await drv.start_capture()
    await drv.start_test()
    for i in range(3):
        await ssh.process.packet(bytes(20 + i), ts=100 + i)
    await asyncio.sleep(0.05)
    await drv.stop_test()
    await drv.stop_capture()
    assert ssh.commands[:5] == [
        "commsignia-device-info",
        "cv2x_get_status",
        "kinematics-sample-client -a -n 1",
        "command -v tcpdump",
        tcpdump_command("lo", "port 7943"),
    ]
    assert ssh.commands[5] == "kill -INT 4242"
    path = tmp_path / "rsu4_raw" / "lo.pcap"
    assert drv.pcap_files_to_merge([]) == [path]
    assert path.read_bytes() == pcap_bytes([(100 + i, 0, bytes(20 + i)) for i in range(3)])
    stats = drv.stats()
    assert stats is not None
    assert stats.packets == 3
    assert ctx.failures == []
    assert warnings == []


async def test_commsignia_precheck_without_gps(make_ctx):
    dev = DeviceConfig(
        name="rsu4", model="commsignia", host="h", username="root", options={"check_gps": False}
    )
    ctx, ssh, _ = make_ctx(dev, FakeSsh({CV2X_STATUS: cv2x_status()}, is_root=True))
    await make_driver(Commsignia, dev, ctx).precheck()
    assert ssh.commands == ["commsignia-device-info", "cv2x_get_status", "command -v tcpdump"]


async def test_commsignia_precheck_radio_not_active(make_ctx):
    dev = DeviceConfig(name="rsu4", model="commsignia", host="h", username="root")
    ctx, ssh, _ = make_ctx(dev, FakeSsh({CV2X_STATUS: cv2x_status("SUSPENDED", "SUSPENDED")}, is_root=True))
    with pytest.raises(
        DeviceNotReady, match=re.escape("C-V2X radio not active (RX SUSPENDED, TX SUSPENDED)")
    ):
        await make_driver(Commsignia, dev, ctx).precheck()
    assert ssh.commands == ["commsignia-device-info", "cv2x_get_status"]


def commsignia(
    make_ctx: DeviceContextFactory, muci: Response | Callable[[str], Response]
) -> tuple[Commsignia, FakeSsh]:
    """A Commsignia driver whose muci clock command gives ``muci``, on a BusyBox device whose
    date has no %N."""
    dev = DeviceConfig(name="rsu4", model="commsignia", host="h", username="root")
    ssh = FakeSsh(
        {
            re.escape(MUCI_CLOCK_COMMAND): muci,
            r"date \+%s\.%N": lambda _: (0, f"{int(time.time())}.%N\n", ""),
            r"date \+%s": lambda _: (0, f"{int(time.time())}\n", ""),
        }
    )
    ctx, ssh, _ = make_ctx(dev, ssh)
    return make_driver(Commsignia, dev, ctx), ssh


def muci_output(ms: int, sep: str = " = ") -> Response:
    """The output of the muci clock command for a time of ``ms``, with exit status 1, as on
    the device."""
    return 1, f"deviceStatus.miscData.timeStampMs{sep}{ms}\n", ""


@pytest.mark.parametrize("sep", [" = ", "=", "  =\t "])
async def test_commsignia_clock_muci(make_ctx, sep):
    drv, ssh = commsignia(make_ctx, lambda _: muci_output(round(time.time() * 1000) + 2500, sep))
    sample = await measure_clock(drv.clock_sources())
    assert sample.resolution == "ms"
    assert sample.offset_s == pytest.approx(2.5, abs=0.05)
    assert sample.uncertainty_s >= 0.0005
    assert sample.fallbacks == ()
    assert ssh.commands == [MUCI_CLOCK_COMMAND] * SAMPLES


def raise_timeout(command: str) -> Response:
    raise CommandError(f"'{command}' timed out after 30 s")


@pytest.mark.parametrize(
    ("muci", "error"),
    [
        ((127, "", "sh: muci: not found\n"), f"unexpected '{MUCI_CLOCK_COMMAND}' output: ''"),
        ((1, "deviceStatus.miscData.uptimeMs = 1793048368185\n", ""), "unexpected"),
        ((1, "deviceStatus.miscData.timeStampMs = 1793048368185.5\n", ""), "unexpected"),
        ((1, "deviceStatus.miscData.timeStampMs = N/A\n", ""), "unexpected"),
        ((1, "deviceStatus.miscData.timeStampMs =\n", ""), "unexpected"),
        (muci_output(-1793048368185), "unexpected"),
        (muci_output(1793048368185, sep=""), "unexpected"),
        (muci_output(1793048368185, sep=" "), "unexpected"),
        (muci_output(1793048368185, sep=": "), "unexpected"),
        ((1, "deviceStatus.miscData.timeStampMs = 1793048368185\nextra\n", ""), "unexpected"),
        (muci_output(10**20), "unexpected"),
        (raise_timeout, f"'{MUCI_CLOCK_COMMAND}' timed out after 30 s"),
        (muci_output(1793048368), "implausible timestamp: 1793048368"),
        (muci_output(1793048368185123), "implausible"),
        (muci_output(0), "implausible"),
        (muci_output(round(MUCI_CLOCK_EARLIEST * 1000) - 1), "implausible"),
        (muci_output(round(MUCI_CLOCK_LATEST * 1000)), "implausible"),
    ],
)
async def test_commsignia_clock_falls_back_to_date(make_ctx, muci, error):
    drv, ssh = commsignia(make_ctx, muci)
    sample = await measure_clock(drv.clock_sources())
    assert sample.resolution == "s"
    assert sample.offset_s == pytest.approx(0, abs=1.1)
    first, second = sample.fallbacks
    assert error in first
    assert first.endswith("; falling back to date (ns)")
    assert second.endswith("; falling back to date (s)")
    assert ssh.commands == [MUCI_CLOCK_COMMAND, "date +%s.%N", *["date +%s"] * SAMPLES]


async def test_commsignia_clock_earliest_plausible_time(make_ctx):
    ms = round(MUCI_CLOCK_EARLIEST * 1000)
    drv, _ = commsignia(make_ctx, muci_output(ms))
    [muci, *_] = drv.clock_sources()
    assert await muci.read() == ms / 1000


@pytest.mark.parametrize("driver", [Kapsch, Ettifos])
async def test_rmnet_stream_cycle(make_ctx, tmp_path, driver):
    dev = DeviceConfig(name="rsu5", model=driver.model_id, role="rsu", host="h", username="u")
    ctx, ssh, warnings = make_ctx(dev)
    drv = make_driver(driver, dev, ctx)
    await drv.precheck()
    await drv.start_capture()
    for i in range(2):
        await ssh.process.packet(bytes(20 + i), ts=100 + i)
    await asyncio.sleep(0.05)
    await drv.stop_capture()
    assert ssh.commands == [
        "command -v tcpdump",
        "sudo -n true",
        tcpdump_command("rmnet_data1", sudo=True),
        "sudo -n kill -INT 4242",
    ]
    assert len(pcap_packets(tmp_path / "rsu5_raw" / "rmnet_data1.pcap")) == 2
    assert ctx.failures == []
    assert warnings == []


async def test_yunex_captures_rx_and_tx(make_ctx, tmp_path):
    dev = DeviceConfig(
        name="rsu6", model="yunex", role="rsu", host="h", username="admin", options={"tx_filter": "udp"}
    )
    ctx, ssh, warnings = make_ctx(dev)
    drv = make_driver(Yunex, dev, ctx)
    await drv.precheck()
    await drv.start_capture()
    rx, tx = ssh.processes
    await rx.packet(b"r1", ts=1)
    await tx.packet(b"t1", ts=2)
    await asyncio.sleep(0.05)
    await drv.stop_capture()
    assert ssh.commands[:6] == [
        "command -v tcpdump",
        "sudo -n true",
        "sudo -n ip link set atk-cv2x-rx up",
        "sudo -n ip link set atk-cv2x-tx up",
        tcpdump_command("atk-cv2x-rx", sudo=True),
        tcpdump_command("atk-cv2x-tx", "udp", sudo=True),
    ]
    assert sorted(ssh.commands[6:]) == ["sudo -n kill -INT 4242", "sudo -n kill -INT 4243"]
    raw = tmp_path / "rsu6_raw"
    assert drv.pcap_files_to_merge([]) == [raw / "rx.pcap", raw / "tx.pcap"]
    assert pcap_packets(raw / "rx.pcap") == [b"r1"]
    assert pcap_packets(raw / "tx.pcap") == [b"t1"]
    assert ctx.failures == []
    assert warnings == []


async def test_yunex_interface_bringup_failure(make_ctx):
    dev = DeviceConfig(name="rsu6", model="yunex", role="rsu", host="h", username="admin")
    ssh = FakeSsh({r"sudo -n ip link set atk-cv2x-tx up": (1, "", 'Cannot find device "atk-cv2x-tx"\n')})
    ctx, _, _ = make_ctx(dev, ssh)
    drv = make_driver(Yunex, dev, ctx)
    with pytest.raises(DriverError, match='Cannot find device "atk-cv2x-tx"'):
        await drv.start_capture()
    assert ssh.processes == []  # no capture was started


async def test_generic_linux_commands(make_ctx):
    dev = DeviceConfig(
        name="pi",
        model="generic-linux",
        role="rsu",
        host="h",
        username="u",
        options={
            "use_sudo": True,
            "interface": "wlan0",
            "start_commands": ["app start --role {role} --id {name}", "echo ${HOME}"],
            "stop_commands": ["app stop"],
        },
    )
    ctx, ssh, _ = make_ctx(dev)
    drv = make_driver(GenericLinux, dev, ctx)
    await drv.precheck()
    await drv.start_capture()
    await drv.start_test()
    await drv.stop_test()
    await drv.stop_capture()
    assert ssh.commands == [
        "command -v tcpdump",
        "sudo -n true",
        tcpdump_command("wlan0", sudo=True),
        "app start --role rsu --id pi",
        "echo ${HOME}",
        "app stop",
        "sudo -n kill -INT 4242",
    ]


@pytest.mark.parametrize(
    ("use_sudo", "is_root", "sudo"),
    [(None, False, True), (False, False, False), (None, True, False), (False, True, False)],
)
async def test_generic_linux_use_sudo(make_ctx, use_sudo, is_root, sudo):
    # use_sudo is None for the default, which is to run tcpdump with sudo.
    options: dict[str, object] = {"interface": "eth0"}
    if use_sudo is not None:
        options["use_sudo"] = use_sudo
    dev = DeviceConfig(name="pi", model="generic-linux", host="h", username="u", options=options)
    ctx, ssh, _ = make_ctx(dev, FakeSsh(is_root=is_root))
    drv = make_driver(GenericLinux, dev, ctx)
    await drv.precheck()
    await drv.start_capture()
    await drv.stop_capture()
    assert ssh.commands == [
        "command -v tcpdump",
        *(["sudo -n true"] if sudo else []),
        tcpdump_command("eth0", sudo=sudo),
        f"{'sudo -n ' if sudo else ''}kill -INT 4242",
    ]


# ---------------------------------------------------------------------------
# Mock
# ---------------------------------------------------------------------------


def test_mock_options():
    specs = {s.name: s for s in Mock.Options.schema()}
    assert specs["fail_phase"].kind == "choice"
    assert "running" in specs["fail_phase"].choices
    _, errors = Mock.Options.from_mapping({"fail_phase": "sometime"})
    assert errors.keys() == {"fail_phase"}


def test_mock_packet_is_broadcast_udp_with_sequence_number():
    pkt = Ether(synthetic_packet("obu1", 7))
    assert pkt[IP].dst == "255.255.255.255"
    assert pkt[UDP].dport == 50000
    assert bytes(pkt[UDP].payload) == b"\x00\x00\x00\x07obu1"
