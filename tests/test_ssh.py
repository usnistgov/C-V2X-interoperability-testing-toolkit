# SPDX-License-Identifier: NIST-Software

import errno
import re
import shlex
from types import SimpleNamespace
from typing import Any

import asyncssh
import pytest
from conftest import FakeStream, Response

from cv2x_tester.config import DeviceConfig, Settings
from cv2x_tester.logs import DeviceLogger
from cv2x_tester.ssh import (
    KEEPALIVE_COUNT_MAX,
    KEEPALIVE_INTERVAL,
    CommandError,
    CommandResult,
    SshError,
    SshSession,
)

# What a fake connection does for a command: return an exit status, stdout and stderr, or
# raise an exception.
type FakeResponse = Response | Exception


class FakeProcess:
    """Fake asyncssh process, as returned by ``FakeConnection.create_process()``."""

    def __init__(self, exit_status: int) -> None:
        self.stdout = FakeStream()
        self.stderr = FakeStream()
        self.exit_status = exit_status
        self.closed = False

    async def wait_closed(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class FakeConnection:
    """Fake asyncssh connection that records the commands it runs.

    ``responses`` maps regular expressions, which must match the whole command, to the
    responses of ``run()``. ``files`` maps remote paths to the contents that ``cat``
    commands started with ``create_process()`` output.
    """

    def __init__(
        self, responses: dict[str, FakeResponse] | None = None, files: dict[str, bytes] | None = None
    ) -> None:
        self.responses = responses or {}
        self.files = files or {}
        self.hang = False
        self.commands: list[str] = []
        self.processes: list[FakeProcess] = []
        self.clients: list[asyncssh.SSHClient] = []  # the session's clients, one per connect
        self.kwargs: dict[str, Any] = {}  # the arguments of the last asyncssh.connect() call
        self.aborted = False
        self.closed = False

    async def run(self, command: str, **kwargs: object) -> SimpleNamespace:
        """Record the command and answer it with the response of the first pattern that
        matches it: return the exit status, stdout and stderr, or raise the exception. A
        command that matches no pattern succeeds with no output."""
        self.commands.append(command)
        matches = (r for pattern, r in self.responses.items() if re.fullmatch(pattern, command))
        response = next(matches, (0, "", ""))
        if isinstance(response, Exception):
            raise response
        status, stdout, stderr = response
        return SimpleNamespace(exit_status=status, exit_signal=None, stdout=stdout, stderr=stderr)

    async def create_process(self, command: str, **kwargs: object) -> FakeProcess:
        """Record the ``cat`` command and start a fake process for it. The process outputs
        the file's contents from ``files``, or cat's error message and exit status 1 if
        there is no such file. If ``hang`` is set, the output streams are never closed, which
        simulates a stalled download."""
        self.commands.append(command)
        path = shlex.split(command)[-1]
        process = FakeProcess(0 if path in self.files else 1)
        self.processes.append(process)
        if path in self.files:
            await process.stdout.feed(self.files[path])
        else:
            await process.stderr.feed(f"cat: {path}: No such file or directory\n".encode())
        if not self.hang:
            await process.stdout.close()
            await process.stderr.close()
        return process

    def abort(self) -> None:
        self.aborted = True

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass


def timeout_error(command: str) -> asyncssh.TimeoutError:
    """Return the error that asyncssh raises when ``command`` times out."""
    return asyncssh.TimeoutError(None, command, None, None, None, None, "", "")


def patch_connect(monkeypatch: pytest.MonkeyPatch, result: FakeConnection | Exception) -> None:
    """Make ``asyncssh.connect()`` return the fake connection ``result``, or raise ``result``
    if it is an exception. The connection records the arguments, and creates the session's
    client with ``client_factory``, as asyncssh does."""

    async def fake_connect(**kwargs: Any) -> FakeConnection:
        if isinstance(result, Exception):
            raise result
        result.kwargs = kwargs
        result.clients.append(kwargs["client_factory"]())
        return result

    monkeypatch.setattr(asyncssh, "connect", fake_connect)


def make_session(**device: Any) -> tuple[SshSession, list[str]]:
    """Return an SSH session for a device whose config has the given fields, and the list
    that collects the messages passed to the session's ``on_lost`` callback. Commands time
    out after 2 s."""
    fields: dict[str, Any] = {"name": "obu1", "model": "cohda-mk6", "host": "10.0.0.9", "username": "user"}
    dev = DeviceConfig(**(fields | device))
    lost: list[str] = []
    session = SshSession(dev, Settings(command_timeout=2), DeviceLogger(dev.name), on_lost=lost.append)
    return session, lost


async def connect(
    monkeypatch: pytest.MonkeyPatch, conn: FakeConnection | None = None
) -> tuple[SshSession, FakeConnection, list[str]]:
    """Connect a session from ``make_session()`` through the fake connection ``conn``, or a
    new one. Return the session, the connection, and the messages passed to ``on_lost``."""
    conn = conn or FakeConnection()
    patch_connect(monkeypatch, conn)
    session, lost = make_session()
    await session.connect()
    return session, conn, lost


# ---------------------------------------------------------------------------
# Connecting
# ---------------------------------------------------------------------------


async def test_connect_passes_the_credentials(monkeypatch, tmp_path):
    conn = FakeConnection()
    patch_connect(monkeypatch, conn)
    dev = DeviceConfig(
        name="rsu1",
        model="commsignia",
        host="[fe80::1%eth0]",
        port=2222,
        username="root",
        password="pw",
        key_passphrase="pp",
    )
    key = tmp_path / "id_ed25519"
    session = SshSession(dev, Settings(connect_timeout=7), DeviceLogger(dev.name), key_path=key)
    await session.connect()
    kwargs = conn.kwargs.copy()
    del kwargs["client_factory"]
    assert kwargs == {
        "host": "fe80::1%eth0",
        "port": 2222,
        "username": "root",
        "known_hosts": None,
        "connect_timeout": 7,
        "keepalive_interval": KEEPALIVE_INTERVAL,
        "keepalive_count_max": KEEPALIVE_COUNT_MAX,
        "password": "pw",
        "client_keys": [str(key)],
        "passphrase": "pp",
    }


async def test_connect_without_password_or_key(monkeypatch):
    conn = FakeConnection()
    patch_connect(monkeypatch, conn)
    session, _ = make_session()
    await session.connect(timeout=3)
    assert conn.kwargs["connect_timeout"] == 3
    assert not {"password", "client_keys", "passphrase"} & conn.kwargs.keys()


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (asyncssh.PermissionDenied("permission denied"), "authentication failed"),
        (TimeoutError(), "timed out"),
        (ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused"), "Connection refused"),
        (asyncssh.ConnectionLost("connection closed by peer"), "connection closed by peer"),
        (ValueError(), "ValueError"),
    ],
)
async def test_connect_error_messages(monkeypatch, error, message):
    patch_connect(monkeypatch, error)
    session, _ = make_session(port=2222)
    with pytest.raises(SshError) as excinfo:
        await session.connect()
    assert str(excinfo.value) == f"cannot connect to 10.0.0.9:2222: {message}"
    assert not session.connected


async def test_connect_error_message_hides_the_secrets(monkeypatch):
    patch_connect(monkeypatch, ValueError("passphrase 's3cret' is wrong for password hunter2"))
    session, _ = make_session(password="hunter2", key_passphrase="s3cret")
    with pytest.raises(SshError) as excinfo:
        await session.connect()
    assert (
        str(excinfo.value)
        == "cannot connect to 10.0.0.9:22: passphrase '******' is wrong for password ******"
    )


@pytest.mark.parametrize(
    ("response", "is_root"),
    [
        ((0, "0\n", ""), True),
        ((0, "1000\n", ""), False),
        ((127, "", "sh: id: not found\n"), False),
        (timeout_error("id -u"), False),
        (asyncssh.ChannelOpenError(asyncssh.OPEN_CONNECT_FAILED, "refused"), False),
    ],
)
async def test_connect_finds_out_whether_the_login_user_is_root(monkeypatch, response, is_root):
    session, conn, _ = await connect(monkeypatch, FakeConnection({"id -u": response}))
    assert conn.commands == ["id -u"]
    assert session.is_root is is_root
    # Even when id -u fails, connect() succeeds and leaves the session connected.
    assert session.connected


# ---------------------------------------------------------------------------
# Running commands
# ---------------------------------------------------------------------------


async def test_run_returns_the_result(monkeypatch):
    session, _, _ = await connect(monkeypatch, FakeConnection({"uptime": (0, "up 3 days\n", "")}))
    result = await session.run("uptime")
    assert result == CommandResult("uptime", exit_status=0, stdout="up 3 days\n", stderr="")


async def test_run_failure(monkeypatch):
    conn = FakeConnection({"cv2x_get_status": (2, "", "line1\nradio down\n")})
    session, _, _ = await connect(monkeypatch, conn)
    with pytest.raises(CommandError) as excinfo:
        await session.run("cv2x_get_status")
    assert str(excinfo.value) == "'cv2x_get_status' failed with exit status 2: radio down"
    assert excinfo.value.result is not None
    assert excinfo.value.result.exit_status == 2
    # Without check, the result is returned.
    result = await session.run("cv2x_get_status", check=False)
    assert result.exit_status == 2
    assert result.stderr == "line1\nradio down\n"


async def test_run_timeout(monkeypatch):
    session, _, _ = await connect(monkeypatch, FakeConnection({"sleep 9": timeout_error("sleep 9")}))
    with pytest.raises(CommandError, match=r"^'sleep 9' timed out after 2 s$"):
        await session.run("sleep 9")
    with pytest.raises(CommandError, match=r"^'sleep 9' timed out after 0\.5 s$"):
        await session.run("sleep 9", timeout=0.5)


async def test_run_connection_error(monkeypatch):
    error = ConnectionResetError(errno.ECONNRESET, "Connection reset by peer")
    session, _, _ = await connect(monkeypatch, FakeConnection({"uptime": error}))
    with pytest.raises(SshError, match=r"^'uptime' failed: Connection reset by peer$"):
        await session.run("uptime")


async def test_run_without_connection():
    session, _ = make_session()
    with pytest.raises(SshError, match=r"^not connected$"):
        await session.run("uptime")


# ---------------------------------------------------------------------------
# Downloading files
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sudo", [False, True])
async def test_download(monkeypatch, tmp_path, sudo):
    conn = FakeConnection(files={"/tmp/log/run 1/rx.pcap": b"pcap data"})
    session, _, _ = await connect(monkeypatch, conn)
    local = tmp_path / "rx.pcap"
    assert await session.read_file_via_cat("/tmp/log/run 1/rx.pcap", local, sudo=sudo) == 9
    assert local.read_bytes() == b"pcap data"
    assert conn.commands[-1] == ("sudo -n " if sudo else "") + "cat '/tmp/log/run 1/rx.pcap'"


async def test_download_of_a_missing_file(monkeypatch, tmp_path):
    session, _, _ = await connect(monkeypatch)
    local = tmp_path / "rx.pcap"
    with pytest.raises(CommandError, match=r"^cannot read /tmp/rx\.pcap: No such file or directory$"):
        await session.read_file_via_cat("/tmp/rx.pcap", local)
    assert not local.exists()


async def test_download_timeout(monkeypatch, tmp_path):
    conn = FakeConnection(files={"/tmp/rx.pcap": b"partial"})
    conn.hang = True
    session, _, _ = await connect(monkeypatch, conn)
    local = tmp_path / "rx.pcap"
    with pytest.raises(CommandError, match=r"^download of /tmp/rx\.pcap timed out$"):
        await session.read_file_via_cat("/tmp/rx.pcap", local, timeout=0.05)
    assert not local.exists()
    assert conn.processes[-1].closed


# ---------------------------------------------------------------------------
# Losing and closing the connection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (ConnectionResetError(errno.ECONNRESET, "Connection reset by peer"), "Connection reset by peer"),
        (None, "closed by remote host"),
    ],
)
async def test_lost_connection_is_reported(monkeypatch, error, reason):
    session, conn, lost = await connect(monkeypatch)
    conn.clients[-1].connection_lost(error)
    assert lost == [f"SSH connection lost: {reason}"]
    assert not session.connected


async def test_loss_of_a_replaced_connection_is_ignored(monkeypatch):
    session, conn, lost = await connect(monkeypatch)
    session.abort()
    await session.connect()
    conn.clients[0].connection_lost(None)
    assert lost == []
    assert session.connected


async def test_aborted_or_closed_connection_is_not_reported_as_lost(monkeypatch):
    session, conn, lost = await connect(monkeypatch)
    session.abort()
    # asyncssh calls connection_lost() even when the session aborted or closed the connection.
    conn.clients[-1].connection_lost(None)
    assert conn.aborted
    assert not session.connected
    await session.connect()
    await session.close()
    conn.clients[-1].connection_lost(None)
    assert conn.closed
    assert not session.connected
    assert lost == []
