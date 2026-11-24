# SPDX-License-Identifier: NIST-Software

"""Small helpers shared by the engine, the CLI and the GUI."""

import contextlib
import datetime
import os
import re
import secrets
import stat
from pathlib import Path

MIN_DURATION = 1
MAX_DURATION = 24 * 3600

_UNITS_RE = re.compile(r"^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$")


def parse_duration(text: str) -> int:
    """Parse a duration such as ``90``, ``1:30``, ``1:02:03`` or ``1m30s`` into seconds.

    Raises ValueError if the text is malformed or outside 1 s to 24 h.
    """
    s = text.strip().lower().replace(" ", "")
    if not s:
        raise ValueError("duration is empty")
    if s.isdecimal():
        seconds = int(s)
    elif ":" in s:
        parts = s.split(":")
        if len(parts) not in (2, 3) or not all(p.isdecimal() for p in parts):
            raise ValueError(f"invalid duration {text!r}")
        nums = [int(p) for p in parts]
        if any(n >= 60 for n in nums[1:]):
            raise ValueError(f"invalid duration {text!r}")
        seconds = 0
        for n in nums:
            seconds = seconds * 60 + n
    else:
        m = _UNITS_RE.match(s)
        if not m or not any(m.groups()):
            raise ValueError(f"invalid duration {text!r}")
        h, mi, sec = (int(g) if g else 0 for g in m.groups())
        seconds = h * 3600 + mi * 60 + sec
    if not MIN_DURATION <= seconds <= MAX_DURATION:
        raise ValueError("duration must be between 1 s and 24 h")
    return seconds


def format_duration(seconds: float) -> str:
    """Format seconds as ``MM:SS`` or ``H:MM:SS``."""
    total = max(0, int(seconds))
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def local_now() -> datetime.datetime:
    return datetime.datetime.now().astimezone()


def iso(ts: datetime.datetime | None) -> str | None:
    """``ts`` in ISO 8601 format with milliseconds, or None."""
    return ts.isoformat(timespec="milliseconds") if ts else None


def time_of_day(ts: datetime.datetime | None = None) -> str:
    """Format ``ts`` as HH:MM:SS.mmm. If ``ts`` is None, use the current local time."""
    return (ts or local_now()).strftime("%H:%M:%S.%f")[:-3]


def format_offset(seconds: float, decimals: int = 3) -> str:
    """Format a clock offset with an explicit sign, e.g. ``+0.120 s``. The value is
    rounded first, so a tiny negative offset shows as ``+0.000 s``, not ``-0.000 s``."""
    return f"{round(seconds, decimals) + 0.0:+.{decimals}f} s"  # + 0.0 turns -0.0 into 0.0


def strip_brackets(host: str) -> str:
    """Remove the brackets around an IPv6 literal (``[fe80::1]``)."""
    h = host.strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h


def format_address(host: str, port: int) -> str:
    """Return ``host:port``, bracketing IPv6 literals (``[fe80::1%eth0]:22``)."""
    h = strip_brackets(host)
    return f"[{h}]:{port}" if ":" in h else f"{h}:{port}"


def human_bytes(n: int | None) -> str:
    """Format a byte count with a decimal unit (1 kB = 1000 B), or an empty string for None."""
    if n is None:
        return ""
    if n < 1000:
        return f"{n} B"
    if n < 999.95e3:
        return f"{n / 1e3:.1f} kB"
    if n < 999.95e6:
        return f"{n / 1e6:.1f} MB"
    return f"{n / 1e9:.1f} GB"


def slugify(text: str) -> str:
    """Make a test name safe for use in a directory name."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", text.strip())
    return slug.strip("-._")


def last_line(text: str, default: str = "") -> str:
    """The last non-empty line of command output (usually the most specific error)."""
    return next((ln.strip() for ln in reversed(text.splitlines()) if ln.strip()), default)


def atomic_write(target: Path, text: str, *, new_file_mode: int | None = None) -> None:
    """Write ``text`` to ``target`` through a temporary file and a rename, so that the
    file is never half written. An existing file keeps its mode. A new file gets
    ``new_file_mode``, or the default mode (set by the umask) if it is None."""
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        mode: int | None = stat.S_IMODE(target.stat().st_mode)
    except FileNotFoundError:
        mode = new_file_mode
    tmp = target.with_name(f".{target.name}.{secrets.token_hex(4)}.tmp")
    # Created with its final mode, so that a new private file is never readable by others.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o666 if mode is None else mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        if mode is not None and os.name == "posix":
            os.chmod(tmp, mode)  # the umask may have cleared some of its bits
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
