# SPDX-License-Identifier: NIST-Software

"""Configuration file: loading and validation (tomllib), saving (tomli-w).

Saving regenerates the whole file from the in-memory configuration: comments,
formatting and unknown keys are not preserved, and only non-default values are
written.
"""

import ipaddress
import os
import re
import stat
import sys
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import tomli_w

from . import APP_NAME, drivers
from .options import Options, option
from .util import MAX_DURATION, MIN_DURATION, atomic_write, format_address, strip_brackets


@dataclass
class ConfigIssue:
    """A problem found while loading a config file.

    ``details`` lists the individual reasons, if any, such as the invalid fields of a
    skipped device."""

    message: str
    details: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        return f"{self.message}: {'; '.join(self.details)}" if self.details else self.message


class ConfigError(Exception):
    """The file cannot be used at all; ``problems`` lists every reason."""

    def __init__(self, path: Path, problems: list[ConfigIssue]) -> None:
        super().__init__(f"{path}: " + "; ".join(map(str, problems)))
        self.path = path
        self.problems = problems


class ConfigConflictError(Exception):
    """The file was modified on disk since it was loaded or last saved."""


def app_base_dir() -> Path:
    """Directory of the packaged executable, or the CWD when running from source."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path.cwd()


def expand_home(path: str) -> Path:
    """Expand a leading ``~`` (environment variables are not expanded). Raises
    ValueError if the home directory can't be found, e.g. for ``~name`` with an unknown user."""
    p = Path(path)
    if not path.startswith("~"):
        return p
    try:
        return p.expanduser()
    except RuntimeError:
        raise ValueError(f"home directory '{p.parts[0]}' not found") from None


def resolve_output_dir(output_dir: str, base_dir: Path | None = None) -> Path:
    """Return the absolute path of the output directory ``output_dir``. A relative path is
    resolved against ``base_dir``, by default the app base dir. Raises ValueError if a leading
    ``~`` can't be expanded."""
    p = expand_home(output_dir)
    return p if p.is_absolute() else (base_dir or app_base_dir()) / p


# --------------------------------------------------------------------------
# Global settings
# --------------------------------------------------------------------------


@dataclass(kw_only=True)
class Settings(Options):
    output_dir: str = option("results", label="Output directory", required=True)
    default_duration: int = option(60, label="Default test duration", min=MIN_DURATION, max=MAX_DURATION)
    clock_skew_warning: float = option(2.0, min=0, max=86400, decimals=3)
    connect_timeout: int = option(15, min=1, max=86400)
    command_timeout: int = option(30, min=1, max=86400)
    stop_timeout: int = option(60, min=1, max=86400)
    collect_timeout: int = option(300, min=1, max=86400)
    keep_raw_files: bool = option(False)
    delete_remote_files: bool = option(True)

    @classmethod
    def check(cls, name: str, value: Any) -> Any:
        """Like :meth:`Options.check`, but also reject an ``output_dir`` whose leading ``~``
        can't be expanded."""
        value = super().check(name, value)
        if name == "output_dir":
            expand_home(value)
        return value


# --------------------------------------------------------------------------
# Devices
# --------------------------------------------------------------------------

ROLES = ("obu", "rsu")
_NAME_RE = re.compile(r"[A-Za-z0-9._-]+")
# Names that Windows reserves for devices, even with an extension (NUL.txt is the same as NUL).
_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))}
)
_STR_FIELDS = ("name", "model", "role", "host", "username", "password", "key_file", "key_passphrase")
_BOOL_FIELDS = ("enabled", "keep_raw_files", "delete_remote_files")


@dataclass(eq=False, kw_only=True)
class DeviceConfig:
    name: str = ""
    model: str = ""
    role: str = "obu"
    host: str = ""
    port: int = 22
    username: str = ""
    password: str | None = None
    key_file: str | None = None
    key_passphrase: str | None = None
    enabled: bool = True
    keep_raw_files: bool | None = None  # None: use the global setting
    delete_remote_files: bool | None = None  # None: use the global setting
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def address(self) -> str:
        return format_address(self.host, self.port)

    @property
    def driver_class(self) -> type[drivers.Driver[Any]] | None:
        return drivers.get_driver(self.model)

    @property
    def secrets(self) -> list[str]:
        return [s for s in (self.password, self.key_passphrase) if s]

    def driver_options(self) -> drivers.DriverOptions:
        cls = self.driver_class
        if cls is None:
            raise ValueError(f"unknown model {self.model!r}")
        opts, _ = cls.Options.from_mapping(self.options)
        return opts


def _host_error(host: str) -> str | None:
    """Check IP address literals. Only IPv6 addresses contain ':', and only IPv4 addresses
    are all digits and dots (a hostname's last label is never numeric). Hostnames are
    left to the connection attempt."""
    h = strip_brackets(host)
    if ":" in h:
        if h.count(":") == 1:
            return "put the port in the port field, not in the host"
        try:
            ipaddress.IPv6Address(h)
        except ValueError:
            return "not a valid IPv6 address"
    elif re.fullmatch(r"[0-9.]+", h):
        try:
            ipaddress.IPv4Address(h)
        except ValueError:
            return "not a valid IPv4 address"
    return None


def validate_device(dev: DeviceConfig, others: list[DeviceConfig]) -> dict[str, str]:
    """Check a device's fields. Returns {field: message}, where the field of a driver option
    is ``options.<name>``; ``others`` are the other devices in the config (for the
    unique-name check)."""
    errs: dict[str, str] = {}
    if not dev.name:
        errs["name"] = "required"
    elif not _NAME_RE.fullmatch(dev.name):
        errs["name"] = "only letters, digits, '.', '_' and '-' are allowed"
    elif dev.name.split(".")[0].upper() in _WINDOWS_RESERVED:
        errs["name"] = f"'{dev.name.split('.')[0]}' is a reserved file name on Windows"
    elif same := next((o for o in others if o is not dev and o.name.lower() == dev.name.lower()), None):
        # File names are not case-sensitive on Windows and macOS.
        errs["name"] = (
            f"duplicate device name '{dev.name}'"
            if same.name == dev.name
            else f"device name '{dev.name}' differs from '{same.name}' only in case"
        )
    driver = drivers.get_driver(dev.model) if dev.model else None
    if not dev.model:
        errs["model"] = "required"
    elif driver is None:
        errs["model"] = f"unknown model '{dev.model}'"
    if dev.role not in ROLES:
        errs["role"] = "expected 'obu' or 'rsu'"
    needs_ssh = driver is None or driver.uses_ssh
    if needs_ssh and not dev.host.strip():
        errs["host"] = "required"
    elif error := _host_error(dev.host):
        errs["host"] = error
    if isinstance(dev.port, bool) or not isinstance(dev.port, int) or not 1 <= dev.port <= 65535:
        errs["port"] = "expected an integer between 1 and 65535"
    if needs_ssh and not dev.username:
        errs["username"] = "required"
    if dev.key_file:
        try:
            expand_home(dev.key_file)
        except ValueError as e:
            errs["key_file"] = str(e)
    if driver is not None:
        _, opt_errors = driver.Options.from_mapping(dev.options)
        errs |= {f"options.{name}": message for name, message in opt_errors.items()}
    return errs


def _parse_device(
    raw: dict[str, Any], others: list[DeviceConfig]
) -> tuple[DeviceConfig | None, dict[str, str], list[str]]:
    """Build a device from a ``[[devices]]`` table.

    Returns (device, errors, ignored keys); the device is None if there are errors.
    """
    values: dict[str, Any] = {}
    errors: dict[str, str] = {}
    ignored: list[str] = []
    for key, value in raw.items():
        if key in _STR_FIELDS:
            ok, expected = isinstance(value, str), "a string"
        elif key == "port":
            ok, expected = isinstance(value, int) and not isinstance(value, bool), "an integer"
        elif key in _BOOL_FIELDS:
            ok, expected = isinstance(value, bool), "true or false"
        elif key == "options":
            ok, expected = isinstance(value, dict), "a table"
        else:
            ignored.append(key)
            continue
        if ok:
            values[key] = value
        else:
            errors[key] = f"expected {expected}"
    dev = DeviceConfig(**values)
    driver = dev.driver_class
    if driver is not None:
        known = {spec.name for spec in driver.Options.schema()}
        ignored += [f"options.{k}" for k in dev.options if k not in known]
        dev.options = {k: v for k, v in dev.options.items() if k in known}
    errors = validate_device(dev, others) | errors  # type errors take precedence
    return (None if errors else dev), errors, ignored


def _has_secrets(values: dict[str, Any]) -> bool:
    """Whether the file sets a password or passphrase, including on skipped devices."""
    return any(raw.get("password") or raw.get("key_passphrase") for raw in values.get("devices", []))


def _device_to_dict(dev: DeviceConfig) -> dict[str, Any]:
    """TOML table for a device: name, model and role, plus every non-default value."""
    out: dict[str, Any] = {"name": dev.name, "model": dev.model, "role": dev.role}
    defaults = DeviceConfig()
    for key in (
        "host",
        "port",
        "username",
        "password",
        "key_file",
        "key_passphrase",
        "enabled",
        "keep_raw_files",
        "delete_remote_files",
    ):
        value = getattr(dev, key)
        if value not in (None, "") and value != getattr(defaults, key):
            out[key] = value
    driver = dev.driver_class
    if driver is not None:
        defaults_opts = driver.Options().to_mapping()
        opts = dev.driver_options().to_mapping()
        changed = {k: v for k, v in opts.items() if v != defaults_opts[k]}
        if changed:
            out["options"] = changed
    return out


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

FILE_HEADER = (
    f"# {APP_NAME} configuration.\n"
    "# WARNING: saving from the GUI overwrites this whole file.\n"
    "# Comments, formatting and unknown keys added by hand will be lost.\n\n"
)


class Config:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.settings = Settings()
        self.devices: list[DeviceConfig] = []
        self.skipped: list[ConfigIssue] = []
        self.permission_warning: str | None = None
        self._mtime_ns: int | None = None

    # -- loading -----------------------------------------------------------

    @classmethod
    def load(cls, path: Path) -> Config:
        """Load and validate ``path``. Raises ConfigError if the file is unreadable,
        is not valid TOML, or has an invalid global setting; invalid devices are
        skipped and unknown keys ignored (both listed in ``skipped``)."""
        try:
            data = path.read_bytes()
            st = path.stat()
        except OSError as e:
            issue = ConfigIssue("cannot read the file", [e.strerror or str(e)])
            raise ConfigError(path, [issue]) from e
        try:
            values = tomllib.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
            issue = ConfigIssue("invalid TOML", [str(e)])
            raise ConfigError(path, [issue]) from e
        cfg = cls(path)
        problems = cfg._parse(values)
        if problems:
            raise ConfigError(path, problems)
        cfg._mtime_ns = st.st_mtime_ns
        if os.name == "posix" and stat.S_IMODE(st.st_mode) & 0o077 and _has_secrets(values):
            cfg.permission_warning = (
                "config file is readable by group/others and contains "
                "plaintext passwords or passphrases; consider 'chmod 600'"
            )
        return cfg

    @classmethod
    def load_or_empty(cls, path: Path) -> Config:
        """Load ``path`` if it exists, otherwise return an empty config bound to it."""
        return cls.load(path) if path.exists() else cls(path)

    def _parse(self, values: dict[str, Any]) -> list[ConfigIssue]:
        """Fill in settings and devices; return the problems that reject the file."""
        problems = []
        known = {f.name for f in fields(Settings)}
        for key, value in values.items():
            if key == "devices":
                continue
            if key not in known:
                self.skipped.append(ConfigIssue(f"unknown key '{key}' ignored"))
                continue
            try:
                setattr(self.settings, key, Settings.check(key, value))
            except ValueError as e:
                problems.append(ConfigIssue(f"setting '{key}': {e}"))
        raw_devices = values.get("devices", [])
        if not isinstance(raw_devices, list) or not all(isinstance(d, dict) for d in raw_devices):
            problems.append(ConfigIssue("'devices' must be an array of tables ([[devices]])"))
        if problems:
            return problems
        for i, raw in enumerate(raw_devices):
            label = raw["name"] if isinstance(raw.get("name"), str) and raw["name"] else f"#{i + 1}"
            dev, errors, ignored = _parse_device(raw, self.devices)
            self.skipped += [ConfigIssue(f"device '{label}': unknown key '{key}' ignored") for key in ignored]
            if dev is None:
                details = []
                for key, msg in errors.items():
                    if key.startswith("options."):
                        details.append(f"option '{key.removeprefix('options.')}': {msg}")
                    else:
                        details.append(f"field '{key}': {msg}")
                self.skipped.append(ConfigIssue(f"device '{label}' skipped", details))
            else:
                self.devices.append(dev)
        return []

    # -- queries ------------------------------------------------------------

    def device(self, name: str) -> DeviceConfig | None:
        return next((d for d in self.devices if d.name == name), None)

    def key_file_path(self, dev: DeviceConfig) -> Path | None:
        if not dev.key_file:
            return None
        p = expand_home(dev.key_file)
        if p.is_absolute():
            return p
        base = self.path.parent if self.path else app_base_dir()
        return base / p

    def output_dir(self, base_dir: Path | None = None) -> Path:
        return resolve_output_dir(self.settings.output_dir, base_dir)

    def keep_raw_files(self, dev: DeviceConfig) -> bool:
        return self.settings.keep_raw_files if dev.keep_raw_files is None else dev.keep_raw_files

    def delete_remote_files(self, dev: DeviceConfig) -> bool:
        if dev.delete_remote_files is None:
            return self.settings.delete_remote_files
        return dev.delete_remote_files

    # -- saving ------------------------------------------------------------

    def is_loaded_file(self, path: Path) -> bool:
        return self.path is not None and path.resolve() == self.path.resolve()

    def modified_on_disk(self) -> bool:
        """True if the file changed on disk since it was loaded or saved."""
        if self.path is None:
            return False
        try:
            mtime = self.path.stat().st_mtime_ns
        except FileNotFoundError:
            return self._mtime_ns is not None
        return self._mtime_ns is None or mtime != self._mtime_ns

    def to_dict(self) -> dict[str, Any]:
        """The configuration as written to disk: only non-default values."""
        defaults = Settings()
        data: dict[str, Any] = {}
        for f in fields(Settings):
            value = getattr(self.settings, f.name)
            if value != getattr(defaults, f.name):
                data[f.name] = value
        if self.devices:
            data["devices"] = [_device_to_dict(d) for d in self.devices]
        return data

    def to_toml(self) -> str:
        # Devices are written block by block: given the whole dict, tomli-w would
        # render short devices as one-line inline tables instead of [[devices]].
        data = self.to_dict()
        devices = data.pop("devices", [])
        blocks = [tomli_w.dumps(data)] if data else []
        for dev in devices:
            options = dev.pop("options", None)
            block = "[[devices]]\n" + tomli_w.dumps(dev)
            if options:
                block += "\n[devices.options]\n" + tomli_w.dumps(options)
            blocks.append(block)
        return FILE_HEADER + "\n".join(blocks)

    def save(self, path: Path | None = None, *, force: bool = False) -> None:
        """Atomically write the config. Raises ConfigConflictError if the target is
        the loaded file and it changed on disk (unless ``force``), OSError on I/O errors."""
        target = path if path is not None else self.path
        if target is None:
            raise ValueError("no path to save to")
        if self.is_loaded_file(target) and not force and self.modified_on_disk():
            raise ConfigConflictError(f"{target} was modified by another program")
        atomic_write(target, self.to_toml(), new_file_mode=0o600)
        self.path = target
        self._mtime_ns = target.stat().st_mtime_ns
        self.skipped = []
