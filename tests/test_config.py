# SPDX-License-Identifier: NIST-Software

import os
import tomllib
from pathlib import Path

import pytest

from cv2x_tester.config import (
    FILE_HEADER,
    Config,
    ConfigConflictError,
    ConfigError,
    ConfigIssue,
    DeviceConfig,
    app_base_dir,
    expand_home,
    validate_device,
)
from cv2x_tester.drivers.cohda_mk6 import CohdaMk6Options

EXAMPLE = """\
# lab config
output_dir = "out"  # run folders
connect_timeout = 5
mystery = 1

[[devices]]
name = "obu1"  # first OBU
model = "cohda-mk6"
role = "obu"
host = "fe80::1%eth0"
username = "user"
password = "user"  # plaintext
vendor_note = "ignored"

[devices.options]
check_gps = false  # no GPS on the bench

[[devices]]
name = "rsu4"
model = "commsignia"
role = "rsu"
host = "192.168.0.64"
port = 2222
username = "root"
enabled = false
keep_raw_files = false

[devices.options]
interface = "lo"
"""


def write(tmp_path: Path, text: str, name: str = "config.toml") -> Path:
    p = tmp_path / name
    p.write_text(text)
    p.chmod(0o600)
    return p


def test_load_example(tmp_path):
    cfg = Config.load(write(tmp_path, EXAMPLE))
    assert cfg.settings.output_dir == "out"
    assert cfg.settings.connect_timeout == 5
    assert cfg.settings.command_timeout == 30  # default
    assert [d.name for d in cfg.devices] == ["obu1", "rsu4"]
    obu, rsu = cfg.devices
    assert obu.options == {"check_gps": False}
    opts = obu.driver_options()
    assert isinstance(opts, CohdaMk6Options)
    assert opts.check_gps is False
    assert obu.address == "[fe80::1%eth0]:22"
    assert rsu.port == 2222
    assert rsu.enabled is False
    assert rsu.keep_raw_files is False
    assert [str(s) for s in cfg.skipped] == [
        "unknown key 'mystery' ignored",
        "device 'obu1': unknown key 'vendor_note' ignored",
    ]
    assert cfg.permission_warning is None


@pytest.mark.parametrize("text", ["output_dir = \n", "\xff"])
def test_invalid_toml_rejects_file(tmp_path, text):
    p = tmp_path / "c.toml"
    p.write_bytes(text.encode("latin-1"))
    with pytest.raises(ConfigError) as exc:
        Config.load(p)
    assert exc.value.path == p
    assert exc.value.problems[0].message.startswith("invalid TOML")


def test_missing_file_rejected(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        Config.load(tmp_path / "nope.toml")


def test_load_or_empty(tmp_path):
    cfg = Config.load_or_empty(tmp_path / "nope.toml")
    assert cfg.devices == []
    assert cfg.path == tmp_path / "nope.toml"


def test_bad_settings_reject_file(tmp_path):
    text = (
        'default_duration = "long"\nconnect_timeout = 2.5\ncommand_timeout = 86401\nstop_timeout = -1\n'
        "clock_skew_warning = -0.1\n"
        '[[devices]]\nname = "m"\nmodel = "mock"\n'
    )
    with pytest.raises(ConfigError) as exc:
        Config.load(write(tmp_path, text))
    assert exc.value.problems == [
        ConfigIssue("setting 'default_duration': expected an integer"),
        ConfigIssue("setting 'connect_timeout': expected an integer"),
        ConfigIssue("setting 'command_timeout': expected an integer between 1 and 86400"),
        ConfigIssue("setting 'stop_timeout': expected an integer between 1 and 86400"),
        ConfigIssue("setting 'clock_skew_warning': expected a number between 0 and 86400"),
    ]


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ("0", True),
        ("0.001", True),
        ("2", True),
        ("86400", True),
        ("0.0001", False),
        ("2.0005", False),
        ("nan", False),
    ],
)
def test_clock_skew_warning_values(tmp_path, value, valid):
    path = write(tmp_path, f"clock_skew_warning = {value}\n")
    if valid:
        assert Config.load(path).settings.clock_skew_warning == float(value)
    else:
        with pytest.raises(ConfigError):
            Config.load(path)


@pytest.mark.parametrize("text", ["devices = 3\n", "devices = [1, 2]\n", "[devices]\nname = 'x'\n"])
def test_malformed_devices_reject_file(tmp_path, text):
    with pytest.raises(ConfigError, match="array of tables"):
        Config.load(write(tmp_path, text))


def test_bad_devices_are_skipped(tmp_path):
    text = """
[[devices]]
name = "bad name"
model = "cohda-mk6"
host = "h"
username = "u"

[[devices]]
name = "x"
model = "unknown-model"
host = "h"
username = "u"

[[devices]]
name = "roles"
model = "mock"
role = "car"
port = 99999

[[devices]]
name = "typed"
model = "mock"
port = "22"

[[devices]]
name = "dup"
model = "mock"

[[devices]]
name = "dup"
model = "mock"

[[devices]]
name = "opts"
model = "commsignia"
host = "h"
username = "u"
[devices.options]
interface = 42

[[devices]]
model = "mock"
"""
    cfg = Config.load(write(tmp_path, text))
    assert [d.name for d in cfg.devices] == ["dup"]  # the first "dup" is kept
    skipped = [str(s) for s in cfg.skipped]
    assert len(skipped) == 7
    assert skipped[0].startswith("device 'bad name' skipped: field 'name'")
    assert "field 'model': unknown model 'unknown-model'" in skipped[1]
    assert "field 'role'" in skipped[2]
    assert "field 'port'" in skipped[2]
    assert "field 'port': expected an integer" in skipped[3]
    assert "duplicate device name 'dup'" in skipped[4]
    assert "option 'interface': expected a string" in skipped[5]
    assert skipped[6].startswith("device '#8' skipped: field 'name': required")
    # Each problem of a skipped device is kept separately.
    assert cfg.skipped[2] == ConfigIssue(
        "device 'roles' skipped",
        ["field 'role': expected 'obu' or 'rsu'", "field 'port': expected an integer between 1 and 65535"],
    )


def test_device_with_invalid_options_is_skipped(tmp_path):
    text = (
        '[[devices]]\nname = "pi"\nmodel = "generic-linux"\nhost = "h"\nusername = "u"\n'
        "options = { filter = 42 }\n"
    )
    cfg = Config.load(write(tmp_path, text))
    assert cfg.devices == []
    # Each invalid option is reported separately.
    assert cfg.skipped == [
        ConfigIssue(
            "device 'pi' skipped",
            ["option 'interface': required", "option 'filter': expected a string"],
        )
    ]


def test_unknown_option_is_ignored(tmp_path):
    text = '[[devices]]\nname = "m"\nmodel = "mock"\n[devices.options]\nstep_delay_ms = 500\nturbo = true\n'
    cfg = Config.load(write(tmp_path, text))
    assert cfg.devices[0].options == {"step_delay_ms": 500}
    assert cfg.skipped == [ConfigIssue("device 'm': unknown key 'options.turbo' ignored")]


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_permission_warning(tmp_path):
    path = write(tmp_path, EXAMPLE)
    path.chmod(0o644)
    warning = Config.load(path).permission_warning
    assert warning is not None
    assert "readable by group/others" in warning


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_no_permission_warning_without_secrets(tmp_path):
    no_secrets = '[[devices]]\nname = "m"\nmodel = "mock"\n'
    path = write(tmp_path, no_secrets)
    path.chmod(0o644)
    assert Config.load(path).permission_warning is None
    # A skipped device's password is still in the file, so it still counts.
    path.write_text(no_secrets + '\n[[devices]]\nname = "bad"\nmodel = "nope"\npassword = "x"\n')
    warning = Config.load(path).permission_warning
    assert warning is not None
    assert "readable by group/others" in warning


def test_save_regenerates_with_only_non_defaults(tmp_path):
    path = write(tmp_path, EXAMPLE)
    cfg = Config.load(path)
    cfg.save()
    text = path.read_text()
    assert text.startswith(FILE_HEADER)
    assert "# lab config" not in text
    assert "mystery" not in text
    assert "vendor_note" not in text
    # Devices and their options are written as tables, not inline.
    assert text.count("\n[[devices]]\n") == 2
    assert text.count("\n[devices.options]\n") == 1
    assert cfg.skipped == []
    data = tomllib.loads(text)
    assert data == {
        "output_dir": "out",
        "connect_timeout": 5,
        "devices": [
            {
                "name": "obu1",
                "model": "cohda-mk6",
                "role": "obu",
                "host": "fe80::1%eth0",
                "username": "user",
                "password": "user",
                "options": {"check_gps": False},
            },
            {
                "name": "rsu4",
                "model": "commsignia",
                "role": "rsu",
                "host": "192.168.0.64",
                "port": 2222,
                "username": "root",
                "enabled": False,
                "keep_raw_files": False,
            },
        ],
    }
    # "interface = lo" is the commsignia default, so it is not written back.
    saved_once = text
    Config.load(path).save()
    assert path.read_text() == saved_once  # stable


def test_save_modifications(tmp_path):
    path = write(tmp_path, EXAMPLE)
    cfg = Config.load(path)
    cfg.settings.stop_timeout = 90
    cfg.settings.connect_timeout = 15  # back to the default: no longer written
    obu = cfg.devices[0]
    obu.password = None
    obu.options = {"check_gps": True}  # default
    obu.delete_remote_files = False
    new = DeviceConfig(
        name="lin",
        model="generic-linux",
        role="rsu",
        host="10.0.0.9",
        username="pi",
        options={"interface": "wlan0", "start_commands": ["echo hi"]},
    )
    cfg.devices = [cfg.devices[1], obu, new]
    cfg.save()
    data = tomllib.loads(path.read_text())
    assert data["stop_timeout"] == 90
    assert "connect_timeout" not in data
    assert [d["name"] for d in data["devices"]] == ["rsu4", "obu1", "lin"]
    obu_t = data["devices"][1]
    assert "password" not in obu_t
    assert "options" not in obu_t
    assert obu_t["delete_remote_files"] is False
    assert data["devices"][2]["options"] == {"interface": "wlan0", "start_commands": ["echo hi"]}
    reloaded = Config.load(path)
    assert [d.name for d in reloaded.devices] == ["rsu4", "obu1", "lin"]
    assert reloaded.skipped == []


def test_empty_config_save(tmp_path):
    cfg = Config(tmp_path / "sub" / "new.toml")
    cfg.save()
    assert (tmp_path / "sub" / "new.toml").read_text() == FILE_HEADER


def test_new_file_is_private(tmp_path):
    cfg = Config(tmp_path / "new.toml")
    cfg.devices.append(DeviceConfig(name="m", model="mock"))
    cfg.save()
    path = tmp_path / "new.toml"
    assert tomllib.loads(path.read_text())["devices"] == [{"name": "m", "model": "mock", "role": "obu"}]
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


def test_atomic_save_keeps_mode_and_leaves_no_temp(tmp_path):
    path = write(tmp_path, EXAMPLE)
    path.chmod(0o640)
    cfg = Config.load(path)
    cfg.settings.default_duration = 5
    cfg.save()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["config.toml"]
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o640


def test_save_detects_external_modification(tmp_path):
    path = write(tmp_path, EXAMPLE)
    cfg = Config.load(path)
    path.write_text(EXAMPLE + "\n# edited elsewhere\n")
    os.utime(path, ns=(1, 1))
    assert cfg.modified_on_disk()
    with pytest.raises(ConfigConflictError):
        cfg.save()
    cfg.save(force=True)
    assert not cfg.modified_on_disk()


def test_save_as_does_not_check_original(tmp_path):
    path = write(tmp_path, EXAMPLE)
    cfg = Config.load(path)
    os.utime(path, ns=(1, 1))
    other = tmp_path / "other.toml"
    assert cfg.is_loaded_file(path)
    assert not cfg.is_loaded_file(other)
    cfg.save(other)  # no conflict: a different file
    assert cfg.path == other
    assert cfg.skipped == []


def test_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert app_base_dir() == tmp_path
    cfg = Config(tmp_path / "cfg" / "c.toml")
    assert cfg.output_dir() == tmp_path / "results"
    cfg.settings.output_dir = "~/runs"
    assert cfg.output_dir() == Path.home() / "runs"
    cfg.settings.output_dir = "$HOME/runs"  # env vars are not expanded
    assert cfg.output_dir() == tmp_path / "$HOME" / "runs"
    dev = DeviceConfig(name="a", key_file="keys/id")
    assert cfg.key_file_path(dev) == tmp_path / "cfg" / "keys" / "id"
    dev.key_file = "~/.ssh/id"
    assert cfg.key_file_path(dev) == Path.home() / ".ssh" / "id"


def test_unknown_home_directory(tmp_path):
    with pytest.raises(ValueError, match="home directory '~no-such-user' not found"):
        expand_home("~no-such-user/runs")
    with pytest.raises(ConfigError) as exc:
        Config.load(write(tmp_path, 'output_dir = "~no-such-user/runs"\n'))
    assert exc.value.problems == [
        ConfigIssue("setting 'output_dir': home directory '~no-such-user' not found")
    ]
    dev = DeviceConfig(name="m", model="mock", key_file="~no-such-user/id")
    assert validate_device(dev, []) == {"key_file": "home directory '~no-such-user' not found"}


def test_raw_and_remote_overrides():
    cfg = Config()
    dev = DeviceConfig(name="a")
    assert cfg.keep_raw_files(dev) is False
    assert cfg.delete_remote_files(dev) is True
    dev.keep_raw_files, dev.delete_remote_files = True, False
    assert cfg.keep_raw_files(dev) is True
    assert cfg.delete_remote_files(dev) is False


def test_validate_device_for_dialog():
    other = DeviceConfig(name="taken", model="mock")
    dev = DeviceConfig(name="taken", model="commsignia", host="", username="")
    errs = validate_device(dev, [other])
    assert set(errs) == {"name", "host", "username"}
    mock = DeviceConfig(name="m", model="mock")  # no SSH: host/username optional
    assert validate_device(mock, []) == {}


def test_validate_device_rejects_names_differing_only_in_case():
    other = DeviceConfig(name="obu1", model="mock")
    errs = validate_device(DeviceConfig(name="OBU1", model="mock"), [other])
    assert errs == {"name": "device name 'OBU1' differs from 'obu1' only in case"}


@pytest.mark.parametrize("name", ["con", "NUL", "Com1", "lpt9", "aux.1", "nul.tar.gz"])
def test_validate_device_rejects_windows_reserved_names(name):
    errs = validate_device(DeviceConfig(name=name, model="mock"), [])
    assert errs == {"name": f"'{name.split('.')[0]}' is a reserved file name on Windows"}


@pytest.mark.parametrize("name", ["console", "com10", "nul_1", "obu.con"])
def test_validate_device_allows_names_close_to_reserved_ones(name):
    assert validate_device(DeviceConfig(name=name, model="mock"), []) == {}


def test_validate_device_requires_a_model():
    dev = DeviceConfig(name="obu1", model="", host="10.0.0.1", username="root")
    assert validate_device(dev, []) == {"model": "required"}


@pytest.mark.parametrize(
    ("host", "error"),
    [
        ("192.168.0.64", None),
        ("obu1.lab", None),
        ("fe80::6e5:48ff:fe50:c78%eth0", None),
        ("[fe80::1]", None),
        ("192.168.0.64:22", "put the port in the port field, not in the host"),
        ("fe80::1::2", "not a valid IPv6 address"),
        ("[fe80::zz]", "not a valid IPv6 address"),
        ("192.168.0.300", "not a valid IPv4 address"),
        ("192.168.0", "not a valid IPv4 address"),
        ("192.168.00.1", "not a valid IPv4 address"),  # leading zeros are ambiguous
        ("10.0.0.5.example", None),  # a hostname
    ],
)
def test_validate_device_host(host, error):
    dev = DeviceConfig(name="rsu4", model="commsignia", host=host, username="root")
    assert validate_device(dev, []).get("host") == error
