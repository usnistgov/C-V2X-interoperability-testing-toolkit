# SPDX-License-Identifier: NIST-Software

from dataclasses import dataclass
from typing import Literal

import pytest

from cv2x_tester.options import Options, option


@dataclass
class SampleOptions(Options):
    name: str = option("x", label="Name")
    count: int = option(3, min=1, max=10)
    ratio: float = option(0.5)
    flag: bool = option(True, help="a flag")
    mode: Literal["a", "b"] = option("a")
    items: list[str] = option(["one"])


def test_option_schema():
    specs = {s.name: s for s in SampleOptions.schema()}
    assert specs["name"].kind == "str"
    assert specs["name"].label == "Name"
    assert specs["count"].kind == "int"
    assert specs["count"].min == 1
    assert specs["ratio"].kind == "float"
    assert specs["flag"].kind == "bool"
    assert specs["flag"].help == "a flag"
    assert specs["items"].kind == "list"
    assert specs["items"].default == ["one"]
    assert specs["count"].label == "Count"
    assert specs["mode"].kind == "choice"
    assert specs["mode"].choices == ("a", "b")


def test_option_validation():
    opts, errors = SampleOptions.from_mapping(
        {"count": 5, "ratio": 2, "flag": False, "items": ["a", "b"], "extra": 1}
    )
    assert errors == {}  # unknown keys are ignored
    assert (opts.count, opts.ratio, opts.flag, opts.items) == (5, 2.0, False, ["a", "b"])
    _, errors = SampleOptions.from_mapping({"count": 11, "flag": 1, "items": [1], "name": 3})
    assert errors.keys() == {"count", "flag", "items", "name"}
    _, errors = SampleOptions.from_mapping({"count": True})
    assert errors.keys() == {"count"}  # bool is not an int
    # list defaults are not shared between instances
    a, b = SampleOptions(), SampleOptions()
    a.items.append("z")
    assert b.items == ["one"]


@dataclass
class LimitedOptions(Options):
    count: int = option(3, min=1, max=10)
    low: int = option(5, min=1)
    high: float = option(0.5, max=1)
    ratio: float = option(0.5, min=0, max=1, decimals=3)


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("count", 0, "expected an integer between 1 and 10"),
        ("count", 11, "expected an integer between 1 and 10"),
        ("count", 2.0, "expected an integer"),
        ("low", 0, "must be >= 1"),
        ("high", 1.5, "must be <= 1"),
        ("ratio", 2, "expected a number between 0 and 1"),
        ("ratio", 0.0001, "expected at most 3 decimals"),
        ("ratio", float("nan"), "expected a number"),
        ("high", float("-inf"), "expected a number"),
    ],
)
def test_option_check_rejects(name, value, message):
    with pytest.raises(ValueError, match=f"^{message}$"):
        LimitedOptions.check(name, value)


def test_option_check_converts():
    assert LimitedOptions.check("count", 10) == 10
    assert LimitedOptions.check("ratio", 1) == 1.0
    assert isinstance(LimitedOptions.check("ratio", 1), float)
    assert LimitedOptions.check("ratio", 0.125) == 0.125
    specs = {s.name: s for s in LimitedOptions.schema()}
    assert specs["ratio"].decimals == 3
    assert specs["count"].decimals is None
    assert specs["ratio"].as_dict()["decimals"] == 3
