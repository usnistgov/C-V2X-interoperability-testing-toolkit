# SPDX-License-Identifier: NIST-Software

"""Option schema shared by driver options and the global settings: dataclass fields declared
with :func:`option`, their description (:class:`OptionSpec`) and validation."""

# Ruff's TRY004 wants a TypeError when an isinstance() check fails. Option values are user
# input, so a wrong type is just another invalid value: raise ValueError for all of them.
# ruff: noqa: TRY004

import dataclasses
import enum
import math
import typing
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, Self

type OptionKind = Literal["str", "int", "float", "bool", "choice", "list"]


@dataclass(frozen=True)
class OptionSpec:
    """Description of one option, used for validation and the GUI forms."""

    name: str
    kind: OptionKind
    label: str
    help: str
    default: Any
    choices: tuple[Any, ...] = ()
    min: float | None = None
    max: float | None = None
    decimals: int | None = None  # floats: at most this many decimals
    required: bool = False  # the value must not be empty

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "label": self.label,
            "help": self.help,
            "default": list(self.default) if isinstance(self.default, list) else self.default,
            "choices": list(self.choices),
            "min": self.min,
            "max": self.max,
            "decimals": self.decimals,
            "required": self.required,
        }


def option(
    default: Any,
    *,
    label: str | None = None,
    help: str = "",
    min: float | None = None,
    max: float | None = None,
    decimals: int | None = None,
    required: bool = False,
) -> Any:
    """Declare an option field with its ``default``. Lists get a ``default_factory``
    automatically.

    ``label`` names the option in the GUI and defaults to the field name in sentence case
    (``connect_timeout`` becomes "Connect timeout"). ``help`` describes the option, in the
    GUI and in ``cv2x-tester models``. ``min`` and ``max``, if given, bound an int or float
    value, and ``decimals``, if given, limits how many decimals a float can have.
    ``required`` rejects an empty string or list, so with an empty default the user has to
    set a value.
    """
    metadata = {
        "label": label,
        "help": help,
        "min": min,
        "max": max,
        "decimals": decimals,
        "required": required,
    }
    if isinstance(default, list):
        items = list(default)
        return field(default_factory=lambda: list(items), metadata=metadata)
    return field(default=default, metadata=metadata)


@dataclass
class Options:
    """Base class for a set of options. Subclasses are dataclasses whose fields use
    :func:`option`. Supported field types: str, int, float, bool, Literal[...], Enum
    subclasses and list[str]."""

    @classmethod
    def schema(cls) -> list[OptionSpec]:
        hints = typing.get_type_hints(cls)
        specs = []
        for f in dataclasses.fields(cls):
            kind, choices = _classify(hints[f.name])
            if f.default is not dataclasses.MISSING:
                default = f.default
            elif f.default_factory is not dataclasses.MISSING:
                default = f.default_factory()
            else:
                raise TypeError(f"option {cls.__name__}.{f.name} needs a default")
            if isinstance(default, enum.Enum):
                default = default.value
            md = f.metadata
            specs.append(
                OptionSpec(
                    name=f.name,
                    kind=kind,
                    label=md.get("label") or f.name.replace("_", " ").capitalize(),
                    help=md.get("help", ""),
                    default=default,
                    choices=choices,
                    min=md.get("min"),
                    max=md.get("max"),
                    decimals=md.get("decimals"),
                    required=md.get("required", False),
                )
            )
        return specs

    @classmethod
    def check(cls, name: str, value: Any) -> Any:
        """Validate a raw value of option ``name``. Returns the value converted to the
        option's type, or raises ValueError with a message for the user."""
        spec = next(s for s in cls.schema() if s.name == name)
        return _coerce(spec, value, typing.get_type_hints(cls)[name])

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> tuple[Self, dict[str, str]]:
        """Validate raw TOML values. Returns the options and the errors, as
        {option name: message}.

        Missing or invalid values fall back to the defaults. Unknown keys are ignored.
        """
        hints = typing.get_type_hints(cls)
        errors: dict[str, str] = {}
        values: dict[str, Any] = {}
        for spec in cls.schema():
            if spec.name not in raw:
                if spec.required and _is_empty(spec.default):
                    errors[spec.name] = "required"
                continue
            try:
                values[spec.name] = _coerce(spec, raw[spec.name], hints[spec.name])
            except ValueError as e:
                errors[spec.name] = str(e)
        return cls(**values), errors

    def to_mapping(self) -> dict[str, Any]:
        out = {}
        for f in dataclasses.fields(self):
            v = getattr(self, f.name)
            out[f.name] = v.value if isinstance(v, enum.Enum) else v
        return out


def _classify(tp: Any) -> tuple[OptionKind, tuple[Any, ...]]:
    """Return the option kind of a field with type hint ``tp``, and its allowed values if it
    is a choice (empty otherwise). Raises TypeError for a type that options don't support."""
    origin = typing.get_origin(tp)
    if tp is bool:
        return "bool", ()
    if tp is int:
        return "int", ()
    if tp is float:
        return "float", ()
    if tp is str:
        return "str", ()
    if origin is Literal:
        return "choice", typing.get_args(tp)
    if isinstance(tp, type) and issubclass(tp, enum.Enum):
        return "choice", tuple(m.value for m in tp)
    if origin is list and typing.get_args(tp) == (str,):
        return "list", ()
    raise TypeError(f"unsupported option type {tp!r}")


def _coerce(spec: OptionSpec, value: Any, tp: Any) -> Any:
    """Validate a raw value against ``spec``. Returns the value converted to the option's
    type, using the field's type hint ``tp`` to turn an Enum choice into its member, or
    raises ValueError with a message for the user."""
    match spec.kind:
        case "bool":
            if not isinstance(value, bool):
                raise ValueError("expected true or false")
        case "int":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError("expected an integer")
        case "float":
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ValueError("expected a number")
            value = float(value)
        case "str":
            if not isinstance(value, str):
                raise ValueError("expected a string")
        case "list":
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ValueError("expected a list of strings")
            value = list(value)
        case "choice":
            if value not in spec.choices:
                allowed = ", ".join(repr(c) for c in spec.choices)
                raise ValueError(f"expected one of {allowed}")
            if isinstance(tp, type) and issubclass(tp, enum.Enum):
                value = tp(value)
    if spec.required and _is_empty(value):
        raise ValueError("required")
    if spec.kind in ("int", "float"):
        too_low = spec.min is not None and value < spec.min
        too_high = spec.max is not None and value > spec.max
        if (too_low or too_high) and spec.min is not None and spec.max is not None:
            noun = "an integer" if spec.kind == "int" else "a number"
            raise ValueError(f"expected {noun} between {spec.min:g} and {spec.max:g}")
        if too_low:
            raise ValueError(f"must be >= {spec.min:g}")
        if too_high:
            raise ValueError(f"must be <= {spec.max:g}")
    if spec.kind == "float" and spec.decimals is not None and round(value, spec.decimals) != value:
        raise ValueError(f"expected at most {spec.decimals} decimals")
    return value


def _is_empty(value: Any) -> bool:
    return value == [] or (isinstance(value, str) and not value.strip())
