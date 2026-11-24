# SPDX-License-Identifier: NIST-Software

"""Device drivers.

Every module in this package is imported by :func:`discover`; concrete
:class:`Driver` subclasses register themselves by declaring a ``model_id``.
To add a device model, drop a new module here.
"""

import functools
import importlib
import pkgutil
from typing import Any

from ..options import OptionSpec, option
from .base import (
    _REGISTRY,
    CaptureMode,
    CaptureStats,
    DeviceContext,
    DeviceNotReady,
    Driver,
    DriverError,
    DriverOptions,
    DriverRegistrationError,
)

__all__ = [
    "CaptureMode",
    "CaptureStats",
    "DeviceContext",
    "DeviceNotReady",
    "Driver",
    "DriverError",
    "DriverOptions",
    "DriverRegistrationError",
    "OptionSpec",
    "all_drivers",
    "discover",
    "get_driver",
    "option",
]


@functools.cache
def discover() -> None:
    """Import all driver modules in this package (once)."""
    for info in pkgutil.iter_modules(__path__):
        if not info.name.startswith("_"):
            importlib.import_module(f"{__name__}.{info.name}")


def get_driver(model_id: str) -> type[Driver[Any]] | None:
    discover()
    return _REGISTRY.get(model_id)


def all_drivers() -> list[type[Driver[Any]]]:
    discover()
    return sorted(_REGISTRY.values(), key=lambda d: d.display_name.lower())
