"""Antares CLI package."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("antares-cli")
except PackageNotFoundError:
    __version__ = "0+local"

__all__ = ["__version__"]
