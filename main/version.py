"""Deadbolt package version resolution."""

from importlib.metadata import PackageNotFoundError, version


def get_version() -> str:
    """Return the installed distribution version with a source-tree fallback."""

    try:
        return version("deadbolt")
    except PackageNotFoundError:
        return "1.2.0"
