from __future__ import annotations

from dataclasses import dataclass

from packaging.version import InvalidVersion, Version


def try_parse_version(v: str | None) -> Version | None:
    if not v:
        return None
    try:
        return Version(v)
    except InvalidVersion:
        return None


def version_in_range(
    installed: Version,
    *,
    start_including: Version | None = None,
    start_excluding: Version | None = None,
    end_including: Version | None = None,
    end_excluding: Version | None = None,
) -> bool:
    """
    Check if an installed version is within a bound range.

    NVD CPE matchers sometimes provide boundaries independently; missing bounds mean "unbounded".
    """

    if start_including is not None and installed < start_including:
        return False
    if start_excluding is not None and installed <= start_excluding:
        return False
    if end_including is not None and installed > end_including:
        return False
    if end_excluding is not None and installed >= end_excluding:
        return False
    return True


@dataclass(frozen=True)
class Cvss:
    score: float | None
    vector_string: str | None

