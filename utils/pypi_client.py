from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from utils.http_cache import HttpCache


PYPI_PKG_URL = "https://pypi.org/pypi/{name}/json"


@dataclass
class PyPiClient:
    cache: HttpCache

    def latest_version(self, package_name: str) -> str | None:
        """
        Return latest version as published by PyPI, or None if unavailable.
        """
        url = PYPI_PKG_URL.format(name=package_name)
        try:
            payload: Any = self.cache.get_json(url, timeout_s=30)
        except Exception:
            return None

        try:
            return payload["info"]["version"]
        except Exception:
            return None

