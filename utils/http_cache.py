from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests


def _stable_hash(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class CacheEntry:
    created_at: float
    status_code: int
    payload: Any


class HttpCache:
    """
    Minimal file-based HTTP cache for GET requests.

    This intentionally avoids complex invalidation. You can clear the cache directory to reset.
    """

    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, key: str) -> Path:
        return self.cache_dir / f"{key}.json"

    def get_json(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout_s: int = 30,
        use_cache: bool = True,
    ) -> Any:
        params = params or {}
        headers = headers or {}

        # Avoid hashing secrets into the cache key.
        safe_headers = {k: ("***" if "apiKey" in k.lower() or "authorization" in k.lower() else v) for k, v in headers.items()}

        key = _stable_hash({"url": url, "params": params, "headers": safe_headers})
        path = self._cache_path(key)

        if use_cache and path.exists():
            try:
                with path.open("r", encoding="utf-8") as f:
                    entry = json.load(f)
                return entry["payload"]
            except Exception:
                # If cache entry is corrupt, continue with network fetch.
                pass

        resp = requests.get(url, params=params, headers=headers, timeout=timeout_s)
        resp.raise_for_status()

        payload = resp.json()

        if use_cache:
            entry = CacheEntry(created_at=time.time(), status_code=resp.status_code, payload=payload)
            tmp = path.with_suffix(".json.tmp")
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(entry.__dict__, f, ensure_ascii=False)
            os.replace(tmp, path)

        return payload

