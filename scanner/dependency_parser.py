from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version, InvalidVersion


class DependencySource(str, Enum):
    REQUIREMENTS_FILE = "requirements_file"
    INSTALLED = "installed"


@dataclass(frozen=True)
class Dependency:
    """A dependency identified by canonical package name + exact installed/version value."""

    name: str
    version: str
    source: DependencySource

    @property
    def normalized_name(self) -> str:
        return canonicalize_name(self.name)

    @property
    def version_obj(self) -> Version | None:
        try:
            return Version(self.version)
        except InvalidVersion:
            return None


_COMMENT_RE = re.compile(r"\s+#.*$")


def _strip_inline_comment(line: str) -> str:
    return _COMMENT_RE.sub("", line).strip()


def _parse_exact_version(req: Requirement) -> str | None:
    """
    Return an exact version if the requirement pins it (== or ===), otherwise None.
    """

    # Example: "django==3.2.0"
    for spec in req.specifier:
        if spec.operator in ("==", "===") and spec.version:
            return spec.version
    return None


def parse_requirements_file(path: Path) -> list[Dependency]:
    """
    Parse a requirements.txt file.

    This tool focuses on exact versions (== / ===). If a requirement doesn't pin an exact version,
    it will fall back to attempting to resolve it from the local environment; if not available,
    the dependency will be skipped.
    """

    deps: list[Dependency] = []
    if not path.exists():
        return deps

    # If we need to resolve non-pinned versions, read installed packages once.
    installed = {canonicalize_name(d.metadata["Name"]): d.version for d in _iter_installed_distros()}

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = _strip_inline_comment(raw_line)
        if not line:
            continue
        if line.startswith("-r ") or line.startswith("--requirement "):
            # Basic support for nested requirements.
            include_path = line.split(maxsplit=1)[1].strip().strip('"').strip("'")
            included = (path.parent / include_path).resolve()
            deps.extend(parse_requirements_file(included))
            continue
        if line.startswith("--"):
            # Options (e.g., --extra-index-url) are ignored.
            continue

        try:
            req = Requirement(line)
        except Exception:
            # Best-effort parsing: skip lines that are not valid PEP 508.
            continue

        name = canonicalize_name(req.name)
        exact = _parse_exact_version(req)
        if exact:
            deps.append(Dependency(name=name, version=exact, source=DependencySource.REQUIREMENTS_FILE))
            continue

        # Not pinned: try to resolve current installed version.
        installed_version = installed.get(name)
        if installed_version:
            deps.append(
                Dependency(name=name, version=installed_version, source=DependencySource.REQUIREMENTS_FILE)
            )

    return _dedupe_deps(deps)


def _iter_installed_distros():
    """
    Iterate installed distributions.

    Uses importlib.metadata under the hood (stdlib on Py 3.10+).
    """

    # Keep imports local to reduce import-time overhead.
    from importlib.metadata import distributions

    yield from distributions()


def read_installed_distributions() -> list[Dependency]:
    """
    Return installed distributions as canonical name + version.

    Priority:
    1) `pkg_resources` (dependency-friendly for setuptools environments)
    2) `importlib.metadata` (stdlib fallback)
    """

    deps: list[Dependency] = []

    try:
        import pkg_resources

        for dist in pkg_resources.working_set:
            name = getattr(dist, "project_name", None)
            version = getattr(dist, "version", None)
            if name and version:
                deps.append(
                    Dependency(name=canonicalize_name(name), version=str(version), source=DependencySource.INSTALLED)
                )
        return _dedupe_deps(deps)
    except Exception:
        # Fallback to stdlib.
        pass

    for dist in _iter_installed_distros():
        name = dist.metadata.get("Name")
        version = dist.version
        if not name or not version:
            continue
        deps.append(Dependency(name=canonicalize_name(name), version=version, source=DependencySource.INSTALLED))
    return _dedupe_deps(deps)


def _dedupe_deps(deps: Iterable[Dependency]) -> list[Dependency]:
    seen: set[tuple[str, str]] = set()
    out: list[Dependency] = []
    for d in deps:
        key = (canonicalize_name(d.name), d.version)
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    out.sort(key=lambda x: (x.name, x.version))
    return out


def pipdeptree_direct_dependencies() -> list[Dependency]:
    """
    Optional: use pipdeptree CLI to extract direct dependencies.

    This isn't required by the main flow, but we keep it for future extensions.
    """

    cmd = [sys.executable, "-m", "pipdeptree", "--json-tree"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return []
    import json

    tree = json.loads(proc.stdout)
    deps: list[Dependency] = []
    for node in tree:
        name = canonicalize_name(node["package"]["key"])
        version = node["package"]["installed_version"]
        deps.append(Dependency(name=name, version=version, source=DependencySource.INSTALLED))
    return _dedupe_deps(deps)

