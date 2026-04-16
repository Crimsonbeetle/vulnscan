from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, List, Tuple
import re

from packaging.version import InvalidVersion, Version

from vulnerability.models import Severity, VulnerabilityMatch


# Positive risk weights per vulnerability; higher is worse.
SEVERITY_WEIGHTS: Dict[Severity, int] = {
    "critical": 20,
    "high": 10,
    "medium": 5,
    "low": 2,
    "unknown": 0,
}


@dataclass
class PackageGroup:
    package_name: str
    current_version: str
    vulnerabilities: List[VulnerabilityMatch]
    safe_version: str | None
    # Computed impact if upgrading to safe_version (if known)
    fixed_vulnerability_count: int
    fixed_severity_breakdown: Dict[Severity, int]


def _parse_version_safe(v: str | None) -> Version | None:
    if not v:
        return None
    try:
        return Version(v)
    except InvalidVersion:
        return None


def _infer_safe_version_for_package(vulns: List[VulnerabilityMatch]) -> str | None:
    """
    Compute a minimum safe version for a package given its vulnerabilities.

    Strategy:
    - Use the maximum of all explicit patched_version values (e.g., from GitHub advisories).
    - If none exist, attempt to parse "latest PyPI" hints from fix_recommendation.
    """
    patched_versions: List[Version] = []
    for v in vulns:
        pv = _parse_version_safe(v.patched_version)
        if pv is not None:
            patched_versions.append(pv)

    if patched_versions:
        return str(max(patched_versions))

    # Fallback: look for "latest PyPI version (X)" in fix_recommendation.
    for v in vulns:
        fr = v.fix_recommendation or ""
        marker = "latest PyPI version ("
        if marker in fr and fr.endswith(")."):
            start = fr.find(marker) + len(marker)
            end = fr.rfind(")")
            candidate = fr[start:end].strip()
            if candidate:
                return candidate

    return None


def group_by_package(matches: List[VulnerabilityMatch]) -> List[PackageGroup]:
    grouped: Dict[Tuple[str, str], List[VulnerabilityMatch]] = defaultdict(list)
    for m in matches:
        key = (m.package_name, m.current_version)
        grouped[key].append(m)

    out: List[PackageGroup] = []
    for (name, version), vulns in grouped.items():
        safe_version = _infer_safe_version_for_package(vulns)
        # If we have a safe version, assume all listed vulns are fixed by upgrading to it.
        fixed_count = len(vulns) if safe_version else 0
        fixed_breakdown: Dict[Severity, int] = {}
        if safe_version:
            for v in vulns:
                sev = v.severity or "unknown"
                fixed_breakdown[sev] = fixed_breakdown.get(sev, 0) + 1  # type: ignore[arg-type]
        out.append(
            PackageGroup(
                package_name=name,
                current_version=version,
                vulnerabilities=vulns,
                safe_version=safe_version,
                fixed_vulnerability_count=fixed_count,
                fixed_severity_breakdown=fixed_breakdown,
            )
        )

    out.sort(key=lambda g: g.package_name)
    return out


def compute_security_summary(
    matches: List[VulnerabilityMatch],
    *,
    dependency_count: int,
) -> dict:
    total_vulns = len(matches)
    if total_vulns == 0:
        return {
            "security_score": 100,
            "risk_level": "Low Risk",
            "total_dependencies": dependency_count,
            "vulnerable_packages": 0,
            "total_vulnerabilities": 0,
            "severity_breakdown": {},
        }

    severities: List[Severity] = []
    for m in matches:
        sev = m.severity or "unknown"
        severities.append(sev)  # type: ignore[arg-type]

    sev_counts: Counter = Counter(severities)

    # Total "risk points" as weighted sum.
    total_risk = 0
    for sev, count in sev_counts.items():
        weight = SEVERITY_WEIGHTS.get(sev, 0)
        total_risk += weight * count

    # Normalize risk into a 0–100 band and translate to score.
    # Choose a saturation constant so a handful of serious vulns does not immediately zero the score.
    RISK_SATURATION = 100  # risk >= 100 treated as "max risk" for scoring
    normalized = min(total_risk, RISK_SATURATION) / float(RISK_SATURATION) if RISK_SATURATION > 0 else 0.0

    # Map risk 0 → score 100, risk 1 → score 10 (floor).
    raw_score = 100 - int(round(normalized * 90))
    score = max(10, min(100, raw_score))

    if score >= 80:
        risk = "Low Risk"
    elif score >= 50:
        risk = "Moderate Risk"
    elif score >= 20:
        risk = "High Risk"
    else:
        risk = "Critical Risk"

    vulnerable_packages = len({m.package_name for m in matches})

    return {
        "security_score": score,
        "risk_level": risk,
        "total_dependencies": dependency_count,
        "vulnerable_packages": vulnerable_packages,
        "total_vulnerabilities": total_vulns,
        "severity_breakdown": dict(sev_counts),
    }


# Semver-like version token (digits, dot-separated segments, alnum segments e.g. 3.15.2, 1a)
_VERSION = r"[0-9]+(?:\.[0-9A-Za-z]+)*"


def extract_vulnerable_range(description: str) -> str:
    """
    Derive a human-readable vulnerable version range from free-form advisory text.

    Handles (non-exhaustive):
      - "before X" / "prior to X" → "< X" (all occurrences joined with "; ")
      - "below X" → "< X"
      - "up to X" / "through X" → "<= X"
      - ">= A, < B" (or similar) → preserved with normalized spacing
      - "X and below" / "1.5.0 and below" → "<= X"
      - "3.x before 3.1.12" → "< 3.1.12"

    Returns a non-whitespace string when a pattern matches, otherwise "".

    Examples
    --------
    >>> extract_vulnerable_range("Versions before 3.15.2 are vulnerable")
    '< 3.15.2'
    >>> extract_vulnerable_range("Django before 2.2.24, 3.x before 3.1.12")
    '< 2.2.24; < 3.1.12'
    >>> extract_vulnerable_range("PyJWT 1.5.0 and below")
    '<= 1.5.0'
    """
    if not description:
        return ""

    text = description.strip()

    # Preserve explicit compound constraints like ">= 1.0, < 2.0" (normalize spaces)
    compound = re.search(
        rf"(>=\s*{_VERSION})\s*,\s*(<\s*{_VERSION})",
        text,
        re.IGNORECASE,
    )
    if compound:
        left = re.sub(r"\s+", " ", compound.group(1).strip())
        right = re.sub(r"\s+", " ", compound.group(2).strip())
        return f"{left}, {right}"

    # "X and below" / "1.5.0 and below"
    m = re.search(rf"\b({_VERSION})\s+and\s+below\b", text, re.IGNORECASE)
    if m:
        return f"<= {m.group(1)}"

    # "up to X"
    m = re.search(rf"\bup to\s+({_VERSION})\b", text, re.IGNORECASE)
    if m:
        return f"<= {m.group(1)}"

    # "through X" (same semantic as up-to for many advisories)
    m = re.search(rf"\bthrough\s+({_VERSION})\b", text, re.IGNORECASE)
    if m:
        return f"<= {m.group(1)}"

    # Standalone "below X" (not already handled by "and below")
    m = re.search(rf"\bbelow\s+({_VERSION})\b", text, re.IGNORECASE)
    if m:
        return f"< {m.group(1)}"

    # All "before X" / "prior to X" (including "3.x before 3.1.12" → matches "before 3.1.12")
    before_iter = re.finditer(
        rf"\b(?:before|prior to)\s+({_VERSION})\b",
        text,
        re.IGNORECASE,
    )
    befores = [m.group(1) for m in before_iter]
    if befores:
        return "; ".join(f"< {v}" for v in befores)

    return ""


def _normalize_api_range(vrange: str) -> str:
    """Normalize whitespace for ranges provided by APIs."""
    s = vrange.strip()
    if not s:
        return ""
    # Collapse repeated spaces; keep commas readable
    s = re.sub(r"\s+", " ", s)
    return s


def get_display_vulnerable_range(v: VulnerabilityMatch) -> str:
    """
    Display vulnerable range: API field first, else ``extract_vulnerable_range`` on description.

    Never returns a lone "-" placeholder. If nothing is known, returns a short professional fallback.
    """
    api = _normalize_api_range(v.vulnerable_version_range or "")
    if api and api != "-":
        return api

    extracted = extract_vulnerable_range(v.description or "")
    if extracted:
        return extracted

    # Last resort: avoid empty / dash-only cells in reports
    return "Not specified in advisory data"

