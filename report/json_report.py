from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vulnerability.models import VulnerabilityMatch
from report.summary_utils import group_by_package, compute_security_summary, get_display_vulnerable_range


def _match_to_json(m: VulnerabilityMatch) -> dict[str, Any]:
    return {
        "package_name": m.package_name,
        "current_version": m.current_version,
        "vulnerable_version_range": get_display_vulnerable_range(m),
        "cve_id": m.cve_id,
        "ghsa_id": m.ghsa_id,
        "severity": m.severity,
        "cvss_score": m.cvss_score,
        "description": m.description,
        "fix_recommendation": m.fix_recommendation,
        "provider": m.provider,
        "references": m.references,
        "patched_version": m.patched_version,
    }


def write_json_report(out_path: Path, *, matches: list[VulnerabilityMatch], scan_meta: dict) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    dependency_count = int(scan_meta.get("dependency_count", 0) or 0)
    summary = compute_security_summary(matches, dependency_count=dependency_count)

    package_groups = group_by_package(matches)
    grouped_payload = []
    for g in package_groups:
        grouped_payload.append(
            {
                "package_name": g.package_name,
                "current_version": g.current_version,
                "safe_version": g.safe_version,
                 "fixed_vulnerability_count": g.fixed_vulnerability_count,
                 "fixed_severity_breakdown": g.fixed_severity_breakdown,
                "vulnerabilities": [_match_to_json(m) for m in g.vulnerabilities],
            }
        )

    payload = {
        "scan_meta": {
            **scan_meta,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "summary": summary,
        "packages": grouped_payload,
        "findings": [_match_to_json(m) for m in matches],
    }
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

