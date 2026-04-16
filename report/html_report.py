from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from report.summary_utils import group_by_package, compute_security_summary, get_display_vulnerable_range
from vulnerability.models import VulnerabilityMatch


def write_html_report(
    out_path: Path,
    *,
    matches: list[VulnerabilityMatch],
    scan_meta: dict[str, Any],
) -> None:
    """Generate a standalone HTML security report suitable for demos."""

    dependency_count = int(scan_meta.get("dependency_count", 0) or 0)
    summary = compute_security_summary(matches, dependency_count=dependency_count)
    groups = group_by_package(matches)

    generated_at = datetime.utcnow().isoformat() + "Z"

    def sev_color(sev: str | None) -> str:
        mapping = {
            "critical": "#d32f2f",
            "high": "#f57c00",
            "medium": "#fbc02d",
            "low": "#388e3c",
            "unknown": "#757575",
        }
        return mapping.get((sev or "unknown").lower(), "#757575")

    rows_html = []
    for g in groups:
        for v in g.vulnerabilities:
            ident = v.cve_id or v.ghsa_id or "-"
            sev = v.severity or "unknown"
            color = sev_color(sev)
            vrange = get_display_vulnerable_range(v)
            desc = (v.description or "").strip()
            if len(desc) > 160:
                desc = desc[:157] + "..."
            safe = g.safe_version or ""
            rows_html.append(
                f"<tr>"
                f"<td>{g.package_name}</td>"
                f"<td>{g.current_version}</td>"
                f"<td style='color:{color};font-weight:600'>{sev.capitalize()}</td>"
                f"<td>{ident}</td>"
                f"<td>{vrange}</td>"
                f"<td>{safe}</td>"
                f"<td>{desc}</td>"
                f"</tr>"
            )

    rows_html_str = "\n".join(rows_html) if rows_html else (
        "<tr><td colspan='7' style='text-align:center;padding:1rem;'>"
        "No vulnerabilities found (or lookups disabled).</td></tr>"
    )

    score = summary["security_score"]
    risk = summary["risk_level"]
    if score <= 20:
        score_bg = "#d32f2f"
    elif score <= 50:
        score_bg = "#f57c00"
    elif score <= 80:
        score_bg = "#fbc02d"
    else:
        score_bg = "#388e3c"

    sev = summary["severity_breakdown"]
    sev_items = []
    for name in ["critical", "high", "medium", "low", "unknown"]:
        sev_items.append(f"<span class='sev sev-{name}'>{name.capitalize()}: {sev.get(name, 0)}</span>")
    sev_html = " ".join(sev_items)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Dependency Security Report</title>
  <style>
    body {{
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 0;
      padding: 0;
      background: #0b1020;
      color: #e2e8f0;
    }}
    .container {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 2rem 1.5rem 3rem;
    }}
    h1 {{
      font-size: 1.8rem;
      margin-bottom: 0.5rem;
    }}
    .muted {{
      color: #94a3b8;
      font-size: 0.9rem;
    }}
    .score-card {{
      display: inline-flex;
      align-items: center;
      padding: 0.75rem 1.5rem;
      border-radius: 999px;
      background: {score_bg};
      color: #0b1020;
      font-weight: 700;
      margin: 1rem 0 1.5rem;
    }}
    .score-card span.score {{
      font-size: 1.2rem;
      margin-right: 0.75rem;
    }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 0.75rem;
      margin-bottom: 1.5rem;
    }}
    .summary-card {{
      background: radial-gradient(circle at top left, #1e293b, #020617);
      border-radius: 0.9rem;
      padding: 0.9rem 1rem;
      border: 1px solid #1f2937;
    }}
    .summary-label {{
      font-size: 0.8rem;
      text-transform: uppercase;
      color: #9ca3af;
      letter-spacing: 0.05em;
      margin-bottom: 0.35rem;
    }}
    .summary-value {{
      font-size: 1.1rem;
      font-weight: 600;
    }}
    .sev-tags {{
      margin-top: 0.35rem;
      font-size: 0.75rem;
    }}
    .sev {{
      display: inline-block;
      margin-right: 0.4rem;
      padding: 0.2rem 0.5rem;
      border-radius: 999px;
      background: #020617;
      border: 1px solid #1f2937;
    }}
    .sev-critical {{ color: #fecaca; border-color: #ef4444; }}
    .sev-high {{ color: #ffedd5; border-color: #f97316; }}
    .sev-medium {{ color: #fef9c3; border-color: #eab308; }}
    .sev-low {{ color: #bbf7d0; border-color: #22c55e; }}
    .sev-unknown {{ color: #cbd5f5; border-color: #4b5563; }}

    h2 {{
      margin-top: 2rem;
      margin-bottom: 0.75rem;
      font-size: 1.2rem;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 0.5rem;
      font-size: 0.85rem;
      background: #020617;
      border-radius: 0.75rem;
      overflow: hidden;
      border: 1px solid #1f2937;
    }}
    thead {{
      background: linear-gradient(90deg, #0f172a, #111827);
    }}
    th, td {{
      padding: 0.6rem 0.7rem;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      font-weight: 600;
      color: #e5e7eb;
      border-bottom: 1px solid #1f2937;
      font-size: 0.78rem;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }}
    tbody tr:nth-child(even) {{
      background: #030712;
    }}
    tbody tr:hover {{
      background: #111827;
    }}
    .footer {{
      margin-top: 2rem;
      font-size: 0.75rem;
      color: #6b7280;
      text-align: right;
    }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Dependency Security Report</h1>
    <div class="muted">Input source: {scan_meta.get('input_source')} • Generated at: {generated_at}</div>

    <div class="score-card">
      <span class="score">{score}/100</span>
      <span>{risk}</span>
    </div>

    <div class="summary-grid">
      <div class="summary-card">
        <div class="summary-label">Total Dependencies</div>
        <div class="summary-value">{summary['total_dependencies']}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Vulnerable Packages</div>
        <div class="summary-value">{summary['vulnerable_packages']}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Total Vulnerabilities</div>
        <div class="summary-value">{summary['total_vulnerabilities']}</div>
        <div class="sev-tags">{sev_html}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Providers</div>
        <div class="summary-value">{", ".join(scan_meta.get("providers_enabled", [])) or "None"}</div>
      </div>
    </div>

    <h2>Vulnerabilities</h2>
    <table>
      <thead>
        <tr>
          <th>Package</th>
          <th>Current</th>
          <th>Severity</th>
          <th>CVE / GHSA</th>
          <th>Vulnerable Range</th>
          <th>Safe Version</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        {rows_html_str}
      </tbody>
    </table>

    <div class="footer">
      Generated by depsecscan.
    </div>
  </div>
</body>
</html>
"""

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")

