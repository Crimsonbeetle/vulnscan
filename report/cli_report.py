from __future__ import annotations

from typing import Iterable

from vulnerability.models import VulnerabilityMatch
from report.summary_utils import group_by_package, compute_security_summary, get_display_vulnerable_range


def print_cli_report(matches: list[VulnerabilityMatch], *, scan_meta: dict) -> None:
    """
    Print a rich, grouped report with security score and summary.
    """
    dependency_count = int(scan_meta.get("dependency_count", 0) or 0)
    summary = compute_security_summary(matches, dependency_count=dependency_count)
    package_groups = group_by_package(matches)

    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        console = Console()

        if not matches:
            console.print("[bold green]No vulnerabilities found (or lookups disabled).[/bold green]")
            return

        # Header: Security score and risk level
        score = summary["security_score"]
        risk = summary["risk_level"]
        score_text = Text(f"Security Score: {score}/100 ({risk})", style="bold")
        if score <= 20:
            score_text.stylize("bold red")
        elif score <= 50:
            score_text.stylize("bold yellow")
        elif score <= 80:
            score_text.stylize("bold green")
        else:
            score_text.stylize("bold green")

        console.print(score_text)
        console.print()

        # Summary section
        console.rule("[bold]Summary[/bold]")
        sev = summary["severity_breakdown"]
        sev_line = " | ".join(
            f"{name.capitalize()}: {sev.get(name, 0)}"
            for name in ["critical", "high", "medium", "low", "unknown"]
        )

        console.print(
            f"Total Dependencies: {summary['total_dependencies']}  "
            f"Vulnerable Packages: {summary['vulnerable_packages']}  "
            f"Total Vulnerabilities: {summary['total_vulnerabilities']}"
        )
        console.print(f"Severity Breakdown: {sev_line}")
        console.print()

        # Findings grouped by package
        console.rule("[bold]Findings[/bold]")

        for group in package_groups:
            table = Table(show_header=True, header_style="bold magenta", show_lines=False, expand=True, padding=(0, 1))
            table.add_column("CVE / GHSA", style="red", no_wrap=True)
            table.add_column("Severity", style="yellow", no_wrap=True)
            table.add_column("Vulnerable Range")
            table.add_column("Description")

            for v in group.vulnerabilities:
                ident = "/".join(x for x in [v.cve_id or "", v.ghsa_id or ""] if x) or "-"
                sev_val = (v.severity or "unknown").lower()
                sev_style = {
                    "critical": "bold red",
                    "high": "bold dark_orange3",
                    "medium": "bold yellow",
                    "low": "bold green3",
                    "unknown": "bold grey62",
                }.get(sev_val, "bold")
                sev_text = Text(sev_val.capitalize(), style=sev_style)
                vrange = get_display_vulnerable_range(v)
                desc = (v.description or "").strip()
                if len(desc) > 120:
                    desc = desc[:117] + "..."
                table.add_row(
                    ident,
                    sev_text,
                    vrange,
                    desc,
                )

            header_lines = [f"[bold]{group.package_name}[/bold] ({group.current_version})"]
            if group.safe_version:
                impact = group.fixed_severity_breakdown
                parts = []
                for name in ["critical", "high", "medium", "low"]:
                    c = impact.get(name, 0)
                    if c:
                        parts.append(f"{c} {name.capitalize()}")
                impact_str = ", ".join(parts) if parts else f"{group.fixed_vulnerability_count} vulnerabilities"
                header_lines.append(
                    f"Upgrade: {group.current_version} → {group.safe_version}  "
                    f"(fixes {group.fixed_vulnerability_count} vulnerabilities: {impact_str})"
                )
            else:
                header_lines.append("Recommended upgrade: review advisories for a safe version.")

            console.print(Panel(table, title="\n".join(header_lines), expand=True))

        console.print()
        console.print(f"Scanned {dependency_count} dependencies using providers: {', '.join(scan_meta.get('providers_enabled', []))}")
        return
    except Exception:
        # Fallback: simple text output grouped by package
        pass

    if not matches:
        print("No vulnerabilities found (or lookups disabled).")
        return

    print(f"Security Score: {summary['security_score']}/100 ({summary['risk_level']})")
    print(
        f"Total Dependencies: {summary['total_dependencies']}  "
        f"Vulnerable Packages: {summary['vulnerable_packages']}  "
        f"Total Vulnerabilities: {summary['total_vulnerabilities']}"
    )
    sev = summary["severity_breakdown"]
    print(
        "Severity Breakdown: "
        + ", ".join(f"{k}={sev.get(k, 0)}" for k in ["critical", "high", "medium", "low", "unknown"])
    )
    print()
    print("Findings by package:")
    for group in package_groups:
        print(f"- {group.package_name} ({group.current_version})")
        if group.safe_version:
            print(f"  Recommended upgrade: {group.current_version} -> {group.safe_version}")
        for v in group.vulnerabilities:
            ident = v.cve_id or v.ghsa_id or "-"
            vrange = get_display_vulnerable_range(v)
            print(f"  * {ident} ({v.severity or 'unknown'}) — Vulnerable Range: {vrange}")

