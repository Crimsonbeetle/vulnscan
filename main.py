#!/usr/bin/env python3
"""
depsecscan entry point.

Example:
  python main.py --file requirements.txt
  python main.py --scan-installed
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from report.cli_report import print_cli_report
from report.html_report import write_html_report
from report.json_report import write_json_report
from scanner.dependency_parser import (
    DependencySource,
    parse_requirements_file,
    read_installed_distributions,
    pipdeptree_direct_dependencies,
)
from vulnerability.vulnerability_scanner import VulnerabilityScanner


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Scan Python dependencies (or a repo) for known vulnerabilities.",
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", type=str, help="Path to a requirements.txt file to scan")
    group.add_argument("--scan-installed", action="store_true", help="Scan packages installed in the current environment")
    group.add_argument("--repo", type=str, help="GitHub repository URL or local path to scan (auto-detect requirements.txt)")

    p.add_argument("--out", type=str, default="security_report.json", help="JSON output file path (default: security_report.json)")
    p.add_argument(
        "--html-out",
        type=str,
        default="security_report.html",
        help="HTML output file path for a demo-ready report (default: security_report.html)",
    )
    p.add_argument("--cache-dir", type=str, default=str(Path(".depsecscan_cache").resolve()), help="Cache directory for API responses")
    p.add_argument("--max-deps", type=int, default=0, help="Max number of dependencies to scan (0 = no limit)")
    p.add_argument("--max-workers", type=int, default=8, help="Max concurrency for vulnerability API calls")
    p.add_argument(
        "--include-transitive",
        action="store_true",
        help="When scanning installed packages, include transitive deps via pipdeptree if available",
    )
    p.add_argument(
        "--include-pypi-latest",
        action="store_true",
        help="When possible, suggest fixes using latest PyPI version from PyPI",
    )

    p.add_argument("--disable-nvd", action="store_true", help="Disable NVD lookups")
    p.add_argument("--disable-github-advisories", action="store_true", help="Disable GitHub advisories lookups")

    p.add_argument("--verbose", action="store_true", help="Enable verbose logging to stderr")
    p.add_argument("--log-file", type=str, help="Path to a log file (e.g., scanner.log)")
    return p


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    args = build_arg_parser().parse_args(argv)

    # Logging setup
    log_level = logging.DEBUG if args.verbose else logging.INFO
    handlers: list[logging.Handler] = []
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(log_level)
    handlers.append(stream_handler)
    if args.log_file:
        file_handler = logging.FileHandler(args.log_file, encoding="utf-8")
        file_handler.setLevel(log_level)
        handlers.append(file_handler)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
    )
    log = logging.getLogger("depsecscan")

    input_deps = []
    input_source: DependencySource
    if args.file:
        path = Path(args.file)
        if not path.exists():
            log.error("requirements file not found: %s", path)
            return 2
        log.info("Scanning requirements file: %s", path)
        input_deps = parse_requirements_file(path)
        input_source = DependencySource.REQUIREMENTS_FILE
    elif args.repo:
        # Basic support: clone or use existing path, find a requirements.txt at the root.
        from subprocess import CalledProcessError, run

        repo_arg = args.repo
        repo_path: Path
        if Path(repo_arg).exists():
            repo_path = Path(repo_arg)
        else:
            # Treat as Git URL, clone into cache dir.
            repo_cache_root = Path(args.cache_dir) / "repos"
            repo_cache_root.mkdir(parents=True, exist_ok=True)
            repo_name = os.path.splitext(os.path.basename(repo_arg.rstrip("/")))[0]
            repo_path = repo_cache_root / repo_name
            if not repo_path.exists():
                log.info("Cloning repository %s into %s", repo_arg, repo_path)
                try:
                    run(["git", "clone", "--depth", "1", repo_arg, str(repo_path)], check=True)
                except CalledProcessError as e:
                    log.error("Failed to clone repository: %s", e)
                    return 2
            else:
                log.info("Using cached repository at %s", repo_path)

        req_path = repo_path / "requirements.txt"
        if not req_path.exists():
            log.error("No requirements.txt found in repository path: %s", repo_path)
            return 2
        log.info("Scanning repository requirements: %s", req_path)
        input_deps = parse_requirements_file(req_path)
        input_source = DependencySource.REQUIREMENTS_FILE
    else:
        if args.include_transitive:
            deps = pipdeptree_direct_dependencies()
            if deps:
                input_deps = deps
            else:
                # Best-effort: fall back to the installed list.
                input_deps = read_installed_distributions()
        else:
            input_deps = read_installed_distributions()
        input_source = DependencySource.INSTALLED

    if args.max_deps and args.max_deps > 0:
        input_deps = input_deps[: args.max_deps]

    cache_dir = Path(args.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)

    disable_nvd = bool(args.disable_nvd)
    disable_github = bool(args.disable_github_advisories)

    nvd_api_key = os.environ.get("NVD_API_KEY", "").strip() or None
    github_token = os.environ.get("GITHUB_TOKEN", "").strip() or None

    scanner = VulnerabilityScanner(
        cache_dir=cache_dir,
        enable_nvd=not disable_nvd,
        enable_github_advisories=not disable_github,
        nvd_api_key=nvd_api_key,
        github_token=github_token,
        max_workers=max(args.max_workers, 1),
        include_pypi_latest=bool(args.include_pypi_latest),
    )

    log.info("Scanning %d dependencies with providers: NVD=%s, GitHub=%s", len(input_deps), not disable_nvd, not disable_github)
    matches, scan_meta = scanner.scan(input_deps=input_deps, input_source=input_source)

    # CLI output
    print_cli_report(matches, scan_meta=scan_meta)

    # JSON output
    out_path = Path(args.out)
    write_json_report(out_path, matches=matches, scan_meta=scan_meta)

    # HTML output
    html_out_path = Path(args.html_out)
    write_html_report(html_out_path, matches=matches, scan_meta=scan_meta)

    log.info("JSON report written to %s", out_path)
    log.info("HTML report written to %s", html_out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

