# depsecscan

`depsecscan` is a Python CLI tool that scans a project's Python dependencies and reports known vulnerabilities using:
- NVD (NIST) REST API (CVE matching + CVSS score where available)
- GitHub Advisory Database (pip ecosystem) (GHSA/CVE + vulnerable version ranges)

## Requirements

- Python 3.10+

Optional environment variables:
- `NVD_API_KEY` (recommended to avoid reduced NVD lookup rate limits)
- `GITHUB_TOKEN` (recommended to avoid GitHub API rate limits)

## Setup

From the project root:

```bash
python -m pip install --upgrade pip
pip install .
```

## Usage

Scan an explicit `requirements.txt`:

```bash
python main.py --file sample_requirements.txt
```

Scan currently installed environment packages:

```bash
python main.py --scan-installed
```

Scan a GitHub repository (auto-detect `requirements.txt` in repo root):

```bash
python main.py --repo https://github.com/owner/repo.git
```

Output:
- CLI report printed to stdout (grouped by package, with security score and summary)
- JSON report written to `security_report.json` (default) or set `--out`
- HTML report written to `security_report.html` (default) or set `--html-out`

Useful flags:
- `--out security_report.json`
- `--html-out security_report.html`
- `--cache-dir .depsecscan_cache`
- `--max-deps 50` (limit dependencies scanned)
- `--max-workers 8`
- `--include-transitive` (installed scans only; uses `pipdeptree` if available)
- `--include-pypi-latest` (when possible, suggest fixes using latest PyPI version)
- `--disable-nvd`
- `--disable-github-advisories`
- `--repo <git_url_or_path>` (clone or reuse repo and scan its `requirements.txt`)
- `--verbose` (more detailed logs)
- `--log-file scanner.log` (write logs to a file)

## Example JSON Schema (high-level)

The generated file contains:
- `scan_meta`: tool settings + scan summary
- `findings`: list of vulnerabilities with fields like `package_name`, `current_version`, `cve_id`, `severity`, `fix_recommendation`, etc.

## Notes

- Matching against NVD uses CPE/version-range heuristics and may produce false negatives/positives.
- GitHub advisories include explicit `vulnerable_version_range` and `first_patched_version` for many pip ecosystem advisories, so those tend to be more actionable.

