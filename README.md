# 🔐 VulnScan: Dependency Security Scanner for Python

## 📌 Overview

**DepSecScan** is a Python-based CLI tool that analyzes project dependencies and identifies known security vulnerabilities. It leverages public vulnerability databases such as the **National Vulnerability Database (NVD)** and the **GitHub Advisory Database** to detect CVEs, assess severity, and recommend secure upgrades.

The tool helps developers proactively identify risks introduced by outdated or insecure third-party libraries.

---

## 🚀 Features

* 🔍 Scan `requirements.txt` or installed Python packages
* 🌐 Fetch vulnerabilities from:

  * NVD (CVE + CVSS scores)
  * GitHub Advisory Database (GHSA + version ranges)
* 📊 Security Score (0–100) with risk classification
* 📦 Group vulnerabilities by package
* ⚠️ Severity classification:

  * Critical
  * High
  * Medium
  * Low
* 🛠️ Fix recommendations with upgrade paths
* 📈 Impact analysis (number of vulnerabilities fixed per upgrade)
* 📄 Output formats:

  * CLI (rich formatted table)
  * JSON report
  * HTML report
* ⚡ Optional GitHub repository scanning
* 🧠 Intelligent version range extraction from advisories

---

## 🧰 Tech Stack

* Python 3.10+
* `requests` (API calls)
* `rich` (CLI formatting)
* NVD REST API
* GitHub Advisory API

---

## ⚙️ Requirements

* Python 3.10 or higher

### Optional (Recommended)

Set environment variables to avoid API rate limits:

```bash
export NVD_API_KEY=your_nvd_api_key
export GITHUB_TOKEN=your_github_token
```

---

## 🛠️ Installation

From the project root:

```bash
python -m pip install --upgrade pip
pip install .
```

---

## ▶️ Usage

### 1. Scan a requirements file

```bash
python main.py --file requirements.txt
```

### 2. Scan installed packages

```bash
python main.py --scan-installed
```

### 3. Scan a GitHub repository

```bash
python main.py --repo https://github.com/owner/repo.git
```

---

## 📊 Output

### CLI Output

* Security Score
* Summary statistics
* Vulnerabilities grouped by package
* Fix recommendations

### JSON Report

```bash
security_report.json
```

### HTML Report

```bash
security_report.html
```

---

## 🔧 Useful Flags

```bash
--out security_report.json
--html-out security_report.html
--cache-dir .depsecscan_cache
--max-deps 50
--max-workers 8
--include-transitive
--include-pypi-latest
--disable-nvd
--disable-github-advisories
--repo <git_url_or_path>
--verbose
--log-file scanner.log
```

---

## 📁 Example Output (CLI)

<img width="892" height="548" alt="Screenshot 2026-04-16 at 3 43 37 PM" src="https://github.com/user-attachments/assets/3e731a66-38ec-48f8-b2eb-2cd311fb1a8c" />

---

## 🧠 How It Works

1. Parses dependencies from `requirements.txt` or environment
2. Queries vulnerability databases (NVD + GitHub Advisories)
3. Matches package versions against vulnerable ranges
4. Extracts CVEs, severity, and descriptions
5. Generates a security score and actionable recommendations

---

## ⚠️ Limitations

* Relies on publicly disclosed vulnerabilities (no zero-day detection)
* NVD matching uses heuristics (may produce false positives/negatives)
* Does not analyze application source code or business logic

---

## 🔮 Future Improvements

* CI/CD integration (GitHub Actions)
* Web-based dashboard (Flask/React)
* Support for additional ecosystems (Node.js, Java)
* Static code analysis integration

---

## 👥 Team Members

* Abdul Muqtadir Mohammed
* Faiq Malik
* Haroon Razzack

---

## 🎓 Course Information

**CMPE-279 Sec 01 – Software Security Technologies**

---

## 📄 License

This project is for academic purposes.

---

## ⭐ Acknowledgements

* National Vulnerability Database (NVD)
* GitHub Advisory Database
