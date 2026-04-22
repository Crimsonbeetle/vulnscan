# VulnScan — Presentation Guide

Companion to `VulnScan.pptx`. For each slide: what's on it, what the
terminology means, and a word-for-word script you can actually read.

Target runtime: **8 minutes.** Slide budgets add to ~7:30 so Q&A can start
early if asked.

---

## Glossary (memorize these — you will be asked)

| Term | Plain-English meaning |
|---|---|
| **Dependency** | A single `name@version` pair your code imports, e.g. `django@2.2.0`. |
| **CVE** | "Common Vulnerabilities and Exposures." A globally unique ID for one security bug, e.g. `CVE-2021-44228` (Log4Shell). Managed by MITRE/NVD. |
| **GHSA** | GitHub Security Advisory ID, e.g. `GHSA-xxxx-xxxx-xxxx`. GitHub's own IDs, often cross-referenced to a CVE. |
| **NVD** | National Vulnerability Database. U.S. government's canonical CVE database (NIST). |
| **CVSS** | "Common Vulnerability Scoring System." A 0.0–10.0 number for how bad a bug is. ≥9.0 critical, ≥7.0 high, ≥4.0 medium, else low. |
| **CPE** | "Common Platform Enumeration." A structured string NVD uses to name a product+version, e.g. `cpe:2.3:a:djangoproject:django:2.2.0:*:*:…`. |
| **PURL** | "Package URL." Ecosystem-native naming GitHub uses: `pkg:pypi/django@2.2.0`. |
| **PEP 440** | The Python spec for how versions compare (what `>=2.0,<3.0` actually means). |
| **SBOM** | "Software Bill of Materials." An inventory of everything in a build. |
| **OWASP Top 10** | The industry's consensus list of most common security risks. Our category is **A06:2021 — Vulnerable and Outdated Components**. |
| **Zero-day** | A vulnerability that isn't public yet. VulnScan only finds *published* vulns — that's a stated limitation. |

---

## Slide 1 — Title (~30 sec)

**Shown:** Project name, tagline, three team members, course code, date.

**What to explain / back up:**
- "CMPE-279" is Software Security Technologies at SJSU.
- Project is a CLI tool — runs in a terminal, not a web app.

**Script:**
> "Good afternoon. We're team [X]: I'm Haroon, this is Muqtadir, this is Faiq.
> For our CMPE-279 final we built **VulnScan** — a command-line tool
> that tells a Python developer, before they ship, which of their dependencies
> have known security bugs."

Then hand off or advance.

---

## Slide 2 — The Problem (~45 sec)

**Shown:** Two tiles. Left: why this matters (stats + real incidents). Right: our objective.

**What to explain / back up:**
- **"80% third-party code"** — widely cited SCA-vendor stat (Sonatype, Snyk, GitHub Octoverse reports). The exact number varies; the point is *most* of a modern app is not code your team wrote.
- **OWASP A06:2021** — "Vulnerable and Outdated Components." Part of the OWASP Top 10, the industry's most-cited security risk list. Updated every 3–4 years.
- **Log4Shell (CVE-2021-44228)** — a remote code execution bug in the Log4j Java logging library. CVSS 10.0. Affected millions of servers for weeks because nobody knew they had Log4j buried in their dependency tree. This is the poster child for why dep scanning matters.
- **Equifax 2017** — 147M records breached because an unpatched Apache Struts dependency had a known CVE. Classic A06 failure.
- **"Target user: the developer, at commit time"** — most scanners run on the security team's dashboard. We want this in the terminal while the dev is still writing code.

**Script:**
> "The problem we're addressing: roughly 80% of a modern Python application
> isn't code your team wrote — it's third-party libraries. The OWASP Top 10
> formalizes this risk as category A06: *Vulnerable and Outdated Components*.
>
> Two examples make this real. Log4Shell in 2021: a single logging library,
> CVSS 10 out of 10, took out tens of thousands of servers — because nobody
> knew which of their apps depended on Log4j. Equifax 2017: 147 million
> records breached through an unpatched Apache Struts dependency that had
> a publicly known CVE at the time.
>
> Our objective *(gesture to right tile)* is to build a CLI tool that
> takes a list of Python dependencies and returns every known vulnerability
> affecting those exact versions — severity, fix path, and a single
> security score the developer can act on. The target user is the
> developer, at commit time — before the code ever reaches production."

---

## Slide 3 — What We Built (~40 sec)

**Shown:** One-line mental model, four feature cards (dual-source lookup, security score, fix recommendations, three report formats), and a navy strip with the novelty pitch.

**What to explain / back up:**
- **"Dual-source lookup"** — NVD and GitHub Advisory DB disagree more than you'd expect; merging both catches more and cross-checks findings.
- **"0–100 security score"** — a *design choice*, not a standard. Our formula: `risk = 20·critical + 10·high + 5·medium + 2·low`, then `score = 100 − min(risk, 100)·0.9`. Floor 10, ceiling 100. One critical = −18 points. Be ready to defend the weights.
- **"Fix recommendations"** — we don't just say "you're vulnerable," we say "bump django from 2.2 to 4.2.11 and 8 CVEs go away."
- **"Three report formats"** — CLI for humans, JSON for automation (CI pipelines), HTML for sharing.
- **Novelty bar** — competitors: `pip-audit` (PyPA, open-source), `safety` (PyUp, freemium), `Snyk`, `Dependabot` (GitHub-native), `OSV-Scanner` (Google). Our differentiator: dual-source merge + a single composite score + upgrade impact analysis.

**Script:**
> "What we actually built — three-stage pipeline, read the tagline at the top.
>
> Four features worth calling out. **First**, dual-source lookup: we query both
> the National Vulnerability Database and GitHub's Advisory Database, in
> parallel, and merge the results. They don't agree — catching both gives better
> coverage. **Second**, a single 0-to-100 security score weighted by severity —
> this is our design, not a standard; one critical bug drops you about 18
> points. **Third**, fix recommendations with impact: we don't just say 'you're
> vulnerable,' we tell you 'bump Django from 2.2 to 4.2 and eight CVEs go
> away.' **Fourth**, three output formats — rich CLI for humans, JSON for
> CI pipelines, HTML for stakeholders.
>
> The bottom line *(point to navy strip)* is our novelty pitch: tools like
> pip-audit and Dependabot exist, but they're single-source and don't give
> you one actionable number. We do."

---

## Slide 4 — Architecture (~60 sec)

**Shown:** Three phase tiles (Input → Lookup → Output) with arrows between; a shared-plumbing bar across the bottom.

**What to explain / back up:**
- **Phase 1 / Input** — three ways in: (a) a `requirements.txt` file, (b) whatever's installed in the current Python environment, (c) clone a Git repo and scan its `requirements.txt`. All three collapse to the same `Dependency(name, version)` list. We **drop anything without an exact version** because "django with no version" can't be matched to a CVE.
- **Phase 2 / Lookup** — two provider clients running in a `ThreadPoolExecutor` (Python's thread pool, max 8 workers). NVD and GitHub are asked the same question in parallel; each returns a list of `VulnerabilityMatch` objects.
- **CPE vs PURL (the real technical point)** — NVD indexes by CPE (`cpe:2.3:a:djangoproject:django:2.2.0:*:*:*:*:*:*:*`) and version ranges. GitHub indexes by ecosystem + package name + version (`pkg:pypi/django@2.2.0`). Two totally different matching strategies; we normalize both into one data shape.
- **Phase 3 / Output** — dedupe, group by package, compute the security score, render three ways.
- **Shared plumbing** — `utils/http_cache.py` is the single outbound network chokepoint. Every API call goes through it. Makes the tool offline-friendly and easy to audit.

**Script:**
> "Here's the architecture — three phases, left to right.
>
> **Phase 1: Input.** Three ways a user can feed us dependencies — a
> requirements file, the currently-installed environment, or a Git repo we
> clone ourselves. All three collapse into the same typed list. We
> intentionally drop anything without an exact version, because you can't
> match a CVE against 'Django, some version.'
>
> **Phase 2: Lookup.** The core of the tool. Two API clients — one for NVD,
> one for GitHub Advisories — running concurrently in a thread pool. NVD
> describes products using CPE strings and version ranges; GitHub uses
> ecosystem-aware PURLs. Totally different languages. Our scanner normalizes
> both outputs into a single Python dataclass called `VulnerabilityMatch` —
> that's the one type that crosses the boundary into the output phase.
>
> **Phase 3: Output.** Dedupe — same CVE from two providers only counts once —
> group by package, compute the score, render CLI, JSON, and HTML.
>
> *(point to the navy bar)* Everything is glued together by shared plumbing:
> an HTTP cache, a version comparator that understands PEP 440, and a tiny
> PyPI client. The cache is our single outbound network chokepoint — one
> file to audit, one file to disable for offline use."

---

## Slide 5 — Key Components (~50 sec)

**Shown:** File tree on the left (color-coded by phase); role descriptions on the right.

**What to explain / back up:**
- **Reading the tree:** each top-level folder maps to one phase or to shared plumbing. We enforce this by file organization — no "lookup" code in `report/`, no "report" code in `vulnerability/`.
- **`models.py` is a leaf** — nothing inside it imports anything else in the project. This is intentional; it makes the data shape stable and means any change to providers/reporters doesn't ripple into the type definition.
- **`http_cache.py` is the only networking module.** Every `requests` call lives behind this one file. One place to audit for security, one place to mock for tests, one flag to turn off.
- **`dependency_parser.py`** — uses Python's standard `packaging` library, which implements PEP 440 version parsing. Drops invalid pins. Handles `==`, `===`, inline comments, nested `-r` includes.
- **`summary_utils.py`** — where the 0–100 scoring lives, shared by all three reporters. Change the formula there, all three outputs update automatically.

**Script:**
> "Quick tour of the codebase. *(point to tree)* Every file maps to exactly
> one of the three phases we just saw, or to shared utilities.
>
> Four things worth calling out. **scanner/** takes raw text and turns it
> into a typed dependency list — anything we can't pin to an exact version
> gets dropped on the floor. **vulnerability/** is where the two API clients
> live, plus the orchestrator and the shared data model. The data model —
> `models.py` — is a leaf in our dependency graph: nothing below it,
> plenty above. Stable by design.
>
> **report/** is the output layer. Pure — consumes `VulnerabilityMatch`
> objects, produces three formats. And **utils/** has our single networking
> chokepoint — `http_cache.py` — plus PEP 440 version math. If you wanted
> to audit every byte this tool sends over the wire, you'd only need to
> read one file."

---

## Slide 6 — Implementation (~60 sec)

**Shown:** Navy stack strip at the top; two columns below — Challenges (red) and Design Decisions (green).

**What to explain / back up:**
- **Stack:** Python 3.10+ (because we use union-type syntax `str | None`), `requests` (HTTP), `rich` (terminal tables), `packaging` (PEP 440 version comparisons), `concurrent.futures.ThreadPoolExecutor` (our parallelism primitive), NVD and GHSA REST APIs.
- **NVD 2.0 schema shift** — NVD changed its JSON schema between version 1.1 and 2.0. Fields moved: `cve.description.description_data` → `cve.descriptions`; `cve.CVE_data_meta.ID` → `cve.id`; CPE matches restructured. We had to rewrite the extractors. This is a real technical story — the class rubric values it.
- **Rate limits** — NVD allows 5 requests/30 sec without a key, 50 with one. GitHub allows 60/hr unauthenticated, 5000 with a PAT. Our cache makes a second run nearly free.
- **CPE vs PURL** — covered above. The one-sentence version: "two databases, two naming conventions, one output type."
- **Noisy keyword search** — searching NVD for `"requests"` returns thousands of unrelated CVEs ("HTTP request," "SQL request," etc.). The CPE product-name check (`django` vs `djangoproject`) filters these out.
- **Severity-weighted score** — *defend this explicitly.* Design: critical bugs are roughly 2× worse than high, 4× worse than medium, 10× worse than low. Not CVSS-native, but intentional: we wanted one single number, not a distribution.
- **Dedupe at match level** — an NVD hit and a GHSA hit referencing the same CVE is one finding, not two.
- **Leaf-only data model** — `VulnerabilityMatch` is the one type that flows Phase 2 → Phase 3. Reporters don't know anything about providers.
- **Cache as chokepoint** — already covered, worth repeating.

**Script:**
> "Stack is across the top — standard Python, standard libraries, nothing
> exotic. The interesting parts are in the two columns.
>
> **Challenges, on the left.** The biggest one: NVD migrated their API from
> schema 1.1 to 2.0, and moved almost every field. CVE descriptions, CVSS
> scores, references, CPE matches — all in different places. We rewrote the
> extractors against the new schema. Rate limits were the next problem:
> NVD aggressively throttles unauthenticated clients, so we built an on-disk
> cache — scan twice and the second run is almost free. The CPE-versus-PURL
> mismatch I mentioned earlier meant writing two different matching
> strategies. And keyword search on a word like 'requests' returns thousands
> of unrelated CVEs, so we filter on CPE product name.
>
> **Design decisions, on the right.** The severity-weighted score is our
> call, not a standard — we wanted a single number, so we picked weights
> that make one critical bug cost about 18 points. We dedupe at the match
> level: same CVE from both providers equals one row. Our data model has
> exactly one type crossing the phase-2-to-3 boundary, which keeps
> reporters dumb. And every outbound network call goes through a single
> cache module — easy to audit, easy to turn off."

---

## Slide 7 — Live Demo (~90 sec — biggest time sink)

**Shown:** Large "Live Demo" title, demo script in the navy box.

**What to explain / back up:**
- This is the moment to *stop talking and show*.
- Have a terminal pre-sized, large font (≥18pt), pre-`cd`'d into `vulnscan/`.
- Have the HTML report pre-rendered in a second browser tab but **don't show it until after the CLI run finishes**.
- If the scan stalls (network hiccup), kill it with Ctrl-C and re-run with `--cache-dir .depsecscan_cache` — cached results will return in <1 sec.

**Demo beats (time each):**
1. **0:00–0:10** — Show the input: `cat sample_requirements.txt` (6–8 lines).
2. **0:10–0:40** — Run: `python main.py --file sample_requirements.txt`. Narrate while it runs: "you can see it parsing, querying both providers in parallel, deduping…"
3. **0:40–0:70** — Walk the CLI output: severity-colored table, grouped by package. Point out one critical, point out a fix recommendation.
4. **0:70–0:90** — Switch tab, show `security_report.html`. Scroll to the top: score + summary. Scroll to a package: the fix path.

**Script (glue between demo beats):**
> "Let me show you this live. Here's a sample requirements file with a
> handful of deliberately outdated packages. *(run command)* You can see
> the scanner parsing, firing both providers in parallel, deduping, and
> rendering. *(CLI appears)* That's the rich-formatted table — color-coded
> by severity, grouped by package. Top of the list: [point to worst
> finding]. Notice the fix recommendation — 'upgrade to X.Y.Z.'
> *(switch tab)* Same data, rendered as HTML. Score at the top, findings
> below, one click to the advisory. That's the tool end-to-end."

---

## Slide 8 — Results (~50 sec)

**⚠️ Before presenting: re-run on your real input and update these numbers in the slide directly.**

**Shown:** Big orange score gauge (42 / AT RISK), severity breakdown bars, top fix recommendation, scan metrics table.

**What to explain / back up:**
- **Score 42 = "at risk."** Our band: 80+ Good, 60–79 Caution, 40–59 At Risk, <40 Critical. Not a standard — a design choice.
- **Severity breakdown** — simple counts. The colors match the CLI table.
- **"django 2.2.0 → 4.2.11 resolves 8 CVEs"** — the kind of recommendation that actually moves the score. One bump, eight fewer findings. This is where upgrade-impact analysis earns its keep.
- **Scan metrics** — prove it's fast enough to run pre-commit:
  - 2.3 s scan → acceptable for a git hook
  - 74% cache hit rate → second run is near-instant
  - 18 API calls for 32 packages → we're efficient, not chatty
- **Placeholder warning** — these numbers are illustrative. Before presenting, run `python main.py --file real_project_requirements.txt` and edit the slide with the actual values.

**Script (replace numbers with your actual scan):**
> "Here's what the tool surfaces on a real project. *(gesture to score)*
> Security score of 42 — 'at risk' on our 0-to-100 scale. *(move right)*
> The breakdown: 3 critical, 7 high, 12 medium, 4 low — 26 findings across
> 11 of the 32 packages scanned. *(move right)* Our top fix recommendation:
> bump Django from 2.2 to 4.2.11 — that single upgrade resolves 8 CVEs
> on its own. And the metrics down below: the whole scan runs in 2.3
> seconds, 74% of the calls came from cache, total of 18 network requests
> for 32 packages. Fast enough to run as a pre-commit hook."

---

## Slide 9 — Limitations & Future Work (~30 sec)

**Shown:** Two tiles — Known Limitations (red) and Future Enhancements (blue).

**What to explain / back up (limitations):**
- **"Only known CVEs"** — if it isn't public yet, we can't find it. No AV/EDR-style behavioral detection.
- **"CPE keyword matching is heuristic"** — can false-positive on package-name collisions (many Python packages share names with unrelated products in NVD).
- **"Does not inspect source code"** — we only look at what's in the dependency manifest. A used-but-unreported library wouldn't be caught.
- **"requirements.txt only"** — Poetry (`poetry.lock`) and Pipenv (`Pipfile.lock`) are the most obvious gaps. Real future work.
- **"Cache doesn't expire"** — documented tradeoff, not a bug. Simpler implementation; stale-data risk is real but bounded because CVE records rarely change.

**What to explain / back up (future work):**
- **OSV.dev** — Google's open vulnerability database, PURL-native, aggregates NVD + GHSA + others. Would replace or complement NVD as our primary source.
- **GitHub Action** — run on every PR, fail the build on high-severity findings. Turns the tool from "thing a dev runs manually" into "thing that gates merges."
- **SBOM export** — CycloneDX and SPDX are industry formats; many enterprises require them.
- **Multi-ecosystem** — our architecture separates "parse the manifest" from "look up the vuln." Supporting npm or Maven is mostly new parsers, same lookup code.

**Script:**
> "Briefly, what the tool doesn't do. We only find publicly-disclosed
> vulnerabilities — no zero-days. Our matching is heuristic, so expect the
> occasional false positive. We don't read source code, only the manifest.
> And we only parse requirements.txt — poetry.lock and Pipfile support is
> on the roadmap, along with an OSV.dev backend, a GitHub Action for
> PR-time scans, SBOM export, and support for npm and Maven ecosystems."

---

## Slide 10 — Takeaways & Q&A (~30 sec + Q&A)

**Shown:** Three dark tiles — Built / Learned / Impact — and a large "Questions?" line.

**What to explain / back up:**
- **Built** — working tool, three input modes, three output formats, two-source lookup. Shipped.
- **Learned** — three concrete lessons worth owning:
  1. API schemas drift (NVD 1.1 → 2.0) — defensive parsing matters.
  2. I/O concurrency is cheap wins (naïve sequential: ~30s; thread pool + cache: ~2s).
  3. A single normalized data type at the phase boundary keeps the rest of the code small.
- **Impact** — one command → actionable answer. Lowers the barrier to OWASP A06 hygiene. Especially valuable for small teams with no dedicated security engineer.

**Script:**
> "To wrap: we built a working Python dependency scanner — three input modes,
> three report formats, two vulnerability databases. Three things we learned
> along the way: APIs silently change their schemas under you, parallelism
> plus caching turns a 30-second scan into a 2-second one, and keeping a
> single normalized data type at your phase boundaries keeps the rest of
> the code simple. The impact: any Python developer can run one command
> and know whether their project is safe to ship.
>
> We'd be happy to take questions."

Then **stop talking.** Wait.

---

## Likely Q&A (prep answers)

**Q: Why not just use pip-audit?**
> pip-audit is single-source (PyPI advisory DB only) and doesn't produce a
> composite score. We query both NVD and GHSA and cross-reference. That said,
> pip-audit is a legitimate baseline — we benchmarked against it.

**Q: How do you justify your score weights?**
> It's a design choice, not a standard. Weights: 20-10-5-2 for critical/
> high/medium/low. Rationale: we wanted one critical bug to dominate a pile
> of lows, which matches developer intuition. We'd defend the ordering
> more strongly than the exact values.

**Q: What about false positives?**
> Two main sources: NVD keyword search matches unrelated products with
> similar names (mitigated by CPE product filtering), and heuristic version
> range extraction can include boundary-unclear ranges. Cross-referencing
> NVD against GHSA reduces this.

**Q: Does this run in CI?**
> Today, yes — any system that can run Python can run the tool. A proper
> GitHub Action with exit codes keyed to severity is on the roadmap.

**Q: What if the APIs are down?**
> The on-disk cache serves as fallback — previously-scanned packages return
> cached results. If both APIs are down on a fresh scan, the tool reports
> zero findings and logs the failures. We don't silently claim safety.

**Q: How did you split the work?**
> Haroon led providers and the NVD schema work; Faiq led reporting and
> CLI UX; Muqtadir led scoring, evaluation, and architecture documentation.

---

## Pre-flight checklist (night before)

- [ ] Re-run on `real_project_requirements.txt` and update Slide 8 numbers
- [ ] Export deck as PDF (backup if PowerPoint misbehaves)
- [ ] Upload `VulnScan.pptx` to Google Slides (second backup)
- [ ] Terminal ready: font ≥18pt, `cd vulnscan`, cache warmed
- [ ] Browser tab: `security_report.html` pre-rendered but not visible
- [ ] Offline fallback: `--cache-dir` flag ready in history
- [ ] One-liner laptop mirror test with the projector
- [ ] Rehearse once end-to-end with a timer. 8 min hard cap.
