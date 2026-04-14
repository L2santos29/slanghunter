# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.2.0] — 2026-04-13

> This release delivers 22 discrete improvements across bug fixes, new features, security hardening, and DevOps infrastructure.
> Items are organized by their original category assignments.

### Added

- **D-01** — `pyproject.toml` at project root: build system (`hatchling`), PEP 621 project metadata, optional dependency groups (`dev`, `api`, `all`), CLI entry point (`slanghunter-demo`), `[tool.pytest.ini_options]`, `[tool.mypy]`, and `[tool.hatch.build.targets.wheel]` configuration.
- **D-05** — `CHANGELOG.md` at project root following Keep a Changelog v1.0.0 format.
- **D-02** — GitHub Actions CI workflow (`.github/workflows/ci.yml`): matrix test across Python 3.10/3.11/3.12, `mypy` strict type-checking gate, `flake8` linting gate, `pytest-cov` coverage gate enforcing ≥ 90%.
- **D-03** — `.flake8` configuration file at project root with `max-line-length = 100` and Black-compatible ignore rules (`E203`, `W503`).
- **C-01** — `pytest-cov>=4.0` added to development dependencies; coverage gate (`--cov-fail-under=90`) enforced in CI.
- **C-02** — `mypy>=1.5` added to development dependencies; strict mode configured in `pyproject.toml`.
- **C-03** — `TestCriticalPatternIsolation` test class in `tests/test_slanghunter.py`: parametrized isolation tests for `adderall`, `crystal meth`, and `cloned card` patterns including canonical forms and evasion variants (character substitution, deliberate spacing).
- **C-04** — Direct unit tests for `SlangHunter._build_reasoning()` with controlled `matches` and `flags` inputs, asserting exact reasoning string content and legal citation format.
- **C-05** — `tests/test_demo.py`: unit tests for `demo.py` public phase functions (`phase_input()`, `phase_processing()`, `phase_verdict()`) using `unittest.mock.patch` to intercept `time.sleep` and capture `sys.stdout`.
- **C-06** — `TestCLIEntryPoint` test class: validates `python -m src` exits with code `0` and emits non-empty output.
- **C-07** — Emoji pattern isolation tests: dedicated parametrized tests for emoji-encoded drug and counterfeit signals (`🍃`, `💨`, `🔌`, `💊`).
- **B-01** — `data/` directory with per-category YAML rule files (`data/drugs.yaml`, `data/counterfeit.yaml`, `data/financial_crime.yaml`); `SlangHunter.__init__()` gains a `data_path` argument for operator override; knowledge base validated against a `dataclasses`-based schema at instantiation.
- **F-01** — FastAPI REST API wrapper (`src/api/`): `POST /analyze` and `POST /report` endpoints with Pydantic v2 request/response models; async handler; OpenAPI schema auto-generated.
- **F-02** — `Dockerfile` and `docker-compose.yml` for containerized API deployment; production-grade `uvicorn` startup with configurable concurrency.

### Changed

- **B-02** — `RiskLevel` enum moved to top of `src/slanghunter.py` (above `SlangHunter`); all `-> "RiskLevel"` forward-reference annotations replaced with direct `-> RiskLevel`.
- **B-03** — `demo.py` import changed from `from src.slanghunter import SlangHunter` to `from src import SlangHunter` to route through the public package API defined in `src/__init__.py`.
- **B-04** — `__version__` in `src/__init__.py` replaced with `importlib.metadata.version("slanghunter")` (with `PackageNotFoundError` fallback for editable-install environments); `pyproject.toml` is now the single source of truth for the version string.
- **D-04** — `README.md`: all `<your-username>` placeholder occurrences replaced with `L2santos29`; `requirements.txt` updated with `pytest-cov>=4.0` and `mypy>=1.5`.
- **A-02** — `CRITICAL_THRESHOLD` and `WARNING_THRESHOLD` promoted to class-level attributes on `SlangHunter` (`0.80` and `0.40` respectively); `classify_risk()` now references `self.CRITICAL_THRESHOLD` / `self.WARNING_THRESHOLD` instead of inline literals, making thresholds genuinely configurable via subclassing.

### Fixed

- **A-01** — `print_report()` called `analyze()` twice — once to print the report and once to populate the return value. Refactored to a single `analyze()` call whose result is passed to both `generate_report()` (side-effect) and the caller (return value). Eliminates redundant CPU cost and latent consistency hazard.
- **A-03** — Multi-word keyword matching used plain substring (`kw in normalized`), producing false positives for terms like `"western union"` matching inside `"northwestern unionized workers"`. Fixed by compiling `r'\b' + re.escape(kw) + r'\b'` for each keyword at database build-time and replacing substring checks with `pattern.search()` at scan time.
- **A-04** — `analyze()` had no input validation: passing `None` raised an opaque `AttributeError` deep in the normalization pipeline; unconstrained large strings posed a Denial-of-Service vector. Added a validation block: `TypeError` for non-`str` input, `ValueError` for strings exceeding `MAX_INPUT_LENGTH` (class attribute, default `10_000`), and `ValueError` for negative or non-numeric `price`.

---

## [0.1.0] — 2025-01-01

Initial prototype release of the SlangHunter Trust & Safety engine.

### Added

- **Core engine** (`src/slanghunter.py`, 853 lines): multi-stage analysis pipeline — `_normalize_text()` → `_scan_keywords()` → `_scan_patterns()` → `_check_price_context()` → `_calculate_score()` → `_build_reasoning()` → `analyze()`.
- **Knowledge base** covering three crime categories embedded in `_build_risk_database()`:
  - **Drugs** — 35 keywords, 8 compiled regex patterns, price range `$0–$80`, legal basis: 21 U.S.C. § 841.
  - **Money Laundering** — 39 keywords, 7 compiled regex patterns, price range `$0–$50`, legal basis: 18 U.S.C. § 1956.
  - **Surikae** (counterfeit goods / bait-and-switch) — 35 keywords, 7 compiled regex patterns, price range `$30–$250`, legal basis: 18 U.S.C. § 2320.
  - **Total**: 109 keywords, 22 regex patterns across all categories.
- **Traffic-light risk scoring**: weighted signal accumulation (keyword hit +0.15, pattern hit +0.25, price context +0.20, combo bonus +0.10); score clamped to `[0.0, 1.0]`; final score is max across all category scores.
- **`RiskLevel` enum** with three levels: `CRITICAL` (> 80%), `WARNING` (> 40%), `SAFE` (≤ 40%); each level carries embedded emoji, label, and recommended action string.
- **`generate_report()`** method: ASCII traffic-light report with flags panel, reasoning panel, and legal citation traceability.
- **`print_report()`** method: convenience wrapper that prints the report and returns the verdict dict.
- **`src/__init__.py`**: package metadata (`__version__ = "0.1.0"`) and public re-exports (`SlangHunter`, `RiskLevel`).
- **`src/__main__.py`**: 8-case CLI demo covering all three crime categories, evasion tactics, and clean-listing control cases.
- **`demo.py`**: full three-phase Mercari feed simulation with animated processing pipeline and dashboard summary.
- **Test suite** (`tests/test_slanghunter.py`): 90 tests across 15 test classes covering primary happy paths, evasion pattern detection, price context logic, and edge cases.
- **`requirements.txt`**: development dependencies (`flake8>=6.1.0`, `pytest>=7.4.0`).
- **`README.md`**: full project documentation including architecture diagram, knowledge base table, scoring reference, demo output, and roadmap.
- **`LICENSE`**: PolyForm NonCommercial 1.0.0.
- **`.gitignore`**: standard Python ignore rules.

---

[Unreleased]: https://github.com/L2santos29/slanghunter/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/L2santos29/slanghunter/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/L2santos29/slanghunter/releases/tag/v0.1.0
