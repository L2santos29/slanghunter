# Contributing to SlangHunter

Thank you for your interest in SlangHunter. This document describes the development workflow, coding standards, and guidelines for extending the knowledge base.

> **Note:** SlangHunter is a professional portfolio demonstration project. While feedback, bug reports, and discussion are warmly welcome via the [issue tracker](https://github.com/L2santos29/slanghunter/issues), the project is maintained for **non-commercial and educational demonstration purposes only**. Please review the [LICENSE](LICENSE) before contributing.

---

## 📋 Table of Contents

- [Development Setup](#-development-setup)
- [Running Tests](#-running-tests)
- [Code Style](#-code-style)
- [Adding Knowledge Base Patterns](#-adding-knowledge-base-patterns)
- [Pull Request Checklist](#-pull-request-checklist)
- [License](#-license)

---

## 🛠️ Development Setup

```bash
# 1. Fork and clone the repository
git clone https://github.com/L2santos29/slanghunter.git
cd slanghunter

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows

# 3. Install the package with all development dependencies
pip install -e ".[dev]"

# 4. Verify the installation
pytest
```

For exact reproducibility (strongly recommended for CI and collaborative environments), use the pinned lock file instead of the floating `[dev]` extra:

```bash
pip install -r requirements-dev.lock -e .
```

---

## ✅ Running Tests

The full test suite consists of **133 tests** across 23 test classes and enforces a minimum coverage gate of **80%** (CI enforces ≥ 90%).

```bash
# Run all tests
pytest

# Run with coverage report printed to terminal
pytest --cov=src --cov=api --cov-report=term-missing

# Run a specific test class
pytest tests/test_slanghunter.py::TestInputValidation -v

# Run only tests matching a keyword
pytest -k "drug" -v
```

A pull request that causes the coverage to drop below 80% will fail the CI gate. Any new feature or bug fix **must** be accompanied by tests that cover the changed behavior.

---

## 🎨 Code Style

### Linting — `flake8`

All source files must pass `flake8` with zero warnings. The project configuration is in [`.flake8`](.flake8):

- `max-line-length = 100`
- Ignores: `E203`, `W503` (Black-compatible exceptions)

```bash
flake8 src/ api/ tests/ demo.py
```

### Type Checking — `mypy`

All new code in `src/` and `api/` must pass `mypy` in strict mode. Forward references must use `TYPE_CHECKING` guards where cyclic imports would result.

```bash
mypy src/ --ignore-missing-imports
mypy api/ --ignore-missing-imports
```

### General Conventions

- Follow [PEP 8](https://peps.python.org/pep-0008/) for naming and layout.
- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages (e.g. `fix: correct word-boundary regex for multi-word keywords`).
- Annotate all function signatures with type hints.
- Docstrings follow Google style (`Args:`, `Returns:`, `Raises:`).

---

## 📖 Adding Knowledge Base Patterns

The knowledge base is externalized to [`data/`](data/). Each JSON file represents one crime category. Refer to [`data/README.md`](data/README.md) for the full schema reference.

To add new keywords or regex patterns to an existing category, edit the corresponding file (e.g. [`data/drugs.json`](data/drugs.json)) and reload the engine:

```python
hunter.reload_from_data_dir()   # hot-reload without restarting
```

### ⚠️ ReDoS Security Warning — Read Before Writing Any Regex

> **All new regex patterns must be linear-complexity. Catastrophic backtracking is a security vulnerability.**

Regex patterns with **nested quantifiers** (e.g. `(a+)+`, `(\w+\s*)+`) can exhibit exponential backtracking on adversarially crafted inputs — a class of denial-of-service attack known as **ReDoS (Regular Expression Denial of Service)**. Because SlangHunter processes untrusted marketplace listing text, every pattern in the knowledge base is a potential attack surface.

**Prohibited patterns — do NOT use:**

```python
# ❌ Nested quantifiers — catastrophic backtracking
re.compile(r"(p[3e]r[c]s?)+")        # repeated group with internal quantifier
re.compile(r"(\w+\s*)+end")           # exponential worst-case on long non-matching input
re.compile(r"(a|aa)+b")              # ambiguous alternation inside repetition

# ❌ Backtracking-heavy alternation in unbounded context
re.compile(r"(drug|drugs|dr.gs)+")   # alternation with repetition
```

**Required pattern style — linear complexity only:**

```python
# ✅ Fixed-width substitution groups — O(n) guaranteed
re.compile(r"p[3e]rc[s0]?", re.IGNORECASE)

# ✅ Anchored word boundaries — prevent partial-match explosion
re.compile(r"\bxan[a4@]x\b", re.IGNORECASE)

# ✅ Simple character-class substitution — no nesting
re.compile(r"m[o0][l1][l1]y", re.IGNORECASE)
```

**Before submitting any new regex pattern, verify it against a backtracking analyzer** such as [regex101.com](https://regex101.com) (check the "Match Information" panel for step count on a long non-matching input) or [vuln-regex-detector](https://github.com/nicowillis/vuln-regex-detector).

---

## 📝 Pull Request Checklist

Before opening a pull request, confirm all of the following:

- [ ] Tests pass: `pytest` exits with code `0`
- [ ] Linting is clean: `flake8 src/ api/ tests/ demo.py` produces zero warnings
- [ ] Type checking passes: `mypy src/ --ignore-missing-imports` produces zero errors
- [ ] New patterns are **linear-complexity** — no nested quantifiers, no catastrophic backtracking
- [ ] `CHANGELOG.md` has been updated under `[Unreleased]` with a concise description of the change
- [ ] New public methods include docstrings with `Args:` and `Returns:` sections
- [ ] No new runtime dependencies have been introduced without discussion (the core engine is intentionally dependency-free)

---

## 📄 License

By submitting a contribution, you agree that your changes will be licensed under the same **PolyForm NonCommercial 1.0.0** terms that cover this project. See the [`LICENSE`](LICENSE) file for the full text.
