# 🔍 SlangHunter

![Status](https://img.shields.io/badge/Status-Prototype-yellow)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Tests](https://img.shields.io/badge/Tests-90%20passed-brightgreen)
![PEP 8](https://img.shields.io/badge/PEP%208-0%20warnings-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

**Automated Semantic Risk Detection for Trust & Safety Teams**

> *From manual keyword blocklists to contextual legal-risk scoring — detecting fraud-indicative slang that basic filters miss.*

---

## 📋 Table of Contents

- [The Problem](#the-problem)
- [The Solution](#the-solution)
- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [The Knowledge Base](#the-knowledge-base)
- [Scoring System](#scoring-system)
- [Demo Output](#demo-output)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Legal Disclaimer](#legal-disclaimer)
- [License](#license)

---

## The Problem

Trust & Safety (T&S) teams at online marketplaces face a losing battle:

| Current Approach | Why It Fails |
|---|---|
| **Human moderators** review listings one by one | Doesn't scale — millions of new listings per day |
| **Basic keyword blocklists** (`"cocaine"`, `"gun"`) | Scammers evade them in seconds: `"c0ca!ne"`, `"🔫"` |
| **Regex filters** on exact patterns | Every new evasion requires a manual rule update |

The result: **fraudulent listings for drugs, counterfeit goods, and money laundering schemes hide in plain sight** using character substitution (`p3rcs`), emoji encoding (`🍃💨`), deliberate misspelling (`m0ney fl1p`), and contextual misdirection ("flour" listed at $100/gram).

## The Solution

**SlangHunter** is a prototype detection engine that goes beyond keyword matching:

```
                    ┌─────────────────────────────────────┐
   Plain keyword    │  "xanax" → blocked ✅               │
   filter           │  "x@n@x" → passes through ❌       │
                    │  "x 4 n 4 x" → passes through ❌   │
                    └─────────────────────────────────────┘

                    ┌─────────────────────────────────────┐
   SlangHunter      │  "xanax" → 🔴 CRITICAL ✅          │
   engine           │  "x@n@x" → 🔴 CRITICAL ✅          │
                    │  "x 4 n 4 x" → 🟡 WARNING ✅       │
                    │  + price context amplifies score    │
                    │  + legal statute citation included  │
                    └─────────────────────────────────────┘
```

### Key Differentiators

1. **Semantic Detection** — Compiled regex patterns catch character substitution, emoji encoding, and deliberate spacing (`p3rcs`, `m 0 l l y`, `ca$h app`, `🍃💨🔌`).

2. **Contextual Price Analysis** — Price is an *amplifier*, not a standalone signal. A bookshelf at $45 is fine; "kush" at $45 is suspicious. The engine requires textual evidence before price context can boost the score.

3. **Explainable Verdicts** — Every flag traces back to a specific U.S. federal statute. A compliance auditor can ask *"why did you flag this?"* and get a legal citation, not just a confidence number.

4. **Data ≠ Logic** — The knowledge base (crime categories, keywords, patterns, legal references) is a dictionary. The engine is the loop that reads it. If a law changes tomorrow, you update the dictionary — you never rewrite the motor.

## How It Works

```
Raw Listing ──▶ _normalize_text() ──▶ _scan_keywords() ──▶ _scan_patterns()
                                                                  │
                                                                  ▼
                                                     _check_price_context()
                                                                  │
                                                                  ▼
                                                      _calculate_score()
                                                                  │
                                                                  ▼
                                              ┌───────────────────────────────┐
                                              │  Verdict:                     │
                                              │   • risk_score (0.0 → 1.0)   │
                                              │   • flags[]                   │
                                              │   • reasoning (legal refs)    │
                                              │   • matched_categories[]      │
                                              └───────────────────────────────┘
```

## Quick Start

### Prerequisites

- **Python 3.10+** (uses `X | Y` union type syntax)
- **Git**

### Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/slanghunter.git
cd slanghunter

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate   # Linux/macOS
# venv\Scripts\activate    # Windows

# Install development dependencies
pip install -r requirements.txt
```

### Run the Demo

```bash
# Full Mercari feed simulation (4 cases, visual dashboard)
python demo.py

# Quick 8-case CLI demo
python -m src
```

### Run the Tests

```bash
pytest tests/ -v
```

## Usage Examples

### Basic Analysis

```python
from src.slanghunter import SlangHunter

hunter = SlangHunter()

# Analyze a suspicious listing
verdict = hunter.analyze(
    text="got them p3rcs 💊 real pharma hmu",
    price=30.00
)

print(verdict["risk_score"])          # 0.8
print(verdict["flags"])               # ['drugs:pat:p3rcs', 'drugs:price_context']
print(verdict["matched_categories"])  # ['drugs']
print(verdict["reasoning"])           # [DRUGS] ... Legal basis: 21 U.S.C. § 841
```

### Traffic-Light Report

```python
from src.slanghunter import SlangHunter

hunter = SlangHunter()

# Generate a human-readable report for ops / legal teams
report = hunter.generate_report(
    text="Jordan 1 Retro - 1:1 replica, comes in original box 🔥",
    price=65.00
)
print(report)
```

Output:
```
============================================================
  🔴  SLANGHUNTER VERDICT: CRITICAL
============================================================
  Listing : Jordan 1 Retro - 1:1 replica, comes in original box 🔥
  Price   : $65.00

  Risk Score : [██████████████████████████████] 100%
  Risk Level : 🔴  CRITICAL
  Action     : AUTOMATIC BLOCK — Escalate to Legal

  ┌─ FLAGS ────────────────────────────────────────────────
  │  ⚑  surikae:kw:1:1
  │  ⚑  surikae:kw:replica
  │  ⚑  surikae:kw:comes in original box
  │  ⚑  surikae:pat:1:1
  │  ⚑  surikae:pat:🔥
  │  ⚑  surikae:price_context
  └─────────────────────────────────────────────────────────

  ┌─ REASONING (Traceability) ─────────────────────────────
  │  [SURIKAE]
  │    Keywords matched: '1:1', 'replica', 'comes in original box'
  │    Slang patterns matched: '1:1', '🔥'
  │    Price falls within suspicious range.
  │    Legal basis: 18 U.S.C. § 2320 — Trafficking in Counterfeit Goods
  └─────────────────────────────────────────────────────────

  Categories : SURIKAE
============================================================
```

### Clean Listing (No False Positive)

```python
verdict = hunter.analyze(
    text="Vintage wooden bookshelf, great condition",
    price=45.00
)
print(verdict["risk_score"])  # 0.0  — price alone never triggers a flag
```

## Architecture

```
slanghunter/
│
├── demo.py                    # 🌟 Live Mercari feed simulation (python demo.py)
├── src/
│   ├── __init__.py            # Package metadata & exports
│   ├── __main__.py            # CLI demo entry point (python -m src)
│   └── slanghunter.py         # Core engine + RiskLevel enum
│         │
│         ├── SlangHunter           # Main class
│         │   ├── __init__()        # Builds risk_database
│         │   ├── _normalize_text() # Lowercase + whitespace cleanup
│         │   ├── _scan_keywords()  # Word-boundary keyword matching
│         │   ├── _scan_patterns()  # Compiled regex pattern scanning
│         │   ├── _check_price_context()  # Suspicious price range check
│         │   ├── _calculate_score()      # Cumulative weighted scoring
│         │   ├── _build_reasoning()      # Legal citation builder
│         │   ├── analyze()         # Main API → verdict dict
│         │   ├── classify_risk()   # Score → RiskLevel enum
│         │   ├── generate_report() # Full human-readable report
│         │   └── print_report()    # Print + return verdict
│         │
│         └── RiskLevel(Enum)       # 🔴 CRITICAL / 🟡 WARNING / 🟢 SAFE
│
├── tests/
│   ├── __init__.py
│   └── test_slanghunter.py    # 90 tests across 15 test classes
│
├── .gitignore
├── LICENSE                    # MIT License
├── README.md                  # This file
└── requirements.txt           # flake8 + pytest
```

## The Knowledge Base

Three crime categories, each with four dimensions:

| Category | Keywords | Regex Patterns | Price Threshold | Legal Basis |
|---|---|---|---|---|
| **Drugs** | 35 | 8 compiled patterns | $0 – $80 | [21 U.S.C. § 841](https://www.law.cornell.edu/uscode/text/21/841) |
| **Money Laundering** | 39 | 7 compiled patterns | $0 – $50 | [18 U.S.C. § 1956](https://www.law.cornell.edu/uscode/text/18/1956) |
| **Surikae** *(すり替え)* | 35 | 7 compiled patterns | $30 – $250 | [18 U.S.C. § 2320](https://www.law.cornell.edu/uscode/text/18/2320) |
| **Total** | **109** | **22** | — | — |

> **Surikae** (すり替え) is the Japanese term for "bait-and-switch" — selling counterfeit or misrepresented goods under the guise of authentic products.

### Why a Dictionary, Not Hardcoded Logic?

```python
# ❌ Fragile — logic and data are tangled
if "xanax" in text or "p3rc" in text:
    return "drugs"

# ✅ Maintainable — data drives the engine
self.risk_database = {
    "drugs": {
        "keywords": ["xanax", "percocet", ...],
        "slang_patterns": [re.compile(r"p[3e]rc[s0]?", re.IGNORECASE), ...],
        "risk_threshold": {"min": 0.0, "max": 80.0},
        "legal_reference": {"statute": "21 U.S.C. § 841", ...},
    }
}
```

If Mexico updates its money-laundering statute tomorrow, you change one string in the dictionary. The engine never knows and never cares.

## Scoring System

| Signal | Weight | Example |
|---|---|---|
| Each keyword match | **+0.15** | `"lean"` found → +0.15 |
| Each regex pattern match | **+0.25** | `"p3rcs"` via regex → +0.25 |
| Price in suspicious range | **+0.20** | $25 + text evidence → +0.20 |
| Combo bonus (text + price) | **+0.10** | Both present → extra +0.10 |

- Score is **clamped to [0.0, 1.0]**.
- Price is an **amplifier**, not a detector — a $45 bookshelf scores 0.0.
- Final score is the **max across all categories** (a listing is as risky as its most dangerous match).

### Risk Levels

| Level | Threshold | Emoji | Action |
|---|---|---|---|
| **CRITICAL** | Score > 80% | 🔴 | Automatic block → Escalate to Legal |
| **WARNING** | Score > 40% | 🟡 | Manual review → T&S analyst queue |
| **SAFE** | Score ≤ 40% | 🟢 | Approved → No action required |

## Demo Output

Run `python demo.py` to launch the full Mercari feed simulation:

```
╔══════════════════════════════════════════════════════════════╗
║          🏪  MERCARI LISTING FEED — LIVE SIMULATION           ║
║                Powered by SlangHunter v0.1.0                 ║
╚══════════════════════════════════════════════════════════════╝

  ⏳ Initializing SlangHunter engine... done.
  📚 Knowledge base loaded: 3 categories, 109 keywords, 22 patterns.
  📨 Incoming feed: 4 listings queued.
```

Four carefully designed cases cover 100 % of the business logic:

| # | Case | Listing ID | Verdict | Categories |
|---|---|---|---|---|
| 1 | Control — Legitimate product | MER-2026-00417 | 🟢 SAFE (0 %) | — |
| 2 | Slang — Drug trafficking | MER-2026-01893 | 🔴 CRITICAL (100 %) | DRUGS |
| 3 | Anomaly — Money laundering | MER-2026-03201 | 🔴 CRITICAL (100 %) | MONEY_LAUNDERING |
| 4 | Fraud — Surikae counterfeit | MER-2026-05742 | 🔴 CRITICAL (100 %) | SURIKAE |

Alternatively, run `python -m src` for a quick 8-case CLI demo.

## Roadmap

- [x] **Phase 1** — Project scaffolding & repository structure
- [x] **Phase 2** — Knowledge base architecture (`risk_database`)
- [x] **Phase 3** — Inference engine (normalize → scan → score → verdict)
- [x] **Phase 4** — Report interface & traffic-light system
- [x] **Phase 5** — Documentation, narrative & portfolio polish
- [x] **Phase 5.5** — Live simulation demo (`demo.py`) & repo update
- [ ] **Phase 6** — REST API wrapper (FastAPI + Pydantic models)
- [ ] **Phase 7** — Batch processing & CSV/JSON ingestion
- [ ] **Phase 8** — Dashboard & analytics module

## Contributing

This project is in **prototype phase**. Contributions, ideas, and feedback are welcome.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes using [Conventional Commits](https://www.conventionalcommits.org/)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Legal Disclaimer

> ⚠️ **This software is a prototype built for educational and demonstration purposes only.**
>
> SlangHunter is designed to showcase programmatic legal-risk analysis techniques and is **not intended for production deployment** without proper legal review, regulatory approval, and human oversight.
>
> The crime categories, keywords, and legal references included are **illustrative examples** drawn from publicly available U.S. federal statutes. They do not constitute legal advice. The author assumes no liability for decisions made based on this tool's output.
>
> If you're building something like this for real: **hire a lawyer, not just an engineer.** Better yet — hire a Legal Engineer who can do both. 😉

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>SlangHunter</b> — Built with 🧠 by a Legal Engineer who believes compliance can be automated.<br>
  <i>109 keywords · 22 regex patterns · 3 crime categories · 90 tests · 0 linter warnings</i>
</p>
