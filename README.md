# 🔍 SlangHunter

**Automated Semantic Risk Detection for Trust & Safety Teams**

> From manual keyword filters to programmatic legal-risk scoring — detecting fraud-indicative slang in unstructured marketplace listings.

---

## 📋 Table of Contents

- [Problem Statement](#problem-statement)
- [Solution Overview](#solution-overview)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Problem Statement

Trust & Safety (T&S) teams in online marketplaces currently rely on:

1. **Human moderators** manually reviewing listings one by one.
2. **Basic keyword filters** that scammers easily evade by swapping characters, using emojis, or inventing new slang.

This reactive approach is **expensive**, **slow**, and **unable to scale** with the volume of fraudulent listings.

## Solution Overview

**SlangHunter** is a prototype microservice that:

- **Ingests** unstructured text data (marketplace listings, product descriptions).
- **Applies programmatic legal logic** — combining pattern-matching rules with contextual price analysis.
- **Emits a standardized risk verdict** classifying listings by fraud probability.

The goal is to shift from *"catch what you already know"* to *"detect what looks suspicious even if you've never seen it before"*.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Raw Listing    │────▶│   SlangHunter    │────▶│  Risk Verdict   │
│   (text + price) │     │   Engine (rules  │     │  (score + flags │
│                  │     │    + context)     │     │   + reasoning)  │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

## Getting Started

### Prerequisites

- Python 3.10+
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/slanghunter.git
cd slanghunter

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Quick Start

```python
from src.slanghunter import SlangHunter

hunter = SlangHunter()
verdict = hunter.analyze("Brand new iPhone 15 Pro Max - only $120! DM for details 📲")
print(verdict)
```

## Project Structure

```
slanghunter/
├── src/
│   ├── __init__.py            # Package initializer
│   └── slanghunter.py         # Core detection engine
├── tests/
│   ├── __init__.py            # Test package initializer
│   └── test_slanghunter.py    # Unit tests for the engine
├── .gitignore                 # Git ignore rules
├── README.md                  # This file
└── requirements.txt           # Python dependencies
```

## Roadmap

- [x] **Phase 1** — Project scaffolding & repository setup
- [ ] **Phase 2** — Core detection engine (rule-based + price context)
- [ ] **Phase 3** — Test suite & CI/CD pipeline
- [ ] **Phase 4** — REST API wrapper (Flask/FastAPI)
- [ ] **Phase 5** — Dashboard & reporting module

## Contributing

This project is currently in prototype phase. Contributions, ideas, and feedback are welcome.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <i>Built with 🧠 by a Legal Engineer who believes compliance can be automated.</i>
</p>
