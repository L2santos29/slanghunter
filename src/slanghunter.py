"""
slanghunter.py — Core Detection Engine.

This module contains the main SlangHunter class responsible for
analyzing unstructured marketplace listings and emitting
standardized risk verdicts.

Architecture note:
    The knowledge base (risk_database) is DATA, not logic.
    If a law changes tomorrow, you update the dictionary —
    you never rewrite the engine. This is the separation
    between the "legal brain" and the "detection motor".

Author: Legal Engineer
Created: 2026-02-14
"""

import re


class SlangHunter:
    """
    Semantic risk detection engine for marketplace listings.

    Ingests raw listing text (and optional price context),
    applies rule-based detection logic, and returns a
    structured risk verdict.

    The engine is powered by ``self.risk_database``, a nested
    dictionary where each top-level key represents a crime
    category.  Every category carries:

    - **keywords**: plain-text terms that directly indicate risk.
    - **slang_patterns**: compiled regex patterns that catch
      evasion tactics (letter swaps, emoji encoding, spacing).
    - **risk_threshold**: a ``(min, max)`` price window; listings
      whose price falls inside are contextually suspicious.
    - **legal_reference**: the statute or regulation violated,
      so every flag is traceable to a legal basis.
    """

    # ------------------------------------------------------------------
    # Initialization — build the knowledge base
    # ------------------------------------------------------------------

    def __init__(self):
        """
        Initialize the SlangHunter engine.

        Constructs ``self.risk_database`` — the single source of
        truth for all detection rules.  Adding a new crime type
        is as simple as adding a new key to this dictionary.
        """
        self.risk_database: dict = self._build_risk_database()

    # ------------------------------------------------------------------
    # Knowledge Base Factory
    # ------------------------------------------------------------------

    @staticmethod
    def _build_risk_database() -> dict:
        """
        Build and return the complete risk knowledge base.

        Returns:
            A dictionary keyed by crime category, each containing
            keywords, slang_patterns, risk_threshold, and
            legal_reference.

        Design rationale:
            • ``keywords`` — exact lowercase tokens for fast lookup.
            • ``slang_patterns`` — pre-compiled ``re.Pattern``
              objects that catch character substitution, emoji
              encoding, and deliberate misspelling.
            • ``risk_threshold`` — a ``(min, max)`` tuple in USD.
              A listing whose price lands inside this window
              receives an additional contextual risk bump.
            • ``legal_reference`` — keeps every flag traceable
              to a specific statute.  Compliance teams can audit
              *why* the engine flagged something.
        """
        return {
            # ══════════════════════════════════════════════════
            # 1. DRUGS — Controlled substance trafficking
            # ══════════════════════════════════════════════════
            "drugs": {
                "keywords": [
                    # Opioids & synthetics
                    "fentanyl", "percocet", "oxy", "oxycontin",
                    "xanax", "lean", "codeine", "tramadol",
                    # Stimulants
                    "mdma", "molly", "ecstasy", "adderall",
                    "meth", "crystal", "ice", "speed", "crack",
                    # Cannabis (where illegal / marketplace-banned)
                    "kush", "edibles", "dab", "wax",
                    "cart", "carts", "thc",
                    # Psychedelics
                    "shrooms", "lsd", "acid", "dmt",
                    # Generic evasion terms
                    "plug", "pack", "gas", "za",
                    "script", "scripts", "beans",
                ],
                "slang_patterns": [
                    # "p3rc" / "p3rcs" — Percocet with number swap
                    re.compile(r"p[3e]rc[s0]?", re.IGNORECASE),
                    # "m0lly" / "m 0 l l y" — spaced / swapped
                    re.compile(
                        r"m[\s._]*[o0][\s._]*l[\s._]*l[\s._]*y",
                        re.IGNORECASE,
                    ),
                    # "x@n@x" / "x4n4x" — Xanax evasion
                    re.compile(
                        r"x[\s._]*[@a4][\s._]*n[\s._]*[@a4][\s._]*x",
                        re.IGNORECASE,
                    ),
                    # "f3nt" / "f3ntanyl" — Fentanyl evasion
                    re.compile(r"f[3e]nt(?:anyl)?", re.IGNORECASE),
                    # "4dd3r4ll" — Adderall with number swaps
                    re.compile(
                        r"[a4]dd[3e]r[a4]ll", re.IGNORECASE
                    ),
                    # Emoji-coded: 🍃💨🔌⛽🍄 (leaf, smoke, plug,
                    # gas pump, mushroom)
                    re.compile(
                        r"[\U0001F343\U0001F4A8\U0001F50C"
                        r"\u26FD\U0001F344]"
                    ),
                    # "$h r 0 0 m s" — shrooms with spacing/swaps
                    re.compile(
                        r"[s$][\s._]*h[\s._]*r[\s._]*[o0]"
                        r"[\s._]*[o0][\s._]*m[\s._]*[s$]?",
                        re.IGNORECASE,
                    ),
                    # "kr y s t a l" — crystal meth evasion
                    re.compile(
                        r"[ck][\s._]*r[\s._]*[yi1][\s._]*[s$]"
                        r"[\s._]*t[\s._]*[a@][\s._]*l",
                        re.IGNORECASE,
                    ),
                ],
                "risk_threshold": {
                    "min": 0.0,
                    "max": 80.0,
                    "description": (
                        "Street-level drug prices are typically "
                        "under $80.  A listing in this range that "
                        "also matches slang is highly suspicious."
                    ),
                },
                "legal_reference": {
                    "statute": "21 U.S.C. § 841",
                    "name": (
                        "Controlled Substances Act — "
                        "Prohibited Acts A"
                    ),
                    "summary": (
                        "Unlawful to manufacture, distribute, or "
                        "dispense a controlled substance."
                    ),
                },
            },

            # ══════════════════════════════════════════════════
            # 2. MONEY LAUNDERING — Structuring & value transfer
            # ══════════════════════════════════════════════════
            "money_laundering": {
                "keywords": [
                    # Financial instrument abuse
                    "cash app", "cashapp", "zelle", "venmo",
                    "western union", "moneygram",
                    "wire transfer", "wire",
                    # Crypto laundering
                    "btc", "bitcoin", "eth", "ethereum",
                    "usdt", "tether", "crypto",
                    "tumbler", "mixer",
                    # Gift card laundering
                    "gift card", "giftcard", "gc",
                    "itunes card", "steam card", "amazon card",
                    # Structuring / layering language
                    "flip", "double your money",
                    "money flip", "cash flip",
                    "loading", "load", "method",
                    "blank atm", "cloned card",
                    "fullz", "dumps", "cc dump",
                    # Invoice fraud
                    "invoice", "receipt generator",
                    "bank statement", "pay stub",
                ],
                "slang_patterns": [
                    # "ca$h app" / "ca$happ"
                    re.compile(
                        r"ca[$s]h[\s._]*app", re.IGNORECASE
                    ),
                    # "b1tc0in" / "b!tco!n"
                    re.compile(
                        r"b[i1!][\s._]*t[\s._]*c[\s._]*[o0]"
                        r"[\s._]*[i1!][\s._]*n",
                        re.IGNORECASE,
                    ),
                    # "m0ney fl1p" — money flip evasion
                    re.compile(
                        r"m[o0]n[e3]y[\s._]*fl[i1!]p",
                        re.IGNORECASE,
                    ),
                    # "g1ft c4rd" — gift card evasion
                    re.compile(
                        r"g[i1!]ft[\s._]*c[a4@]rd",
                        re.IGNORECASE,
                    ),
                    # "bl4nk 4tm" — blank ATM card
                    re.compile(
                        r"bl[a4@]nk[\s._]*[a4@]tm",
                        re.IGNORECASE,
                    ),
                    # 💸💰🏦 — money-related emojis in clusters
                    re.compile(
                        r"[\U0001F4B8\U0001F4B0\U0001F3E6]"
                    ),
                    # "cl0ned c4rd" / "clon3d card"
                    re.compile(
                        r"cl[o0]n[e3]d[\s._]*c[a4@]rd",
                        re.IGNORECASE,
                    ),
                ],
                "risk_threshold": {
                    "min": 0.0,
                    "max": 50.0,
                    "description": (
                        "Laundering listings are often priced "
                        "very low ($5-$50) because the 'product' "
                        "is a service (flipping, loading) or a "
                        "digital good (method, fullz)."
                    ),
                },
                "legal_reference": {
                    "statute": "18 U.S.C. § 1956",
                    "name": (
                        "Laundering of Monetary Instruments"
                    ),
                    "summary": (
                        "Knowingly conducting a financial "
                        "transaction involving proceeds of "
                        "unlawful activity."
                    ),
                },
            },

            # ══════════════════════════════════════════════════
            # 3. SURIKAE (すり替え) — Bait-and-switch / counterfeit
            # ══════════════════════════════════════════════════
            "surikae": {
                "keywords": [
                    # Counterfeit indicators
                    "replica", "rep", "reps",
                    "1:1", "aaa quality", "ua",
                    "mirror quality", "top quality copy",
                    "inspired by", "designer inspired",
                    # Bait-and-switch language
                    "not original", "class a", "class b",
                    "oem", "unbranded",
                    "like authentic", "same as original",
                    "high copy", "super copy",
                    # Specific product categories
                    "jordan 1", "yeezy", "airpod",
                    "louis vuitton", "gucci", "rolex",
                    "supreme", "off-white", "balenciaga",
                    # Coded delivery / discretion
                    "comes in original box",
                    "no tags", "without receipt",
                    "factory direct", "guangzhou",
                    "dm for pics", "dm for real pics",
                ],
                "slang_patterns": [
                    # "r3plica" / "r3p" — replica evasion
                    re.compile(
                        r"r[3e]pl[i1!]c[a@]", re.IGNORECASE
                    ),
                    # "1:1" with variations ("1 : 1", "1to1")
                    re.compile(
                        r"1[\s._:]*(?:to)?[\s._:]*1",
                        re.IGNORECASE,
                    ),
                    # "UA" as standalone (Unauthorized Authentic)
                    re.compile(r"\bua\b", re.IGNORECASE),
                    # Brand + "inspired" pattern
                    re.compile(
                        r"(?:gucc[i1!]|lou[i1!]s|rol[e3]x|"
                        r"suprem[e3]|bal[e3]nc[i1!]aga)"
                        r"[\s._]*(?:inspired|style|type|look)",
                        re.IGNORECASE,
                    ),
                    # "AAA" / "AA+" quality markers
                    re.compile(
                        r"\b[aA]{2,3}\+?\s*(?:quality|grade)",
                        re.IGNORECASE,
                    ),
                    # "0EM" / "0.E.M" — OEM evasion
                    re.compile(
                        r"[o0][\s._]*[e3][\s._]*m",
                        re.IGNORECASE,
                    ),
                    # 🔥👟👜⌚ — product emojis often used in
                    # counterfeit sneaker/bag/watch listings
                    re.compile(
                        r"[\U0001F525\U0001F45F"
                        r"\U0001F45C\u231A]"
                    ),
                ],
                "risk_threshold": {
                    "min": 30.0,
                    "max": 250.0,
                    "description": (
                        "Counterfeits are priced high enough to "
                        "seem 'real' but far below retail.  A "
                        "'Rolex' at $150 or 'Jordans' at $45 "
                        "are classic surikae price points."
                    ),
                },
                "legal_reference": {
                    "statute": "18 U.S.C. § 2320",
                    "name": (
                        "Trafficking in Counterfeit Goods "
                        "or Services"
                    ),
                    "summary": (
                        "Intentionally trafficking in goods "
                        "or services using a counterfeit mark."
                    ),
                },
            },
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_categories(self) -> list[str]:
        """
        Return the list of crime categories in the knowledge base.

        Returns:
            A sorted list of category keys (e.g. ['drugs',
            'money_laundering', 'surikae']).
        """
        return sorted(self.risk_database.keys())

    def get_category_info(self, category: str) -> dict | None:
        """
        Return metadata for a specific crime category.

        Args:
            category: The crime category key.

        Returns:
            A dictionary with keyword_count, pattern_count,
            risk_threshold, and legal_reference — or None if
            the category does not exist.
        """
        entry = self.risk_database.get(category)
        if entry is None:
            return None
        return {
            "keyword_count": len(entry["keywords"]),
            "pattern_count": len(entry["slang_patterns"]),
            "risk_threshold": entry["risk_threshold"],
            "legal_reference": entry["legal_reference"],
        }

    def analyze(self, text: str, price: float | None = None) -> dict:
        """
        Analyze a marketplace listing for fraud indicators.

        Args:
            text: The raw listing text to analyze.
            price: Optional listed price for contextual analysis.

        Returns:
            A dictionary containing the risk verdict with keys:
                - risk_score (float): 0.0 (safe) to 1.0 (high risk).
                - flags (list[str]): Detected risk indicators.
                - reasoning (str): Human-readable explanation.
        """
        # TODO: Wire up detection logic in Phase 3
        return {
            "risk_score": 0.0,
            "flags": [],
            "reasoning": "No analysis rules loaded yet.",
        }
