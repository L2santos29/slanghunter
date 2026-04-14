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

import json
import re
import warnings
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from .ml import ScoreAugmentor


class RiskLevel(Enum):
    """
    Traffic-light risk classification.

    Each member carries three presentation attributes:
        - emoji:  visual indicator for console / Slack / email.
        - label:  human-readable severity name.
        - action: recommended operational response.
    """

    CRITICAL = ("🔴", "CRITICAL", "AUTOMATIC BLOCK — Escalate to Legal")
    WARNING = ("🟡", "WARNING", "MANUAL REVIEW — Flag for T&S analyst")
    SAFE = ("🟢", "SAFE", "APPROVED — No action required")

    def __init__(self, emoji: str, label: str, action: str) -> None:
        """Store the display attributes for this risk level.

        Args:
            emoji: Visual indicator (🔴, 🟡, or 🟢).
            label: Human-readable severity label.
            action: Recommended operational response.
        """
        self.emoji = emoji
        self.label = label
        self.action = action


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

    # Classification thresholds promoted to class attributes so
    # operators can tune severity without rewriting method logic.
    THRESHOLD_CRITICAL: ClassVar[float] = 0.80
    THRESHOLD_WARNING: ClassVar[float] = 0.40
    MAX_TEXT_LENGTH: ClassVar[int] = 10_000

    def __init__(self) -> None:
        """
        Initialize the SlangHunter engine.

        Constructs ``self.risk_database`` — the single source of
        truth for all detection rules.  Adding a new crime type
        is as simple as adding a new key to this dictionary.
        """
        self.risk_database: dict[str, dict[str, Any]] = (
            self._build_risk_database()
        )

    @staticmethod
    def _default_data_dir() -> Path:
        """Return the conventional project-level JSON data directory."""
        return Path(__file__).parent.parent / "data"

    @classmethod
    def _load_risk_database(
        cls,
        data_dir: Path | str | None = None,
        *,
        require_exists: bool = False,
    ) -> dict[str, dict[str, Any]]:
        """Load the knowledge base from JSON files or built-in fallback."""
        resolved_data_dir = (
            cls._default_data_dir()
            if data_dir is None
            else Path(data_dir)
        )

        if not resolved_data_dir.exists() or not resolved_data_dir.is_dir():
            if require_exists:
                raise FileNotFoundError(
                    f"data directory not found: {resolved_data_dir}"
                )
            warnings.warn(
                (
                    "JSON knowledge base directory not found; falling back "
                    "to built-in risk database"
                ),
                RuntimeWarning,
                stacklevel=2,
            )
            return cls._build_risk_database()

        json_files = sorted(resolved_data_dir.glob("*.json"))
        if not json_files:
            warnings.warn(
                (
                    "No JSON knowledge base files found; falling back "
                    "to built-in risk database"
                ),
                RuntimeWarning,
                stacklevel=2,
            )
            return cls._build_risk_database()

        loaded_database: dict[str, dict[str, Any]] = {}
        for json_file in json_files:
            with json_file.open("r", encoding="utf-8") as file_obj:
                category_data = json.load(file_obj)

            # Compile regexes at load time so the on-disk format stays
            # JSON-serializable and safe to edit without Python code.
            category_data["slang_patterns"] = [
                re.compile(pattern, re.IGNORECASE)
                for pattern in category_data["slang_patterns"]
            ]
            loaded_database[json_file.stem] = category_data

        return loaded_database

    @classmethod
    def from_data_dir(
        cls, data_dir: Path | str | None = None
    ) -> "SlangHunter":
        """Create an instance backed by JSON data files when available.

        If ``data_dir`` is ``None``, defaults to the project-level
        ``data/`` directory. Missing or empty directories fall back to
        the built-in hardcoded knowledge base with a warning.
        """
        hunter = cls()
        # Reuse normal construction first, then replace the database so
        # fallback behavior stays identical to the default engine path.
        hunter.risk_database = cls._load_risk_database(data_dir)
        return hunter

    def reload_from_data_dir(
        self, data_dir: Path | str | None = None
    ) -> None:
        """Reload the knowledge base from JSON without recreating self.

        If ``data_dir`` is ``None``, the default project-level ``data/``
        directory is used. Explicitly missing directories raise
        ``FileNotFoundError`` so operators can distinguish bad paths from
        fallback behavior.
        """
        reloaded_database = type(self)._load_risk_database(
            data_dir,
            require_exists=data_dir is not None,
        )
        # Replace the full mapping at once so callers never observe a
        # partially reloaded knowledge base.
        self.risk_database = reloaded_database

    # ------------------------------------------------------------------
    # Knowledge Base Factory
    # ------------------------------------------------------------------

    @staticmethod
    def _build_risk_database() -> dict[str, dict[str, Any]]:
        """
        Build and return the complete built-in fallback knowledge base.

        For production deployments, prefer
        ``SlangHunter.from_data_dir()`` so operators can update JSON
        rule files without modifying Python source.

        Returns:
            A dictionary keyed by crime category, each containing
            keywords, slang_patterns, risk_threshold, and
            legal_reference.

        SECURITY NOTE:
            The knowledge base is stored unencrypted in-process memory.
            For adversarial deployments where sellers may attempt to
            reverse-engineer detection patterns, consider fetching the
            knowledge base from a secured remote source at runtime.

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
                # SECURITY: All patterns must be linear-complexity.
                # Nested quantifiers are forbidden to prevent ReDoS.
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
                "jp_legal_reference": {
                    "statute": "薬機法 Art. 84",
                    "name": (
                        "Act on Securing Quality, Efficacy and Safety "
                        "of Pharmaceuticals"
                    ),
                    "summary": (
                        "Prohibits illicit manufacture, sale, and "
                        "distribution of narcotics and stimulants in "
                        "Japan."
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
                # SECURITY: All patterns must be linear-complexity.
                # Nested quantifiers are forbidden to prevent ReDoS.
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
                "jp_legal_reference": {
                    "statute": "組織犯罪処罰法 Art. 10",
                    "name": "Act on Punishment of Organized Crimes",
                    "summary": (
                        "Criminalizes concealment of criminal proceeds "
                        "(money laundering) in Japan."
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
                # SECURITY: All patterns must be linear-complexity.
                # Nested quantifiers are forbidden to prevent ReDoS.
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
                "jp_legal_reference": {
                    "statute": "不正競争防止法 Art. 2",
                    "name": "Unfair Competition Prevention Act",
                    "summary": (
                        "Prohibits use of well-known trade marks and "
                        "sale of counterfeit goods in Japan."
                    ),
                },
            },
        }

    # ------------------------------------------------------------------
    # Scoring weights — tune these to adjust sensitivity
    # ------------------------------------------------------------------

    # Points awarded per detection type (raw, before clamping).
    WEIGHT_KEYWORD: float = 0.15
    WEIGHT_PATTERN: float = 0.25
    WEIGHT_PRICE_CONTEXT: float = 0.20
    # Bonus when BOTH text hits AND price context align.
    WEIGHT_COMBO_BONUS: float = 0.10
    # Maximum raw score is clamped to 1.0.

    # ------------------------------------------------------------------
    # Text Normalization — "80 % of NLP is cleaning"
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_text(text: str) -> str:
        """
        Clean and normalize raw listing text for analysis.

        Steps:
            1. Lowercase the entire string.
            2. Collapse multiple whitespace into single spaces.
            3. Strip leading / trailing whitespace.

        We intentionally do NOT strip special characters or
        emojis because our regex patterns depend on them
        (e.g. ``$``, ``@``, ``🍃``).

        Args:
            text: The raw listing text.

        Returns:
            A cleaned, lowercased string ready for scanning.
        """
        text = text.lower()
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    # ------------------------------------------------------------------
    # Scanning primitives — one concern per method
    # ------------------------------------------------------------------

    @staticmethod
    def _scan_keywords(normalized: str, keywords: list[str]) -> list[str]:
        """
        Scan normalized text for exact keyword matches.

        Both single-word and multi-word keywords use word-boundary
        checks so phrases like ``western union`` do not falsely
        match inside larger words such as ``northwestern``.

        Args:
            normalized: The already-normalized text.
            keywords: List of lowercase keyword strings.

        Returns:
            A list of matched keyword strings (may be empty).
        """
        found: list[str] = []
        for kw in keywords:
            # Boundary anchoring prevents phrase-level false
            # positives inside longer tokens.
            if " " in kw:
                if re.search(rf"\b{re.escape(kw)}\b", normalized):
                    found.append(kw)
            else:
                if re.search(rf"\b{re.escape(kw)}\b", normalized):
                    found.append(kw)
        return found

    @staticmethod
    def _scan_patterns(
        text: str, patterns: list[re.Pattern[str]]
    ) -> list[str]:
        """
        Scan text against a list of compiled regex patterns.

        We run against the *original* (non-lowered) text for
        patterns that match emojis or case-sensitive markers,
        AND against the normalized text for everything else.
        Each pattern object already carries its own flags.

        Args:
            text: The raw (or normalized) text to scan.
            patterns: Compiled ``re.Pattern`` objects.

        Returns:
            A list of matched pattern descriptions (the
            ``.pattern`` attribute of each ``re.Pattern``).
        """
        hits: list[str] = []
        for pat in patterns:
            match = pat.search(text)
            if match:
                hits.append(match.group())
        return hits

    @staticmethod
    def _check_price_context(
        price: float | None,
        threshold: dict[str, Any],
    ) -> bool:
        """
        Determine if a listing price falls inside the suspicious
        price window for a given crime category.

        Args:
            price: The listing price (None if unknown).
            threshold: The ``risk_threshold`` dict with keys
                ``min`` and ``max``.

        Returns:
            True if the price is within the suspicious range.
            False if price is None or outside the range.
        """
        if price is None:
            return False
        return threshold["min"] <= price <= threshold["max"]

    # ------------------------------------------------------------------
    # Scoring — cumulative, not binary
    # ------------------------------------------------------------------

    def _calculate_score(
        self,
        keyword_hits: list[str],
        pattern_hits: list[str],
        price_match: bool,
    ) -> float:
        """
        Compute a cumulative risk score from 0.0 to 1.0.

        Scoring formula:
            score  = (unique_kw_count × WEIGHT_KEYWORD)
                   + (unique_pat_count × WEIGHT_PATTERN)
                   + (WEIGHT_PRICE_CONTEXT if price_match)
                   + (WEIGHT_COMBO_BONUS if text_hit AND price_match)

        The result is clamped to [0.0, 1.0].

        Args:
            keyword_hits: Keywords found in the text.
            pattern_hits: Regex pattern matches found.
            price_match: Whether the price is in the danger zone.

        Returns:
            A float between 0.0 (clean) and 1.0 (maximum risk).
        """
        score = 0.0

        # Each unique keyword contributes its weight.
        score += len(keyword_hits) * self.WEIGHT_KEYWORD
        # Each unique pattern match contributes its weight.
        score += len(pattern_hits) * self.WEIGHT_PATTERN

        has_text_evidence = len(keyword_hits) + len(pattern_hits) > 0

        # Price context is an AMPLIFIER, not a standalone signal.
        # A $45 bookshelf should NOT be flagged just because the
        # price is in a suspicious range.  Price only matters
        # when there is already textual evidence.
        if price_match and has_text_evidence:
            score += self.WEIGHT_PRICE_CONTEXT
            # Combo bonus: text + price together is more damning.
            score += self.WEIGHT_COMBO_BONUS

        # Clamp to [0.0, 1.0].
        return min(max(score, 0.0), 1.0)

    # ------------------------------------------------------------------
    # Verdict builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_reasoning(
        category: str,
        keyword_hits: list[str],
        pattern_hits: list[str],
        price_match: bool,
        legal_ref: dict[str, Any],
    ) -> str:
        """
        Generate a human-readable explanation for a single
        category's findings.

        Args:
            category: Crime category name.
            keyword_hits: Matched keywords.
            pattern_hits: Matched pattern strings.
            price_match: Whether the price triggered context.
            legal_ref: The legal_reference dict.

        Returns:
            A multi-line string summarizing the findings.
        """
        lines: list[str] = []
        lines.append(f"[{category.upper()}]")

        if keyword_hits:
            kw_str = ", ".join(f"'{k}'" for k in keyword_hits)
            lines.append(f"  Keywords matched: {kw_str}")

        if pattern_hits:
            pat_str = ", ".join(f"'{p}'" for p in pattern_hits)
            lines.append(f"  Slang patterns matched: {pat_str}")

        if price_match:
            lines.append("  Price falls within suspicious range.")

        if keyword_hits or pattern_hits:
            lines.append(
                f"  Legal basis: {legal_ref['statute']} "
                f"— {legal_ref['name']}"
            )

        return "\n".join(lines)

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

    def get_category_info(self, category: str) -> dict[str, Any] | None:
        """
        Return metadata for a specific crime category.

        Args:
            category: The crime category key.

        Returns:
            A dictionary with keyword_count, pattern_count,
            risk_threshold, legal_reference, and
            jp_legal_reference — or None if the category does
            not exist.
        """
        entry = self.risk_database.get(category)
        if entry is None:
            return None
        return {
            "keyword_count": len(entry["keywords"]),
            "pattern_count": len(entry["slang_patterns"]),
            "risk_threshold": entry["risk_threshold"],
            "legal_reference": entry["legal_reference"],
            "jp_legal_reference": entry["jp_legal_reference"],
        }

    def analyze(
        self,
        text: str,
        price: float | None = None,
    ) -> dict[str, Any]:
        """
        Analyze a marketplace listing for fraud indicators.

        This is the main entry point.  It normalizes the input,
        scans against every crime category in the knowledge base,
        accumulates a risk score, and returns a structured verdict.

        Args:
            text: The raw listing text to analyze.
            price: Optional listed price (USD) for contextual
                analysis.

        Returns:
            A dictionary containing:
                - risk_score (float): 0.0 (safe) → 1.0 (critical).
                - flags (list[str]): Each flag is
                  ``"category:indicator"`` for downstream filtering.
                - reasoning (str): Human-readable explanation with
                  legal references.
                - matched_categories (list[str]): Which crime
                  categories were triggered.

        Raises:
            TypeError: If ``text`` is not a ``str`` or if ``price``
                is neither numeric nor ``None``.
            ValueError: If ``text`` exceeds
                ``self.MAX_TEXT_LENGTH`` characters or if ``price``
                is negative.
        """
        # Fail fast at the public API boundary so downstream helper
        # methods can rely on stable, validated inputs.
        if not isinstance(text, str):
            raise TypeError(
                f"text must be a str, got {type(text).__name__}"
            )
        if len(text) > self.MAX_TEXT_LENGTH:
            raise ValueError(
                "text exceeds maximum allowed length of "
                f"{self.MAX_TEXT_LENGTH} characters"
            )
        if price is not None and not isinstance(price, (int, float)):
            raise TypeError(
                "price must be a numeric value or None, got "
                f"{type(price).__name__}"
            )
        if price is not None and price < 0:
            raise ValueError("price must be a non-negative numeric value")

        normalized = self._normalize_text(text)

        all_flags: list[str] = []
        all_reasoning: list[str] = []
        matched_categories: list[str] = []
        total_score: float = 0.0

        for cat_name, cat_data in self.risk_database.items():
            # --- 1. Keyword scan (on normalized text) ---
            kw_hits = self._scan_keywords(
                normalized, cat_data["keywords"]
            )

            # --- 2. Pattern scan (on raw + normalized) ---
            # Run on both raw text (for emoji / case patterns)
            # and normalized text (for lowered patterns).
            pat_hits_raw = self._scan_patterns(
                text, cat_data["slang_patterns"]
            )
            pat_hits_norm = self._scan_patterns(
                normalized, cat_data["slang_patterns"]
            )
            # Deduplicate while preserving order.
            seen: set[str] = set()
            pat_hits: list[str] = []
            for hit in pat_hits_raw + pat_hits_norm:
                if hit not in seen:
                    seen.add(hit)
                    pat_hits.append(hit)

            # --- 3. Price context check ---
            price_match = self._check_price_context(
                price, cat_data["risk_threshold"]
            )

            # --- 4. Score this category ---
            cat_score = self._calculate_score(
                kw_hits, pat_hits, price_match
            )

            # --- 5. Accumulate results ---
            # A category is only "matched" if there is text
            # evidence.  Price context alone is never enough
            # to flag a listing — it only amplifies text hits.
            if kw_hits or pat_hits:
                matched_categories.append(cat_name)

                # Build flags as "category:indicator".
                for kw in kw_hits:
                    all_flags.append(f"{cat_name}:kw:{kw}")
                for pat in pat_hits:
                    all_flags.append(f"{cat_name}:pat:{pat}")
                if price_match and (kw_hits or pat_hits):
                    all_flags.append(f"{cat_name}:price_context")

                # Build reasoning block.
                reasoning = self._build_reasoning(
                    cat_name, kw_hits, pat_hits, price_match,
                    cat_data["legal_reference"],
                )
                all_reasoning.append(reasoning)

            # Take the max score across categories — a listing
            # is as risky as its most dangerous category.
            total_score = max(total_score, cat_score)

        # --- Final verdict ---
        if not all_flags:
            reasoning_text = "No risk indicators detected."
        else:
            reasoning_text = "\n".join(all_reasoning)

        return {
            "risk_score": round(total_score, 2),
            "flags": all_flags,
            "reasoning": reasoning_text,
            "matched_categories": matched_categories,
        }

    def analyze_enhanced(
        self,
        text: str,
        price: float | None = None,
        augmentor: "ScoreAugmentor | None" = None,
    ) -> dict[str, Any]:
        """Analyze a listing with optional ML score augmentation.

        Runs the full rule-based analysis pipeline first, then optionally
        applies an ML augmentor for additional confidence scoring.

        Args:
            text: The listing text to analyze.
            price: Optional listing price in USD.
            augmentor: Optional score augmentor. If `None`, this returns the
                same verdict as [SlangHunter.analyze()](src/slanghunter.py:770)
                plus explicit ML metadata fields.

        Returns:
            The standard `analyze()` result dict, extended with:
                - `ml_augmented`: Whether an augmentor was applied.
                - `ml_confidence`: Raw ML confidence.
                - `ml_boosted_score`: Final score after augmentation.

        Design guarantee:
            If no rule-based flags exist, the returned risk score cannot exceed
            `THRESHOLD_WARNING - 0.01` regardless of ML confidence.
        """
        base_result = self.analyze(text, price)
        if augmentor is None:
            return base_result | {
                "ml_augmented": False,
                "ml_confidence": 0.0,
                "ml_boosted_score": base_result["risk_score"],
            }

        has_rule_hits = len(base_result["flags"]) > 0
        # The augmentor only refines confidence around the deterministic
        # verdict; the rule engine remains the legal source of truth.
        candidate_score = augmentor.augment(
            text,
            base_result["risk_score"],
            has_rule_hits,
        )
        if has_rule_hits:
            max_boost = float(getattr(augmentor, "MAX_BOOST", 0.0))
            # Enforce the additive-only contract at the engine boundary so a
            # non-conforming duck-typed augmentor cannot override legal policy.
            boosted_score = min(
                max(base_result["risk_score"], candidate_score),
                min(base_result["risk_score"] + max_boost, 1.0),
            )
        else:
            # No-rule-hit listings may gain soft confidence, but they can never
            # cross the warning threshold without deterministic evidence.
            boosted_score = min(
                max(base_result["risk_score"], candidate_score),
                self.THRESHOLD_WARNING - 0.01,
            )

        ml_confidence = float(getattr(augmentor, "confidence", 0.0))

        return base_result | {
            "risk_score": boosted_score,
            "ml_augmented": True,
            "ml_confidence": ml_confidence,
            "ml_boosted_score": boosted_score,
        }

    def _format_report(
        self,
        text: str,
        price: float | None,
        verdict: dict[str, Any],
    ) -> str:
        """Format a precomputed verdict into the console report."""
        # Centralizing formatting here keeps [generate_report()]
        # and [print_report()] consistent while preserving their
        # public signatures.
        level = self.classify_risk(verdict["risk_score"])
        score_pct = int(verdict["risk_score"] * 100)

        lines: list[str] = []

        # ── Header ──────────────────────────────────────────
        lines.append("=" * 60)
        lines.append(
            f"  {level.emoji}  SLANGHUNTER VERDICT: "
            f"{level.label}"
        )
        lines.append("=" * 60)

        # ── Listing summary ─────────────────────────────────
        # Truncate display text to 80 chars for readability.
        display_text = text if len(text) <= 80 else text[:77] + "..."
        lines.append(f"  Listing : {display_text}")
        if price is not None:
            lines.append(f"  Price   : ${price:,.2f}")
        else:
            lines.append("  Price   : N/A")
        lines.append("")

        # ── Risk score bar ──────────────────────────────────
        bar_len = 30
        filled = int(bar_len * verdict["risk_score"])
        bar = "█" * filled + "░" * (bar_len - filled)
        lines.append(f"  Risk Score : [{bar}] {score_pct}%")
        lines.append(f"  Risk Level : {level.emoji}  {level.label}")
        lines.append(
            f"  Action     : {level.action}"
        )
        lines.append("")

        # ── Flags ───────────────────────────────────────────
        if verdict["flags"]:
            lines.append("  ┌─ FLAGS " + "─" * 48)
            for flag in verdict["flags"]:
                lines.append(f"  │  ⚑  {flag}")
            lines.append("  └" + "─" * 57)
            lines.append("")

        # ── Detailed reasoning (traceability) ───────────────
        lines.append("  ┌─ REASONING (Traceability) " + "─" * 29)
        for rline in verdict["reasoning"].split("\n"):
            lines.append(f"  │  {rline}")
        lines.append("  └" + "─" * 57)
        lines.append("")

        # ── Categories matched ──────────────────────────────
        if verdict["matched_categories"]:
            cats = ", ".join(
                c.upper() for c in verdict["matched_categories"]
            )
            lines.append(f"  Categories : {cats}")
        else:
            lines.append("  Categories : None")

        lines.append("=" * 60)

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Report Generation — "Explainable AI for Legal Teams"
    # ------------------------------------------------------------------

    def classify_risk(self, score: float) -> RiskLevel:
        """
        Map a numeric score to a RiskLevel enum value.

        Thresholds are controlled by the class attributes
        ``THRESHOLD_CRITICAL`` and ``THRESHOLD_WARNING`` so
        subclasses can tune sensitivity without rewriting this
        method.

            - CRITICAL: score > THRESHOLD_CRITICAL → automatic block
            - WARNING:  score > THRESHOLD_WARNING  → manual review
            - SAFE:     otherwise                  → approved

        Args:
            score: A risk score between 0.0 and 1.0.

        Returns:
            A ``RiskLevel`` enum member.
        """
        if score > self.THRESHOLD_CRITICAL:
            return RiskLevel.CRITICAL
        if score > self.THRESHOLD_WARNING:
            return RiskLevel.WARNING
        return RiskLevel.SAFE

    def generate_report(
        self,
        text: str,
        price: float | None = None,
    ) -> str:
        """
        Analyze a listing and produce a full human-readable report.

        This is the presentation layer — it calls ``analyze()``
        once, then formats that verdict for non-technical
        stakeholders (lawyers, ops managers, compliance auditors).

        Every decision is traceable: the report states *what* was
        detected, *which law* it violates, and *why* the risk
        level was assigned.  ("Explainable AI" for Legal Tech.)

        Args:
            text: The raw listing text.
            price: Optional listing price in USD.

        Returns:
            A formatted multi-line string ready for console
            output or logging.
        """
        verdict = self.analyze(text, price)
        return self._format_report(text, price, verdict)

    def print_report(
        self,
        text: str,
        price: float | None = None,
    ) -> dict[str, Any]:
        """
        Analyze, print the human-readable report, and return
        the raw verdict dict.

        Convenience method that analyzes once, prints a report
        derived from that single verdict, and returns the exact
        same dictionary for programmatic use.

        Args:
            text: The raw listing text.
            price: Optional listing price in USD.

        Returns:
            The raw verdict dictionary from ``analyze()``.
        """
        verdict = self.analyze(text, price)
        report = self._format_report(text, price, verdict)
        print(report)
        return verdict
