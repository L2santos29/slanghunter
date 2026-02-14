"""
test_slanghunter.py — Unit tests for the SlangHunter engine.

Run with: pytest tests/ -v
"""

import re

from src.slanghunter import SlangHunter

# Expected crime categories in the knowledge base.
EXPECTED_CATEGORIES = ["drugs", "money_laundering", "surikae"]

# Required keys every category must have.
REQUIRED_CATEGORY_KEYS = [
    "keywords",
    "slang_patterns",
    "risk_threshold",
    "legal_reference",
]


# ==================================================================
# 1. Engine initialization
# ==================================================================

class TestSlangHunterInit:
    """Tests for SlangHunter initialization."""

    def test_engine_instantiates(self):
        """Engine should instantiate without errors."""
        hunter = SlangHunter()
        assert hunter is not None

    def test_risk_database_exists(self):
        """risk_database must be set on initialization."""
        hunter = SlangHunter()
        assert hasattr(hunter, "risk_database")
        assert isinstance(hunter.risk_database, dict)

    def test_risk_database_not_empty(self):
        """risk_database must contain at least one category."""
        hunter = SlangHunter()
        assert len(hunter.risk_database) > 0


# ==================================================================
# 2. Knowledge base structure
# ==================================================================

class TestKnowledgeBaseStructure:
    """Validate the schema of every category in risk_database."""

    def test_expected_categories_present(self):
        """All expected crime categories must exist."""
        hunter = SlangHunter()
        for category in EXPECTED_CATEGORIES:
            assert category in hunter.risk_database, (
                f"Missing category: {category}"
            )

    def test_each_category_has_required_keys(self):
        """Every category must contain the four required keys."""
        hunter = SlangHunter()
        for name, entry in hunter.risk_database.items():
            for key in REQUIRED_CATEGORY_KEYS:
                assert key in entry, (
                    f"Category '{name}' is missing key '{key}'"
                )

    def test_keywords_are_lists_of_strings(self):
        """keywords must be a non-empty list of strings."""
        hunter = SlangHunter()
        for name, entry in hunter.risk_database.items():
            kw = entry["keywords"]
            assert isinstance(kw, list), (
                f"'{name}' keywords is not a list"
            )
            assert len(kw) > 0, (
                f"'{name}' keywords is empty"
            )
            assert all(isinstance(w, str) for w in kw), (
                f"'{name}' keywords contains non-string items"
            )

    def test_slang_patterns_are_compiled_regex(self):
        """slang_patterns must be a list of compiled re.Pattern."""
        hunter = SlangHunter()
        for name, entry in hunter.risk_database.items():
            patterns = entry["slang_patterns"]
            assert isinstance(patterns, list), (
                f"'{name}' slang_patterns is not a list"
            )
            assert len(patterns) > 0, (
                f"'{name}' slang_patterns is empty"
            )
            for pat in patterns:
                assert isinstance(pat, re.Pattern), (
                    f"'{name}' contains a non-compiled pattern: "
                    f"{pat!r}"
                )

    def test_risk_threshold_has_min_and_max(self):
        """risk_threshold must contain min, max, description."""
        hunter = SlangHunter()
        for name, entry in hunter.risk_database.items():
            thr = entry["risk_threshold"]
            assert "min" in thr, (
                f"'{name}' threshold missing 'min'"
            )
            assert "max" in thr, (
                f"'{name}' threshold missing 'max'"
            )
            assert "description" in thr, (
                f"'{name}' threshold missing 'description'"
            )
            assert thr["min"] <= thr["max"], (
                f"'{name}' threshold min > max"
            )

    def test_legal_reference_has_required_fields(self):
        """legal_reference must contain statute, name, summary."""
        hunter = SlangHunter()
        for name, entry in hunter.risk_database.items():
            ref = entry["legal_reference"]
            assert "statute" in ref, (
                f"'{name}' legal_reference missing 'statute'"
            )
            assert "name" in ref, (
                f"'{name}' legal_reference missing 'name'"
            )
            assert "summary" in ref, (
                f"'{name}' legal_reference missing 'summary'"
            )


# ==================================================================
# 3. Slang pattern effectiveness
# ==================================================================

class TestSlangPatternMatching:
    """Verify that regex patterns actually catch evasion tactics."""

    def _matches_any_pattern(self, category: str, text: str) -> bool:
        """Return True if any pattern in the category matches."""
        hunter = SlangHunter()
        patterns = hunter.risk_database[category]["slang_patterns"]
        return any(pat.search(text) for pat in patterns)

    # --- Drugs ---
    def test_drugs_catches_p3rcs(self):
        """Should detect 'p3rcs' as a Percocet evasion."""
        assert self._matches_any_pattern("drugs", "got p3rcs hmu")

    def test_drugs_catches_spaced_molly(self):
        """Should detect 'm 0 l l y' with spacing and swaps."""
        assert self._matches_any_pattern("drugs", "m 0 l l y available")

    def test_drugs_catches_xanax_evasion(self):
        """Should detect 'x@n@x' character substitution."""
        assert self._matches_any_pattern("drugs", "x@n@x for sale")

    def test_drugs_catches_f3nt(self):
        """Should detect 'f3nt' fentanyl abbreviation."""
        assert self._matches_any_pattern("drugs", "real f3nt pressed")

    # --- Money laundering ---
    def test_ml_catches_cash_app_dollar(self):
        """Should detect 'ca$h app' dollar-sign evasion."""
        assert self._matches_any_pattern(
            "money_laundering", "hit me on ca$h app"
        )

    def test_ml_catches_money_flip_evasion(self):
        """Should detect 'm0ney fl1p' number swaps."""
        assert self._matches_any_pattern(
            "money_laundering", "legit m0ney fl1p"
        )

    def test_ml_catches_blank_atm_evasion(self):
        """Should detect 'bl4nk 4tm' number swaps."""
        assert self._matches_any_pattern(
            "money_laundering", "selling bl4nk 4tm cards"
        )

    # --- Surikae (counterfeit) ---
    def test_surikae_catches_replica_evasion(self):
        """Should detect 'r3plica' number swap."""
        assert self._matches_any_pattern(
            "surikae", "best r3plica jordans"
        )

    def test_surikae_catches_1to1(self):
        """Should detect '1:1' quality marker."""
        assert self._matches_any_pattern(
            "surikae", "1:1 quality guaranteed"
        )

    def test_surikae_catches_brand_inspired(self):
        """Should detect 'gucci inspired' pattern."""
        assert self._matches_any_pattern(
            "surikae", "gucci inspired bag"
        )


# ==================================================================
# 4. Public API methods
# ==================================================================

class TestPublicAPI:
    """Tests for get_categories() and get_category_info()."""

    def test_get_categories_returns_sorted_list(self):
        """get_categories() must return a sorted list."""
        hunter = SlangHunter()
        cats = hunter.get_categories()
        assert cats == sorted(EXPECTED_CATEGORIES)

    def test_get_category_info_returns_dict(self):
        """get_category_info() returns a dict for valid category."""
        hunter = SlangHunter()
        info = hunter.get_category_info("drugs")
        assert isinstance(info, dict)
        assert "keyword_count" in info
        assert "pattern_count" in info
        assert "risk_threshold" in info
        assert "legal_reference" in info

    def test_get_category_info_returns_none_for_unknown(self):
        """get_category_info() returns None for unknown category."""
        hunter = SlangHunter()
        assert hunter.get_category_info("nonexistent") is None


# ==================================================================
# 5. Analyze contract (unchanged from Phase 1)
# ==================================================================

class TestSlangHunterAnalyze:
    """Tests for the analyze() method."""

    def test_analyze_returns_dict(self):
        """analyze() should return a dictionary."""
        hunter = SlangHunter()
        result = hunter.analyze("test listing")
        assert isinstance(result, dict)

    def test_analyze_has_required_keys(self):
        """Verdict must contain risk_score, flags, and reasoning."""
        hunter = SlangHunter()
        result = hunter.analyze("test listing")
        assert "risk_score" in result
        assert "flags" in result
        assert "reasoning" in result

    def test_risk_score_in_range(self):
        """risk_score must be between 0.0 and 1.0."""
        hunter = SlangHunter()
        result = hunter.analyze("test listing")
        assert 0.0 <= result["risk_score"] <= 1.0

    def test_flags_is_list(self):
        """flags must be a list."""
        hunter = SlangHunter()
        result = hunter.analyze("test listing")
        assert isinstance(result["flags"], list)
