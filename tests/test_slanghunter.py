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
# 5. Text normalization
# ==================================================================

class TestNormalizeText:
    """Tests for the _normalize_text() private method."""

    def test_lowercases_text(self):
        """Text must be converted to lowercase."""
        result = SlangHunter._normalize_text("SELLING CHEAP STUFF")
        assert result == "selling cheap stuff"

    def test_collapses_whitespace(self):
        """Multiple spaces/tabs/newlines become a single space."""
        result = SlangHunter._normalize_text("word1   word2\tword3\nword4")
        assert result == "word1 word2 word3 word4"

    def test_strips_edges(self):
        """Leading and trailing whitespace is removed."""
        result = SlangHunter._normalize_text("  hello world  ")
        assert result == "hello world"

    def test_preserves_special_chars(self):
        """Special chars ($, @, emojis) must NOT be stripped."""
        result = SlangHunter._normalize_text("ca$h @pp 🍃")
        assert "$" in result
        assert "@" in result
        assert "🍃" in result

    def test_empty_string(self):
        """Empty input returns empty output."""
        assert SlangHunter._normalize_text("") == ""


# ==================================================================
# 6. Keyword scanning
# ==================================================================

class TestKeywordScanning:
    """Tests for _scan_keywords()."""

    def test_finds_single_word_keyword(self):
        """Should find a single-word keyword with word boundaries."""
        hits = SlangHunter._scan_keywords(
            "i have some kush for sale", ["kush", "lean"]
        )
        assert "kush" in hits
        assert "lean" not in hits

    def test_finds_multi_word_keyword(self):
        """Should find multi-word phrases via substring match."""
        hits = SlangHunter._scan_keywords(
            "paying via cash app only", ["cash app", "zelle"]
        )
        assert "cash app" in hits
        assert "zelle" not in hits

    def test_no_false_positives_on_substrings(self):
        """'ice' should NOT match 'price' or 'nice'."""
        hits = SlangHunter._scan_keywords(
            "great price on this nice item", ["ice"]
        )
        assert hits == []

    def test_returns_empty_for_clean_text(self):
        """Clean text should produce no keyword hits."""
        hits = SlangHunter._scan_keywords(
            "brand new bicycle for kids", ["kush", "meth"]
        )
        assert hits == []


# ==================================================================
# 7. Pattern scanning
# ==================================================================

class TestPatternScanning:
    """Tests for _scan_patterns()."""

    def test_returns_matched_strings(self):
        """Matched text fragments should be returned."""
        import re as _re
        patterns = [_re.compile(r"p[3e]rc[s0]?", _re.IGNORECASE)]
        hits = SlangHunter._scan_patterns("got p3rcs hmu", patterns)
        assert len(hits) == 1
        assert "p3rc" in hits[0]

    def test_returns_empty_for_no_match(self):
        """No matches should produce an empty list."""
        import re as _re
        patterns = [_re.compile(r"p[3e]rc[s0]?", _re.IGNORECASE)]
        hits = SlangHunter._scan_patterns("selling a book", patterns)
        assert hits == []


# ==================================================================
# 8. Price context
# ==================================================================

class TestPriceContext:
    """Tests for _check_price_context()."""

    def test_price_inside_range(self):
        """Price inside [min, max] should return True."""
        thr = {"min": 0.0, "max": 80.0, "description": "test"}
        assert SlangHunter._check_price_context(50.0, thr) is True

    def test_price_outside_range(self):
        """Price above max should return False."""
        thr = {"min": 0.0, "max": 80.0, "description": "test"}
        assert SlangHunter._check_price_context(500.0, thr) is False

    def test_price_none(self):
        """None price should return False (no info = no context)."""
        thr = {"min": 0.0, "max": 80.0, "description": "test"}
        assert SlangHunter._check_price_context(None, thr) is False

    def test_price_at_boundary(self):
        """Price exactly at min or max should return True."""
        thr = {"min": 30.0, "max": 250.0, "description": "test"}
        assert SlangHunter._check_price_context(30.0, thr) is True
        assert SlangHunter._check_price_context(250.0, thr) is True


# ==================================================================
# 9. Scoring system
# ==================================================================

class TestScoringSystem:
    """Tests for _calculate_score()."""

    def test_zero_score_for_no_hits(self):
        """No hits = score 0.0."""
        hunter = SlangHunter()
        score = hunter._calculate_score([], [], False)
        assert score == 0.0

    def test_keywords_add_weight(self):
        """Each keyword hit adds WEIGHT_KEYWORD to the score."""
        hunter = SlangHunter()
        score = hunter._calculate_score(["kush"], [], False)
        assert score == hunter.WEIGHT_KEYWORD

    def test_patterns_add_weight(self):
        """Each pattern hit adds WEIGHT_PATTERN to the score."""
        hunter = SlangHunter()
        score = hunter._calculate_score([], ["p3rc"], False)
        assert score == hunter.WEIGHT_PATTERN

    def test_price_alone_scores_zero(self):
        """Price match ALONE must NOT add score (amplifier only)."""
        hunter = SlangHunter()
        score = hunter._calculate_score([], [], True)
        assert score == 0.0

    def test_combo_bonus_when_text_and_price(self):
        """Text + price evidence triggers price + combo bonus."""
        hunter = SlangHunter()
        score = hunter._calculate_score(["kush"], [], True)
        expected = (
            hunter.WEIGHT_KEYWORD
            + hunter.WEIGHT_PRICE_CONTEXT
            + hunter.WEIGHT_COMBO_BONUS
        )
        assert abs(score - expected) < 1e-9

    def test_score_clamped_to_one(self):
        """Score must never exceed 1.0 even with many hits."""
        hunter = SlangHunter()
        many_kw = ["a", "b", "c", "d", "e", "f", "g", "h"]
        many_pat = ["x", "y", "z", "w"]
        score = hunter._calculate_score(many_kw, many_pat, True)
        assert score == 1.0


# ==================================================================
# 10. Full analyze() — integration tests
# ==================================================================

class TestAnalyzeIntegration:
    """End-to-end tests for analyze() with real listings."""

    def test_clean_listing_scores_zero(self):
        """A completely innocent listing should score 0.0."""
        hunter = SlangHunter()
        result = hunter.analyze(
            "Vintage wooden bookshelf, great condition", price=45.0
        )
        assert result["risk_score"] == 0.0
        assert result["flags"] == []
        assert result["matched_categories"] == []

    def test_drug_keyword_detected(self):
        """A listing with a drug keyword should flag 'drugs'."""
        hunter = SlangHunter()
        result = hunter.analyze("Purple lean for sale, DM me")
        assert result["risk_score"] > 0.0
        assert "drugs" in result["matched_categories"]
        assert any("drugs:kw:lean" in f for f in result["flags"])

    def test_drug_slang_evasion_detected(self):
        """Evasion text like 'p3rcs' should still be caught."""
        hunter = SlangHunter()
        result = hunter.analyze("got them p3rcs 💊 hmu")
        assert result["risk_score"] > 0.0
        assert "drugs" in result["matched_categories"]

    def test_drug_with_price_context_scores_higher(self):
        """Drug keyword + suspicious price should boost score."""
        hunter = SlangHunter()
        text_only = hunter.analyze("Selling some kush")
        with_price = hunter.analyze("Selling some kush", price=25.0)
        assert with_price["risk_score"] > text_only["risk_score"]
        assert any(
            "price_context" in f for f in with_price["flags"]
        )

    def test_money_laundering_detected(self):
        """Money flip language should flag money_laundering."""
        hunter = SlangHunter()
        result = hunter.analyze(
            "💸 Money flip! Turn $50 into $500 via Cash App 💰",
            price=10.0,
        )
        assert "money_laundering" in result["matched_categories"]
        assert result["risk_score"] > 0.3

    def test_money_laundering_evasion_detected(self):
        """'m0ney fl1p' evasion should still be caught."""
        hunter = SlangHunter()
        result = hunter.analyze("legit m0ney fl1p, dm me now")
        assert "money_laundering" in result["matched_categories"]

    def test_surikae_counterfeit_detected(self):
        """Counterfeit listing should flag surikae."""
        hunter = SlangHunter()
        result = hunter.analyze(
            "Jordan 1 Retro - 1:1 replica, comes in original box",
            price=65.0,
        )
        assert "surikae" in result["matched_categories"]
        assert result["risk_score"] > 0.3

    def test_surikae_brand_evasion_detected(self):
        """'gucci inspired' should trigger surikae."""
        hunter = SlangHunter()
        result = hunter.analyze(
            "Beautiful gucci inspired handbag 👜 AAA quality"
        )
        assert "surikae" in result["matched_categories"]

    def test_multi_category_listing(self):
        """A listing hitting multiple categories should flag all."""
        hunter = SlangHunter()
        result = hunter.analyze(
            "Selling p3rcs, also do m0ney fl1ps on ca$h app",
            price=30.0,
        )
        assert "drugs" in result["matched_categories"]
        assert "money_laundering" in result["matched_categories"]
        assert result["risk_score"] > 0.4

    def test_price_alone_not_enough_for_high_score(self):
        """Suspicious price WITHOUT text evidence = low score."""
        hunter = SlangHunter()
        result = hunter.analyze(
            "Used textbook for college class", price=25.0
        )
        # Price may match drug/ML thresholds but no text =
        # only price_context weight, which is modest.
        assert result["risk_score"] <= 0.2

    def test_result_has_matched_categories_key(self):
        """Verdict must include the new matched_categories key."""
        hunter = SlangHunter()
        result = hunter.analyze("test listing")
        assert "matched_categories" in result
        assert isinstance(result["matched_categories"], list)

    def test_reasoning_contains_legal_reference(self):
        """Reasoning for a flagged listing must cite the statute."""
        hunter = SlangHunter()
        result = hunter.analyze("Selling some fentanyl")
        assert "21 U.S.C." in result["reasoning"]

    def test_reasoning_clean_listing(self):
        """Clean listing reasoning says no risk detected."""
        hunter = SlangHunter()
        result = hunter.analyze("Selling homemade cookies")
        assert "No risk indicators detected" in result["reasoning"]


# ==================================================================
# 11. Analyze contract (from Phase 1 — must still hold)
# ==================================================================

class TestSlangHunterAnalyze:
    """Tests for the analyze() method contract."""

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
