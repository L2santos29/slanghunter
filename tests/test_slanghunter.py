"""
test_slanghunter.py — Unit tests for the SlangHunter engine.

Run with: pytest tests/ -v
"""

import json
import re

from src.slanghunter import RiskLevel, SlangHunter

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


# ==================================================================
# 12. RiskLevel enum
# ==================================================================

class TestRiskLevel:
    """Tests for the RiskLevel traffic-light enum."""

    def test_enum_has_three_members(self):
        """RiskLevel should have exactly CRITICAL, WARNING, SAFE."""
        members = list(RiskLevel)
        assert len(members) == 3
        names = {m.name for m in members}
        assert names == {"CRITICAL", "WARNING", "SAFE"}

    def test_each_member_has_emoji(self):
        """Every RiskLevel must carry an emoji attribute."""
        for level in RiskLevel:
            assert isinstance(level.emoji, str)
            assert len(level.emoji) > 0

    def test_each_member_has_label(self):
        """Every RiskLevel must carry a label attribute."""
        for level in RiskLevel:
            assert isinstance(level.label, str)
            assert level.label == level.name

    def test_each_member_has_action(self):
        """Every RiskLevel must carry an action attribute."""
        for level in RiskLevel:
            assert isinstance(level.action, str)
            assert len(level.action) > 0

    def test_critical_emoji_is_red(self):
        """CRITICAL should use the red circle emoji."""
        assert RiskLevel.CRITICAL.emoji == "🔴"

    def test_warning_emoji_is_yellow(self):
        """WARNING should use the yellow circle emoji."""
        assert RiskLevel.WARNING.emoji == "🟡"

    def test_safe_emoji_is_green(self):
        """SAFE should use the green circle emoji."""
        assert RiskLevel.SAFE.emoji == "🟢"


# ==================================================================
# 13. classify_risk()
# ==================================================================

class TestClassifyRisk:
    """Tests for the classify_risk() threshold logic."""

    def test_score_zero_is_safe(self):
        """Score 0.0 → SAFE."""
        hunter = SlangHunter()
        assert hunter.classify_risk(0.0) == RiskLevel.SAFE

    def test_score_040_is_safe(self):
        """Score exactly 0.40 → SAFE (boundary: not > 0.40)."""
        hunter = SlangHunter()
        assert hunter.classify_risk(0.40) == RiskLevel.SAFE

    def test_score_041_is_warning(self):
        """Score 0.41 → WARNING."""
        hunter = SlangHunter()
        assert hunter.classify_risk(0.41) == RiskLevel.WARNING

    def test_score_080_is_warning(self):
        """Score exactly 0.80 → WARNING (boundary: not > 0.80)."""
        hunter = SlangHunter()
        assert hunter.classify_risk(0.80) == RiskLevel.WARNING

    def test_score_081_is_critical(self):
        """Score 0.81 → CRITICAL."""
        hunter = SlangHunter()
        assert hunter.classify_risk(0.81) == RiskLevel.CRITICAL

    def test_score_100_is_critical(self):
        """Score 1.0 → CRITICAL."""
        hunter = SlangHunter()
        assert hunter.classify_risk(1.0) == RiskLevel.CRITICAL


# ==================================================================
# 14. generate_report()
# ==================================================================

class TestGenerateReport:
    """Tests for the human-readable report output."""

    def test_report_is_string(self):
        """generate_report() must return a string."""
        hunter = SlangHunter()
        report = hunter.generate_report("test listing")
        assert isinstance(report, str)

    def test_report_contains_verdict_header(self):
        """Report must contain 'SLANGHUNTER VERDICT'."""
        hunter = SlangHunter()
        report = hunter.generate_report("test listing")
        assert "SLANGHUNTER VERDICT" in report

    def test_safe_report_shows_green(self):
        """Clean listing report should show 🟢 and SAFE."""
        hunter = SlangHunter()
        report = hunter.generate_report(
            "Vintage wooden bookshelf", price=45.0
        )
        assert "🟢" in report
        assert "SAFE" in report
        assert "APPROVED" in report

    def test_critical_report_shows_red(self):
        """High-risk listing should show 🔴 and CRITICAL."""
        hunter = SlangHunter()
        report = hunter.generate_report(
            "Purple lean + xanax combo, scripts from the plug 💨🍃",
            price=40.0,
        )
        assert "🔴" in report or "🟡" in report
        # At minimum it should not be SAFE.
        assert "SAFE" not in report or "CRITICAL" in report or "WARNING" in report

    def test_report_contains_listing_text(self):
        """Report must show the listing text."""
        hunter = SlangHunter()
        report = hunter.generate_report("Magic beans for sale")
        assert "Magic beans for sale" in report

    def test_report_contains_price(self):
        """Report must show the price when provided."""
        hunter = SlangHunter()
        report = hunter.generate_report("test item", price=99.99)
        assert "$99.99" in report

    def test_report_shows_na_when_no_price(self):
        """Report must show N/A when price is omitted."""
        hunter = SlangHunter()
        report = hunter.generate_report("test item")
        assert "N/A" in report

    def test_report_contains_risk_score_bar(self):
        """Report must include a visual risk score bar."""
        hunter = SlangHunter()
        report = hunter.generate_report("test item")
        assert "Risk Score" in report
        assert "%" in report

    def test_report_contains_action_recommendation(self):
        """Report must include an action recommendation."""
        hunter = SlangHunter()
        report = hunter.generate_report("test item")
        assert "Action" in report

    def test_report_contains_reasoning_section(self):
        """Report must include a REASONING section."""
        hunter = SlangHunter()
        report = hunter.generate_report("test item")
        assert "REASONING" in report

    def test_report_traceability_shows_legal_ref(self):
        """Flagged listing report must cite the legal statute."""
        hunter = SlangHunter()
        report = hunter.generate_report("Selling fentanyl cheap")
        assert "21 U.S.C." in report

    def test_report_flags_section_present_when_flagged(self):
        """Flagged listing report must show a FLAGS section."""
        hunter = SlangHunter()
        report = hunter.generate_report("got some lean for sale")
        assert "FLAGS" in report
        assert "⚑" in report

    def test_report_no_flags_section_when_clean(self):
        """Clean listing should NOT have a FLAGS section."""
        hunter = SlangHunter()
        report = hunter.generate_report(
            "Vintage bookshelf, great condition"
        )
        assert "⚑" not in report

    def test_report_truncates_long_text(self):
        """Listing text longer than 80 chars should be truncated."""
        hunter = SlangHunter()
        long_text = "A" * 120
        report = hunter.generate_report(long_text)
        assert "..." in report

    def test_report_categories_shown(self):
        """Matched categories must appear in the report."""
        hunter = SlangHunter()
        report = hunter.generate_report(
            "m0ney fl1p on ca$h app 💸", price=20.0
        )
        assert "MONEY_LAUNDERING" in report


# ==================================================================
# 15. print_report() — smoke test
# ==================================================================

class TestPrintReport:
    """Tests for the print_report() convenience method."""

    def test_print_report_returns_verdict_dict(self):
        """print_report() should return the raw analyze() dict."""
        hunter = SlangHunter()
        result = hunter.print_report("test listing")
        assert isinstance(result, dict)
        assert "risk_score" in result
        assert "flags" in result

    def test_print_report_outputs_to_stdout(self, capsys):
        """print_report() should print the report to stdout."""
        hunter = SlangHunter()
        hunter.print_report("Selling kush")
        captured = capsys.readouterr()
        assert "SLANGHUNTER VERDICT" in captured.out


# ==================================================================
# 16. Emoji pattern isolation
# ==================================================================

class TestEmojiPatternMatching:
    """Verify isolated emoji regex patterns compile and match."""

    def _scan_category_patterns(self, category: str, text: str) -> list[str]:
        """Return matched fragments for one category's pattern set."""
        hunter = SlangHunter()
        patterns = hunter.risk_database[category]["slang_patterns"]
        return hunter._scan_patterns(text, patterns)

    def test_drugs_leaf_emoji_pattern(self):
        """The leaf emoji should hit the drugs emoji pattern."""
        hits = self._scan_category_patterns("drugs", "🍃")
        assert "🍃" in hits

    def test_drugs_smoke_emoji_pattern(self):
        """The smoke emoji should hit the drugs emoji pattern."""
        hits = self._scan_category_patterns("drugs", "💨")
        assert "💨" in hits

    def test_money_wings_emoji_pattern(self):
        """Money-with-wings should hit laundering emoji patterns."""
        hits = self._scan_category_patterns("money_laundering", "💸")
        assert "💸" in hits

    def test_money_bag_emoji_pattern(self):
        """Money bag should hit laundering emoji patterns."""
        hits = self._scan_category_patterns("money_laundering", "💰")
        assert "💰" in hits

    def test_surikae_fire_emoji_pattern(self):
        """Fire should hit the surikae emoji pattern."""
        hits = self._scan_category_patterns("surikae", "🔥")
        assert "🔥" in hits

    def test_surikae_shoe_emoji_pattern(self):
        """Sneaker should hit the surikae emoji pattern."""
        hits = self._scan_category_patterns("surikae", "👟")
        assert "👟" in hits

    def test_clean_text_with_no_emojis_returns_empty_list(self):
        """Plain text should not produce emoji-pattern hits."""
        hunter = SlangHunter()
        patterns = hunter.risk_database["surikae"]["slang_patterns"]
        assert hunter._scan_patterns("ordinary listing text", patterns) == []


# ==================================================================
# 17. Missing high-risk pattern coverage
# ==================================================================

class TestMissingPatternCoverage:
    """Cover high-risk evasion patterns with dedicated isolation tests."""

    def test_adderall_evasion_pattern(self):
        """Adderall number-swap evasion should flag drugs."""
        hunter = SlangHunter()
        result = hunter.analyze("4dd3r4ll available tonight")
        assert "drugs" in result["matched_categories"]
        assert any(flag.startswith("drugs:pat:") for flag in result["flags"])

    def test_crystal_meth_evasion_pattern(self):
        """Spaced crystal evasion should flag drugs."""
        hunter = SlangHunter()
        result = hunter.analyze("c r y s t a l ready for pickup")
        assert "drugs" in result["matched_categories"]
        assert any(flag.startswith("drugs:pat:") for flag in result["flags"])

    def test_blank_atm_evasion_pattern(self):
        """Blank ATM number-swap evasion should flag laundering."""
        hunter = SlangHunter()
        result = hunter.analyze("bl4nk 4tm cards available")
        assert "money_laundering" in result["matched_categories"]
        assert any(
            flag.startswith("money_laundering:pat:")
            for flag in result["flags"]
        )

    def test_cloned_card_evasion_pattern(self):
        """Cloned-card number-swap evasion should flag laundering."""
        hunter = SlangHunter()
        result = hunter.analyze("cl0ned c4rd with fresh balance")
        assert "money_laundering" in result["matched_categories"]
        assert any(
            flag.startswith("money_laundering:pat:")
            for flag in result["flags"]
        )


# ==================================================================
# 18. _build_reasoning() isolation
# ==================================================================

class TestBuildReasoning:
    """Validate direct formatting behavior of _build_reasoning()."""

    def test_build_reasoning_includes_all_evidence_sections(self):
        """Reasoning should include the header, evidence, and law."""
        reasoning = SlangHunter._build_reasoning(
            "money_laundering",
            ["cash app", "gift card"],
            ["m0ney fl1p", "💸"],
            True,
            {
                "statute": "18 U.S.C. § 1956",
                "name": "Laundering of Monetary Instruments",
                "summary": "Knowingly conducting a financial transaction.",
            },
        )
        assert "[MONEY_LAUNDERING]" in reasoning
        assert "'cash app'" in reasoning
        assert "'gift card'" in reasoning
        assert "'m0ney fl1p'" in reasoning
        assert "'💸'" in reasoning
        assert "Price falls within suspicious range." in reasoning
        assert "18 U.S.C. § 1956" in reasoning

    def test_build_reasoning_empty_hits_returns_minimal_string(self):
        """No hits should still return a minimal valid heading."""
        reasoning = SlangHunter._build_reasoning(
            "drugs",
            [],
            [],
            False,
            {
                "statute": "21 U.S.C. § 841",
                "name": "Controlled Substances Act",
                "summary": "Summary placeholder.",
            },
        )
        assert reasoning == "[DRUGS]"


# ==================================================================
# 19. analyze() input validation
# ==================================================================

class TestAnalyzeInputValidation:
    """Ensure public API input guards fail fast with clear errors."""

    def test_analyze_raises_type_error_for_none_text(self):
        """None text should raise TypeError before normalization."""
        import pytest

        hunter = SlangHunter()
        with pytest.raises(TypeError):
            hunter.analyze(None)

    def test_analyze_raises_type_error_for_integer_text(self):
        """Integer text should raise TypeError before normalization."""
        import pytest

        hunter = SlangHunter()
        with pytest.raises(TypeError):
            hunter.analyze(42)

    def test_analyze_raises_value_error_for_overlength_text(self):
        """Text beyond the configured limit should raise ValueError."""
        import pytest

        hunter = SlangHunter()
        with pytest.raises(ValueError):
            hunter.analyze("x" * 10_001)

    def test_analyze_accepts_max_length_text(self):
        """Text exactly at the configured limit should be accepted."""
        hunter = SlangHunter()
        result = hunter.analyze("x" * 10_000)
        assert isinstance(result, dict)

    def test_analyze_raises_type_error_for_string_price(self):
        """String prices should raise TypeError."""
        import pytest

        hunter = SlangHunter()
        with pytest.raises(TypeError):
            hunter.analyze("text", price="free")

    def test_analyze_raises_value_error_for_negative_price(self):
        """Negative numeric prices should raise ValueError."""
        import pytest

        hunter = SlangHunter()
        with pytest.raises(ValueError):
            hunter.analyze("test listing", price=-1.0)

    def test_analyze_accepts_none_price(self):
        """None remains a valid optional price input."""
        hunter = SlangHunter()
        result = hunter.analyze("test listing", price=None)
        assert isinstance(result, dict)

    def test_analyze_accepts_integer_price(self):
        """Integer prices should be accepted as numeric input."""
        hunter = SlangHunter()
        result = hunter.analyze("test listing", price=10)
        assert isinstance(result, dict)


# ==================================================================
# 20. __main__.py entry point
# ==================================================================

class TestMainEntryPoint:
    """Smoke-test the module entry point used by python -m src."""

    def test_main_runs_without_error(self, capsys):
        """Calling main() should print non-empty demo output."""
        from src.__main__ import main

        main()
        captured = capsys.readouterr()
        assert captured.out.strip() != ""
        assert any(
            marker in captured.out
            for marker in ["RISK ANALYSIS", "SAFE", "WARNING", "CRITICAL"]
        )


# ==================================================================
# 21. JSON-backed knowledge base loading
# ==================================================================

class TestFromDataDir:
    """Validate JSON-backed factory and reload behavior."""

    def test_from_data_dir_loads_json_rules(self, tmp_path):
        """Factory should compile regex strings from JSON files."""
        rule_file = tmp_path / "drugs.json"
        rule_file.write_text(
            json.dumps(
                {
                    "keywords": ["fentanyl", "percocet"],
                    "slang_patterns": ["p[3e]rc[s0]?"],
                    "risk_threshold": {
                        "min": 0.0,
                        "max": 80.0,
                        "description": "Short test range.",
                    },
                    "legal_reference": {
                        "statute": "21 U.S.C. § 841",
                        "name": "Controlled Substances Act",
                        "summary": "Test summary.",
                    },
                    "jp_legal_reference": {
                        "statute": "薬機法 Art. 84",
                        "name": "Japanese statute",
                        "summary": "Test summary.",
                    },
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        hunter = SlangHunter.from_data_dir(tmp_path)

        assert hunter.get_categories() == ["drugs"]
        assert isinstance(
            hunter.risk_database["drugs"]["slang_patterns"][0],
            re.Pattern,
        )
        result = hunter.analyze("got p3rcs hmu", price=20.0)
        assert "drugs" in result["matched_categories"]

    def test_from_data_dir_falls_back_for_missing_directory(self, tmp_path):
        """Missing directories should warn and use built-in rules."""
        import warnings

        missing_dir = tmp_path / "missing"
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            hunter = SlangHunter.from_data_dir(missing_dir)

        assert hunter.get_categories() == sorted(EXPECTED_CATEGORIES)
        assert any(
            "falling back to built-in risk database" in str(item.message)
            for item in caught
        )

    def test_reload_from_data_dir_raises_for_missing_explicit_path(
        self, tmp_path
    ):
        """Explicit reload paths should fail fast when they do not exist."""
        import pytest

        hunter = SlangHunter()
        with pytest.raises(FileNotFoundError):
            hunter.reload_from_data_dir(tmp_path / "missing")

    def test_from_data_dir_falls_back_for_empty_directory(self, tmp_path):
        """Existing but empty directories should trigger fallback warning."""
        import warnings

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            hunter = SlangHunter.from_data_dir(tmp_path)

        assert hunter.get_categories() == sorted(EXPECTED_CATEGORIES)
        assert any(
            "No JSON knowledge base files found" in str(item.message)
            for item in caught
        )

    def test_reload_from_data_dir_uses_default_directory_when_omitted(
        self, monkeypatch, tmp_path
    ):
        """Reload should use the default data directory when no path is passed."""
        (tmp_path / "drugs.json").write_text(
            json.dumps(
                {
                    "keywords": ["ketamine"],
                    "slang_patterns": ["k[e3]t[a@]m[i1]n[e3]"],
                    "risk_threshold": {
                        "min": 5.0,
                        "max": 40.0,
                        "description": "Reloaded range.",
                    },
                    "legal_reference": {
                        "statute": "21 U.S.C. § 841",
                        "name": "Controlled Substances Act",
                        "summary": "Reload test.",
                    },
                    "jp_legal_reference": {
                        "statute": "薬機法 Art. 84",
                        "name": "Japanese statute",
                        "summary": "Reload test.",
                    },
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(
            SlangHunter,
            "_default_data_dir",
            staticmethod(lambda: tmp_path),
        )

        hunter = SlangHunter()
        hunter.reload_from_data_dir()

        assert SlangHunter._default_data_dir() == tmp_path
        assert hunter.get_categories() == ["drugs"]
        assert hunter.get_category_info("drugs")["keyword_count"] == 1


class TestPackageExports:
    """Cover package-level export and version fallback behavior."""

    def test_version_falls_back_when_package_metadata_is_missing(
        self, monkeypatch
    ):
        """Editable-source execution should keep a stable fallback version."""
        import importlib
        import importlib.metadata as importlib_metadata
        import src

        original_version = importlib_metadata.version

        def raise_not_found(_: str) -> str:
            raise importlib_metadata.PackageNotFoundError

        monkeypatch.setattr(importlib_metadata, "version", raise_not_found)
        reloaded_src = importlib.reload(src)
        assert reloaded_src.__version__ == "0.1.0"
        assert "SlangHunter" in reloaded_src.__all__

        monkeypatch.setattr(importlib_metadata, "version", original_version)
        importlib.reload(src)


class TestApiLayer:
    """Exercise the FastAPI wrapper and Pydantic models."""

    def test_analyze_request_rejects_whitespace_only_text(self):
        """API model should reject payloads that are not meaningfully non-empty."""
        import pytest
        from pydantic import ValidationError

        from api.models import AnalyzeRequest

        with pytest.raises(ValidationError):
            AnalyzeRequest(text="   ")

    def test_health_endpoint_returns_status_and_version(self):
        """Health endpoint should expose the deployment contract."""
        from api.main import app, health

        payload = health()

        assert payload["status"] == "ok"
        assert payload["version"]
        assert app.title == "SlangHunter API"

    def test_category_endpoints_return_data_and_404(self):
        """Category metadata endpoint should expose known categories only."""
        import pytest
        from fastapi import HTTPException

        from api.main import get_category, list_categories

        categories_payload = list_categories()
        detail_payload = get_category("drugs")

        assert "drugs" in categories_payload["categories"]
        assert detail_payload.keyword_count > 0

        with pytest.raises(HTTPException) as exc_info:
            get_category("not-real")

        assert exc_info.value.status_code == 404

    def test_analyze_endpoint_returns_serialized_verdict(self):
        """Analyze endpoint should map engine output into the response model."""
        from api.main import analyze_listing
        from api.models import AnalyzeRequest

        response = analyze_listing(
            AnalyzeRequest(text="Purple lean on ca$h app", price=20.0)
        )

        assert response.risk_level in {"CRITICAL", "WARNING", "SAFE"}
        assert response.risk_emoji
        assert response.risk_action
        assert "drugs" in response.matched_categories

    def test_analyze_endpoint_converts_engine_errors_to_http_400(
        self, monkeypatch
    ):
        """Endpoint should translate engine validation errors into HTTP errors."""
        import pytest
        from fastapi import HTTPException

        import api.main as api_main
        from api.models import AnalyzeRequest

        def raise_engine_error(text: str, price: float | None) -> dict[str, str]:
            raise ValueError("boom")

        monkeypatch.setattr(api_main.hunter, "analyze", raise_engine_error)

        with pytest.raises(HTTPException) as exc_info:
            api_main.analyze_listing(AnalyzeRequest(text="valid text", price=1.0))

        assert exc_info.value.status_code == 400

    def test_startup_logs_loaded_category_count(self, monkeypatch):
        """Startup hook should log operational visibility details."""
        import asyncio

        import api.main as api_main

        log_messages: list[tuple[str, int]] = []

        def capture_info(message: str, category_count: int) -> None:
            log_messages.append((message, category_count))

        monkeypatch.setattr(api_main.LOGGER, "info", capture_info)
        asyncio.run(api_main.log_startup())

        assert log_messages
        assert "SlangHunter API started" in log_messages[0][0]
        assert log_messages[0][1] == len(api_main.hunter.get_categories())

    def test_reload_endpoint_refreshes_module_level_hunter(
        self, monkeypatch, tmp_path
    ):
        """Reload endpoint should repopulate the singleton from JSON files."""
        import api.main as api_main

        (tmp_path / "surikae.json").write_text(
            json.dumps(
                {
                    "keywords": ["mirror quality"],
                    "slang_patterns": ["\\bua\\b"],
                    "risk_threshold": {
                        "min": 30.0,
                        "max": 250.0,
                        "description": "Reloaded surikae range.",
                    },
                    "legal_reference": {
                        "statute": "18 U.S.C. § 2320",
                        "name": "Counterfeit Goods",
                        "summary": "Reload test.",
                    },
                    "jp_legal_reference": {
                        "statute": "不正競争防止法 Art. 2",
                        "name": "Japanese counterfeit law",
                        "summary": "Reload test.",
                    },
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(
            SlangHunter,
            "_default_data_dir",
            staticmethod(lambda: tmp_path),
        )
        api_main.hunter = SlangHunter()

        response = api_main.reload_knowledge_base()

        assert response == {
            "status": "reloaded",
            "categories": ["surikae"],
        }
        assert api_main.hunter.get_categories() == ["surikae"]


# ==================================================================
# 22. ML augmentation layer
# ==================================================================

class TestMLAugmentor:
    """Validate the optional additive ML scoring layer."""

    @staticmethod
    def _build_augmentor():
        """Train a default augmentor from the current knowledge base."""
        from src.ml import TfidfAugmentor

        hunter = SlangHunter()
        return TfidfAugmentor.from_knowledge_base(hunter.risk_database)

    def test_tfidf_augmentor_init_requires_sklearn(self, monkeypatch):
        """Constructor should raise a helpful error when sklearn is unavailable."""
        import builtins
        import pytest

        pytest.importorskip("sklearn")
        from src.ml import TfidfAugmentor

        original_import = builtins.__import__

        def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name.startswith("sklearn"):
                raise ImportError("mocked sklearn import failure")
            return original_import(name, globals, locals, fromlist, level)

        monkeypatch.setattr(builtins, "__import__", fake_import)

        with pytest.raises(ImportError, match="scikit-learn is required"):
            TfidfAugmentor()

    def test_tfidf_augmentor_from_knowledge_base_trains(self):
        """Factory should return a fitted augmentor ready for scoring."""
        import pytest

        pytest.importorskip("sklearn")

        augmentor = self._build_augmentor()

        assert augmentor._is_fitted is True

    def test_augment_no_rule_hits_capped_below_warning(self):
        """No-rule cases must remain capped below the warning threshold."""
        import pytest

        pytest.importorskip("sklearn")

        augmentor = self._build_augmentor()
        result = augmentor.augment("buying kush now", 0.39, False)

        assert result <= SlangHunter.THRESHOLD_WARNING - 0.01
        assert result < SlangHunter.THRESHOLD_WARNING

    def test_augment_with_rule_hits_can_exceed_warning(self):
        """Rule-backed cases may cross warning when ML adds confidence."""
        import pytest

        pytest.importorskip("sklearn")

        augmentor = self._build_augmentor()
        result = augmentor.augment("buying kush now", 0.40, True)

        assert result > SlangHunter.THRESHOLD_WARNING
        assert result <= 0.40 + augmentor.MAX_BOOST

    def test_analyze_enhanced_no_augmentor_returns_base(self):
        """Without an augmentor, enhanced analysis must mirror base analysis."""
        import pytest

        pytest.importorskip("sklearn")

        hunter = SlangHunter()
        base_result = hunter.analyze("Selling some kush", price=25.0)
        enhanced_result = hunter.analyze_enhanced("Selling some kush", price=25.0)

        assert enhanced_result["risk_score"] == base_result["risk_score"]
        assert enhanced_result["flags"] == base_result["flags"]
        assert enhanced_result["reasoning"] == base_result["reasoning"]
        assert (
            enhanced_result["matched_categories"]
            == base_result["matched_categories"]
        )
        assert enhanced_result["ml_augmented"] is False
        assert enhanced_result["ml_confidence"] == 0.0
        assert enhanced_result["ml_boosted_score"] == base_result["risk_score"]

    def test_analyze_enhanced_with_augmentor_adds_ml_fields(self):
        """Enhanced analysis should expose ML metadata alongside the verdict."""
        import pytest

        pytest.importorskip("sklearn")

        hunter = SlangHunter()
        augmentor = self._build_augmentor()
        result = hunter.analyze_enhanced(
            "buying kush now",
            augmentor=augmentor,
        )

        assert result["ml_augmented"] is True
        assert 0.0 <= result["ml_confidence"] <= 1.0
        assert result["ml_boosted_score"] == result["risk_score"]
        assert (
            result["risk_score"]
            >= hunter.analyze("buying kush now")["risk_score"]
        )

    def test_analyze_enhanced_critical_requires_rule_hits(self):
        """ML alone must never escalate a clean listing to critical risk."""
        import pytest

        pytest.importorskip("sklearn")

        hunter = SlangHunter()
        augmentor = self._build_augmentor()
        result = hunter.analyze_enhanced(
            "ordinary ceramic vase with floral pattern",
            augmentor=augmentor,
        )

        assert result["flags"] == []
        assert result["risk_score"] <= hunter.THRESHOLD_WARNING - 0.01
        assert result["risk_score"] < hunter.THRESHOLD_CRITICAL

    def test_score_augmentor_protocol_satisfied_by_tfidf(self):
        """TfidfAugmentor should satisfy the runtime-checkable protocol."""
        import pytest

        pytest.importorskip("sklearn")
        from src import ScoreAugmentor

        augmentor = self._build_augmentor()

        assert isinstance(augmentor, ScoreAugmentor)
