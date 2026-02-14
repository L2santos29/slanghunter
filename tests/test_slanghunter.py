"""
test_slanghunter.py — Unit tests for the SlangHunter engine.

Run with: pytest tests/ -v
"""

from src.slanghunter import SlangHunter


class TestSlangHunterInit:
    """Tests for SlangHunter initialization."""

    def test_engine_instantiates(self):
        """Engine should instantiate without errors."""
        hunter = SlangHunter()
        assert hunter is not None


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
