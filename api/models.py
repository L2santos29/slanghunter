"""Pydantic request and response models for the SlangHunter API."""

from typing import Optional

from pydantic import BaseModel, Field, field_validator


class AnalyzeRequest(BaseModel):
    """Validated payload for listing analysis requests."""

    text: str = Field(
        ...,
        min_length=1,
        max_length=10_000,
        description="Listing text to analyze",
    )
    price: Optional[float] = Field(
        None,
        ge=0,
        description="Listing price in USD (optional)",
    )

    @field_validator("text")
    @classmethod
    def validate_text(cls, value: str) -> str:
        """Reject whitespace-only payloads before the engine runs."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("text must contain at least one non-whitespace character")
        return stripped


class CategoryInfo(BaseModel):
    """Serialized metadata for one knowledge-base category."""

    keyword_count: int
    pattern_count: int
    risk_threshold: dict[str, object]
    legal_reference: dict[str, object]
    jp_legal_reference: dict[str, object]


class AnalyzeResponse(BaseModel):
    """HTTP response model for analyzed listings."""

    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: str
    risk_emoji: str
    risk_action: str
    flags: list[str]
    matched_categories: list[str]
    reasoning: str
