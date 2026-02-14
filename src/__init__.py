"""
SlangHunter — Automated Semantic Risk Detection Engine.

A programmatic tool for Trust & Safety teams to detect
fraud-indicative slang in unstructured marketplace listings.
"""

from .slanghunter import RiskLevel, SlangHunter

__version__ = "0.1.0"
__all__ = ["SlangHunter", "RiskLevel", "__version__"]
