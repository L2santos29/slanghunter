"""
SlangHunter — Automated Semantic Risk Detection Engine.

A programmatic tool for Trust & Safety teams to detect
fraud-indicative slang in unstructured marketplace listings.

Examples:
    >>> from src import SlangHunter
    >>> hunter = SlangHunter.from_data_dir()
    >>> verdict = hunter.analyze("m0ney fl1p on ca$h app", price=20.0)
"""

from importlib.metadata import PackageNotFoundError, version

from .slanghunter import RiskLevel, SlangHunter

try:
    __version__ = version("slanghunter")
except PackageNotFoundError:
    # Running from source bypasses installed package metadata, so
    # keep a stable fallback for tests and local development.
    __version__ = "0.1.0"

__all__ = ["SlangHunter", "RiskLevel", "__version__"]

try:
    from .ml import ScoreAugmentor, TfidfAugmentor

    __all__.extend(["ScoreAugmentor", "TfidfAugmentor"])
except ImportError:
    pass
