"""
src/ml.py — ML Score Augmentation Layer

Provides the ScoreAugmentor protocol and a TF-IDF based concrete
implementation. This module is OPTIONAL. Install with:
pip install slanghunter[ml]

Design principle: ML augmentation is additive and never authoritative.
A CRITICAL verdict always requires at least one rule-based match in the
core engine.
"""

from typing import Any, Protocol, runtime_checkable


BENIGN_LISTING_TEXTS: list[str] = [
    "selling used laptop in good condition",
    "vintage ceramic vase from the 1990s",
    "handmade candles scented lavender",
    "wooden dining table with minor scratches",
    "children bicycle barely used",
    "office chair ergonomic mesh back",
    "kitchen mixer works perfectly",
    "winter coat size medium clean condition",
    "set of classic novels paperback edition",
    "gaming monitor 27 inch full hd",
    "wireless mouse and keyboard bundle",
    "pet carrier approved for travel",
    "running shoes size 9 worn twice",
    "ceramic dinner plates set of six",
    "garden tools bundle rake and shovel",
    "portable speaker with bluetooth audio",
    "smartphone case for iphone 14",
    "baby stroller folds easily for storage",
    "yoga mat with carrying strap",
    "coffee grinder stainless steel blades",
    "camping tent sleeps two people",
    "wall art print with wooden frame",
    "desk lamp with adjustable brightness",
    "board game complete with all pieces",
    "knitted scarf handmade wool blend",
    "used textbook for economics course",
    "baking tray non stick surface",
    "film camera with original lens cap",
    "storage shelf for garage organization",
    "table fan quiet motor for bedroom",
]


@runtime_checkable
class ScoreAugmentor(Protocol):
    """Duck-typing protocol for ML score augmentation.

    Any object implementing [ScoreAugmentor.augment()](src/ml.py:56)
    satisfies this protocol and can be passed to
    `SlangHunter.analyze_enhanced()`.
    """

    MAX_BOOST: float

    def augment(self, text: str, base_score: float, has_rule_hits: bool) -> float:
        """Return an augmented risk score.

        Args:
            text: The original non-normalized listing text.
            base_score: The score from the rule-based engine in `[0.0, 1.0]`.
            has_rule_hits: Whether the rule engine found text evidence.

        Returns:
            Augmented score in `[0.0, 1.0]`.
        """
        ...


class TfidfAugmentor:
    """TF-IDF + Logistic Regression score augmentor.

    Auto-trains from the SlangHunter knowledge base on first instantiation.
    No pre-trained model files are required.

    Raises:
        ImportError: If `scikit-learn` is not installed. Install with
            `pip install slanghunter[ml]`.
    """

    MAX_BOOST: float = 0.15
    _THRESHOLD_WARNING: float = 0.40

    def __init__(self) -> None:
        """Initialize the optional sklearn-backed model objects lazily."""
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.linear_model import LogisticRegression
        except ImportError as exc:
            raise ImportError(
                "scikit-learn is required. Install with: pip install slanghunter[ml]"
            ) from exc

        # Keep sklearn imports local so importing [src/ml.py](src/ml.py)
        # never forces an optional dependency at package import time.
        self._vectorizer: Any = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=500,
        )
        self._classifier: Any = LogisticRegression(
            max_iter=200,
            random_state=42,
        )
        self._is_fitted: bool = False
        self._last_confidence: float = 0.0

    @classmethod
    def from_knowledge_base(
        cls,
        knowledge_base: dict[str, Any],
    ) -> "TfidfAugmentor":
        """Create and train an augmentor from a SlangHunter knowledge base.

        The synthetic positives are intentionally generated from the same
        vocabulary as the rule engine so the model acts as a confidence
        booster around known signals rather than an independent authority.
        """
        augmentor = cls()

        texts: list[str] = []
        labels: list[int] = []
        positive_templates = (
            "buying {keyword} now",
            "get your {keyword} here",
            "selling {keyword} cheap",
        )

        for category_data in knowledge_base.values():
            for keyword in category_data["keywords"]:
                for template in positive_templates:
                    texts.append(template.format(keyword=keyword))
                    labels.append(1)

        texts.extend(BENIGN_LISTING_TEXTS)
        labels.extend([0] * len(BENIGN_LISTING_TEXTS))

        augmentor.fit(texts, labels)
        return augmentor

    def fit(self, texts: list[str], labels: list[int]) -> None:
        """Fit the vectorizer and classifier on labeled training texts."""
        X = self._vectorizer.fit_transform(texts)
        self._classifier.fit(X, labels)
        self._is_fitted = True

    def augment(self, text: str, base_score: float, has_rule_hits: bool) -> float:
        """Return a bounded additive score using the latest ML confidence.

        The additive cap preserves the legal architecture: without rule hits,
        the result can never cross the warning threshold boundary.
        """
        if not self._is_fitted:
            self._last_confidence = 0.0
            return base_score

        prob = self._classifier.predict_proba(
            self._vectorizer.transform([text])
        )[0][1]
        self._last_confidence = float(prob)
        ml_boost = self._last_confidence * self.MAX_BOOST

        if not has_rule_hits:
            capped_score = min(
                base_score + ml_boost,
                self._THRESHOLD_WARNING - 0.01,
            )
            return max(0.0, min(capped_score, 1.0))

        boosted_score = min(base_score + ml_boost, 1.0)
        return max(0.0, min(boosted_score, 1.0))

    @property
    def confidence(self) -> float:
        """Return the last computed positive-class probability."""
        return self._last_confidence
