# backend/app/ml/feature_detector.py
import re
import numpy as np
from urllib.parse import urlparse

class URLFeatureExtractor:
    """
    Auto-detect feature mode:
    
    1. TF-IDF model (vectorizer required)
    2. Numeric model (n_features_in_ == X)
    3. Custom models handled safely
    """

    def __init__(self, model, vectorizer=None):
        self.model = model
        self.vectorizer = vectorizer

        # Auto-detect model input type
        self.feature_count = getattr(model, "n_features_in_", None)
        self.is_vector_model = vectorizer is not None

    def extract_numeric_features(self, url: str):
        """Basic numeric URL features for ML models."""
        return np.array([[
            len(url),
            sum(c.isdigit() for c in url),
            len(re.findall(r"[-._/?=&]", url))
        ]])

    def transform(self, url: str):
        """Return features for prediction depending on model type."""

        # CASE 1 — TF-IDF based model
        if self.is_vector_model:
            return self.vectorizer.transform([url])

        # CASE 2 — Numeric model with known feature count
        if self.feature_count == 3:
            return self.extract_numeric_features(url)

        # CASE 3 — Numeric model with more features
        if self.feature_count and self.feature_count > 3:
            # For now, pad extended models with simple 3 features
            base = self.extract_numeric_features(url)[0]
            padded = np.pad(base, (0, self.feature_count - 3))
            return np.array([padded])

        # Unknown model structure
        raise ValueError(
            f"Unsupported ML model format. Cannot infer input shape: {self.feature_count}"
        )
