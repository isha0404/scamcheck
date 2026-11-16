"""The machine learning model: TF-IDF features + logistic regression.

Why this model?
- Logistic regression gives a probability *and* a weight per word, so we can
  show which words pushed a message towards "scam". That matters more here than
  squeezing out the last 0.5% of accuracy with a black box.
- Word n-grams capture phrases ("claim your prize"); character n-grams cope
  with the misspellings and txt-speak scammers use ("ur", "w1n", "fr33").
"""
from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

# Same idea as data.py: an env var wins, then ./models in the current folder.
DEFAULT_MODEL_PATH = Path(os.environ.get("SCAMCHECK_MODEL", Path.cwd() / "models" / "scamcheck.joblib"))


def build_pipeline() -> Pipeline:
    features = FeatureUnion([
        ("word", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=2, sublinear_tf=True,
                                 token_pattern=r"(?u)\b[\w£']+\b")),
        ("char", TfidfVectorizer(lowercase=True, analyzer="char_wb", ngram_range=(3, 5), min_df=2,
                                 sublinear_tf=True)),
    ])
    clf = LogisticRegression(C=8.0, class_weight="balanced", max_iter=2000)
    return Pipeline([("features", features), ("clf", clf)])


@dataclass
class ScamModel:
    pipeline: Pipeline
    metadata: dict

    # --- prediction -----------------------------------------------------------
    def probability(self, text: str) -> float:
        """Probability (0-1) that the message is a scam."""
        return float(self.pipeline.predict_proba([text])[0, 1])

    def top_terms(self, text: str, n: int = 6) -> list[dict]:
        """Words/phrases in this message that pushed the model towards 'scam' the most.

        For a linear model the contribution of a feature is simply
        (its TF-IDF value in this message) x (the weight the model learned for it).
        Only word features are used, because character fragments aren't readable.
        """
        union: FeatureUnion = self.pipeline.named_steps["features"]
        word_vec: TfidfVectorizer = union.transformer_list[0][1]
        coef = self.pipeline.named_steps["clf"].coef_[0][: len(word_vec.vocabulary_)]
        x = word_vec.transform([text]).tocoo()
        contrib = [(word_vec.get_feature_names_out()[j], v * coef[j]) for j, v in zip(x.col, x.data)]
        # Keep terms a person can learn from: drop numbers and fragments of web addresses
        noise = {"uk", "co", "com", "www", "http", "https", "the", "to", "a", "your", "you", "is", "of"}
        contrib = [c for c in contrib if c[1] > 0 and not c[0].replace(" ", "").isdigit()
                   and len(c[0]) > 2 and not set(c[0].split()) <= noise]
        contrib.sort(key=lambda c: -c[1])
        # Prefer phrases over the single words inside them
        chosen: list[tuple[str, float]] = []
        for term, w in contrib:
            if any(term in t or t in term for t, _ in chosen):
                continue
            chosen.append((term, w))
            if len(chosen) == n:
                break
        return [{"term": t, "weight": round(float(w), 4)} for t, w in chosen]

    # --- persistence ----------------------------------------------------------
    def save(self, path: Path = DEFAULT_MODEL_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"pipeline": self.pipeline, "metadata": self.metadata}, path)

    @classmethod
    def load(cls, path: Path = DEFAULT_MODEL_PATH) -> "ScamModel":
        """Load a model you trained yourself.

        Security note: joblib files are Python pickles and can run code when
        loaded. Never load a model file from a source you don't trust.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(
                f"No trained model at {path}. Train one first with:  python -m scamcheck.train")
        data = joblib.load(path)
        meta = data["metadata"]
        if meta.get("sklearn_version") != sklearn.__version__:
            import warnings
            warnings.warn(f"Model was trained with scikit-learn {meta.get('sklearn_version')} but "
                          f"{sklearn.__version__} is installed. Retrain if predictions look wrong.")
        return cls(data["pipeline"], meta)


def new_metadata(metrics: dict, n_train: int) -> dict:
    return {
        "trained_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "sklearn_version": sklearn.__version__,
        "numpy_version": np.__version__,
        "n_train": n_train,
        "metrics": metrics,
    }
