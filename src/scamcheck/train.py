"""Train, evaluate and save the model.

    python -m scamcheck.train

Evaluation is reported separately for the 2012 UCI messages and the modern UK
examples, because a model that's great on old spam can still miss today's scams.
A Naive Bayes baseline is trained on the same split for comparison.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

from .data import load_all
from .checker import decide
from .model import DEFAULT_MODEL_PATH, ScamModel, build_pipeline, new_metadata
from .signals import detect

SEED = 42


def scores(y_true, y_pred) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "false_positives": int(fp), "false_negatives": int(fn),
        "true_positives": int(tp), "true_negatives": int(tn), "n": int(len(y_true)),
    }


def split(texts, labels, test_size):
    return train_test_split(texts, labels, test_size=test_size, random_state=SEED, stratify=labels)


def main(argv=None) -> dict:
    ap = argparse.ArgumentParser(description="Train the ScamCheck model")
    ap.add_argument("--out", type=Path, default=DEFAULT_MODEL_PATH)
    ap.add_argument("--metrics", type=Path, default=Path(DEFAULT_MODEL_PATH).with_name("metrics.json"))
    args = ap.parse_args(argv)

    data = load_all()
    u_tr, u_te, uy_tr, uy_te = split(*data["uci"], test_size=0.2)
    m_tr, m_te, my_tr, my_te = split(*data["modern"], test_size=0.3)
    X_train, y_train = u_tr + m_tr, uy_tr + my_tr

    candidates = {
        "logistic_regression": build_pipeline(),
        "naive_bayes_baseline": Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=2)),
                                          ("clf", MultinomialNB(alpha=0.1))]),
    }
    metrics = {}
    for name, pipe in candidates.items():
        pipe.fit(X_train, y_train)
        metrics[name] = {
            "uci_test": scores(uy_te, pipe.predict(u_te)),
            "modern_uk_test": scores(my_te, pipe.predict(m_te)),
        }

    # The full system as users see it: model + warning-sign rules.
    # A message counts as flagged if the verdict is "scam" or "suspicious".
    lr = candidates["logistic_regression"]

    def system_predict(texts):
        probs = lr.predict_proba(texts)[:, 1]
        return [int(decide(p, detect(t), t)[0] != "no_signs") for t, p in zip(texts, probs)]

    metrics["model_plus_rules"] = {
        "uci_test": scores(uy_te, system_predict(u_te)),
        "modern_uk_test": scores(my_te, system_predict(m_te)),
    }

    # Final model: same settings, retrained on *all* data now that we've measured it.
    final = build_pipeline().fit(data["uci"][0] + data["modern"][0], data["uci"][1] + data["modern"][1])
    model = ScamModel(final, new_metadata(metrics, n_train=len(data["uci"][0]) + len(data["modern"][0])))
    model.save(args.out)
    args.metrics.parent.mkdir(parents=True, exist_ok=True)
    args.metrics.write_text(json.dumps(metrics, indent=2))

    print(f"{'model':<24}{'test set':<16}{'precision':>10}{'recall':>9}{'F1':>8}{'FP':>5}{'FN':>5}")
    for name, sets in metrics.items():
        for set_name, s in sets.items():
            print(f"{name:<24}{set_name:<16}{s['precision']:>10.3f}{s['recall']:>9.3f}{s['f1']:>8.3f}"
                  f"{s['false_positives']:>5}{s['false_negatives']:>5}")
    print(f"\nSaved model to {args.out}\nSaved metrics to {args.metrics}")
    return metrics


if __name__ == "__main__":
    main()
