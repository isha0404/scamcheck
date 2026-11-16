"""Load the training data.

1. SMS Spam Collection (UCI, 2012): 5,574 real labelled SMS messages.
   Almeida, T. & Hidalgo, J. (2011). https://doi.org/10.24432/C5CC84 (CC BY 4.0)
2. modern_uk_examples.tsv: modern UK-style scam texts (parcel fees, HMRC,
   bank 'new payee', 'Hi Mum') and genuine look-alike messages, written for this
   project because the 2012 data contains almost none of today's scams.
"""
from __future__ import annotations

from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
UCI_FILE = DATA_DIR / "SMSSpamCollection"
MODERN_FILE = DATA_DIR / "modern_uk_examples.tsv"


def load_tsv(path: Path) -> tuple[list[str], list[int]]:
    """Read 'label<TAB>text' lines. Returns (texts, labels) with 1 = scam/spam, 0 = genuine."""
    texts, labels = [], []
    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            label, sep, text = line.partition("\t")
            if not sep or label not in ("ham", "spam"):
                raise ValueError(f"{path.name} line {n}: expected 'ham' or 'spam', a tab, then the message")
            texts.append(text.strip())
            labels.append(1 if label == "spam" else 0)
    return texts, labels


def load_all() -> dict[str, tuple[list[str], list[int]]]:
    return {"uci": load_tsv(UCI_FILE), "modern": load_tsv(MODERN_FILE)}
