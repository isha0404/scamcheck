import json

import pytest

from scamcheck.checker import MAX_LENGTH, check, decide
from scamcheck.data import load_tsv, MODERN_FILE, UCI_FILE
from scamcheck.signals import Signal


# --- data --------------------------------------------------------------------
def test_datasets_load_with_expected_sizes():
    texts, labels = load_tsv(UCI_FILE)
    assert len(texts) == 5574 and sum(labels) == 747          # matches the published dataset
    m_texts, m_labels = load_tsv(MODERN_FILE)
    assert len(m_texts) > 150 and 0.3 < sum(m_labels) / len(m_labels) < 0.6


def test_bad_data_line_is_reported(tmp_path):
    bad = tmp_path / "bad.tsv"
    bad.write_text("maybe\tsome text\n")
    with pytest.raises(ValueError, match="line 1"):
        load_tsv(bad)


# --- model quality -------------------------------------------------------------
def test_metrics_meet_minimum_quality(model_path):
    metrics = json.loads(model_path.with_name("metrics.json").read_text())
    system = metrics["model_plus_rules"]
    assert system["uci_test"]["precision"] >= 0.95
    assert system["uci_test"]["recall"] >= 0.90
    assert system["modern_uk_test"]["recall"] >= 0.90
    # the chosen model must beat the Naive Bayes baseline
    assert metrics["logistic_regression"]["uci_test"]["f1"] > metrics["naive_bayes_baseline"]["uci_test"]["f1"]


@pytest.mark.parametrize("text", [
    "Royal Mail: Your parcel could not be delivered. Pay the £1.45 fee within 12 hours: royalmail-redelivery-uk.com",
    "HMRC: You are eligible for a tax refund of £286. Verify your details at hmrc-refund.info",
    "Hi Mum, this is my new number. Can you transfer £400 today? It's urgent",
    "URGENT! You have won a £2000 prize GUARANTEED. Call 09058094507 to claim. Valid 12hrs only",
    "Your bank account is locked due to unusual activity. Confirm your card details at bit.ly/bank-fix",
])
def test_obvious_scams_are_caught(model, text):
    assert check(text, model).verdict == "scam"


@pytest.mark.parametrize("text", [
    "Are we still on for dinner tonight? Table is booked for 7",
    "Your verification code is 482913. Do not share this code with anyone.",
    "Royal Mail: Your parcel from ASOS is due today between 10:15 and 11:15. Track it at royalmail.com/track",
    "Your NHS appointment is on Tuesday at 10:20. Reply CANCEL if you can no longer attend.",
    "Thanks for today, it was lovely to catch up",
])
def test_genuine_messages_are_not_flagged(model, text):
    assert check(text, model).verdict == "no_signs"


def test_model_explains_with_readable_terms(model):
    terms = [t["term"] for t in model.top_terms("Congratulations you have won a free prize, claim now")]
    assert terms and all(not t.isdigit() and len(t) > 2 for t in terms)
    assert any(w in " ".join(terms) for w in ("won", "prize", "claim", "free"))


# --- verdict logic --------------------------------------------------------------
def test_high_signal_makes_at_least_suspicious_even_if_model_is_unsure():
    sig = Signal("code_request", "t", "d", "high")
    assert decide(0.05, [sig])[0] == "suspicious"


def test_thresholds():
    assert decide(0.9, [])[0] == "scam"
    assert decide(0.6, [])[0] == "suspicious"
    assert decide(0.1, [])[0] == "no_signs"


def test_input_validation(model):
    with pytest.raises(ValueError):
        check("   ", model)
    with pytest.raises(ValueError):
        check("x" * (MAX_LENGTH + 1), model)


def test_result_serialises(model):
    d = check("Pay now at bit.ly/x", model).to_dict()
    json.dumps(d)
    assert {"verdict", "label", "risk", "signals", "model_terms", "advice"} <= d.keys()
