"""Combine the model and the warning-sign rules into one verdict.

    risk = max(model probability, rule score)

Either layer on its own can raise the alarm: the model catches scams that
"sound" like scams, and the rules catch structural tricks (a fake Royal Mail
link, a request for a security code) even in wording the model hasn't seen.
Any HIGH-severity sign means the verdict is at least "suspicious".
"""
from __future__ import annotations

from dataclasses import dataclass

from .model import ScamModel
from .signals import HIGH, MEDIUM, Signal, detect, official_links, rule_score

MAX_LENGTH = 2000            # a text message is rarely more than a few hundred characters
SCAM_THRESHOLD = 0.75
SUSPICIOUS_THRESHOLD = 0.5

VERDICTS = {
    "scam": ("Likely scam",
             "Don't tap any links, reply, or call numbers in this message."),
    "suspicious": ("Be careful",
                   "This has some warning signs. Check with the sender another way before doing anything."),
    "no_signs": ("No obvious warning signs",
                 "This doesn't look like a typical scam, but no tool is perfect. If it asks for money "
                 "or details, check first."),
}

ADVICE = [
    "If a message claims to be from a company, contact them using the phone number or website you "
    "already know, not the one in the message.",
    "In the UK you can forward scam texts to 7726 for free, then delete them.",
    "If you've already shared bank details, call your bank straight away using the number on your card.",
]


@dataclass
class Result:
    verdict: str
    label: str
    summary: str
    risk: float
    model_probability: float
    rule_score: float
    signals: list[Signal]
    model_terms: list[dict]

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict, "label": self.label, "summary": self.summary,
            "risk": round(self.risk, 3), "model_probability": round(self.model_probability, 3),
            "rule_score": round(self.rule_score, 3),
            "signals": [s.to_dict() for s in self.signals],
            "model_terms": self.model_terms, "advice": ADVICE,
        }


def decide(model_probability: float, signals: list[Signal], text: str = "") -> tuple[str, float, float]:
    rs = rule_score(signals)
    p = model_probability
    # Reassurance: the only links go to the named company's real website and there are
    # no medium/high warning signs. Genuine delivery and bank texts look like this.
    if text and official_links(text) and not any(s.severity in (HIGH, MEDIUM) for s in signals):
        p *= 0.5
    risk = max(p, rs)
    if risk >= SCAM_THRESHOLD:
        verdict = "scam"
    elif risk >= SUSPICIOUS_THRESHOLD or any(s.severity == HIGH for s in signals):
        verdict = "suspicious"
    else:
        verdict = "no_signs"
    return verdict, risk, rs


def check(text: str, model: ScamModel) -> Result:
    text = text.strip()
    if not text:
        raise ValueError("Please paste a message to check.")
    if len(text) > MAX_LENGTH:
        raise ValueError(f"That's too long for a text message (limit {MAX_LENGTH} characters).")
    p = model.probability(text)
    signals = detect(text)
    verdict, risk, rs = decide(p, signals, text)
    label, summary = VERDICTS[verdict]
    terms = model.top_terms(text) if verdict != "no_signs" else []
    return Result(verdict, label, summary, risk, p, rs, signals, terms)
