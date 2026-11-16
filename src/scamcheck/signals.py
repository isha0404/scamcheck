"""Rule-based warning signs.

The machine learning model says *how* scam-like a message is; these rules say
*why*, in words a non-technical person can act on. Each rule returns Signals
with a plain-English title, an explanation, a severity, and the exact span of
text that triggered it so the web app can highlight it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

LOW, MEDIUM, HIGH = "low", "medium", "high"
WEIGHT = {LOW: 0.05, MEDIUM: 0.15, HIGH: 0.35}


@dataclass
class Signal:
    id: str
    title: str
    detail: str
    severity: str
    spans: list[tuple[int, int]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "detail": self.detail,
                "severity": self.severity, "spans": [list(s) for s in self.spans]}


# --- organisations scammers commonly impersonate in the UK, and their real domains ---
BRANDS: dict[str, tuple[str, list[str]]] = {
    # key: (display name, official domains)
    "royal mail": ("Royal Mail", ["royalmail.com"]),
    "royalmail": ("Royal Mail", ["royalmail.com"]),
    "evri": ("Evri", ["evri.com"]),
    "hermes": ("Evri", ["evri.com"]),
    "dpd": ("DPD", ["dpd.co.uk", "dpd.com"]),
    "dhl": ("DHL", ["dhl.com", "dhl.co.uk"]),
    "post office": ("Post Office", ["postoffice.co.uk"]),
    "hmrc": ("HMRC", ["gov.uk"]),
    "gov.uk": ("GOV.UK", ["gov.uk"]),
    "dvla": ("DVLA", ["gov.uk"]),
    "nhs": ("NHS", ["nhs.uk"]),
    "tv licen": ("TV Licensing", ["tvlicensing.co.uk"]),
    "hsbc": ("HSBC", ["hsbc.co.uk", "hsbc.com"]),
    "barclays": ("Barclays", ["barclays.co.uk"]),
    "lloyds": ("Lloyds Bank", ["lloydsbank.com"]),
    "halifax": ("Halifax", ["halifax.co.uk"]),
    "natwest": ("NatWest", ["natwest.com"]),
    "santander": ("Santander", ["santander.co.uk"]),
    "nationwide": ("Nationwide", ["nationwide.co.uk"]),
    "monzo": ("Monzo", ["monzo.com"]),
    "starling": ("Starling", ["starlingbank.com"]),
    "paypal": ("PayPal", ["paypal.com"]),
    "amazon": ("Amazon", ["amazon.co.uk", "amazon.com"]),
    "amzn": ("Amazon", ["amazon.co.uk", "amazon.com"]),
    "netflix": ("Netflix", ["netflix.com"]),
    "apple": ("Apple", ["apple.com"]),
    "icloud": ("Apple", ["apple.com", "icloud.com"]),
    "microsoft": ("Microsoft", ["microsoft.com"]),
    "disney": ("Disney+", ["disneyplus.com"]),
    "instagram": ("Instagram", ["instagram.com"]),
    "whatsapp": ("WhatsApp", ["whatsapp.com"]),
    "tesco": ("Tesco", ["tesco.com"]),
    "morrisons": ("Morrisons", ["morrisons.com"]),
    "sky": ("Sky", ["sky.com"]),
    "vodafone": ("Vodafone", ["vodafone.co.uk"]),
    " ee": ("EE", ["ee.co.uk"]),
    "o2": ("O2", ["o2.co.uk"]),
}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at",
              "ow.ly", "tiny.cc", "goo.gl", "rebrand.ly", "t.ly", "s.id"}
RISKY_TLDS = {"xyz", "top", "icu", "live", "online", "site", "click", "link", "info", "cc", "tk",
              "ml", "ga", "cf", "gq", "buzz", "rest", "help", "support", "services", "shop", "vip", "win"}
COMMON_TLDS = RISKY_TLDS | {"com", "uk", "org", "net", "co", "io", "me", "app", "gov", "us", "eu", "de",
                            "fr", "ru", "cn", "biz", "store", "page", "tv", "ly", "gd", "at", "id"}

# Domains: optional scheme, then labels, ending in a known TLD. Also bare IPv4 links.
_URL = re.compile(
    r"(?:https?://)?(?:www\.)?"
    r"(?P<host>(?:\d{1,3}(?:\.\d{1,3}){3})|(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?P<tld>[a-z]{2,10}))"
    r"(?P<path>/[^\s]*)?",
    re.IGNORECASE,
)
_IP_HOST = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@dataclass
class Link:
    text: str
    host: str
    start: int
    end: int


def find_links(text: str) -> list[Link]:
    links = []
    for m in _URL.finditer(text):
        host = m["host"].lower().rstrip(".")
        is_ip = bool(_IP_HOST.match(host))
        has_scheme = m.group(0).lower().startswith(("http", "www"))
        if not is_ip and (m["tld"] or "").lower() not in COMMON_TLDS:
            continue
        if is_ip and not (has_scheme or m["path"]):
            continue                                   # a bare version number like 1.2.3.4
        # avoid matching the "." in "e.g." or a sentence ending like "today.Next"
        if not is_ip and not has_scheme and len(host.split(".")[0]) < 2:
            continue
        links.append(Link(m.group(0).rstrip(".,!?)"), host, m.start(), m.start() + len(m.group(0).rstrip(".,!?)"))))
    return links


def _is_official(host: str, official: list[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in official)


def _spans(pattern: re.Pattern, text: str) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in pattern.finditer(text)]


def _rx(*words: str) -> re.Pattern:
    return re.compile(r"\b(?:" + "|".join(words) + r")\b", re.IGNORECASE)


URGENCY = _rx(r"urgent(?:ly)?", r"immediately", r"within \d+ ?(?:hours?|hrs?|minutes|mins|days?)",
              r"today", r"before midnight", r"final (?:notice|attempt|warning|reminder)", r"last chance",
              r"expires?", r"expired", r"deadline", r"act now", r"asap", r"right away", r"overdue")
PAYMENT = _rx(r"(?:small |shipping |handling |redelivery |delivery |customs |postage )?(?:fee|charge)",
              r"pay(?:ment)? (?:now|today|within)", r"unpaid", r"outstanding", r"settle", r"fine",
              r"penalty", r"toll", r"only pay")
MONEY = re.compile(r"£\s?\d[\d,]*(?:\.\d{2})?")
THREAT = _rx(r"suspended", r"suspension", r"locked", r"blocked", r"frozen", r"restricted", r"limited",
             r"deactivated", r"closed", r"deleted", r"unusual activity", r"suspicious activity",
             r"security breach", r"legal action", r"prosecution", r"arrest", r"warrant", r"disconnection",
             r"returned to sender", r"will be (?:returned|destroyed)")
PRIZE = _rx(r"won", r"winner", r"winnings", r"prize", r"claim (?:your|now|before)", r"selected",
            r"chosen", r"congratulations", r"free (?:gift|iphone|samsung)", r"gift ?card", r"voucher",
            r"reward points?", r"lucky")
REFUND = _rx(r"tax refund", r"rebate", r"refund of £", r"(?:are )?(?:owed|entitled to|eligible for)",
             r"overcharge(?:d)?", r"overpaid", r"compensation")
DETAILS = _rx(r"(?:verify|confirm|update) (?:your )?(?:details|identity|information|account|billing|payment|card)",
              r"card details", r"bank details", r"(?:your|card and) pin", r"security details",
              r"(?:enter|confirm|send|share|give)[^.?!]{0,15}password",
              r"enter(?:ing)? your card")
CODE_REQUEST = re.compile(
    r"\b(?:send|share|forward|tell|read|give|reply with)\b[^.?!]{0,40}\bcode\b"
    r"|\bcode\b[^.?!]{0,30}\b(?:to us|with (?:us|our team|me))\b"
    r"|\bcode\b[^?!]{0,60}\b(?:forward|send|share) (?:it|this|that)\b",
    re.IGNORECASE)
CODE_WARNING = re.compile(r"\b(?:do not|don't|never)\b[^.?!]{0,20}\b(?:share|give)\b", re.IGNORECASE)
FAMILY_GREETING = re.compile(r"\b(?:hi|hey|hello)\s+(?:mum|mom|dad|mam|mummy)\b", re.IGNORECASE)
NEW_PHONE = re.compile(r"\b(?:(?:this is )?(?:my )?new (?:phone )?number|lost my phone|phone (?:broke|smashed)|my phone broke|"
                       r"temporary number|dropped my phone|using a friend's)\b", re.IGNORECASE)
SEND_MONEY = _rx(r"(?:send|transfer)\s+(?:me\s+)?(?:£\s?\d[\d,]*|money)", r"pay (?:a|for) (?:bill|something)")
PREMIUM = re.compile(r"\b(?:09\d{8,9}|087[0-3]\d{7}|\d{2,3}p ?(?:/|per) ?(?:min|msg|mt|week)|150p)\b", re.IGNORECASE)
CALL_NUMBER = re.compile(r"\bcall\b[^.?!]{0,40}?(?:0\d{3}\s?\d{3}\s?\d{3,4}|0\d{4}\s?\d{6}|07\d{3}\s?\d{6})", re.IGNORECASE)
NOT_YOU = _rx(r"not you\??", r"(?:was|wasn't|was not|did) (?:not )?you", r"if this was not you", r"if you did not")
INVEST = _rx(r"crypto(?:currency)?", r"bitcoin", r"guaranteed (?:returns?|profit|approval)", r"double your money",
             r"invest(?:ment)?", r"no credit checks?")
JOB = re.compile(r"\b(?:earn|make)\s+£\s?\d[\d,]*(?:\s?-\s?£?\d[\d,]*)?\s*(?:a|per)?\s*(?:day|daily|hour|week)\b"
                 r"|\b(?:part[- ]time job|work from home|online job)\b", re.IGNORECASE)
CHAT_APPS = _rx(r"whatsapp", r"telegram")
REPLY_TO_ACTIVATE = re.compile(r"\breply\b[^.?!]{0,30}\b(?:reopen|activate) (?:this|the) (?:message|link)\b", re.IGNORECASE)


def detect(text: str) -> list[Signal]:
    """Return every warning sign found in a message, most serious first."""
    signals: list[Signal] = []
    lower = text.lower()
    links = find_links(text)
    suspicious_links = False

    # --- links -------------------------------------------------------------
    impersonated = mentioned_brands(text)

    for link in links:
        host = link.host
        official_match = any(_is_official(host, official) for _, official in impersonated)
        if not official_match:
            suspicious_links = True
        if _IP_HOST.match(host):
            signals.append(Signal("ip_link", "Link goes to a bare number address",
                                  f"'{link.text}' is a numeric IP address instead of a website name. "
                                  "Real organisations don't send links like this.", HIGH, [(link.start, link.end)]))
            continue
        if host in SHORTENERS:
            signals.append(Signal("short_link", "Link hides where it really goes",
                                  f"'{link.text}' uses a link shortener, so you can't see the real website "
                                  "before you tap it.", MEDIUM, [(link.start, link.end)]))
            continue
        # The message names a company, but the link isn't that company's website
        mismatched = [name for name, official in impersonated if not _is_official(host, official)]
        # A brand name hidden inside a different domain, e.g. royalmail-redelivery-uk.com
        lookalike = [name for key, (name, official) in BRANDS.items()
                     if re.sub(r"[^a-z0-9]", "", key) and re.sub(r"[^a-z0-9]", "", key) in re.sub(r"[^a-z0-9]", "", host)
                     and len(re.sub(r"[^a-z0-9]", "", key)) >= 3 and not _is_official(host, official)]
        if lookalike or (mismatched and not official_match):
            name = (lookalike or mismatched)[0]
            signals.append(Signal("fake_link", f"Link is not the real {name} website",
                                  f"The message looks like it's from {name}, but '{host}' is not one of "
                                  f"{name}'s official websites. Scammers register lookalike addresses.",
                                  HIGH, [(link.start, link.end)]))
        elif host.rsplit(".", 1)[-1] in RISKY_TLDS:
            signals.append(Signal("risky_domain", "Unusual website ending",
                                  f"'{host}' ends in '.{host.rsplit('.', 1)[-1]}', an ending that is cheap to "
                                  "register and often used for scam sites.", MEDIUM, [(link.start, link.end)]))
        elif not official_match:
            signals.append(Signal("link", "Contains a link",
                                  "Be careful with links in texts. If in doubt, go to the organisation's "
                                  "website yourself instead of tapping the link.", LOW, [(link.start, link.end)]))

    # --- what the message asks you to do ---------------------------------------
    code_req = _spans(CODE_REQUEST, text)
    if code_req and not CODE_WARNING.search(text):
        signals.append(Signal("code_request", "Asks you to share a security code",
                              "No genuine company or friend will ever ask you to send them a code you've "
                              "received. Sharing it lets someone take over your account.", HIGH, code_req))

    new_phone = _spans(NEW_PHONE, text)
    family = []
    if new_phone:
        greeting = _spans(FAMILY_GREETING, text)
        money = _spans(SEND_MONEY, text) + _spans(CHAT_APPS, text)
        family = new_phone + greeting + money
        if greeting or money:
            signals.append(Signal("family_impersonation", "Claims to be a family member on a new number",
                                  "The 'Hi Mum, new number' scam is very common. Call your family member on the "
                                  "number you already have before replying or sending money.",
                                  HIGH if money else MEDIUM, family))
        else:
            signals.append(Signal("new_number", "Mentions a new phone number",
                                  "If someone says they have a new number, check it's really them by contacting "
                                  "their old number or calling them.", LOW, new_phone))

    details = _spans(DETAILS, text)
    if details:
        signals.append(Signal("personal_details", "Asks for personal or payment details",
                              "Banks, HMRC and delivery firms don't ask you to confirm card or account "
                              "details through a text message link.", HIGH if links else MEDIUM, details))

    pay = _spans(PAYMENT, text)
    if pay and (MONEY.search(text) or links):
        signals.append(Signal("payment_request", "Asks you to pay a fee",
                              "A small 'redelivery' or 'release' fee is a classic trick to collect your card "
                              "details. Genuine delivery firms rarely charge by text.",
                              MEDIUM, pay + _spans(MONEY, text)))

    call = _spans(CALL_NUMBER, text)
    if call and (_spans(NOT_YOU, text) or _spans(THREAT, text) or "fraud" in lower or "support" in lower):
        signals.append(Signal("call_number", "Gives you a number to call",
                              "Scammers include their own phone number. Only call your bank or a company on "
                              "the number printed on your card or on their official website.", MEDIUM, call))

    premium = _spans(PREMIUM, text)
    if premium:
        signals.append(Signal("premium_rate", "Premium-rate number or charges",
                              "Numbers starting 09 or 087, and per-message charges like 150p, can cost a lot.",
                              MEDIUM, premium))

    if REPLY_TO_ACTIVATE.search(text):
        signals.append(Signal("reply_trick", "Asks you to reply to 'activate' a link",
                              "This trick gets around your phone's protection that disables links from "
                              "unknown senders.", HIGH, _spans(REPLY_TO_ACTIVATE, text)))

    # --- pressure tactics -----------------------------------------------------
    threat = _spans(THREAT, text)
    if threat:
        signals.append(Signal("threat", "Threatens bad consequences",
                              "Warnings that your account will be closed, or that you'll be fined or "
                              "arrested, are designed to scare you into acting without thinking.",
                              MEDIUM, threat))
    urgent = _spans(URGENCY, text)
    if urgent and (suspicious_links or pay or threat or details or family or call):
        signals.append(Signal("urgency", "Rushes you to act quickly",
                              "Scammers create a deadline so you don't stop to check. A genuine organisation "
                              "will give you time.", MEDIUM, urgent))

    # --- too good to be true ----------------------------------------------------
    prize = _spans(PRIZE, text)
    if prize:
        signals.append(Signal("prize", "Promises a prize or reward",
                              "If you didn't enter a competition, you can't have won it.",
                              MEDIUM if (links or premium or _spans(DETAILS, text)) else LOW, prize))
    refund = _spans(REFUND, text)
    if refund and (links or details or _spans(_rx("reply", "call", "click"), text)):
        signals.append(Signal("refund", "Offers a refund or money you're 'owed'",
                              "HMRC and energy companies don't tell you about refunds by text with a link.",
                              MEDIUM, refund))
    invest = _spans(INVEST, text)
    if invest:
        signals.append(Signal("investment", "Promises easy or guaranteed money",
                              "Nobody can guarantee investment returns. 'Double your money' offers are scams.",
                              MEDIUM, invest))
    job = _spans(JOB, text)
    if job:
        signals.append(Signal("job", "Offers easy money for little work",
                              "Unrequested job offers paying hundreds a day, often moved to WhatsApp or "
                              "Telegram, are a common way to steal money or recruit 'money mules'.",
                              HIGH if _spans(CHAT_APPS, text) else MEDIUM, job + _spans(CHAT_APPS, text)))

    order = {HIGH: 0, MEDIUM: 1, LOW: 2}
    return sorted(signals, key=lambda s: order[s.severity])


def mentioned_brands(text: str) -> list[tuple[str, list[str]]]:
    lower = text.lower()
    found = []
    for key, (name, official) in BRANDS.items():
        pattern = r"\bee\b" if key.strip() == "ee" else r"\b" + re.escape(key.strip())
        if re.search(pattern, lower):
            found.append((name, official))
    return found


def official_links(text: str) -> list[str]:
    """Links that go to the real website of a company the message names."""
    brands = mentioned_brands(text)
    return [l.host for l in find_links(text) if any(_is_official(l.host, off) for _, off in brands)]


def rule_score(signals: list[Signal]) -> float:
    """Combine signals into a 0-1 risk score. Each signal independently 'adds'
    risk, so two medium signals are more worrying than one, but the score
    never exceeds 1."""
    remaining = 1.0
    for s in signals:
        remaining *= 1 - WEIGHT[s.severity]
    return round(1 - remaining, 4)
