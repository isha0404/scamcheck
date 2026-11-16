import pytest

from scamcheck.signals import HIGH, detect, find_links, official_links, rule_score


def ids(text):
    return {s.id for s in detect(text)}


# --- links -------------------------------------------------------------------
@pytest.mark.parametrize("text,host", [
    ("go to royalmail-redelivery-uk.com now", "royalmail-redelivery-uk.com"),
    ("visit https://www.evri.com/track", "evri.com"),
    ("tap bit.ly/abc123", "bit.ly"),
    ("log in at http://185.244.12.9/secure", "185.244.12.9"),
])
def test_finds_links(text, host):
    assert [l.host for l in find_links(text)] == [host]


@pytest.mark.parametrize("text", ["It costs £1.45 today", "Meet at 3.30pm", "e.g. tomorrow", "version 1.2.3.4"])
def test_does_not_mistake_numbers_or_abbreviations_for_links(text):
    assert find_links(text) == []


def test_lookalike_brand_domain_is_high():
    sigs = detect("Royal Mail: pay your fee at royalmail-redelivery-uk.com")
    fake = [s for s in sigs if s.id == "fake_link"]
    assert fake and fake[0].severity == HIGH and "Royal Mail" in fake[0].title


def test_named_brand_with_unrelated_link_is_flagged():
    assert "fake_link" in ids("HSBC: a new payee was added. Cancel at secure-cancel-payee.com")


def test_real_brand_link_is_not_flagged():
    text = "Royal Mail: your parcel is due today. Track at royalmail.com/track"
    assert "fake_link" not in ids(text)
    assert official_links(text) == ["royalmail.com"]


def test_subdomain_of_official_site_is_trusted():
    assert official_links("Evri: track at track.evri.com/123") == ["track.evri.com"]


def test_brand_name_as_subdomain_of_other_site_is_fake():
    # evri.redelivery-help.top is NOT evri.com, even though it starts with "evri."
    assert "fake_link" in ids("Evri: rebook at evri.redelivery-help.top")


def test_shortener_and_ip_links():
    assert "short_link" in ids("Update now: bit.ly/x")
    assert "ip_link" in ids("Restore access at 185.244.12.9/secure")


# --- behaviours --------------------------------------------------------------
def test_code_request_flagged_but_code_warning_is_not():
    assert "code_request" in ids("Please send us the 6 digit code we just sent you")
    assert "code_request" in ids("I sent my code to your number by mistake, can you forward it to me?")
    assert "code_request" not in ids("Your code is 123456. Never share this code with anyone.")


def test_hi_mum_scam():
    sigs = {s.id: s for s in detect("Hi Mum, new number. Can you send £300 today?")}
    assert sigs["family_impersonation"].severity == HIGH


def test_friend_asking_for_new_number_is_only_low():
    sigs = detect("Can you send me your new number? I lost my contacts")
    assert [s.severity for s in sigs] == ["low"]


def test_payment_and_urgency():
    found = ids("Pay the £1.99 customs fee within 24 hours: dpd-customs.xyz")
    assert {"payment_request", "urgency", "fake_link"} <= found


def test_urgency_alone_with_official_link_is_ignored():
    assert ids("Evri: your parcel arrives today. Track at evri.com/track") == set()


def test_job_scam():
    assert "job" in ids("Part-time job, earn £300 a day. Contact us on WhatsApp")


def test_ordinary_messages_have_no_signs():
    for text in ["Are we still on for coffee tomorrow?", "Running late, see you at 7",
                 "Your dentist appointment is tomorrow at 3:30pm"]:
        assert detect(text) == []


def test_spans_point_at_the_trigger_text():
    text = "Your account is suspended. Verify your details at bit.ly/x"
    for s in detect(text):
        for start, end in s.spans:
            assert 0 <= start < end <= len(text)
    threat = next(s for s in detect(text) if s.id == "threat")
    a, b = threat.spans[0]
    assert text[a:b].lower() == "suspended"


def test_rule_score_is_bounded_and_monotonic():
    assert rule_score([]) == 0
    one = rule_score(detect("bit.ly/x"))
    many = rule_score(detect("URGENT: account suspended. Verify your card details now at bit.ly/x"))
    assert 0 < one < many <= 1
