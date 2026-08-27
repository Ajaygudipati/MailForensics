from email.message import EmailMessage

from app.services.analysis_service import analyze_email


def make_email(subject, sender, body, recipient="user@example.com") -> bytes:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    msg["Date"] = "Mon, 01 Jan 2024 12:00:00 +0000"
    msg.set_payload(body)
    return msg.as_bytes()


def test_phishing_content_without_url_is_not_legit():
    raw = make_email(
        "Your Microsoft account is suspended",
        'Microsoft Security <security@outlook-support-security.net>',
        "We detected unusual activity on your Microsoft account. Verify your password and MFA code immediately to avoid account suspension.",
    )

    result = analyze_email(raw, "phishing.eml")

    assert result["classification"] == "PHISHING"
    assert result["risk_score"] >= 60


def test_legitimate_transactional_email_stays_legitimate():
    raw = make_email(
        "Your Microsoft 365 invoice is ready",
        'Microsoft Billing <billing@microsoft.com>',
        "This is a transactional email from Microsoft. Your invoice is available in the billing portal at https://account.microsoft.com/billing.",
    )

    result = analyze_email(raw, "legit.eml")

    assert result["classification"] == "LEGITIMATE"
    assert result["risk_score"] < 40


def test_legitimate_branded_transaction_from_brand_domain_is_not_phishing():
    raw = make_email(
        "Netflix payment failed",
        'Netflix Billing <billing@netflix.com>',
        "We couldn't process your Netflix payment. Your account remains active and you can update your billing information in your Netflix account. Visit https://www.netflix.com/account/billing.",
    )

    result = analyze_email(raw, "netflix_legit.eml")

    assert result["classification"] == "LEGITIMATE"
    assert result["risk_score"] < 45


def test_branded_transaction_from_other_domain_is_phishing():
    raw = make_email(
        "Netflix payment failed",
        'Netflix Account Security <security@netflix-payment-alert.com>',
        "We couldn't process your Netflix payment. Verify your password and MFA code immediately to update your billing information. Visit https://netflix-payment-verification.xyz/login.",
    )

    result = analyze_email(raw, "netflix_phish.eml")

    assert result["classification"] == "PHISHING"
    assert result["risk_score"] >= 60


def test_promotion_email_with_brand_mention_is_not_phishing_by_default():
    raw = make_email(
        "Limited time offer from Adobe",
        'Adobe News <offers@newsletter-mailer.com>',
        "Save 40% on Creative Cloud this week with our limited time offer. Visit https://adobe-offers-mail.com/claim to explore the latest deals and exclusive pricing.",
    )

    result = analyze_email(raw, "promo.eml")

    assert result["message_category"]["code"] in {"ADVERTISEMENT", "MARKETING_NEWSLETTER"}
    assert result["classification"] != "PHISHING"
