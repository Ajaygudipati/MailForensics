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
