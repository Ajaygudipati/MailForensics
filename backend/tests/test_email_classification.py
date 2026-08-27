from email.message import EmailMessage

from app.services.analysis_service import analyze_email


def make_email(subject, sender, body, recipient="user@example.com") -> bytes:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    msg["Date"] = "Mon, 01 Jan 2024 12:00:00 +0000"
    msg.set_content(body)
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


def test_vishing_email_with_phone_and_login_pressure_is_phishing():
    raw = make_email(
        "Urgent security alert - call now",
        "Account Support <support@account-alerts.example>",
        "Your account is locked due to unusual activity. Call +1 (800) 555-0199 immediately and provide the verification code to restore your login.",
    )

    result = analyze_email(raw, "vishing.eml")

    assert result["classification"] == "PHISHING"
    assert "VISHING" in result["categories"]
    assert "+1 (800) 555-0199" in result["indicators"]["phone_numbers"]
    assert any(f["title"] == "Voice-phishing (vishing) risk" for f in result["findings"])


def test_phone_number_without_suspicious_call_context_is_not_vishing():
    raw = make_email(
        "Your order receipt",
        "Store Receipts <receipts@store.example>",
        "Thank you for your purchase. For general customer service, our published contact number is 800-555-0199. Your receipt is attached.",
    )

    result = analyze_email(raw, "receipt.eml")

    assert "VISHING" not in result["categories"]
    assert not any(f["title"] == "Voice-phishing (vishing) risk" for f in result["findings"])


def test_spanish_phishing_language_is_detected():
    raw = make_email(
        "Su cuenta está suspendida",
        "Seguridad <alertas@account-check.example>",
        "Detectamos actividad inusual. Verifique su contraseña e inicie sesión inmediatamente en https://account-check.example/login.",
    )

    result = analyze_email(raw, "spanish-phishing.eml")

    assert result["classification"] == "PHISHING"
    assert any(f["title"] == "Suspicious language in message" for f in result["findings"])


def test_spanish_promotion_is_not_phishing_without_security_pressure():
    raw = make_email(
        "Oferta especial de Adobe",
        "Noticias <offers@newsletter.example>",
        "Ahorra 40% con nuestra oferta especial y descubre nuevos productos. Visita https://newsletter.example/oferta.",
    )

    result = analyze_email(raw, "spanish-promotion.eml")

    assert result["classification"] != "PHISHING"


def test_foreign_language_vishing_with_international_number_is_phishing():
    raw = make_email(
        "Votre compte est suspendu - appelez maintenant",
        "Service de sécurité <alert@secure-account.example>",
        "Nous avons détecté une activité inhabituelle. Vérifiez votre mot de passe et appelez le +33 1 23 45 67 89 immédiatement pour réactiver votre compte.",
    )

    result = analyze_email(raw, "french-vishing.eml")

    assert result["classification"] == "PHISHING"
    assert "VISHING" in result["categories"]
    assert any(f["title"] == "Suspicious language in message" for f in result["findings"])
    assert any("33" in number and "23" in number for number in result["indicators"]["phone_numbers"])


def test_authentication_failure_and_call_target_escalate_sparse_message():
    raw = make_email(
        "Security notice",
        "Security Desk <notice@untrusted.example>",
        "Call 020 7946 0958 now about your account.",
    )
    raw = raw.replace(
        b"Date: Mon, 01 Jan 2024 12:00:00 +0000",
        b"Date: Mon, 01 Jan 2024 12:00:00 +0000\nAuthentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail",
    )

    result = analyze_email(raw, "header-vishing.eml")

    assert result["classification"] == "PHISHING"
    assert "VISHING" in result["categories"]
