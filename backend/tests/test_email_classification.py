import base64
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
    sender_domain = next(domain for domain in result["domains"] if domain["domain"] == "microsoft.com")
    assert sender_domain["reliability"] == "High"


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
    sender_domain = next(domain for domain in result["domains"] if domain["domain"] == "netflix-payment-alert.com")
    assert sender_domain["reliability"] == "Low"


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


def test_mcafee_subscription_call_scam_is_phishing():
    raw = make_email(
        "McAfee subscription renewal notice",
        "McAfee Billing <billing@support-renewal.example>",
        "Your McAfee antivirus subscription has expired. Call +1-888-555-0147 immediately to renew and avoid losing protection.",
    )

    result = analyze_email(raw, "mcafee-vishing.eml")

    assert result["classification"] == "PHISHING"
    assert "VISHING" in result["categories"]
    assert "support-renewal.example" in result["indicators"]["domains"]


def test_crypto_wallet_call_scam_with_external_link_is_phishing():
    raw = make_email(
        "Urgent Coinbase wallet security call",
        "Coinbase Security <security@coinbase-help.example>",
        "Your crypto wallet transaction is on hold. Call 1 800 555 0188 now to secure your account and recover your funds at https://coinbase-verify.example/secure.",
    )

    result = analyze_email(raw, "crypto-vishing.eml")

    assert result["classification"] == "PHISHING"
    assert "VISHING" in result["categories"]
    assert any(f["title"] == "Voice-phishing (vishing) risk" for f in result["findings"])


def test_spanish_single_word_alert_subject_is_phishing():
    raw = make_email(
        "¡Atención!: Bloqueo...",
        "Centro de seguridad <notice@account-review.example>",
        "Su acceso será bloqueado. Revise el mensaje para recuperar el acceso.",
    )

    result = analyze_email(raw, "spanish-alert-subject.eml")

    assert result["classification"] == "PHISHING"
    assert any(f["title"] == "Foreign-language phishing subject" for f in result["findings"])


def test_foreign_language_normal_subject_is_not_phishing_from_subject_alone():
    raw = make_email(
        "Oferta especial de verano",
        "Noticias <offers@newsletter.example>",
        "Descubre nuestras novedades y descuentos de temporada.",
    )

    result = analyze_email(raw, "spanish-normal-subject.eml")

    assert result["classification"] != "PHISHING"


def test_clean_senate_gov_marketing_message_is_legitimate_not_spam():
    message = EmailMessage()
    message["Subject"] = "Senator Moody's constituent newsletter"
    message["From"] = "Senator Moody <newsletter@moody.senate.gov>"
    message["To"] = "user@example.com"
    message["Date"] = "Mon, 01 Jan 2024 12:00:00 +0000"
    message["List-Unsubscribe"] = "<mailto:unsubscribe@moody.senate.gov>"
    message.set_content("Read this month's constituent update, committee news, and public service information from Senator Moody's office.")

    result = analyze_email(message.as_bytes(), "moody-newsletter.eml")

    assert result["classification"] == "LEGITIMATE"
    assert "MARKETING" in result["categories"]
    assert "SPAM" not in result["categories"]


def test_html_preview_sanitizes_active_content_and_embeds_inline_images():
    message = EmailMessage()
    message["Subject"] = "Visual receipt"
    message["From"] = "Store <receipts@store.example>"
    message["To"] = "user@example.com"
    message["Date"] = "Mon, 01 Jan 2024 12:00:00 +0000"
    message.set_content("Plain text receipt")
    message.add_alternative('<html><body><h1>Receipt</h1><img src="cid:logo"><script>alert(1)</script></body></html>', subtype="html")
    html_part = message.get_payload()[-1]
    html_part.add_related(b"fake-png-bytes", maintype="image", subtype="png", cid="<logo>")

    result = analyze_email(message.as_bytes(), "visual-receipt.eml")

    assert result["html_preview"]
    assert "data:image/png;base64," in result["html_preview"]
    assert "<script" not in result["html_preview"]
    assert "alert(1)" not in result["html_preview"]


def test_base64_encoded_plain_body_is_visible_in_inbox_preview():
    encoded_body = base64.b64encode("This is the visible message body.".encode("utf-8"))
    raw = (
        b"From: Store <receipts@store.example>\r\n"
        b"To: user@example.com\r\n"
        b"Subject: Encoded receipt\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        + encoded_body
    )

    result = analyze_email(raw, "encoded-receipt.eml")

    assert "This is the visible message body." in result["html_preview"]
