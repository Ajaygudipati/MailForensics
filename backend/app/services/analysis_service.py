import base64, hashlib, ipaddress, re, unicodedata, uuid
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html import escape
from html.parser import HTMLParser
from urllib.parse import urlparse, unquote
from .whois_service import get_whois

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PHONE_RE = re.compile(r"(?<![\w])(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,5}\)?[\s.-]?)(?:\d[\s.-]?){6,13}\d(?!\w)")
SUSPICIOUS_TLDS = {"zip", "top", "xyz", "click", "gq", "work", "country", "icu", "sbs"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "is.gd"}
KEYWORDS = {
    "urgent": ("Urgency language", "urgent|immediately|action required|within 24 hours|asap|today only"),
    "credential": ("Credential harvesting language", "password|verify your account|sign in|login|mfa|credentials|security code|otp|one[- ]time passcode|reset your password|update your password"),
    "financial": ("Financial request", "invoice|payment|wire transfer|bank account|gift card|refund|transfer money|card details|cvv|debit card"),
    "threat": ("Fear or account threat", "suspended|locked|termination|security alert|unusual activity|account compromised|unauthorized login|restricted"),
}

KNOWN_BRANDS = {
    "microsoft": {"domains": {"microsoft.com", "office.com", "outlook.com", "live.com", "xbox.com"}},
    "netflix": {"domains": {"netflix.com"}},
    "paypal": {"domains": {"paypal.com"}},
    "google": {"domains": {"google.com", "gmail.com"}},
    "apple": {"domains": {"apple.com", "icloud.com"}},
    "amazon": {"domains": {"amazon.com"}},
    "dropbox": {"domains": {"dropbox.com"}},
    "linkedin": {"domains": {"linkedin.com"}},
    "adobe": {"domains": {"adobe.com"}},
        "mcafee": {"domains": {"mcafee.com"}},
        "norton": {"domains": {"norton.com", "gen-digital.com"}},
        "coinbase": {"domains": {"coinbase.com"}},
        "ledger": {"domains": {"ledger.com"}},
        "metamask": {"domains": {"metamask.io"}},
}

PHISHING_HINTS = (
    "password reset",
    "verify your password",
    "mfa code",
    "security code",
    "account suspended",
    "suspended due to unusual activity",
    "update your payment",
    "bank account update",
    "invoice payment failed",
    "verify credentials",
    "confirm your identity",
    "login now",
    "action required",
    "immediately",
)
MULTILINGUAL_PHISHING_HINTS = (
    # Spanish
    "verifique su contraseña", "verifica tu contraseña", "inicie sesión", "inicia sesión", "cuenta suspendida", "actividad inusual", "actualice su pago", "llame ahora",
    # French
    "vérifiez votre mot de passe", "connectez-vous", "compte suspendu", "activité inhabituelle", "mettez à jour votre paiement", "appelez maintenant",
    # German
    "bestätigen sie ihr passwort", "melden sie sich an", "konto gesperrt", "ungewöhnliche aktivität", "zahlung aktualisieren", "rufen sie jetzt an",
    # Portuguese
    "verifique sua senha", "faça login", "conta suspensa", "atividade incomum", "atualize seu pagamento", "ligue agora",
    # Italian
    "verifica la tua password", "accedi al tuo account", "account sospeso", "attività insolita", "aggiorna il pagamento", "chiama ora",
    # Dutch
    "bevestig uw wachtwoord", "log in", "account opgeschort", "ongebruikelijke activiteit", "werk uw betaling bij", "bel nu",
    # Hindi (Devanagari)
    "अपना पासवर्ड सत्यापित करें", "खाते में लॉगिन करें", "खाता निलंबित", "असामान्य गतिविधि", "भुगतान अपडेट करें", "अभी कॉल करें",
    # Arabic
    "تحقق من كلمة المرور", "سجل الدخول", "الحساب معلق", "نشاط غير معتاد", "تحديث الدفع", "اتصل الآن",
    # Chinese and Japanese
    "验证您的密码", "登录您的账户", "账户已暂停", "异常活动", "更新付款信息", "立即致电", "パスワードを確認", "ログインしてください", "アカウントが停止", "不審なアクティビティ", "支払い情報を更新", "今すぐ電話",
)
MULTILINGUAL_SUSPICIOUS_TERMS = (
    "contraseña", "suspendida", "suspender", "inusual", "verifique", "inicie sesión", "llame", "mot de passe", "suspendu", "inhabituelle", "vérifiez", "connectez-vous", "appelez", "passwort", "gesperrt", "ungewöhnliche", "bestätigen", "anmelden", "anrufen", "senha", "suspensa", "incomum", "verifique", "faça login", "ligue", "password", "sospeso", "insolita", "verifica", "accedi", "chiama", "wachtwoord", "opgeschort", "ongebruikelijke", "bevestig", "log in", "bel", "كلمة المرور", "معلق", "غير معتاد", "تحقق", "سجل الدخول", "اتصل", "पासवर्ड", "निलंबित", "असामान्य", "सत्यापित", "लॉगिन", "कॉल", "密码", "暂停", "异常", "验证", "登录", "致电", "パスワード", "停止", "不審", "確認", "ログイン", "電話"
)
MULTILINGUAL_SUBJECT_TERMS = (
    "atención", "alerta", "bloqueo", "bloqueada", "suspendida", "urgente", "seguridad", "verificación",
    "attention", "alerte", "blocage", "bloqué", "suspendu", "urgent", "sécurité", "vérification",
    "achtung", "warnung", "gesperrt", "sperrung", "dringend", "sicherheit", "bestätigung",
    "atenção", "alerta", "bloqueada", "suspensa", "urgente", "segurança", "verificação",
    "attenzione", "blocco", "bloccato", "sospeso", "urgente", "sicurezza", "verifica",
    "let op", "waarschuwing", "geblokkeerd", "dringend", "beveiliging", "verificatie",
    "تنبيه", "محظور", "معلق", "عاجل", "أمان", "تحقق", "चेतावनी", "अवरुद्ध", "निलंबित", "तत्काल", "सुरक्षा",
    "警告", "已封锁", "暂停", "紧急", "安全", "验证", "警告", "停止", "緊急", "セキュリティ", "確認"
)
VISHING_CALL_TERMS = ("call", "phone", "telephone", "speak to", "contact our", "dial", "ring", "llame", "llamar", "llámenos", "appelez", "appeler", "telefonieren", "anrufen", "ligue", "ligar", "chiama", "bel", "اتصل", "कॉल", "कॉल करें", "立即致电", "今すぐ電話")
VISHING_PRESSURE_TERMS = ("login", "log in", "sign in", "verify", "security", "account", "password", "mfa", "otp", "payment", "refund", "suspended", "locked", "unauthorized", "urgent", "immediately", "subscription", "renewal", "expired", "antivirus", "virus", "malware", "wallet", "crypto", "cryptocurrency", "bitcoin", "ethereum", "seed phrase", "recovery phrase", "withdrawal", "transaction", "cuenta", "contraseña", "verifique", "suspendida", "activité", "mot de passe", "gesperrt", "passwort", "senha", "pagamento", "sospeso", "password", "оплата", "пароль", "аккаунт", "الحساب", "كلمة المرور", "खाता", "पासवर्ड", "密码", "账户", "パスワード", "アカウント")

# A small public-suffix safeguard for common multi-label registrations.  A
# production deployment should replace this with the Public Suffix List.
MULTI_LABEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au", "co.in", "com.br", "co.jp", "co.nz", "com.mx", "com.sg"}
TRUSTED_PUBLIC_SUFFIXES = (".gov", ".mil")
CATEGORY_RULES = (
    ("ONE_TIME_PASSWORD", "One-time password", r"\b(?:otp|one[- ]time (?:passcode|code)|verification code|security code)\b"),
    ("SUBSCRIPTION", "Subscription & renewal", r"\b(?:subscription|renewal|renewed|billing cycle|membership|trial period|cancel subscription)\b"),
    ("ADVERTISEMENT", "Advertisement & promotion", r"\b(?:advertisement|advertising|sponsored|promotion|promotional|discount|coupon|sale|limited time offer)\b"),
    ("JOB_APPLICATION", "Job application update", r"\b(?:application status|applicant|associate software|job application|candidate|recruitment process|hiring team)\b"),
    ("PAYMENT_ALERT", "Payment alert", r"\b(?:payment alert|payment failed|card charged|transaction|refund|chargeback|bank transfer)\b"),
    ("DELIVERY_NOTIFICATION", "Delivery notification", r"\b(?:delivery notification|out for delivery|delivered|tracking id|courier|shipment update)\b"),
    ("SECURITY_NOTIFICATION", "Security notification", r"\b(?:security notification|login attempt|sign-in attempt|new device|multi-factor authentication)\b"),
    ("SYSTEM_NOTIFICATION", "System notification", r"\b(?:automated message|system notification|do not reply|no-reply|notification)\b"),
    ("PASSWORD_RESET", "Password reset", r"\b(?:reset (?:your )?password|password reset)\b"),
    ("ACCOUNT_SECURITY", "Account security", r"\b(?:security alert|unusual activity|new sign[- ]in|account (?:was )?locked)\b"),
    ("ORDER", "Order", r"\b(?:order (?:confirmation|number|update)|purchase confirmation|your order)\b"),
    ("SHIPPING_DELIVERY", "Shipping & delivery", r"\b(?:delivery|shipment|tracking (?:number|update)|package)\b"),
    ("PAYMENT_INVOICE", "Payment & invoice", r"\b(?:invoice|payment (?:received|due|failed)|receipt|wire transfer)\b"),
    ("MARKETING_NEWSLETTER", "Marketing & newsletter", r"\b(?:unsubscribe|newsletter|special offer|exclusive offer|promotional)\b"),
    ("MEETING_CALENDAR", "Meeting & calendar", r"\b(?:meeting|calendar invite|scheduled|zoom|teams meeting)\b"),
    ("SUPPORT", "Customer support", r"\b(?:support ticket|case number|help (?:request|desk))\b"),
    ("DOCUMENT_SHARING", "Document sharing", r"\b(?:shared (?:a )?(?:document|file)|document (?:is )?ready|view (?:the )?document)\b"),
    ("HR_RECRUITING", "HR & recruiting", r"\b(?:job (?:application|offer)|interview|recruiter|career opportunity)\b"),
    ("LEGAL_COMPLIANCE", "Legal & compliance", r"\b(?:terms of service|privacy policy|legal notice|compliance)\b"),
    ("SOCIAL_MEDIA", "Social media", r"\b(?:new follower|liked your|connection request|social network)\b"),
    ("TRAVEL", "Travel", r"\b(?:flight|hotel reservation|boarding pass|itinerary)\b"),
    ("HEALTHCARE", "Healthcare", r"\b(?:appointment|prescription|patient portal|medical)\b"),
    ("GOVERNMENT", "Government", r"\b(?:tax|passport|government|benefits)\b"),
    ("EDUCATION", "Education", r"\b(?:course|university|student|enrollment)\b"),
)

def _header(msg, name): return str(msg.get(name, "")).strip()
def _domain(address):
    match = re.search(r"@([A-Za-z0-9.-]+)", address or "")
    return match.group(1).lower() if match else ""
def _organizational_domain(domain):
    """Return a pragmatic registrable domain, so tm.openai.com == openai.com."""
    labels = (domain or "").strip(".").lower().split(".")
    if len(labels) < 2: return domain.lower() if domain else ""
    suffix = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if suffix in MULTI_LABEL_SUFFIXES and len(labels) >= 3 else suffix
def _same_organization(first, second):
    return bool(first and second and _organizational_domain(first) == _organizational_domain(second))

def _is_trusted_public_domain(domain):
    normalized = (domain or "").strip(".").lower()
    return any(normalized.endswith(suffix) for suffix in TRUSTED_PUBLIC_SUFFIXES)

def _domain_reliability(domain):
    normalized = (domain or "").strip(".").lower()
    signals = []
    if not normalized:
        return {"score": 0, "label": "Unknown", "signals": ["No sender domain was available"]}
    score = 70
    if not re.fullmatch(r"[a-z0-9.-]+", normalized) or "." not in normalized:
        score -= 35
        signals.append("Malformed or non-registrable sender domain")
    if IP_RE.fullmatch(normalized):
        score -= 45
        signals.append("Sender uses an IP address instead of a domain")
    if normalized.startswith("xn--") or ".xn--" in normalized:
        score -= 30
        signals.append("Punycode domain can conceal lookalike characters")
    tld = normalized.rsplit(".", 1)[-1] if "." in normalized else ""
    if tld in SUSPICIOUS_TLDS:
        score -= 25
        signals.append(f"High-abuse TLD: .{tld}")
    if _is_trusted_public_domain(normalized):
        score = max(score, 88)
        signals.append("Recognized public-sector domain suffix")
    if any(_organizational_domain(normalized) == domain_name for brand in KNOWN_BRANDS.values() for domain_name in brand["domains"]):
        score = max(score, 84)
        signals.append("Matches a known brand organization")
    risky_tokens = ("verify", "secure", "support", "alert", "payment", "renewal", "recovery", "wallet", "login", "account")
    if normalized.count("-") >= 2 and any(token in normalized for token in risky_tokens):
        score -= 22
        signals.append("Multiple separators and security-themed domain tokens")
    label = "High" if score >= 75 else "Medium" if score >= 50 else "Low" if score >= 25 else "Very low"
    return {"score": max(0, min(100, score)), "label": label, "signals": signals or ["No obvious structural domain warning"]}

def _domain_relationship(sender_domain, reply_domain, subject, body):
    if not reply_domain: return {"verdict": "NO_REPLY_TO", "confidence": "high", "company_mentions": [], "matched_terms": [], "explanation": "No Reply-To address was present."}
    if _same_organization(sender_domain, reply_domain):
        return {"verdict": "SAME_ORGANIZATION", "confidence": "high", "company_mentions": [], "matched_terms": [], "explanation": "Reply-To belongs to the same registrable organization as the visible sender."}
    text = f"{subject}\n{body}"
    company_mentions = list(dict.fromkeys(re.findall(r"(?:at|from|with|join|on behalf of)\s+([A-Z][A-Za-z0-9&.-]*(?:\s+[A-Z][A-Za-z0-9&.-]*){0,4})", text)))
    body_terms = set(re.findall(r"[a-z0-9]{4,}", text.lower()))
    domain_terms = set(re.findall(r"[a-z0-9]{4,}", reply_domain.lower()))
    matched_terms = sorted(term for term in body_terms if any(term in domain_term or domain_term in term for domain_term in domain_terms))
    if matched_terms:
        return {"verdict": "CONTEXTUALLY_ALIGNED", "confidence": "medium", "company_mentions": company_mentions, "matched_terms": matched_terms[:8], "explanation": "The Reply-To domain is different from the visible sender, but its name is supported by company language in the message."}
    return {"verdict": "UNEXPLAINED_MISMATCH", "confidence": "medium", "company_mentions": company_mentions, "matched_terms": [], "explanation": "The Reply-To domain is different from the visible sender and was not matched to recognizable company language."}

def _whois_lookup(domain):
    result = get_whois(domain)
    if result["status"] != "success":
        return {"status": "lookup_failed", "error": "; ".join(result["issues"]), "response": result}
    data = result["data"]
    return {"status": "available", "created_date": data["creation_date"], "updated_date": data["updated_date"], "expiry_date": data["expiration_date"], "registrar": data["registrar"], "registrant": data["registrant"], "registrant_country": data["country"], "domain_status": data["status"], "nameservers": data["name_servers"], "response": result}
def _classify_message(subject, body, msg):
    corpus = f"{subject}\n{body}".lower()
    for code, label, pattern in CATEGORY_RULES:
        match = re.search(pattern, corpus, re.I)
        if match:
            return {"code": code, "label": label, "confidence": "high", "evidence": match.group(0), "note": "Category describes the email's apparent purpose, not its safety."}
    if _header(msg, "List-Unsubscribe") or _header(msg, "List-ID"):
        return {"code":"MARKETING_NEWSLETTER", "label":"Marketing & newsletter", "confidence":"medium", "evidence":"List-Unsubscribe or List-ID header", "note":"Category describes the email's apparent purpose, not its safety."}
    return {"code":"GENERAL", "label":"General / uncategorized", "confidence":"low", "evidence":"No strong category pattern", "note":"Category describes the email's apparent purpose, not its safety."}

def _received_chain(msg):
    """Normalize Received headers into chronological mail hops (oldest first)."""
    hops = []
    for index, value in enumerate(reversed(msg.get_all("Received", [])), start=1):
        text = str(value).replace("\n", " ").replace("\r", " ")
        route, _, timestamp = text.rpartition(";")
        from_match = re.search(r"\bfrom\s+([^\s(]+)", route, re.I)
        by_match = re.search(r"\bby\s+([^\s(]+)", route, re.I)
        ips = IP_RE.findall(route)
        protocol = re.search(r"\bwith\s+([^\s;]+)", route, re.I)
        tls = bool(re.search(r"\b(?:TLS|ESMTPS|SMTPS)\b", route, re.I))
        hops.append({
            "hop": index,
            "from_host": from_match.group(1) if from_match else "Unspecified sender host",
            "to_host": by_match.group(1) if by_match else "Unspecified receiving host",
            "ip": ips[0] if ips else None,
            "timestamp": timestamp.strip() or "Timestamp unavailable",
            "protocol": protocol.group(1).upper() if protocol else "SMTP",
            "tls": tls,
            "raw": text,
        })
    return hops
def _safe_html(value): return escape(value or "")

def _decode_text_part(part):
    payload = part.get_payload(decode=True)
    if payload is None:
        raw_payload = part.get_payload()
        return raw_payload if isinstance(raw_payload, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeError):
        return payload.decode("utf-8", errors="replace")

class _EmailPreviewSanitizer(HTMLParser):
    allowed_tags = {"a", "article", "b", "blockquote", "br", "div", "em", "h1", "h2", "h3", "head", "hr", "i", "img", "li", "main", "ol", "p", "section", "small", "span", "strong", "table", "tbody", "td", "th", "thead", "title", "tr", "u", "ul"}
    allowed_attributes = {"alt", "align", "height", "title", "width"}

    def __init__(self, cid_images):
        super().__init__(convert_charrefs=True)
        self.cid_images = cid_images
        self.output = []
        self.ignored_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in {"embed", "form", "iframe", "object", "script", "style"}:
            self.ignored_depth += 1
            return
        if self.ignored_depth:
            return
        if tag not in self.allowed_tags:
            return
        safe_attrs = []
        for name, value in attrs:
            name = name.lower()
            value = value or ""
            if tag == "img" and name == "src":
                cid = value[4:].strip("<>") if value.lower().startswith("cid:") else ""
                value = self.cid_images.get(cid, value)
                if not (value.startswith("data:image/") or value.startswith("https://") or value.startswith("http://")):
                    continue
                safe_attrs.append(("src", value))
            elif name in self.allowed_attributes:
                safe_attrs.append((name, value))
            elif tag == "a" and name == "href" and value.lower().startswith(("https://", "http://")):
                safe_attrs.extend((("href", value), ("target", "_blank"), ("rel", "noopener noreferrer")))
        rendered = "<" + tag + "".join(f' {name}="{escape(value, quote=True)}"' for name, value in safe_attrs) + ">"
        self.output.append(rendered)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag.lower() in {"embed", "form", "iframe", "object", "script", "style"}:
            self.ignored_depth = max(0, self.ignored_depth - 1)
            return
        if self.ignored_depth:
            return
        if tag.lower() in self.allowed_tags and tag.lower() not in {"br", "hr", "img"}:
            self.output.append(f"</{tag.lower()}>")

    def handle_data(self, data):
        if self.ignored_depth:
            return
        self.output.append(escape(data))

    def handle_comment(self, data):
        return

def _render_html_preview(msg, html_parts, plain_parts=None):
    cid_images = {}
    for part in msg.walk():
        content_id = part.get("Content-ID")
        payload = part.get_payload(decode=True)
        if content_id and payload and part.get_content_maintype() == "image":
            mime_type = part.get_content_type()
            cid_images[str(content_id).strip("<>")] = f"data:{mime_type};base64,{base64.b64encode(payload).decode('ascii')}"
    sanitizer = _EmailPreviewSanitizer(cid_images)
    if html_parts:
        sanitizer.feed("\n".join(html_parts))
    elif plain_parts:
        plain_text = "\n".join(plain_parts).strip()
        cursor = 0
        for match in URL_RE.finditer(plain_text):
            sanitizer.handle_data(plain_text[cursor:match.start()])
            url = match.group(0)
            sanitizer.output.append(f'<a href="{escape(url, quote=True)}" target="_blank" rel="noopener noreferrer">{escape(url)}</a>')
            cursor = match.end()
        sanitizer.handle_data(plain_text[cursor:])
        sanitizer.output.insert(0, '<div class="plain-message">')
        sanitizer.output.append("</div>")
    else:
        return None
    return """<!doctype html><html><head><meta charset="utf-8"><style>body{margin:0;padding:28px;background:#f5f7f8;color:#172126;font:15px Arial,sans-serif;line-height:1.55}main{max-width:760px;margin:auto;background:#fff;padding:28px;border:1px solid #dfe6e8}img{max-width:100%;height:auto}a{color:#147d68}table{max-width:100%;border-collapse:collapse}td,th{padding:6px;border:1px solid #dfe6e8}.plain-message{white-space:pre-wrap;overflow-wrap:anywhere}</style></head><body><main>""" + "".join(sanitizer.output) + "</main></body></html>"
def _is_public_ip(ip):
    try: return ipaddress.ip_address(ip).is_global
    except ValueError: return False

def _auth(msg):
    auth = " ".join([_header(msg, "Authentication-Results"), _header(msg, "Received-SPF")]).lower()
    def status(name):
        if re.search(rf"{name}[=\s]+pass", auth): return "PASS"
        if re.search(rf"{name}[=\s]+(?:fail|softfail|temperror|permerror)", auth): return "FAIL"
        return "NONE"
    return {
        "spf": {"status": status("spf"), "record": "Not queried — parsed from message headers only."},
        "dkim": {"status": status("dkim"), "signing_domain": re.search(r"\bd=([^;\s]+)", _header(msg, "DKIM-Signature")) .group(1) if re.search(r"\bd=([^;\s]+)", _header(msg, "DKIM-Signature")) else None},
        "dmarc": {"status": status("dmarc"), "policy": "Unknown"},
        "arc": {"status": "PRESENT" if _header(msg, "ARC-Seal") else "NONE"},
    }

def _urls(text):
    found = []
    for original in dict.fromkeys(URL_RE.findall(text or "")):
        normalized = original if original.startswith("http") else "https://" + original
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower()
        risks = []
        if parsed.scheme == "http": risks.append("Unencrypted HTTP link")
        if host in SHORTENERS: risks.append("URL shortener obscures final destination")
        if host.startswith("xn--"): risks.append("Punycode host can mask lookalike characters")
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", host): risks.append("IP-address URL")
        if (host.rsplit(".", 1)[-1] if "." in host else "") in SUSPICIOUS_TLDS: risks.append("High-abuse TLD")
        if any(x in (parsed.query or "").lower() for x in ["password", "token", "login", "redirect"]): risks.append("Sensitive or redirect-style query parameter")
        found.append({"original": original, "normalized": normalized, "host": host, "domain": host, "path": unquote(parsed.path), "protocol": parsed.scheme, "risk_score": min(100, len(risks) * 22), "signals": risks, "reputation": "Unknown / no intelligence available"})
    return found

def _phone_numbers(text):
    numbers = []
    for match in PHONE_RE.findall(text or ""):
        value = re.sub(r"\s+", " ", match).strip(" .-")
        digits = re.sub(r"\D", "", value)
        if 7 <= len(digits) <= 15 and value not in numbers:
            numbers.append(value)
    return numbers

def _fold_text(text):
    return "".join(char for char in unicodedata.normalize("NFKD", text.lower()) if not unicodedata.combining(char))

def _localized_phishing_hits(text, allow_single=False):
    lowered = (text or "").lower()
    folded = _fold_text(lowered)
    exact_hits = [hint for hint in MULTILINGUAL_PHISHING_HINTS if hint in lowered or _fold_text(hint) in folded]
    term_hits = [term for term in MULTILINGUAL_SUSPICIOUS_TERMS if term in lowered or _fold_text(term) in folded]
    single_hits = [term for term in MULTILINGUAL_SUBJECT_TERMS if term in lowered or _fold_text(term) in folded] if allow_single else []
    return list(dict.fromkeys(exact_hits + (term_hits if len(term_hits) >= 2 else []) + single_hits))

def _has_phishing_language(text):
    lowered = (text or "").lower()
    return any(hint in lowered for hint in PHISHING_HINTS) or bool(_localized_phishing_hits(lowered))

def _suspicious_foreign_subject(subject):
    hits = _localized_phishing_hits(subject, allow_single=True)
    alert_format = bool(re.search(r"[!¡¿?:…]|\.\.\.", subject or ""))
    return (hits and alert_format) or len(set(hits)) >= 2, hits

def _looks_like_vishing(subject, body, raw_headers, sender_domain="", urls=None):
    text = f"{subject}\n{body}\n{raw_headers}".lower()
    numbers = _phone_numbers(f"{subject}\n{body}")
    call_terms = [term for term in VISHING_CALL_TERMS if re.search(rf"\b{re.escape(term)}\b", text)]
    pressure_terms = [term for term in VISHING_PRESSURE_TERMS if re.search(rf"\b{re.escape(term)}\b", text)]
    header_risk = bool(re.search(r"(?:authentication-results|received-spf):[^\n]*(?:fail|softfail|permerror)", text, re.I))
    brand_mismatch = any(
        brand in text
        and not any(_organizational_domain(sender_domain) == domain for domain in KNOWN_BRANDS[brand]["domains"])
        for brand in KNOWN_BRANDS
    )
    external_link = any(
        url.get("host") and not _same_organization(sender_domain, url.get("host", ""))
        for url in (urls or [])
    )
    return numbers and call_terms and (pressure_terms or header_risk or brand_mismatch or external_link), numbers, call_terms, pressure_terms

def _attachments(msg):
    items=[]
    dangerous = {"exe", "js", "vbs", "ps1", "bat", "cmd", "scr", "lnk", "hta", "docm", "xlsm"}
    for part in msg.walk():
        filename = part.get_filename()
        if not filename or part.get_content_disposition() not in ("attachment", "inline"): continue
        payload = part.get_payload(decode=True) or b""
        ext = filename.rsplit(".",1)[-1].lower() if "." in filename else ""
        signals=[]
        if ext in dangerous: signals.append("Potentially executable or macro-enabled attachment")
        if re.search(r"\.(pdf|doc|xls|jpg|png)\.(exe|js|vbs|scr)$", filename, re.I): signals.append("Double-extension filename")
        items.append({"name": filename, "mime_type": part.get_content_type(), "size": len(payload), "extension": ext or "None", "sha256": hashlib.sha256(payload).hexdigest(), "sha1": hashlib.sha1(payload).hexdigest(), "md5": hashlib.md5(payload).hexdigest(), "risk_score": 75 if signals else 0, "signals": signals, "reputation": "Unknown / no intelligence available"})
    return items

def _extract_brand_mentions(subject: str, body: str):
    text = f"{subject}\n{body}".lower()
    hits = []
    for brand in KNOWN_BRANDS:
        if brand in text:
            hits.append(brand)
    return hits


def _looks_like_brand_impersonation(sender_domain: str, subject: str, body: str, urls: list[dict]):
    sender = (sender_domain or "").lower()
    text = f"{subject}\n{body}".lower()
    mentioned_brands = [brand for brand in KNOWN_BRANDS if brand in text]
    if not mentioned_brands:
        return False

    marketing_only = any(keyword in text for keyword in ["newsletter", "unsubscribe", "special offer", "limited time offer", "promotional", "bulk", "advertising", "sponsored", "discount", "coupon", "sale"]) and not any(token in text for token in ["password", "mfa", "otp", "security code", "verification code", "update your password", "verify your account", "login now", "payment failed", "update your payment", "wire transfer", "refund", "bank account", "gift card", "invoice payment failed", "suspended", "locked", "account compromised", "unauthorized login"]) 
    if marketing_only:
        return False

    for brand in mentioned_brands:
        brand_domains = KNOWN_BRANDS[brand]["domains"]
        sender_matches_brand = any(domain in sender for domain in brand_domains)
        if sender_matches_brand:
            continue

        external_urls = [
            url for url in urls
            if (url.get("host") or "").lower() and not any(domain in (url.get("host") or "").lower() for domain in brand_domains)
        ]
        if external_urls:
            return True

        if any(phrase in text for phrase in ["verify your password", "mfa code", "security code", "update your payment", "login now", "account suspended"]):
            return True

    return False


def _classification_categories(score, findings, urls, attachments, sender_domain, subject, body):
    text = f"{subject}\n{body}".lower()
    categories = []
    if any(f["title"] == "Voice-phishing (vishing) risk" for f in findings):
        categories.append("VISHING")

    marketing_signals = any(keyword in text for keyword in ["newsletter", "unsubscribe", "special offer", "limited time offer", "promotional", "bulk", "advertising", "sponsored", "discount", "coupon", "sale"])
    if marketing_signals:
        categories.append("MARKETING")

    if any(title in {"Brand impersonation risk", "Sender identity mismatch"} for title in [f["title"] for f in findings]):
        categories.append("BRAND_IMPERSONATION")
    branded_sender = bool(sender_domain) and any(brand_name in (subject + " " + body).lower() for brand_name in KNOWN_BRANDS)
    if any(keyword in text for keyword in ["password", "mfa", "otp", "verify your account", "security code", "verification code", "update your password", "login now"]) and branded_sender:
        categories.append("CREDENTIAL_PHISHING")
    if any(keyword in text for keyword in ["payment failed", "update your payment", "bank account", "wire transfer", "invoice payment failed", "gift card", "refund"]) and branded_sender:
        categories.append("PAYMENT_PHISHING")
    if any(keyword in text for keyword in ["suspended", "security alert", "unusual activity", "account compromised", "locked", "unauthorized login"]):
        categories.append("ACCOUNT_COMPROMISE")
    if any(a.get("signals") for a in attachments):
        categories.append("MALWARE")
    if any(u.get("risk_score", 0) >= 50 for u in urls):
        categories.append("SUSPICIOUS_URL")
    if any(keyword in text for keyword in ["newsletter", "unsubscribe", "special offer", "limited time offer", "promotional", "bulk", "advertising"]) and not _is_trusted_public_domain(sender_domain):
        categories.append("SPAM")
    if any(keyword in text for keyword in ["keep this confidential", "urgent", "make a payment", "bank account change", "gift card", "vendor", "payroll", "invoice fraud"]):
        categories.append("BEC")

    if not categories:
        if score >= 60:
            categories.append("SUSPICIOUS")
        elif score >= 25:
            categories.append("SPAM")
        else:
            categories.append("LEGITIMATE")

    return list(dict.fromkeys(categories))


def _classification(score, findings, urls, attachments, sender_domain, subject, body):
    severe = {f["title"] for f in findings if f["severity"] in {"HIGH", "CRITICAL"}}
    text = f"{subject}\n{body}".lower()
    phishing_signal = _has_phishing_language(text)
    brand_impersonation = _looks_like_brand_impersonation(sender_domain, subject, body, urls)
    risky_urls = any(u.get("risk_score", 0) >= 50 for u in urls)
    suspicious_sender = bool(sender_domain) and not any(domain in sender_domain.lower() for brand in KNOWN_BRANDS for domain in KNOWN_BRANDS[brand]["domains"]) and (brand_impersonation or phishing_signal)
    trusted_public_origin = _is_trusted_public_domain(sender_domain)

    marketing_only = any(keyword in text for keyword in ["newsletter", "unsubscribe", "special offer", "limited time offer", "promotional", "bulk", "advertising", "sponsored", "discount", "coupon", "sale"]) and not any(hint in text for hint in ["password", "mfa", "otp", "security code", "verification code", "update your password", "verify your account", "login now", "payment failed", "update your payment", "wire transfer", "refund", "bank account", "gift card", "invoice payment failed", "suspended", "locked", "account compromised", "unauthorized login"]) and not any(f["title"] in {"Brand impersonation risk", "Sender identity mismatch", "Credential harvesting intent", "Financial-pressure narrative"} for f in findings)

    if marketing_only:
        return "LEGITIMATE" if trusted_public_origin or score < 25 else "SPAM"

    if trusted_public_origin and not severe and not risky_urls and not attachments and not phishing_signal and not brand_impersonation:
        return "LEGITIMATE"

    if "Voice-phishing (vishing) risk" in severe or "Foreign-language phishing subject" in severe or "Credential harvesting intent" in severe or "Brand impersonation risk" in severe or "Financial-pressure narrative" in severe:
        return "PHISHING"
    if suspicious_sender or brand_impersonation:
        return "PHISHING"
    if score >= 80 and (urls or attachments):
        return "PHISHING"
    if score >= 60 and ("Authentication failure" in severe or "Sender identity mismatch" in severe or risky_urls):
        return "PHISHING"
    if score >= 45 and (phishing_signal or risky_urls):
        return "PHISHING"
    if score >= 50:
        return "SUSPICIOUS"
    if score >= 25:
        return "SPAM"
    return "LEGITIMATE" if score < 25 else "UNKNOWN"

def analyze_email(raw: bytes, filename: str):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    headers = [{"name": k, "value": str(v)} for k,v in msg.items()]
    raw_headers = raw.split(b"\n\n",1)[0].decode("utf-8", "replace")
    plain, html = [], []
    for p in msg.walk():
        if p.get_content_disposition() == "attachment": continue
        if p.get_content_type() == "text/plain": plain.append(_decode_text_part(p))
        elif p.get_content_type() == "text/html": html.append(_decode_text_part(p))
    body = "\n".join(plain) + "\n" + "\n".join(html)
    sender, recipient, reply_to, return_path = _header(msg,"From"), _header(msg,"To"), _header(msg,"Reply-To"), _header(msg,"Return-Path")
    subject = _header(msg, "Subject") or "(No subject)"
    sender_domain, reply_domain = _domain(sender), _domain(reply_to)
    sender_reliability = _domain_reliability(sender_domain)
    auth, urls, attachments = _auth(msg), _urls(body + "\n" + raw_headers), _attachments(msg)
    vishing, phone_numbers, call_terms, pressure_terms = _looks_like_vishing(subject, body, raw_headers, sender_domain, urls)
    message_category = _classify_message(subject, body, msg)
    findings=[]
    def finding(sev, title, description, evidence, recommendation): findings.append({"severity":sev,"title":title,"description":description,"evidence":evidence,"why_it_matters":description,"recommendation":recommendation})
    auth_fails = [name.upper() for name, data in auth.items() if data.get("status") == "FAIL"]
    if auth_fails: finding("HIGH", "Authentication failure", "One or more sender authentication controls failed.", ", ".join(auth_fails), "Verify the sender through an independent channel.")
    if sender_reliability["score"] < 45:
        finding("MEDIUM", "Low sender-domain reliability", "The visible sender domain has structural or naming characteristics commonly seen in disposable, lookalike, or abuse-prone infrastructure. This is supporting evidence, not proof of phishing by itself.", "; ".join(sender_reliability["signals"]), "Validate the sender using an independent official source before trusting links, payments, or account requests.")
    same_org_reply = _same_organization(sender_domain, reply_domain)
    domain_relationship = _domain_relationship(sender_domain, reply_domain, subject, f"{sender}\n{body}")
    if not vishing and phone_numbers and call_terms and (auth_fails or (reply_domain and sender_domain and not same_org_reply)):
        vishing = True
    if reply_domain and sender_domain and not same_org_reply:
        if domain_relationship["verdict"] == "CONTEXTUALLY_ALIGNED":
            finding("INFO", "Contextually aligned intermediate domain", "Reply-To uses a different company domain, but the message body contains matching company language. This can indicate a legitimate MTA, recruiting, CRM, or notification relay.", f"From: {sender_domain}; Reply-To: {reply_domain}; matched terms: {', '.join(domain_relationship['matched_terms'])}", "Confirm the relationship with authentication results and the observed mail path before trusting the message.")
        else:
            finding("HIGH", "Sender identity mismatch", "Reply-To uses a different organizational domain from the visible sender and could not be explained by message context.", f"From: {sender_domain} ({_organizational_domain(sender_domain)}); Reply-To: {reply_domain} ({_organizational_domain(reply_domain)})", "Do not reply or submit credentials until verified.")
    elif reply_domain and sender_domain and same_org_reply and reply_domain != sender_domain:
        finding("INFO", "Aligned Reply-To subdomain", "Reply-To is a subdomain or sibling host within the sender's organizational domain; this is common for transactional mail.", f"From: {sender_domain}; Reply-To: {reply_domain}; organization: {_organizational_domain(sender_domain)}", "No action is required from this signal alone. Continue to evaluate authentication and other indicators.")
    if (_header(msg, "List-Unsubscribe") or _header(msg, "List-ID") or _header(msg, "Precedence").lower() == "bulk"):
        finding("INFO", "Bulk or marketing mail context", "List-management headers indicate a marketing or newsletter delivery pattern. This does not prove the sender is legitimate.", "List-Unsubscribe, List-ID, or Precedence: bulk present", "Evaluate authentication, sender alignment, and links before trusting the message.")
    for u in urls:
        if u["signals"]: finding("MEDIUM" if u["risk_score"] < 50 else "HIGH", "Suspicious URL characteristic", "; ".join(u["signals"]), u["original"], "Open links only after independent validation.")
    for a in attachments:
        if a["signals"]: finding("HIGH", "Risky attachment", "; ".join(a["signals"]), a["name"], "Do not open the attachment outside a sandbox.")
    keyword_hits=[]
    normalized_body=body.lower()
    localized_hits = _localized_phishing_hits(f"{subject}\n{body}\n{raw_headers}")
    foreign_subject_risk, foreign_subject_hits = _suspicious_foreign_subject(subject)
    threat_score = 0
    for key, (label, pattern) in KEYWORDS.items():
        hit = re.search(pattern, normalized_body)
        if hit:
            keyword_hits.append(label)
            if key in {"urgent", "threat", "credential", "financial"}:
                threat_score += 8 if key in {"credential", "financial"} else 5
            finding("MEDIUM" if key in {"urgent", "threat"} else "INFO", label, "Language associated with this message type was detected; interpret it alongside independent technical signals.", hit.group(0), "Slow down and validate unexpected requests through a trusted channel.")
    if localized_hits:
        threat_score += 12
        finding("HIGH", "Suspicious language in message", "The email contains translated or non-English account, security, payment, or call-to-action language associated with phishing. Language alone is evaluated together with headers, links, and other evidence.", ", ".join(localized_hits[:8]), "Verify the sender and any requested action through an official channel; do not use contact details or links supplied by the message.")
    if foreign_subject_risk:
        threat_score += 15
        finding("HIGH", "Foreign-language phishing subject", "The subject contains localized blocking, alert, security, or verification language in an urgent format. This is treated as a strong indicator when evaluated with sender identity, authentication, links, and message content.", ", ".join(foreign_subject_hits[:8]), "Verify the message through the organization's official website instead of using links or contact details in the email.")
    if _looks_like_brand_impersonation(sender_domain, subject, body, urls):
        threat_score += 18
        finding("HIGH", "Brand impersonation risk", "The email references a known brand but the sender and destination context do not align with that brand's legitimate infrastructure.", f"Brand mentions: {', '.join(_extract_brand_mentions(subject, body))}; sender domain: {sender_domain}", "Verify the sender through a trusted official channel and do not click account-related links.")
    if any(hint in normalized_body for hint in ["password", "mfa", "otp", "verification code", "security code", "update your password", "verify your account", "login now"]):
        threat_score += 12
        finding("HIGH", "Credential harvesting intent", "The message is actively trying to get a password, MFA code, OTP, or other credentials.", "Credentials requested in the subject or body", "Do not provide any credentials or codes to unverified senders.")
    if any(hint in normalized_body for hint in ["payment failed", "update your payment", "wire transfer", "refund", "bank account", "gift card"]):
        threat_score += 10
        finding("HIGH", "Financial-pressure narrative", "The email attempts to create urgency around a financial action or payment problem.", "Account or payment action requested", "Verify payment requests through a known official channel before responding.")
    if vishing:
        threat_score += 15
        finding("HIGH", "Voice-phishing (vishing) risk", "The message directs the recipient to call a phone number while discussing account, login, security, or payment action. This combination is a common voice-phishing pattern.", f"Phone number(s): {', '.join(phone_numbers)}; call language: {', '.join(call_terms)}; suspicious context: {', '.join(pressure_terms)}", "Do not call the number in the email. Use the organization's official website or a trusted statement to find its phone number.")
    if "<script" in body.lower() or "javascript:" in body.lower(): finding("HIGH", "Active content in HTML", "HTML contains JavaScript-like active content.", "script/javascript URI detected", "Do not render this HTML outside a sandbox.")
    received_chain = _received_chain(msg)
    html_preview = _render_html_preview(msg, html, plain)
    received_ips = list(dict.fromkeys(ip for ip in IP_RE.findall(raw_headers) if _is_public_ip(ip)))
    if received_ips: ips=[{"ip":ip,"reverse_dns":"Not queried","reputation":"Unknown / no intelligence available","is_public":True} for ip in received_ips]
    else: ips=[]
    score_breakdown=[]
    def category(name, max_score, raw_score): score_breakdown.append({"category":name,"score":min(max_score,raw_score),"max_score":max_score,"explanation":"Independent signals only; capped to prevent double-counting."})
    category("Authentication",25, 18 if auth_fails else (5 if all(v["status"]=="NONE" for v in auth.values() if "status" in v) else 0))
    category("Spoofing",15, 13 if reply_domain and sender_domain and domain_relationship["verdict"] == "UNEXPLAINED_MISMATCH" else 0)
    category("URLs",20,min(20,sum(7 for u in urls if u["signals"])))
    category("Attachments",10,min(10,sum(8 for a in attachments if a["signals"])))
    category("Content",15, min(15, threat_score))
    category("Infrastructure",10,3 if received_ips else 0)
    category("Domain Reliability",10, max(0, round((70 - sender_reliability["score"]) / 7)))
    category("Threat Intelligence",10,0)
    score=min(100,sum(x["score"] for x in score_breakdown))

    phishing_boost = 0
    if _has_phishing_language(normalized_body):
        phishing_boost += 25
    if "Brand impersonation risk" in {f["title"] for f in findings}:
        phishing_boost += 20
    if "Financial-pressure narrative" in {f["title"] for f in findings}:
        phishing_boost += 15
    if "Credential harvesting intent" in {f["title"] for f in findings}:
        phishing_boost += 20
    if "Voice-phishing (vishing) risk" in {f["title"] for f in findings}:
        phishing_boost += 25
    if "Sender identity mismatch" in {f["title"] for f in findings}:
        phishing_boost += 15
    if any(key in {"urgent", "threat", "credential", "financial"} for key in ["urgent", "threat", "credential", "financial"] if re.search(KEYWORDS[key][1], normalized_body, re.I)):
        phishing_boost += 10
    score = min(100, score + phishing_boost)
    classification=_classification(score, findings, urls, attachments, sender_domain, subject, body)
    categories = _classification_categories(score, findings, urls, attachments, sender_domain, subject, body)
    confidence = round(min(0.99, max(0.1, 0.35 + (score / 100) * 0.55 + (len(categories) * 0.03))), 2)
    level = "Very Low" if score<20 else "Low" if score<40 else "Medium" if score<60 else "High" if score<80 else "Critical"
    domains=list(dict.fromkeys(filter(None,[sender_domain,reply_domain]+[u["domain"] for u in urls])))
    domain_data=[]
    for domain in domains:
        whois = _whois_lookup(domain)
        whois_signals = []
        if whois.get("status") == "available":
            whois_signals = [f"Registrar: {whois.get('registrar', 'Unknown')}", f"Registrant: {whois.get('registrant', 'Unknown')}", f"Expires: {whois.get('expiry_date', 'Unknown')}"]
            if whois.get("nameservers"): whois_signals.append(f"Nameservers: {', '.join(whois['nameservers'][:3])}")
        if domain.startswith("xn--"): whois_signals.insert(0, "Punycode domain")
        reliability = _domain_reliability(domain)
        domain_data.append({"domain":domain,"role":"Sender" if domain==sender_domain else "Referenced","age":f"Created: {whois.get('created_date', 'Unknown')}","dns":"WHOIS available" if whois.get("status") == "available" else "Not queried","reputation":"WHOIS data available" if whois.get("status") == "available" else "Unknown / no intelligence available","reliability_score":reliability["score"],"reliability":reliability["label"],"signals":list(dict.fromkeys(reliability["signals"] + whois_signals)),"whois":whois})
    all_addresses=[a for _,a in getaddresses([sender,recipient,reply_to,return_path])]
    timeline=[{"time":datetime.now(timezone.utc).strftime("%H:%M:%S"),"event":"Sample parsed in memory"},{"time":"+00:01","event":"Headers, MIME parts, URLs and attachments extracted"},{"time":"+00:02","event":"Authentication and weighted risk engine completed"},{"time":"+00:02","event":f"Classification: {classification}"}]
    explanation = f"This email is classified as {classification}. " + (findings[0]["description"] if findings else "No high-confidence suspicious signals were identified from the available message data.")
    return {"id":str(uuid.uuid4()),"email_metadata":{"filename":filename,"subject":subject,"sender":sender or "Unknown","recipient":recipient or "Unknown","date":_header(msg,"Date") or "Unknown","reply_to":reply_to or "Not set","return_path":return_path or "Not set","message_id":_header(msg,"Message-ID") or "Not set","size":len(raw),"mime_type":msg.get_content_type(),"url_count":len(urls),"attachment_count":len(attachments),"sender_domain":sender_domain or "Unknown","sending_ip":received_ips[0] if received_ips else "Unknown"},"classification":classification,"categories":categories,"confidence":confidence,"message_category":message_category,"domain_relationship":domain_relationship,"verdict_explanation":explanation,"risk_score":score,"risk_level":level,"score_breakdown":score_breakdown,"authentication":auth,"headers":headers,"received_chain":received_chain,"domains":domain_data,"ips":ips,"urls":urls,"attachments":attachments,"content_analysis":{"social_engineering_indicators":keyword_hits,"vishing_numbers":phone_numbers,"html_detected":bool(html),"javascript_detected":"<script" in body.lower() or "javascript:" in body.lower(),"tracking_pixels":len(re.findall(r"<img[^>]+(?:width=[\"']?1|height=[\"']?1)", body, re.I)),"preview_text":_safe_html("\n".join(plain)[:3000])},"threat_intelligence":{"status":"No external intelligence provider configured","note":"Missing API data is not treated as clean."},"findings":findings,"indicators":{"emails":list(dict.fromkeys(all_addresses)),"domains":domains,"ips":received_ips,"urls":[u["normalized"] for u in urls],"phone_numbers":phone_numbers,"hashes":[a["sha256"] for a in attachments],"message_ids":[_header(msg,"Message-ID")] if _header(msg,"Message-ID") else []},"recommendations":[f["recommendation"] for f in findings if f["severity"] != "INFO"] or ["No immediate action. Retain the original sample if further verification is needed."],"timeline":timeline,"raw_headers":raw_headers,"html_preview":html_preview}
