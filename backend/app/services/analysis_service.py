import hashlib, ipaddress, re, uuid
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html import escape
from urllib.parse import urlparse, unquote
from .whois_service import get_whois

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
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

# A small public-suffix safeguard for common multi-label registrations.  A
# production deployment should replace this with the Public Suffix List.
MULTI_LABEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au", "co.in", "com.br", "co.jp", "co.nz", "com.mx", "com.sg"}
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
    for brand, meta in KNOWN_BRANDS.items():
        brand_domains = meta["domains"]
        if any(brand_domain in sender for brand_domain in brand_domains):
            return False
        if brand in text and not any(domain in sender for domain in brand_domains):
            return True
    for url in urls:
        host = (url.get("host") or "").lower()
        for brand, meta in KNOWN_BRANDS.items():
            if brand in host:
                continue
            if brand in (subject + " " + body).lower() and url.get("risk_score", 0) >= 50:
                return True
    return False


def _classification_categories(score, findings, urls, attachments, sender_domain, subject, body):
    text = f"{subject}\n{body}".lower()
    categories = []

    if any(title in {"Brand impersonation risk", "Sender identity mismatch"} for title in [f["title"] for f in findings]):
        categories.append("BRAND_IMPERSONATION")
    if any(keyword in text for keyword in ["password", "mfa", "otp", "verify your account", "security code", "verification code", "update your password", "login now"]):
        categories.append("CREDENTIAL_PHISHING")
    if any(keyword in text for keyword in ["payment failed", "update your payment", "bank account", "wire transfer", "invoice payment failed", "gift card", "refund"]):
        categories.append("PAYMENT_PHISHING")
    if any(keyword in text for keyword in ["suspended", "security alert", "unusual activity", "account compromised", "locked", "unauthorized login"]):
        categories.append("ACCOUNT_COMPROMISE")
    if any(a.get("signals") for a in attachments):
        categories.append("MALWARE")
    if any(u.get("risk_score", 0) >= 50 for u in urls):
        categories.append("SUSPICIOUS_URL")
    if any(keyword in text for keyword in ["newsletter", "unsubscribe", "special offer", "limited time offer", "promotional", "bulk", "advertising"]):
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
    phishing_signal = any(hint in text for hint in PHISHING_HINTS)
    brand_impersonation = _looks_like_brand_impersonation(sender_domain, subject, body, urls)
    risky_urls = any(u.get("risk_score", 0) >= 50 for u in urls)
    suspicious_sender = bool(sender_domain) and not any(domain in sender_domain.lower() for brand in KNOWN_BRANDS for domain in KNOWN_BRANDS[brand]["domains"]) and (brand_impersonation or phishing_signal)

    if "Credential harvesting intent" in severe or "Brand impersonation risk" in severe or "Financial-pressure narrative" in severe:
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
        try:
            if p.get_content_type() == "text/plain": plain.append(p.get_content())
            elif p.get_content_type() == "text/html": html.append(p.get_content())
        except Exception: pass
    body = "\n".join(plain) + "\n" + "\n".join(html)
    sender, recipient, reply_to, return_path = _header(msg,"From"), _header(msg,"To"), _header(msg,"Reply-To"), _header(msg,"Return-Path")
    subject = _header(msg, "Subject") or "(No subject)"
    sender_domain, reply_domain = _domain(sender), _domain(reply_to)
    auth, urls, attachments = _auth(msg), _urls(body + "\n" + raw_headers), _attachments(msg)
    message_category = _classify_message(subject, body, msg)
    findings=[]
    def finding(sev, title, description, evidence, recommendation): findings.append({"severity":sev,"title":title,"description":description,"evidence":evidence,"why_it_matters":description,"recommendation":recommendation})
    auth_fails = [name.upper() for name, data in auth.items() if data.get("status") == "FAIL"]
    if auth_fails: finding("HIGH", "Authentication failure", "One or more sender authentication controls failed.", ", ".join(auth_fails), "Verify the sender through an independent channel.")
    same_org_reply = _same_organization(sender_domain, reply_domain)
    domain_relationship = _domain_relationship(sender_domain, reply_domain, subject, f"{sender}\n{body}")
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
    threat_score = 0
    for key, (label, pattern) in KEYWORDS.items():
        hit = re.search(pattern, normalized_body)
        if hit:
            keyword_hits.append(label)
            if key in {"urgent", "threat", "credential", "financial"}:
                threat_score += 8 if key in {"credential", "financial"} else 5
            finding("MEDIUM" if key in {"urgent", "threat"} else "INFO", label, "Language associated with this message type was detected; interpret it alongside independent technical signals.", hit.group(0), "Slow down and validate unexpected requests through a trusted channel.")
    if _looks_like_brand_impersonation(sender_domain, subject, body, urls):
        threat_score += 18
        finding("HIGH", "Brand impersonation risk", "The email references a known brand but the sender and destination context do not align with that brand's legitimate infrastructure.", f"Brand mentions: {', '.join(_extract_brand_mentions(subject, body))}; sender domain: {sender_domain}", "Verify the sender through a trusted official channel and do not click account-related links.")
    if any(hint in normalized_body for hint in ["password", "mfa", "otp", "verification code", "security code", "update your password", "verify your account", "login now"]):
        threat_score += 12
        finding("HIGH", "Credential harvesting intent", "The message is actively trying to get a password, MFA code, OTP, or other credentials.", "Credentials requested in the subject or body", "Do not provide any credentials or codes to unverified senders.")
    if any(hint in normalized_body for hint in ["payment failed", "update your payment", "wire transfer", "refund", "bank account", "gift card"]):
        threat_score += 10
        finding("HIGH", "Financial-pressure narrative", "The email attempts to create urgency around a financial action or payment problem.", "Account or payment action requested", "Verify payment requests through a known official channel before responding.")
    if "<script" in body.lower() or "javascript:" in body.lower(): finding("HIGH", "Active content in HTML", "HTML contains JavaScript-like active content.", "script/javascript URI detected", "Do not render this HTML outside a sandbox.")
    received_chain = _received_chain(msg)
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
    category("Threat Intelligence",10,0)
    score=min(100,sum(x["score"] for x in score_breakdown))

    phishing_boost = 0
    if any(hint in normalized_body for hint in ["password", "mfa", "otp", "verification code", "security code", "update your password", "verify your account", "login now"]):
        phishing_boost += 25
    if "Brand impersonation risk" in {f["title"] for f in findings}:
        phishing_boost += 20
    if "Financial-pressure narrative" in {f["title"] for f in findings}:
        phishing_boost += 15
    if "Credential harvesting intent" in {f["title"] for f in findings}:
        phishing_boost += 20
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
        domain_data.append({"domain":domain,"role":"Sender" if domain==sender_domain else "Referenced","age":f"Created: {whois.get('created_date', 'Unknown')}","dns":"WHOIS available" if whois.get("status") == "available" else "Not queried","reputation":"WHOIS data available" if whois.get("status") == "available" else "Unknown / no intelligence available","signals":whois_signals,"whois":whois})
    all_addresses=[a for _,a in getaddresses([sender,recipient,reply_to,return_path])]
    timeline=[{"time":datetime.now(timezone.utc).strftime("%H:%M:%S"),"event":"Sample parsed in memory"},{"time":"+00:01","event":"Headers, MIME parts, URLs and attachments extracted"},{"time":"+00:02","event":"Authentication and weighted risk engine completed"},{"time":"+00:02","event":f"Classification: {classification}"}]
    explanation = f"This email is classified as {classification}. " + (findings[0]["description"] if findings else "No high-confidence suspicious signals were identified from the available message data.")
    return {"id":str(uuid.uuid4()),"email_metadata":{"filename":filename,"subject":subject,"sender":sender or "Unknown","recipient":recipient or "Unknown","date":_header(msg,"Date") or "Unknown","reply_to":reply_to or "Not set","return_path":return_path or "Not set","message_id":_header(msg,"Message-ID") or "Not set","size":len(raw),"mime_type":msg.get_content_type(),"url_count":len(urls),"attachment_count":len(attachments),"sender_domain":sender_domain or "Unknown","sending_ip":received_ips[0] if received_ips else "Unknown"},"classification":classification,"categories":categories,"confidence":confidence,"message_category":message_category,"domain_relationship":domain_relationship,"verdict_explanation":explanation,"risk_score":score,"risk_level":level,"score_breakdown":score_breakdown,"authentication":auth,"headers":headers,"received_chain":received_chain,"domains":domain_data,"ips":ips,"urls":urls,"attachments":attachments,"content_analysis":{"social_engineering_indicators":keyword_hits,"html_detected":bool(html),"javascript_detected":"<script" in body.lower() or "javascript:" in body.lower(),"tracking_pixels":len(re.findall(r"<img[^>]+(?:width=[\"']?1|height=[\"']?1)", body, re.I)),"preview_text":_safe_html("\n".join(plain)[:3000])},"threat_intelligence":{"status":"No external intelligence provider configured","note":"Missing API data is not treated as clean."},"findings":findings,"indicators":{"emails":list(dict.fromkeys(all_addresses)),"domains":domains,"ips":received_ips,"urls":[u["normalized"] for u in urls],"hashes":[a["sha256"] for a in attachments],"message_ids":[_header(msg,"Message-ID")] if _header(msg,"Message-ID") else []},"recommendations":[f["recommendation"] for f in findings if f["severity"] != "INFO"] or ["No immediate action. Retain the original sample if further verification is needed."],"timeline":timeline,"raw_headers":raw_headers,"html_preview":None}
