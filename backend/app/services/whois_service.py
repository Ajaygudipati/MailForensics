import whois

from app.utils.date_formatter import format_date


def get_whois(domain: str):
    try:
        result = whois.whois(domain)
        name_servers = result.name_servers or []
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        return {
            "status": "success",
            "data": {
                "domain": result.domain_name or domain,
                "registrar": result.registrar or "Unknown",
                "creation_date": format_date(result.creation_date),
                "expiration_date": format_date(result.expiration_date),
                "updated_date": format_date(getattr(result, "updated_date", None)),
                "name_servers": name_servers,
                "registrant": getattr(result, "org", None) or getattr(result, "name", None) or "Redacted / unavailable",
                "country": getattr(result, "country", None) or "Unknown",
                "status": getattr(result, "status", None) or "Unknown",
            },
            "issues": [],
            "recommendations": [],
        }
    except Exception as error:
        return {
            "status": "failed",
            "data": {},
            "issues": [str(error)],
            "recommendations": ["Unable to retrieve WHOIS information."],
        }
