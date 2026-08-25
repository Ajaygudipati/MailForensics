from datetime import date, datetime
from typing import Any


def format_date(value: Any) -> str:
    if not value:
        return "Unknown"
    if isinstance(value, (list, tuple)):
        value = next((item for item in value if item), None)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)
