from typing import Any
from pydantic import BaseModel

class AnalysisResponse(BaseModel):
    id: str
    email_metadata: dict[str, Any]
    classification: str
    message_category: dict[str, Any]
    domain_relationship: dict[str, Any]
    verdict_explanation: str
    risk_score: int
    risk_level: str
    score_breakdown: list[dict[str, Any]]
    authentication: dict[str, Any]
    headers: list[dict[str, str]]
    received_chain: list[dict[str, Any]]
    domains: list[dict[str, Any]]
    ips: list[dict[str, Any]]
    urls: list[dict[str, Any]]
    attachments: list[dict[str, Any]]
    content_analysis: dict[str, Any]
    threat_intelligence: dict[str, Any]
    findings: list[dict[str, Any]]
    indicators: dict[str, list[str]]
    recommendations: list[str]
    timeline: list[dict[str, str]]
    raw_headers: str
    html_preview: str | None = None
