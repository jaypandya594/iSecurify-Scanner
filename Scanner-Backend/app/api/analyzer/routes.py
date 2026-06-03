from datetime import timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.db.base import get_db
from app.db.models import ScanSummary, ScanScoreHistory, User
from app.core.middleware import protect
import httpx
import os

router = APIRouter(prefix="/score", tags=["Scoring"])

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

def build_categorized_vulnerabilities(scans: ScanSummary) -> dict:
    categorized = {}

    if scans.app_security:
        categorized["Application Security"] = scans.app_security
    if scans.network_security:
        categorized["Network Security"] = scans.network_security
    if scans.tls_security:
        categorized["TLS Security"] = scans.tls_security
    if scans.dns_security:
        categorized["DNS Security"] = scans.dns_security

    return categorized


@router.get("/get_score")
def get_score(
    domain: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect)
):
    score = db.query(ScanSummary).filter(
        ScanSummary.org_id == current_user.org_id,
        ScanSummary.domain == domain.strip().lower()
    ).first()
    if not score:
        raise HTTPException(
            status_code=404,
            detail="Score not found for the given domain."
        )
    return {
        "org_id": score.org_id,
        "domain_score": score.domain_score,
        "host": {
            "domain": score.domain,
            "mail_security": score.mail_security or {}
        },
        "severity": score.severity,
        "categorized_vulnerabilities": build_categorized_vulnerabilities(score),
        "ips": score.ips or []
    }


@router.delete("/delete_score/{org_id}")
def delete_score(
    org_id: str,
    db: Session = Depends(get_db)
):
    score = db.query(ScanSummary).filter(
        ScanSummary.org_id == org_id
    ).first()
    if not score:
        raise HTTPException(status_code=404, detail="Score not found")
    
    db.delete(score)
    db.commit()
    return {"detail": "Score deleted successfully"}


@router.get("/ip-reputation")
async def ip_reputation(
    ip: str = Query(..., description="IP address to check"),
    current_user: User = Depends(protect),
):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="AbuseIPDB API key not configured")

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
                headers={"Key": api_key, "Accept": "application/json"},
            )
            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"AbuseIPDB error: {response.text}",
                )
            result = response.json().get("data", {})
            return {
                "ip": ip,
                "abuseConfidenceScore": result.get("abuseConfidenceScore", 0),
                "totalReports": result.get("totalReports", 0),
                "countryCode": result.get("countryCode", ""),
                "isp": result.get("isp", ""),
                "domain": result.get("domain", ""),
                "isPublic": result.get("isPublic", True),
                "usageType": result.get("usageType", ""),
                "lastReportedAt": result.get("lastReportedAt"),
            }
    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail=f"Failed to reach AbuseIPDB: {exc}")


@router.get("/history")
def get_score_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(protect)
):
    if not current_user.org_id:
        raise HTTPException(status_code=400, detail="User not associated with an organization")

    history = (
        db.query(ScanScoreHistory)
        .filter(ScanScoreHistory.org_id == current_user.org_id)
        .order_by(ScanScoreHistory.scan_date.desc())
        .all()
    )

    return [
        {
            "org_id": item.org_id,
            "domain": item.domain,
            "domain_score": item.domain_score,
            "result": item.result or {},
            "scan_date": (
                item.scan_date.astimezone(timezone.utc).isoformat()
                if item.scan_date and item.scan_date.tzinfo is not None
                else item.scan_date.isoformat() if item.scan_date else None
            ),
        }
        for item in history
    ]
