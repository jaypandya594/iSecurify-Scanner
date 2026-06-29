import random
import string
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from app.core.middleware import require_admin
from app.db.base import get_db
from app.db.models import ReportedIssue, User

router = APIRouter(prefix="/report-issue", tags=["report-issue"])


# ─── Schemas ──────────────────────────────────────────────────────────────────

class ReportIssueRequest(BaseModel):
    domain: str
    subdomain: Optional[str] = None
    rule: str
    severity: Optional[str] = None
    issueType: str
    message: Optional[str] = None
    org_id: Optional[str] = None


class UpdateIssueRequest(BaseModel):
    status: str                      # reviewed | dismissed
    admin_note: Optional[str] = None


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _generate_ref_id() -> str:
    chars = string.ascii_uppercase + string.digits
    return "REF-" + "".join(random.choices(chars, k=6))


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post("")
def submit_report(req: ReportIssueRequest, db: Session = Depends(get_db)):
    """Any authenticated or unauthenticated user can submit a report."""
    # Generate a unique ref_id (retry on collision)
    for _ in range(10):
        ref_id = _generate_ref_id()
        if not db.query(ReportedIssue).filter_by(ref_id=ref_id).first():
            break

    issue = ReportedIssue(
        org_id=req.org_id,
        domain=req.domain,
        subdomain=req.subdomain,
        rule=req.rule,
        severity=req.severity,
        issue_type=req.issueType,
        message=req.message,
        ref_id=ref_id,
        status="open",
    )
    db.add(issue)
    db.commit()
    db.refresh(issue)
    return {"ref_id": issue.ref_id, "status": issue.status}


@router.get("")
def list_reports(
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Admin only — list all reported issues, optionally filtered by status."""
    q = db.query(ReportedIssue)
    if status:
        q = q.filter(ReportedIssue.status == status)
    issues = q.order_by(ReportedIssue.reported_at.desc()).all()
    return [
        {
            "id": i.id,
            "ref_id": i.ref_id,
            "domain": i.domain,
            "subdomain": i.subdomain,
            "rule": i.rule,
            "severity": i.severity,
            "issue_type": i.issue_type,
            "message": i.message,
            "status": i.status,
            "reported_at": i.reported_at,
            "reviewed_at": i.reviewed_at,
            "admin_note": i.admin_note,
        }
        for i in issues
    ]


@router.patch("/{issue_id}")
def update_report(
    issue_id: int,
    req: UpdateIssueRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Admin only — mark a report as reviewed or dismissed."""
    issue = db.query(ReportedIssue).filter_by(id=issue_id).first()
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")

    if req.status not in ("open", "reviewed", "dismissed"):
        raise HTTPException(status_code=400, detail="Invalid status")

    issue.status = req.status
    issue.admin_note = req.admin_note
    issue.reviewed_by = admin.user_id
    issue.reviewed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(issue)
    return {"ref_id": issue.ref_id, "status": issue.status}
