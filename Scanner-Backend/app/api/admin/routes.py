from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.admin.schemas import BlacklistEmailRequest, CreateAdminRequest
from app.api.admin.service import (
    block_email,
    create_subscription_plan,
    delete_promo_code,
    delete_subscription_plan,
    generate_promo_code,
    get_audit_logs,
    get_blacklisted_emails,
    get_promo_codes,
    get_scan_summaries,
    get_security_alerts,
    get_subscription_plans,
    get_total_scans,
    get_users_by_org,
    provision_admin_account,
    unblock_email,
    update_subscription_plan,
)
from app.core.middleware import require_admin
from app.db.base import get_db
from app.db.models import User

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/generate-promo")
def generate_promo(
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    return generate_promo_code(db, current_admin=current_admin, ip_address=request.client.host if request.client else None)


@router.get("/promo-codes")
def list_promo_codes(
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return get_promo_codes(db)


@router.delete("/promo-codes/{code}/delete")
def delete_promo(
    code: str,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    """Delete a promo code (both used and unused codes can be deleted)"""
    return delete_promo_code(code, db, current_admin=current_admin, ip_address=request.client.host if request.client else None)


@router.get("/users")
def list_users_by_org(
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return get_users_by_org(db)


@router.post("/create-admin")
def create_admin(
    req: CreateAdminRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    return provision_admin_account(req.email, current_admin, db, ip_address=request.client.host if request.client else None)


@router.post("/blacklist/block")
def block_user_by_email(
    req: BlacklistEmailRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    return block_email(req.email, current_admin, db, ip_address=request.client.host if request.client else None)


@router.post("/blacklist/unblock")
def unblock_user_by_email(
    req: BlacklistEmailRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    return unblock_email(req.email, db, current_admin=current_admin, ip_address=request.client.host if request.client else None)


@router.get("/blacklist")
def list_blacklisted_emails(
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return get_blacklisted_emails(db)


@router.get("/scans/summaries")
def list_scan_summaries(
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return get_scan_summaries(db)


@router.get("/scans/total")
def get_scans_total(
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return get_total_scans(db)


@router.get("/subscription/plans")
def list_subscription_plans(
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return get_subscription_plans(db)


@router.post("/subscription/plans")
def create_plan(
    req: dict,
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return create_subscription_plan(req, db)


@router.put("/subscription/plans/{plan_id}")
def update_plan(
    plan_id: str,
    req: dict,
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return update_subscription_plan(plan_id, req, db)


@router.delete("/subscription/plans/{plan_id}")
def delete_plan(
    plan_id: str,
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return delete_subscription_plan(plan_id, db)


@router.get("/audit/logs")
def list_audit_logs(
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return {"logs": get_audit_logs(db)}


@router.get("/security/alerts")
def list_security_alerts(
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return {"alerts": get_security_alerts(db)}
