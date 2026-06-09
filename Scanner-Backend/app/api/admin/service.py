import random
import secrets
import string
import uuid

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.api.auth.service import hashPassword
from app.db.models import Blacklist, Organization, PromoCode, ScanScoreHistory, ScanSummary, User, SubscriptionPlan
from app.utils.email import send_new_admin_credentials_email


def _generate_promo_string(length: int = 10) -> str:
    chars = string.ascii_uppercase + string.digits
    return "".join(random.choices(chars, k=length))


def _normalize_email(email: str) -> str:
    return email.lower().strip()


def _serialize_user(user: User, blocked_emails: set[str]) -> dict:
    return {
        "user_id": user.user_id,
        "email": user.email,
        "role": user.role,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "is_blacklisted": user.email.lower() in blocked_emails,
        "email_verified": bool(user.email_verified),
    }


def generate_promo_code(db: Session) -> dict:
    code_str = _generate_promo_string()

    while db.query(PromoCode).filter(PromoCode.code == code_str).first():
        code_str = _generate_promo_string()

    promo = PromoCode(
        code_id=str(uuid.uuid4()),
        code=code_str,
        is_used=False,
    )

    db.add(promo)
    db.commit()
    db.refresh(promo)

    return {
        "message": "Promo code generated successfully",
        "code": promo.code,
    }


def get_promo_codes(db: Session) -> list[dict]:
    codes = db.query(PromoCode).all()
    used_by_ids = {code.used_by for code in codes if code.used_by}

    users_by_id = {}
    if used_by_ids:
        users_by_id = {
            user.user_id: user
            for user in db.query(User).filter(User.user_id.in_(used_by_ids)).all()
        }

    org_ids = {user.org_id for user in users_by_id.values() if user.org_id}
    orgs_by_id = {}
    if org_ids:
        orgs_by_id = {
            org.org_id: org
            for org in db.query(Organization).filter(Organization.org_id.in_(org_ids)).all()
        }

    owner_ids = {org.user_id for org in orgs_by_id.values() if org.user_id}
    owners_by_id = {}
    if owner_ids:
        owners_by_id = {
            owner.user_id: owner
            for owner in db.query(User).filter(User.user_id.in_(owner_ids)).all()
        }

    return [
        {
            "code": code.code,
            "is_used": code.is_used,
            "used_at": code.used_at.isoformat() if code.used_at else None,
            "used_by": (
                owners_by_id.get(orgs_by_id.get(user.org_id).user_id).email
                if code.used_by
                and (user := users_by_id.get(code.used_by))
                and user.org_id in orgs_by_id
                and orgs_by_id[user.org_id].user_id in owners_by_id
                else None
            ),
        }
        for code in codes
    ]


def delete_promo_code(code_str: str, db: Session) -> dict:
    """Delete a promo code by its code string (both used and unused codes can be deleted)."""
    promo = db.query(PromoCode).filter(PromoCode.code == code_str).first()

    if not promo:
        raise HTTPException(status_code=404, detail="Promo code not found")

    if promo.is_used and promo.used_by:
        user = db.query(User).filter(User.user_id == promo.used_by).first()
        if user and user.org_id:
            org = db.query(Organization).filter(Organization.org_id == user.org_id).first()
            if org:
                current_domains = len(org.domain or [])
                org.max_domains = max(1, org.max_domains - 1, current_domains)

    db.delete(promo)
    db.commit()

    return {
        "message": "Promo code deleted successfully",
        "code": promo.code,
    }


def get_users_by_org(db: Session) -> dict:
    organizations = db.query(Organization).order_by(Organization.domain.asc()).all()
    users = (
        db.query(User)
        .filter(User.email_verified.is_(True))
        .order_by(User.created_at.desc())
        .all()
    )
    blocked_emails = {blocked.email for blocked in db.query(Blacklist).all()}

    users_by_org: dict[str, list[User]] = {}
    unassigned_users = []
    for user in users:
        if user.org_id:
            users_by_org.setdefault(user.org_id, []).append(user)
        else:
            unassigned_users.append(user)

    admin_only = [u for u in unassigned_users if u.role == "admin"]

    return {
        "organizations": [
            {
                "org_id": org.org_id,
                "domain": org.domain,
                "max_domains": org.max_domains,
                "users": [
                    _serialize_user(user, blocked_emails)
                    for user in users_by_org.get(org.org_id, [])
                ],
            }
            for org in organizations
        ],
        "admin": [
            _serialize_user(user, blocked_emails)
            for user in admin_only
        ],
    }


def block_email(email: str, current_admin: User, db: Session) -> dict:
    normalized_email = _normalize_email(email)

    if normalized_email == current_admin.email.lower():
        raise HTTPException(status_code=400, detail="Admin cannot block their own email")

    existing = db.query(Blacklist).filter(Blacklist.email == normalized_email).first()
    if existing:
        raise HTTPException(status_code=409, detail="Email is already blocked")

    blocked_user = Blacklist(
        email=normalized_email,
        blocked_by=current_admin.user_id,
    )
    db.add(blocked_user)
    db.commit()
    db.refresh(blocked_user)

    return {
        "message": "Email blocked successfully",
        "email": blocked_user.email,
        "blocked_by": blocked_user.blocked_by,
        "created_at": blocked_user.created_at.isoformat() if blocked_user.created_at else None,
    }


def unblock_email(email: str, db: Session) -> dict:
    normalized_email = _normalize_email(email)

    deleted_count = (
        db.query(Blacklist)
        .filter(Blacklist.email == normalized_email)
        .delete(synchronize_session=False)
    )

    if deleted_count == 0:
        raise HTTPException(status_code=404, detail="Email is not blocked")

    db.commit()

    return {
        "message": "Email unblocked successfully",
        "email": normalized_email,
    }


def get_blacklisted_emails(db: Session) -> list[dict]:
    blocked_users = db.query(Blacklist).order_by(Blacklist.created_at.desc()).all()

    return [
        {
            "email": blocked_user.email,
            "blocked_by": blocked_user.blocked_by,
            "created_at": blocked_user.created_at.isoformat() if blocked_user.created_at else None,
        }
        for blocked_user in blocked_users
    ]


def get_scan_summaries(db: Session) -> list[dict]:
    summaries = db.query(ScanSummary).all()
    org_ids = {summary.org_id for summary in summaries}

    organizations = {}
    if org_ids:
        organizations = {
            org.org_id: org
            for org in db.query(Organization).filter(Organization.org_id.in_(org_ids)).all()
        }

    owner_ids = {org.user_id for org in organizations.values()}
    owners = {}
    if owner_ids:
        owners = {
            user.user_id: user
            for user in db.query(User).filter(User.user_id.in_(owner_ids)).all()
        }

    return [
        {
            "org_id": summary.org_id,
            "organization_domain": organizations.get(summary.org_id).domain
            if organizations.get(summary.org_id) else None,
            "owner_email": owners.get(organizations[summary.org_id].user_id).email
            if summary.org_id in organizations and organizations[summary.org_id].user_id in owners else None,
            "domain": summary.domain,
            "domain_score": summary.domain_score,
            "severity": summary.severity,
            "mail_security": summary.mail_security or {},
            "app_security": summary.app_security or {},
            "network_security": summary.network_security or {},
            "tls_security": summary.tls_security or {},
            "dns_security": summary.dns_security or {},
            "ips": summary.ips or [],
        }
        for summary in summaries
    ]


def get_total_scans(db: Session) -> dict:
    total_scans = db.query(ScanScoreHistory).count()
    return {"total_scans": total_scans}


def provision_admin_account(email: str, current_admin: User, db: Session) -> dict:
    normalized = _normalize_email(email)

    if normalized == current_admin.email.lower():
        raise HTTPException(status_code=400, detail="Cannot provision an admin account for your own email")

    if db.query(Blacklist).filter(Blacklist.email == normalized).first():
        raise HTTPException(status_code=400, detail="This email is blocked")

    if db.query(User).filter(User.email == normalized).first():
        raise HTTPException(status_code=400, detail="A user with this email already exists")

    plain_password = secrets.token_urlsafe(12)
    new_admin = User(
        user_id=str(uuid.uuid4()),
        email=normalized,
        password=hashPassword(plain_password),
        role="admin",
        org_id=None,
        email_verified=True,
    )
    db.add(new_admin)

    try:
        send_new_admin_credentials_email(
            to_email=normalized,
            plain_password=plain_password,
            invited_by_email=current_admin.email,
        )
    except Exception as email_err:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send credentials email to {normalized}: {str(email_err)}",
        )

    db.commit()

    return {
        "message": "Admin account created and credentials sent by email",
        "email": normalized,
    }


def _serialize_plan(plan: SubscriptionPlan) -> dict:
    return {
        "plan_id": plan.plan_id,
        "name": plan.name,
        "price": plan.price,
        "icon": plan.icon,
        "color": plan.color,
        "container_color": plan.container_color,
        "popular": bool(plan.popular),
        "features": plan.features or [],
        "tags": plan.tags or [],
    }


def get_subscription_plans(db: Session) -> list[dict]:
    plans = db.query(SubscriptionPlan).all()
    return [_serialize_plan(p) for p in plans]


def seed_default_subscription_plans(db: Session) -> None:
    if db.query(SubscriptionPlan).count() > 0:
        return

    default_plans = [
        {
            "plan_id": "enterprise-plus",
            "name": "Enterprise Plus",
            "price": 499,
            "icon": "rocket_launch",
            "color": "primary",
            "container_color": "primary-container",
            "popular": True,
            "features": ["Unlimited Scans", "Priority Support", "Custom Integrations"],
        },
        {
            "plan_id": "business-pro",
            "name": "Business Pro",
            "price": 199,
            "icon": "business_center",
            "color": "tertiary",
            "container_color": "tertiary-container",
            "popular": False,
            "features": ["Advanced Analytics", "Team Management", "API Access"],
        },
        {
            "plan_id": "standard",
            "name": "Standard",
            "price": 49,
            "icon": "work",
            "color": "secondary",
            "container_color": "secondary-container",
            "popular": False,
            "features": ["Basic Scanning", "Email Support", "Monthly Reports"],
        },
        {
            "plan_id": "free-tier",
            "name": "Free Tier",
            "price": 0,
            "icon": "hourglass_top",
            "color": "outline-variant",
            "container_color": "outline-variant",
            "popular": False,
            "features": ["5 Scans/Month", "Basic Reports", "Community Support"],
        },
    ]

    for plan_data in default_plans:
        plan = SubscriptionPlan(**plan_data)
        db.add(plan)
    db.commit()


def create_subscription_plan(req: dict, db: Session) -> dict:
    plan_id = req.get("plan_id") or str(uuid.uuid4())

    if db.query(SubscriptionPlan).filter(SubscriptionPlan.plan_id == plan_id).first():
        raise HTTPException(status_code=409, detail="Plan with this id already exists")

    plan = SubscriptionPlan(
        plan_id=plan_id,
        name=req.get("name"),
        price=req.get("price", 0),
        icon=req.get("icon"),
        color=req.get("color"),
        container_color=req.get("container_color"),
        popular=bool(req.get("popular", False)),
        features=req.get("features", []),
        tags=req.get("tags", []),
    )

    db.add(plan)
    db.commit()
    db.refresh(plan)

    return _serialize_plan(plan)


def update_subscription_plan(plan_id: str, req: dict, db: Session) -> dict:
    plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.plan_id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    if "name" in req and req["name"] is not None:
        plan.name = req["name"]
    if "price" in req and req["price"] is not None:
        plan.price = req["price"]
    if "icon" in req:
        plan.icon = req.get("icon")
    if "color" in req:
        plan.color = req.get("color")
    if "container_color" in req:
        plan.container_color = req.get("container_color")
    if "popular" in req and req["popular"] is not None:
        plan.popular = bool(req["popular"])
    if "features" in req and req["features"] is not None:
        plan.features = req["features"]
    if "tags" in req and req["tags"] is not None:
        plan.tags = req["tags"]

    db.add(plan)
    db.commit()
    db.refresh(plan)

    return _serialize_plan(plan)


def delete_subscription_plan(plan_id: str, db: Session) -> dict:
    plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.plan_id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    db.delete(plan)
    db.commit()

    return {"message": "Subscription plan deleted successfully", "plan_id": plan_id}
