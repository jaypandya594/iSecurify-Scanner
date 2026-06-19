from fastapi import APIRouter, HTTPException, Depends , Response
from app.api.auth.schemas import (
    RegisterRequest, LoginRequest, InviteRequest,
    RedeemPromoRequest, ForgotPasswordOtpRequest,
    ForgotPasswordResetRequest, ResetPasswordRequest,
    AddDomainRequest, VerifyEmailRequest,
)
from sqlalchemy.orm import Session
from app.db.base import get_db
from app.api.auth.service import (
    login_user, register, verify_registration, invite_member,
    get_members, redeem_promo_code, add_domain,
    send_forgot_password_otp, verify_otp_and_reset_password,
    reset_password_with_old_password,
)
from app.core.middleware import require_owner, protect
from app.db.models import User, Organization
from app.utils.captcha import verify_captcha

router = APIRouter(prefix='/auth', tags=['auth'])

@router.post('/register')
async def register_route(req: RegisterRequest, db: Session = Depends(get_db)):
    await verify_captcha(req.captcha_token)

    email = req.email
    password = req.password
    domain = req.domain

    if not email or not password or not domain or not domain.strip():
        raise HTTPException(status_code=400, detail="Please fill all the fields")

    try:
        return register(email, password, domain, db)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.post('/verify-email')
def verify_email_route(req: VerifyEmailRequest, db: Session = Depends(get_db)):
    if not req.token or not str(req.token).strip():
        raise HTTPException(status_code=400, detail="Invalid verification link")

    try:
        return verify_registration(req.token.strip(), db)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.post('/login')
async def login(req: LoginRequest, response: Response, db: Session = Depends(get_db)):
    await verify_captcha(req.captcha_token)

    if not req.email or not req.password:
        raise HTTPException(status_code=400, detail="Please fill all the fields")

    try:
        result = login_user(req.email, req.password, db)

        # Set HttpOnly cookie — JS can never read or overwrite this
        response.set_cookie(
            key="token",
            value=result["token"],
            httponly=True,
            secure=False,       # change to True when you deploy on HTTPS
            samesite="lax",
            max_age=60 * 60 * 24,  # 24 hours (matches your generateToken)
            path="/",
        )

        # Return user info but NOT the token in the body
        return {
            "message": "Login successful",
            "user": result["user"],
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.post('/forgot-password')
def forgot_password(req: ForgotPasswordOtpRequest, db: Session = Depends(get_db)):
    try:
        return send_forgot_password_otp(req.email, db)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.post('/forgot-password/reset')
def forgot_password_reset(req: ForgotPasswordResetRequest, db: Session = Depends(get_db)):
    if not req.otp or not req.new_password:
        raise HTTPException(status_code=400, detail="Please fill all the fields")

    try:
        return verify_otp_and_reset_password(req.email, req.otp, req.new_password, db)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.post('/reset-password')
def reset_password(
    req: ResetPasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect)
):
    if not req.old_password or not req.new_password:
        raise HTTPException(status_code=400, detail="Please fill all the fields")

    try:
        return reset_password_with_old_password(current_user.user_id, req.old_password, req.new_password, db)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.post('/invite')
def invite_members(
    req: InviteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_owner)
):
    try:
        return invite_member(current_user, req.email, db)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.get('/members')
def list_members(
    db: Session = Depends(get_db),
    current_user: User = Depends(protect)
):
    try:
        return get_members(current_user, db)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.get('/profile')
def get_profile(
    current_user: User = Depends(protect),
    db: Session = Depends(get_db)
):
    org = db.query(Organization).filter(Organization.org_id == current_user.org_id).first()
    return {
        "user_id": current_user.user_id,
        "org_id": current_user.org_id,
        "email": current_user.email,
        "role": current_user.role,
        "domain": org.domain if org else None,
        "max_domains": org.max_domains if org else 0
    }

@router.post('/add-domain')
def add_domain_route(
    req: AddDomainRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect)
):
    try:
        return add_domain(current_user.user_id, req.domain, db)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.post('/redeem-promo')
def redeem_promo(
    req: RedeemPromoRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect)
):
    try:
        return redeem_promo_code(current_user.user_id, req.code, db)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")
    
@router.post('/logout')
def logout(response: Response):
    response.delete_cookie(key="token", path="/")
    return {"message": "Logged out"}
