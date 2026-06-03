import json
import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.redis_queue import RedisClient
from app.core.middleware import protect
from app.db.base import get_db
from app.db.models import User
from app.api.fix.schemas import (
    FixRequest, 
    FixSubmitResponse, 
    FixResultRequest, 
    FixResultResponse,
    PortFixRequestSchema
)
from app.api.fix.service import queue_fix_job

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/fix", tags=["Fix"])

redis_client = RedisClient()
QUEUE_NAME = "fix_queue"


@router.get("/status/{scan_id}")
def get_fix_status(scan_id: str):
    from sqlalchemy import text
    from app.db.base import engine
    
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT scan_id, status, is_open, port_number, host, updated_at FROM port_fix_requests WHERE scan_id = :scan_id LIMIT 1"),
            {"scan_id": scan_id}
        ).fetchone()
    
    if not result:
        raise HTTPException(status_code=404, detail="Fix request not found")
    
    return {
        "scan_id": result.scan_id,
        "status": result.status,
        "is_open": result.is_open,
        "port_number": result.port_number,
        "host": result.host,
        "updated_at": result.updated_at,
    }

@router.post("/port")
async def create_port_fix(
    payload: PortFixRequestSchema,
    db: Session = Depends(get_db),
):
    """
    Queue a port fix job and return the scan_id for tracking.
    
    This endpoint:
    1. ✅ Validates domain exists in scan_summary
    2. Creates a PortFixRequest in the database
    3. Queues the job in Redis
    4. Returns scan_id so frontend can track the result
    
    Errors:
    - 400: Domain not found / Invalid port
    - 500: Server error
    """
    try:
        # ✅ Validate inputs first
        if not payload.domain:
            raise HTTPException(
                status_code=400,
                detail="Domain is required"
            )
        
        port = payload.data.get("port")
        if not port or not isinstance(port, int) or port <= 0 or port > 65535:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid port: {port}. Must be between 1-65535"
            )
        
        # ✅ Queue the fix (includes validation)
        result = await queue_fix_job(
            org_id=payload.org_id,
            domain=payload.domain,
            fix_type=payload.fix_type,
            data=payload.data,
            db=db,
            user_id=payload.user_id if hasattr(payload, 'user_id') else None,
        )

        scan_id = result.get("scan_id")

        logger.info(
            f"Fix queued successfully: "
            f"scan_id={scan_id}, "
            f"domain={payload.domain}, "
            f"port={port}"
        )

        return {
            "ok": True,
            "message": "Fix queued — verification will run shortly.",
            "scan_id": scan_id,
        }

    except HTTPException as http_err:
        # ✅ Re-raise HTTP exceptions (validation errors)
        logger.warning(f"Validation error: {http_err.detail}")
        raise http_err
        
    except Exception as e:
        # ✅ Log unexpected errors
        logger.error(f"Error queuing fix: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to queue fix: {str(e)}"
        )


@router.post("/submit", response_model=FixSubmitResponse)
def submit_fix(
    request: FixRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """
    Alternative endpoint for submitting fixes with user authentication.
    """
    if request.org_id != current_user.org_id:
        raise HTTPException(status_code=403, detail="Organization mismatch")
    
    try:
        queue_payload = {
            "scan_id": request.org_id,
            "domain": request.domain,
            "fix_type": request.fix_type,
            "data": request.data,
        }
        redis_client.redis.rpush(QUEUE_NAME, json.dumps(queue_payload))
    except Exception as e:
        logger.error(f"Error in submit_fix: {str(e)}")
        raise HTTPException(
            status_code=503,
            detail="Redis connection failed. Please try again later."
        )

    return FixSubmitResponse(
        message="Fix request queued successfully",
        org_id=request.org_id,
    )


@router.post("/result", response_model=FixResultResponse)
def submit_fix_result(
    request: FixResultRequest, 
    db: Session = Depends(get_db)
):
    try:
        from app.api.fix.service import apply_fix_result
        
        # ✅ Log exactly what we receive
        logger.info(f"Fix result received: scan_id={request.scan_id}, domain={request.domain}, fix_type={request.fix_type}, result={request.result}")
        
        fix_result = apply_fix_result(
            org_id=request.scan_id,
            domain=request.domain,
            fix_type=request.fix_type,
            result=request.result,
            db=db,
            scan_id=request.scan_id,
        )
        
        logger.info(f"Fix result applied: {fix_result}")
        
    except Exception as e:
        logger.error(f"Error in submit_fix_result: {str(e)}", exc_info=True)
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Failed to update scan summary after fix result"
        )

    return FixResultResponse(
        message="Fix result stored successfully",
        org_id=request.scan_id,
        domain_score=fix_result.get("domain_score") or 0,
        severity=fix_result.get("severity") or "unknown",
    )

# Health check endpoint
@router.get("/health")
def health_check():
    """Health check for the fix service"""
    return {
        "status": "ok",
        "service": "fix-queue"
    }
