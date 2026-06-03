from typing import Any, Optional
from pydantic import BaseModel


class FixRequest(BaseModel):
    org_id: str
    domain: str
    fix_type: str
    data: Any


class FixSubmitResponse(BaseModel):
    message: str
    org_id: str


class FixResultResponse(BaseModel):
    message: str
    org_id: str
    domain_score: int
    severity: str


class FixResultRequest(BaseModel):
    scan_id: str
    domain: str
    fix_type: str
    result: Any
from pydantic import BaseModel


# class CreateFixRequest(BaseModel):

#     scan_id: str

#     org_id: str

#     user_id: str | None = None

#     domain: str

#     host: str

#     port_number: int

#     service: str | None = None
class PortFixRequestSchema(BaseModel):
    org_id: str
    domain: str
    fix_type: str
    data: dict