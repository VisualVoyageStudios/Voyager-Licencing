"""
Voyager EA Licensing
─────────────────────
Drop into your existing FastAPI project and wire up with:

    from licensing import router as licensing_router
    app.include_router(licensing_router)

Then merge EaLicense into wherever your other models/migrations live —
juggling two separate Base classes in one app usually isn't worth it.

Environment variable required:
    VOYAGER_ADMIN_KEY   — a long random secret only you know.
                           Sent as the X-Admin-Key header on admin requests.
"""

import secrets
import os
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional, List

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column, Session

from database import Base, get_db


class LicenseStatus(str, Enum):
    active = "active"
    revoked = "revoked"


class EaLicense(Base):
    __tablename__ = "ea_licenses"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    product_id: Mapped[str] = mapped_column(String, index=True)
    account_number: Mapped[str] = mapped_column(String, index=True)
    broker_server: Mapped[str] = mapped_column(String)
    license_key: Mapped[str] = mapped_column(String, unique=True, index=True)
    status: Mapped[str] = mapped_column(String, default=LicenseStatus.active.value)
    customer_email: Mapped[Optional[str]] = mapped_column(String, default=None)
    notes: Mapped[Optional[str]] = mapped_column(String, default=None)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=None)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class LicenseCreateRequest(BaseModel):
    product_id: str
    account_number: str
    broker_server: str
    customer_email: Optional[str] = None
    notes: Optional[str] = None
    valid_days: Optional[int] = None


class LicenseResponse(BaseModel):
    id: int
    product_id: str
    account_number: str
    broker_server: str
    license_key: str
    status: str
    customer_email: Optional[str]
    expires_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class VerifyRequest(BaseModel):
    product_id: str
    account_number: str
    broker_server: str
    license_key: str


class VerifyResponse(BaseModel):
    valid: bool
    reason: str


def require_admin(x_admin_key: str = Header(...)):
    expected = os.environ.get("VOYAGER_ADMIN_KEY")
    if not expected or not secrets.compare_digest(x_admin_key, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin key")


router = APIRouter(prefix="/licenses", tags=["ea-licensing"])


@router.post("", response_model=LicenseResponse, dependencies=[Depends(require_admin)])
def create_license(payload: LicenseCreateRequest, db: Session = Depends(get_db)):
    key = "VGR-" + secrets.token_urlsafe(18).replace("_", "").replace("-", "")[:24].upper()

    expires_at = None
    if payload.valid_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=payload.valid_days)

    lic = EaLicense(
        product_id=payload.product_id,
        account_number=payload.account_number,
        broker_server=payload.broker_server,
        license_key=key,
        customer_email=payload.customer_email,
        notes=payload.notes,
        expires_at=expires_at,
        status=LicenseStatus.active.value,
    )
    db.add(lic)
    db.commit()
    db.refresh(lic)
    return lic


@router.patch("/{license_id}/revoke", response_model=LicenseResponse, dependencies=[Depends(require_admin)])
def revoke_license(license_id: int, db: Session = Depends(get_db)):
    lic = db.query(EaLicense).filter(EaLicense.id == license_id).first()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")
    lic.status = LicenseStatus.revoked.value
    db.commit()
    db.refresh(lic)
    return lic


@router.get("", response_model=List[LicenseResponse], dependencies=[Depends(require_admin)])
def list_licenses(
    product_id: Optional[str] = None,
    account_number: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(EaLicense)
    if product_id:
        q = q.filter(EaLicense.product_id == product_id)
    if account_number:
        q = q.filter(EaLicense.account_number == account_number)
    return q.order_by(EaLicense.created_at.desc()).all()


@router.post("/verify", response_model=VerifyResponse)
def verify_license(payload: VerifyRequest, db: Session = Depends(get_db)):
    lic = (
        db.query(EaLicense)
        .filter(
            EaLicense.product_id == payload.product_id,
            EaLicense.account_number == payload.account_number,
            EaLicense.broker_server == payload.broker_server,
            EaLicense.license_key == payload.license_key,
        )
        .first()
    )

    if not lic:
        return VerifyResponse(valid=False, reason="No matching license for this account/key/broker")
    if lic.status != LicenseStatus.active.value:
        return VerifyResponse(valid=False, reason="License revoked")
    if lic.expires_at and lic.expires_at < datetime.now(timezone.utc):
        return VerifyResponse(valid=False, reason="License expired")

    return VerifyResponse(valid=True, reason="OK")
