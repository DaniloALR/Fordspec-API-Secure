import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean, Column, Integer, String, Text, DateTime, ForeignKey, UniqueConstraint
)
from sqlalchemy.orm import relationship
from app.db.database import Base
from app.security.data_privacy import EncryptedString


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Attribute(Base):
    __tablename__ = "attribute"
    id = Column(Integer, primary_key=True, index=True)
    category = Column(String(80), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    data_type = Column(String(20), default="text")
    unit = Column(String(20), nullable=True)
    display_order = Column(Integer, default=0)
    __table_args__ = (UniqueConstraint("category", "name", name="uq_attr_cat_name"),)


class VehicleVersion(Base):
    __tablename__ = "vehicle_version"
    id = Column(Integer, primary_key=True, index=True)
    brand = Column(String(60), nullable=False, index=True)
    model = Column(String(60), nullable=False, index=True)
    version = Column(String(160), nullable=False)
    __table_args__ = (
        UniqueConstraint("brand", "model", "version", name="uq_vehicle_bmv"),
    )
    values = relationship("SpecValue", back_populates="vehicle", cascade="all, delete-orphan")


class SpecValue(Base):
    __tablename__ = "spec_value"
    id = Column(Integer, primary_key=True)
    vehicle_id = Column(Integer, ForeignKey("vehicle_version.id", ondelete="CASCADE"))
    attribute_id = Column(Integer, ForeignKey("attribute.id"))
    value = Column(Text, nullable=True)
    status = Column(String(20), default="confirmed")
    source = Column(String(200), nullable=True)

    vehicle = relationship("VehicleVersion", back_populates="values")
    attribute = relationship("Attribute")


class SpecRequest(Base):
    __tablename__ = "spec_request"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    brand = Column(String(60))
    model = Column(String(60))
    version = Column(String(160))
    requested_by = Column(String(40), nullable=True, index=True)
    created_at = Column(DateTime, default=_utcnow)


class AppUser(Base):
    __tablename__ = "app_user"
    id = Column(Integer, primary_key=True)
    username = Column(String(40), unique=True, nullable=False, index=True)
    password_hash = Column(String(100), nullable=False)
    role = Column(String(20), nullable=False)
    email = Column(EncryptedString, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    failed_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    token_version = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_event"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=_utcnow, nullable=False, index=True)
    actor = Column(String(60), nullable=False)
    action = Column(String(60), nullable=False, index=True)
    resource = Column(String(200), nullable=False)
    ip = Column(String(60), nullable=True)
    trace_id = Column(String(36), nullable=True)
    prev_hash = Column(String(64), nullable=False)
    hash = Column(String(64), nullable=False)
