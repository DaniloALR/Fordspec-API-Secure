import uuid
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey, UniqueConstraint
)
from sqlalchemy.orm import relationship
from app.db.database import Base


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
    created_at = Column(DateTime, default=datetime.utcnow)
