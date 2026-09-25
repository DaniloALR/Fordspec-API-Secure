from sqlalchemy.orm import Session
from app.db import models


class AttributeRepository:
    def list_all(self, db: Session):
        return (
            db.query(models.Attribute)
            .order_by(models.Attribute.display_order)
            .all()
        )

    def names_set(self, db: Session):
        return {a.name for a in db.query(models.Attribute.name).all()}


class VehicleRepository:
    def list_versions(self, db: Session, brand: str, model: str | None = None):
        q = db.query(models.VehicleVersion).filter(
            models.VehicleVersion.brand.ilike(brand)
        )
        if model:
            q = q.filter(models.VehicleVersion.model.ilike(model))
        return q.all()

    def find_version(self, db: Session, brand: str, model: str, version: str):
        return (
            db.query(models.VehicleVersion)
            .filter(
                models.VehicleVersion.brand.ilike(brand),
                models.VehicleVersion.model.ilike(model),
                models.VehicleVersion.version.ilike(version),
            )
            .first()
        )


class SpecRepository:
    def values_for_vehicle(self, db: Session, vehicle_id: int):
        return (
            db.query(models.SpecValue)
            .filter(models.SpecValue.vehicle_id == vehicle_id)
            .all()
        )

    def save_request(self, db: Session, brand, model, version):
        req = models.SpecRequest(brand=brand, model=model, version=version)
        db.add(req)
        db.commit()
        db.refresh(req)
        return req

    def get_request(self, db: Session, request_id: str):
        return (
            db.query(models.SpecRequest)
            .filter(models.SpecRequest.id == request_id)
            .first()
        )
