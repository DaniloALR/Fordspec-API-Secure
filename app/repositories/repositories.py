from sqlalchemy.orm import Session
from app.db import models


def _literal(texto: str) -> str:
    return texto.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


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
            models.VehicleVersion.brand.ilike(_literal(brand), escape="\\")
        )
        if model:
            q = q.filter(models.VehicleVersion.model.ilike(_literal(model), escape="\\"))
        return q.all()

    def find_version(self, db: Session, brand: str, model: str, version: str):
        return (
            db.query(models.VehicleVersion)
            .filter(
                models.VehicleVersion.brand.ilike(_literal(brand), escape="\\"),
                models.VehicleVersion.model.ilike(_literal(model), escape="\\"),
                models.VehicleVersion.version.ilike(_literal(version), escape="\\"),
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

    def save_request(self, db: Session, brand, model, version, requested_by=None):
        req = models.SpecRequest(brand=brand, model=model, version=version,
                                 requested_by=requested_by)
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


class UserRepository:
    def get_by_username(self, db: Session, username: str):
        return (
            db.query(models.AppUser)
            .filter(models.AppUser.username == username)
            .first()
        )

    def list_all(self, db: Session):
        return db.query(models.AppUser).order_by(models.AppUser.username).all()

    def count_active_by_role(self, db: Session, role: str) -> int:
        return (
            db.query(models.AppUser)
            .filter(models.AppUser.role == role, models.AppUser.is_active.is_(True))
            .count()
        )

    def add(self, db: Session, user):
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    def save(self, db: Session):
        db.commit()


class AuditRepository:
    def list_recent(self, db: Session, limit: int, actor: str | None = None):
        q = db.query(models.AuditEvent)
        if actor:
            q = q.filter(models.AuditEvent.actor == actor)
        return q.order_by(models.AuditEvent.id.desc()).limit(limit).all()
