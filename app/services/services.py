from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.repositories.repositories import (
    AttributeRepository, VehicleRepository, SpecRepository
)
from app.core.exceptions import VersionNotFound, InvalidAttribute


class CatalogService:
    def __init__(self):
        self.repo = AttributeRepository()

    def list_attributes(self, db: Session):
        return self.repo.list_all(db)


class VehicleService:
    def __init__(self):
        self.repo = VehicleRepository()

    def list_versions(self, db: Session, brand: str, model: str | None):
        return self.repo.list_versions(db, brand, model)


class SpecService:
    def __init__(self):
        self.attr_repo = AttributeRepository()
        self.vehicle_repo = VehicleRepository()
        self.spec_repo = SpecRepository()

    def generate(self, db: Session, brand: str, model: str, version: str,
                 attributes: list[str] | None, requested_by: str | None = None):
        vehicle = self.vehicle_repo.find_version(db, brand, model, version)
        if not vehicle:
            raise VersionNotFound(brand, model, version)

        valid_names = self.attr_repo.names_set(db)
        if attributes:
            invalid = [a for a in attributes if a not in valid_names]
            if invalid:
                raise InvalidAttribute(invalid)

        values = {
            sv.attribute_id: sv
            for sv in self.spec_repo.values_for_vehicle(db, vehicle.id)
        }

        all_attrs = self.attr_repo.list_all(db)
        items = []
        for attr in all_attrs:
            if attributes and attr.name not in attributes:
                continue
            sv = values.get(attr.id)
            if sv and sv.value not in (None, ""):
                items.append({
                    "attribute": attr.name, "category": attr.category,
                    "value": sv.value, "unit": attr.unit,
                    "status": sv.status or "confirmed", "source": sv.source,
                })
            else:
                items.append({
                    "attribute": attr.name, "category": attr.category,
                    "value": "ND", "unit": attr.unit,
                    "status": "not_available", "source": None,
                })

        req = self.spec_repo.save_request(db, brand, model, version, requested_by)

        return {
            "id": req.id,
            "vehicle": {"brand": brand, "model": model, "version": version},
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_attributes": len(items),
            "items": items,
        }

    def get_request(self, db: Session, request_id: str):
        return self.spec_repo.get_request(db, request_id)
