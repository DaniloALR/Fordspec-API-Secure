from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.services.services import CatalogService, VehicleService
from app.schemas.schemas import AttributeOut, VehicleOut
from app.security.rbac import require_permission

# Sprint 3: catálogo passa a exigir autenticação — a base curada é o ativo de
# inteligência competitiva e ficava exposta a scraping anônimo (OWASP API6:2023).
router = APIRouter(prefix="/v1", tags=["catalog & vehicles"],
                   dependencies=[Depends(require_permission("catalog:read"))])
catalog_service = CatalogService()
vehicle_service = VehicleService()


@router.get("/attributes", response_model=list[AttributeOut],
            summary="Lista o dicionário de atributos (14 categorias)")
def list_attributes(db: Session = Depends(get_db)):
    attrs = catalog_service.list_attributes(db)
    return [AttributeOut(category=a.category, name=a.name, unit=a.unit) for a in attrs]


@router.get("/vehicles", response_model=list[VehicleOut],
            summary="Lista versões disponíveis na base curada")
def list_vehicles(
    brand: str = Query(..., max_length=60, examples=["Ford"]),
    model: str | None = Query(None, max_length=60, examples=["Ranger"]),
    db: Session = Depends(get_db),
):
    vehicles = vehicle_service.list_versions(db, brand, model)
    return [VehicleOut(brand=v.brand, model=v.model, version=v.version) for v in vehicles]
