import io
import csv
from fastapi import APIRouter, Depends, Path, Query, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.services.services import SpecService
from app.schemas.schemas import SpecSheet
from app.security.validation import SecureSpecRequestIn
from app.security.rbac import get_current_user, require_role
from app.security.audit import log_auditoria

router = APIRouter(prefix="/v1", tags=["specs"])
spec_service = SpecService()


@router.post("/specs", response_model=SpecSheet, status_code=201,
             summary="Gera a ficha técnica padronizada (requer autenticação)")
def create_spec(payload: SecureSpecRequestIn,
                db: Session = Depends(get_db),
                user: dict = Depends(get_current_user)):
    log_auditoria(user["sub"], "gerar_ficha",
                  f"{payload.brand}/{payload.model}/{payload.version}")
    return spec_service.generate(
        db, payload.brand, payload.model, payload.version, payload.attributes
    )


@router.get("/specs/export",
            summary="Exporta a ficha no formato BASE (CSV) — requer curador/admin")
def export_spec(
    brand: str = Query("Ford", max_length=60),
    model: str = Query("Ranger", max_length=60),
    version: str = Query(..., max_length=120),
    db: Session = Depends(get_db),
    user: dict = Depends(require_role("curador", "admin")),  # RBAC
):
    log_auditoria(user["sub"], "exportar_ficha", f"{brand}/{model}/{version}")
    sheet = spec_service.generate(db, brand, model, version, None)
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";")
    writer.writerow(["Categoria", "Atributo", "Valor", "Status"])
    for it in sheet["items"]:
        writer.writerow([it["category"], it["attribute"], it["value"], it["status"]])
    buf.seek(0)
    fname = f"ficha_{brand}_{model}_{version}.csv".replace(" ", "_")
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/specs/{request_id}",
            summary="Recupera os metadados de uma ficha gerada")
def get_spec(request_id: str = Path(..., max_length=36),
             db: Session = Depends(get_db),
             user: dict = Depends(get_current_user)):
    req = spec_service.get_request(db, request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Ficha não encontrada.")
    return {
        "id": req.id, "brand": req.brand, "model": req.model,
        "version": req.version, "created_at": str(req.created_at),
    }
