import csv
import io
import re

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.observability import metrics
from app.schemas.schemas import SpecSheet
from app.security.audit import log_evento_seguranca, registrar_auditoria
from app.security.data_privacy import pseudonimizar
from app.security.rbac import has_permission, require_permission
from app.security.validation import SecureSpecRequestIn, sanitizar_texto
from app.services.services import SpecService

router = APIRouter(prefix="/v1", tags=["specs"])
spec_service = SpecService()

_UUID_RE = r"^[0-9a-fA-F-]{36}$"


def _texto_query(valor: str, campo: str) -> str:
    try:
        return sanitizar_texto(valor, campo)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


def _nome_arquivo_seguro(*partes: str) -> str:
    base = "_".join(partes)
    return "ficha_" + re.sub(r"[^A-Za-z0-9._-]", "_", base)[:100] + ".csv"


def _celula_csv_segura(valor) -> str:
    texto = "" if valor is None else str(valor)
    return "'" + texto if texto[:1] in ("=", "+", "-", "@", "\t", "\r") else texto


@router.post("/specs", response_model=SpecSheet, status_code=201,
             summary="Gera a ficha técnica padronizada (brigadista, gestor, administrador)")
def create_spec(payload: SecureSpecRequestIn,
                db: Session = Depends(get_db),
                user: dict = Depends(require_permission("spec:create"))):
    sheet = spec_service.generate(
        db, payload.brand, payload.model, payload.version, payload.attributes,
        requested_by=pseudonimizar(user["sub"]),
    )
    metrics.SPECS_GENERATED.inc()
    registrar_auditoria(db, user["sub"], "gerar_ficha",
                        f"{payload.brand}/{payload.model}/{payload.version}")
    return sheet


@router.get("/specs/export",
            summary="Exporta a ficha no formato BASE (CSV) — gestor/administrador")
def export_spec(
    brand: str = Query("Ford", max_length=60),
    model: str = Query("Ranger", max_length=60),
    version: str = Query(..., max_length=120),
    db: Session = Depends(get_db),
    user: dict = Depends(require_permission("spec:export")),
):
    brand = _texto_query(brand, "brand")
    model = _texto_query(model, "model")
    version = _texto_query(version, "version")
    sheet = spec_service.generate(db, brand, model, version, None,
                                  requested_by=pseudonimizar(user["sub"]))
    registrar_auditoria(db, user["sub"], "exportar_ficha", f"{brand}/{model}/{version}")
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";")
    writer.writerow(["Categoria", "Atributo", "Valor", "Status"])
    for it in sheet["items"]:
        writer.writerow([_celula_csv_segura(it[k])
                         for k in ("category", "attribute", "value", "status")])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition":
                 f'attachment; filename="{_nome_arquivo_seguro(brand, model, version)}"'},
    )


@router.get("/specs/{request_id}",
            summary="Recupera os metadados de uma ficha gerada (dono ou gestor/admin)")
def get_spec(request_id: str = Path(..., pattern=_UUID_RE),
             db: Session = Depends(get_db),
             user: dict = Depends(require_permission("spec:read_own"))):
    req = spec_service.get_request(db, request_id)
    dono = req is not None and req.requested_by == pseudonimizar(user["sub"])
    if not req or not (dono or has_permission(user, "spec:read_any")):
        if req:
            metrics.AUTHZ_DENIED.labels(permission="spec:read_any").inc()
            log_evento_seguranca("bola_bloqueado", detalhe=f"ficha={request_id}",
                                 usuario=user["sub"])
        raise HTTPException(status_code=404, detail="Ficha não encontrada.")
    return {
        "id": req.id, "brand": req.brand, "model": req.model,
        "version": req.version, "created_at": str(req.created_at),
    }
