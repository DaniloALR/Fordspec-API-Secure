import hmac

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.core.config import settings
from app.core.exceptions import DomainError
from app.db.database import Base, engine
from app.db import models  # noqa: F401
from app.observability.metrics import registry
from app.routers import admin, auth, catalog, specs
from app.security.audit import log_erro
from app.security.protection import (
    BodySizeLimitMiddleware, RateLimitMiddleware, RequestContextMiddleware,
    SecurityHeadersMiddleware,
)

APP_VERSION = "2.0.0"

# Em produção o schema é gerenciado apenas por migrações Alembic.
if not settings.is_production:
    Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="FordSpec AI — API (DevSecOps)",
    version=APP_VERSION,
    description="API do Desafio 01 com segurança contínua (Sprint 3 — DevSecOps).",
    # documentação interativa desabilitada em produção (reduz superfície de ataque)
    docs_url="/docs" if settings.docs_enabled else None,
    redoc_url="/redoc" if settings.docs_enabled else None,
    openapi_url="/openapi.json" if settings.docs_enabled else None,
)

# add_middleware empilha: o ÚLTIMO adicionado é o mais externo.
# BodySizeLimit fica mais interno: nenhum BaseHTTPMiddleware entre ele e a rota
# (esses envolvem o `receive` em task groups e mascarariam o 413).
app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=False,  # autenticação via header Bearer, não cookies
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID", "Retry-After"],
    max_age=600,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestContextMiddleware)


@app.exception_handler(DomainError)
async def domain_error_handler(request: Request, exc: DomainError):
    return JSONResponse(
        status_code=exc.status,
        content={"error": exc.error, "message": exc.message, "status": exc.status},
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    # não ecoa o valor recebido ("input"): evita refletir payload malicioso
    detalhes = [{"campo": ".".join(str(p) for p in e.get("loc", [])), "erro": e.get("msg")}
                for e in exc.errors()]
    return JSONResponse(
        status_code=422,
        content={"error": "validation_error", "message": "Entrada inválida.",
                 "status": 422, "details": detalhes},
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    # nunca expõe stack trace ao cliente; o detalhe fica no log com o trace_id
    log_erro("erro_nao_tratado", f"{type(exc).__name__}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error",
                 "message": "Erro interno. Informe o X-Request-ID ao suporte.",
                 "status": 500},
    )


@app.get("/", tags=["health"], summary="Health check")
def root():
    return {"service": "FordSpec AI", "status": "ok", "version": APP_VERSION}


@app.get("/metrics", include_in_schema=False)
def metrics_endpoint(request: Request):
    # Em produção exige o token do Prometheus (além da NetworkPolicy no k8s).
    if settings.metrics_token:
        recebido = request.headers.get("authorization", "")
        if not hmac.compare_digest(recebido, f"Bearer {settings.metrics_token}"):
            return JSONResponse(status_code=401, content={
                "error": "unauthorized", "message": "Token de métricas inválido.",
                "status": 401})
    return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)


app.include_router(auth.router)
app.include_router(catalog.router)
app.include_router(specs.router)
app.include_router(admin.router)
