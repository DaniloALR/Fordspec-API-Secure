from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.db.database import Base, engine
from app.db import models  # noqa: F401
from app.core.exceptions import DomainError
from app.routers import catalog, specs, auth
from app.security.protection import RateLimitMiddleware, SecurityHeadersMiddleware

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="FordSpec AI — API (Secure)",
    version="1.1.0",
    description="API do Desafio 01 com camadas de segurança (Cybersecurity).",
)

ALLOWED_ORIGINS = ["https://app.fordspec.local", "http://localhost:8081"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)


@app.exception_handler(DomainError)
async def domain_error_handler(request: Request, exc: DomainError):
    return JSONResponse(
        status_code=exc.status,
        content={"error": exc.error, "message": exc.message, "status": exc.status},
    )


@app.get("/", tags=["health"], summary="Health check")
def root():
    return {"service": "FordSpec AI (Secure)", "status": "ok", "version": "1.1.0"}


app.include_router(auth.router)
app.include_router(catalog.router)
app.include_router(specs.router)
