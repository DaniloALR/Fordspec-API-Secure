import time
import hmac
import hashlib
import os
from collections import defaultdict, deque
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

RATE_LIMIT = 60
WINDOW_SECONDS = 60
_hits: dict[str, deque] = defaultdict(deque)

HMAC_SECRET = os.getenv("HMAC_SECRET", "segredo-hmac-trocar-em-producao").encode()


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client = request.client.host if request.client else "unknown"
        now = time.time()
        janela = _hits[client]
        while janela and janela[0] < now - WINDOW_SECONDS:
            janela.popleft()
        if len(janela) >= RATE_LIMIT:
            return JSONResponse(
                status_code=429,
                content={"error": "rate_limited",
                         "message": "Muitas requisições. Tente novamente em instantes.",
                         "status": 429},
            )
        janela.append(now)
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        return resp


def assinar_payload(corpo: bytes) -> str:
    return hmac.new(HMAC_SECRET, corpo, hashlib.sha256).hexdigest()


def verificar_assinatura(corpo: bytes, assinatura: str) -> bool:
    esperado = assinar_payload(corpo)
    return hmac.compare_digest(esperado, assinatura or "")
