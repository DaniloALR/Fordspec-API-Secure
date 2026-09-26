import re
import threading
import time
import uuid
from collections import defaultdict, deque

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import settings
from app.observability import metrics
from app.security.audit import (
    client_ip_var, contexto_var, log_acesso, log_evento_seguranca, trace_id_var,
)

WINDOW_SECONDS = 60
SEM_LIMITE = {"/metrics"}


def _erro(status: int, error: str, message: str, headers: dict | None = None):
    return JSONResponse(status_code=status, headers=headers,
                        content={"error": error, "message": message, "status": status})


def _ip(request_or_scope) -> str:
    client = request_or_scope.client if hasattr(request_or_scope, "client") \
        else request_or_scope.get("client")
    if not client:
        return "unknown"
    return client.host if hasattr(client, "host") else client[0]


class RateLimiter:
    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    @staticmethod
    def regra(path: str) -> tuple[str, int]:
        if path == "/v1/auth/login":
            return "login", settings.rate_limit_login
        if path == "/v1/auth/refresh":
            return "refresh", settings.rate_limit_refresh
        return "default", settings.rate_limit_default

    def permitir(self, chave: str, limite: int) -> tuple[bool, int]:
        agora = time.time()
        with self._lock:
            janela = self._hits[chave]
            while janela and janela[0] < agora - WINDOW_SECONDS:
                janela.popleft()
            if len(janela) >= limite:
                return False, int(janela[0] + WINDOW_SECONDS - agora) + 1
            janela.append(agora)
            if len(self._hits) > 10_000:
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return True, 0

    def limpar(self):
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in SEM_LIMITE:
            return await call_next(request)
        ip = _ip(request)
        regra, limite = limiter.regra(request.url.path)
        ok, retry = limiter.permitir(f"{regra}:{ip}", limite)
        if not ok:
            metrics.RATE_LIMITED.labels(rule=regra).inc()
            log_evento_seguranca("rate_limit_excedido", ip, f"regra={regra} limite={limite}/min")
            return _erro(429, "rate_limited",
                         "Muitas requisições. Tente novamente em instantes.",
                         {"Retry-After": str(retry)})
        return await call_next(request)


class _PayloadTooLarge(HTTPException):
    def __init__(self, max_bytes: int):
        super().__init__(status_code=413,
                         detail=f"Corpo da requisição excede {max_bytes} bytes.")


class BodySizeLimitMiddleware:
    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        headers = dict(scope.get("headers") or [])
        cl = headers.get(b"content-length")
        if cl is not None:
            if not cl.isdigit():
                return await _erro(400, "bad_request", "Content-Length inválido.")(scope, receive, send)
            if int(cl) > self.max_bytes:
                return await self._rejeitar(scope, receive, send)

        recebido = 0

        async def receive_limitado():
            nonlocal recebido
            msg = await receive()
            if msg["type"] == "http.request":
                recebido += len(msg.get("body", b""))
                if recebido > self.max_bytes:
                    self._registrar(scope)
                    raise _PayloadTooLarge(self.max_bytes)
            return msg

        try:
            await self.app(scope, receive_limitado, send)
        except _PayloadTooLarge:
            await self._resposta_413()(scope, receive, send)

    def _registrar(self, scope):
        metrics.PAYLOAD_TOO_LARGE.inc()
        log_evento_seguranca("payload_excedido", _ip(scope), f"limite={self.max_bytes}B")

    def _resposta_413(self):
        return _erro(413, "payload_too_large",
                     f"Corpo da requisição excede {self.max_bytes} bytes.")

    async def _rejeitar(self, scope, receive, send):
        self._registrar(scope)
        await self._resposta_413()(scope, receive, send)


_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        recebido = request.headers.get("x-request-id", "")
        trace_id = recebido if _REQUEST_ID_RE.match(recebido) else str(uuid.uuid4())
        ip = _ip(request)
        trace_id_var.set(trace_id)
        client_ip_var.set(ip)
        ctx: dict = {}
        contexto_var.set(ctx)

        inicio = time.perf_counter()
        response = await call_next(request)
        duracao = time.perf_counter() - inicio

        rota_obj = request.scope.get("route")
        rota = getattr(rota_obj, "path", "nao_mapeada")
        metrics.HTTP_REQUESTS.labels(request.method, rota, str(response.status_code)).inc()
        metrics.HTTP_LATENCY.labels(request.method, rota).observe(duracao)
        if response.status_code == 422:
            metrics.INPUT_REJECTED.labels(route=rota).inc()
        if request.url.path != "/metrics":
            log_acesso(request.method, rota, response.status_code, duracao * 1000, ip,
                       ctx.get("usuario"))
        response.headers["X-Request-ID"] = trace_id
        return response


_CSP_API = "default-src 'none'; frame-ancestors 'none'"
_CSP_DOCS = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
             "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
             "img-src 'self' data: https://fastapi.tiangolo.com; frame-ancestors 'none'")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)
        docs = request.url.path in ("/docs", "/redoc", "/docs/oauth2-redirect")
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = _CSP_DOCS if docs else _CSP_API
        resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        resp.headers["Cache-Control"] = "no-store"
        return resp
