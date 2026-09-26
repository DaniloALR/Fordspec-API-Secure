import contextvars
import hashlib
import json
import logging
import os
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from app.core.config import settings
from app.observability import metrics

trace_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("trace_id", default=None)
client_ip_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("client_ip", default=None)
contexto_var: contextvars.ContextVar[dict | None] = contextvars.ContextVar("contexto", default=None)

_CAMPOS_PROIBIDOS = ("senha", "password", "token", "secret", "authorization")

logger = logging.getLogger("fordspec.security")
logger.setLevel(logging.INFO)
logger.propagate = False
if not logger.handlers:
    logger.addHandler(logging.StreamHandler(sys.stdout))
    if settings.log_file:
        os.makedirs(os.path.dirname(settings.log_file) or ".", exist_ok=True)
        logger.addHandler(RotatingFileHandler(
            settings.log_file, maxBytes=5_000_000, backupCount=5, encoding="utf-8"))


def _sanitizar(campos: dict) -> dict:
    return {k: v for k, v in campos.items()
            if not any(p in k.lower() for p in _CAMPOS_PROIBIDOS)}


def _emit(tipo: str, nivel: str = "INFO", **campos):
    registro = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "nivel": nivel,
        "tipo": tipo,
        "servico": "fordspec-api",
        "ambiente": settings.app_env,
        "trace_id": campos.pop("trace_id", None) or trace_id_var.get(),
        **_sanitizar(campos),
    }
    logger.log(getattr(logging, nivel, logging.INFO), json.dumps(registro, ensure_ascii=False, default=str))


def log_evento_seguranca(evento: str, ip: str | None = None, detalhe: str = "",
                         nivel: str = "WARNING", **extra):
    _emit("seguranca", nivel=nivel, evento=evento, ip=ip or client_ip_var.get(),
          detalhe=detalhe, **extra)


def log_auditoria(usuario: str, acao: str, recurso: str, **extra):
    _emit("auditoria", usuario=usuario, acao=acao, recurso=recurso,
          ip=client_ip_var.get(), **extra)


def log_acesso(metodo: str, rota: str, status: int, duracao_ms: float,
               ip: str, usuario: str | None = None):
    _emit("acesso", nivel="ERROR" if status >= 500 else "INFO", metodo=metodo,
          rota=rota, status=status, duracao_ms=round(duracao_ms, 2), ip=ip,
          usuario=usuario)


def log_erro(evento: str, detalhe: str):
    _emit("erro", nivel="ERROR", evento=evento, detalhe=detalhe)


GENESIS_HASH = "0" * 64


def _hash_evento(prev_hash: str, ts: datetime, actor: str, action: str,
                 resource: str, ip: str | None) -> str:
    conteudo = "|".join([prev_hash, ts.isoformat(), actor, action, resource, ip or ""])
    return hashlib.sha256(conteudo.encode("utf-8")).hexdigest()


_audit_lock = threading.Lock()


def registrar_auditoria(db, actor: str, action: str, resource: str):
    from app.db.models import AuditEvent

    log_auditoria(actor, action, resource)
    ip = client_ip_var.get()
    with _audit_lock:
        ultimo = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
        prev = ultimo.hash if ultimo else GENESIS_HASH
        ts = datetime.now(timezone.utc).replace(tzinfo=None)
        evento = AuditEvent(
            ts=ts, actor=actor, action=action, resource=resource[:200], ip=ip,
            trace_id=trace_id_var.get(), prev_hash=prev,
            hash=_hash_evento(prev, ts, actor, action, resource[:200], ip),
        )
        db.add(evento)
        db.commit()
    return evento


def verificar_cadeia(db) -> dict:
    from app.db.models import AuditEvent

    prev = GENESIS_HASH
    total = 0
    for ev in db.query(AuditEvent).order_by(AuditEvent.id).all():
        total += 1
        esperado = _hash_evento(prev, ev.ts, ev.actor, ev.action, ev.resource, ev.ip)
        if ev.prev_hash != prev or ev.hash != esperado:
            return {"integra": False, "total": total, "registro_adulterado": ev.id}
        prev = ev.hash
    return {"integra": True, "total": total, "registro_adulterado": None}


class SuspiciousActivityMonitor:
    def __init__(self, limite: int = 5, janela_segundos: int = 300):
        self.limite = limite
        self.janela = janela_segundos
        self._falhas: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def registrar_falha(self, ip: str) -> bool:
        agora = time.time()
        with self._lock:
            fila = self._falhas[ip]
            while fila and fila[0] < agora - self.janela:
                fila.popleft()
            fila.append(agora)
            qtd = len(fila)
        if qtd >= self.limite:
            metrics.BRUTE_FORCE_ALERTS.inc()
            log_evento_seguranca("brute_force_suspeito", ip,
                                 f"{qtd} falhas em {self.janela}s", nivel="CRITICAL")
            return True
        return False

    def resetar(self, ip: str):
        with self._lock:
            self._falhas.pop(ip, None)

    def limpar(self):
        with self._lock:
            self._falhas.clear()


monitor = SuspiciousActivityMonitor()
