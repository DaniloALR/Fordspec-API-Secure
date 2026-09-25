import json
import logging
import sys
import uuid
from datetime import datetime, timezone

logger = logging.getLogger("fordspec.security")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler(sys.stdout)
logger.addHandler(_handler)


def _emit(tipo: str, **campos):
    registro = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tipo": tipo,
        "trace_id": campos.pop("trace_id", str(uuid.uuid4())),
        **campos,
    }
    logger.info(json.dumps(registro, ensure_ascii=False))


def log_evento_seguranca(evento: str, ip: str, detalhe: str = "", trace_id: str = None):
    _emit("seguranca", evento=evento, ip=ip, detalhe=detalhe, trace_id=trace_id)


def log_auditoria(usuario: str, acao: str, recurso: str, trace_id: str = None):
    _emit("auditoria", usuario=usuario, acao=acao, recurso=recurso, trace_id=trace_id)


class SuspiciousActivityMonitor:
    def __init__(self, limite: int = 5):
        self.limite = limite
        self._falhas: dict[str, int] = {}

    def registrar_falha(self, ip: str) -> bool:
        self._falhas[ip] = self._falhas.get(ip, 0) + 1
        if self._falhas[ip] >= self.limite:
            log_evento_seguranca("brute_force_suspeito", ip,
                                 f"{self._falhas[ip]} falhas consecutivas")
            return True
        return False

    def resetar(self, ip: str):
        self._falhas.pop(ip, None)


monitor = SuspiciousActivityMonitor()
