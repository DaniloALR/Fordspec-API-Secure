import hashlib
import hmac
import json
import math
import re
import secrets
import threading
import time
from collections import OrderedDict

VERSAO = 1
MAX_PAYLOAD_BYTES = 2048
MAX_CLOCK_SKEW_S = 30
DEVICE_ID_RE = re.compile(r"^[a-z0-9-]{3,40}$")
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
CAMPOS = {"v", "device_id", "ts", "nonce", "data", "sig"}

FAIXAS = {
    "velocidade_kmh": (0, 300),
    "rpm": (0, 9000),
    "temp_motor_c": (-40, 150),
    "bateria_v": (0, 60),
    "combustivel_pct": (0, 100),
    "odometro_km": (0, 2_000_000),
    "lat": (-90, 90),
    "lon": (-180, 180),
}
CASAS_LOCALIZACAO = 3


class TelemetryRejected(Exception):
    def __init__(self, motivo: str):
        super().__init__(motivo)
        self.motivo = motivo


def chave_dispositivo(chave_mestra: bytes, device_id: str) -> bytes:
    return hmac.new(chave_mestra, f"fordspec-device:{device_id}".encode(),
                    hashlib.sha256).digest()


def _canonico(msg: dict) -> bytes:
    sem_assinatura = {k: v for k, v in msg.items() if k != "sig"}
    return json.dumps(sem_assinatura, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def assinar(device_id: str, dados: dict, chave: bytes, agora: float | None = None,
            nonce: str | None = None) -> bytes:
    msg = {
        "v": VERSAO,
        "device_id": device_id,
        "ts": int(agora if agora is not None else time.time()),
        "nonce": nonce or secrets.token_hex(16),
        "data": dados,
    }
    msg["sig"] = hmac.new(chave, _canonico(msg), hashlib.sha256).hexdigest()
    return json.dumps(msg, separators=(",", ":")).encode("utf-8")


class NonceCache:
    def __init__(self, ttl: int = 2 * MAX_CLOCK_SKEW_S, limite: int = 100_000):
        self.ttl = ttl
        self.limite = limite
        self._itens: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def registrar(self, chave: str, agora: float) -> bool:
        with self._lock:
            while self._itens:
                antigo, ts = next(iter(self._itens.items()))
                if ts >= agora - self.ttl and len(self._itens) < self.limite:
                    break
                self._itens.popitem(last=False)
            if chave in self._itens:
                return False
            self._itens[chave] = agora
            return True


def minimizar_localizacao(dados: dict) -> dict:
    saida = dict(dados)
    for campo in ("lat", "lon"):
        if campo in saida:
            saida[campo] = round(saida[campo], CASAS_LOCALIZACAO)
    return saida


def verificar(bruto: bytes, chave_mestra: bytes, nonces: NonceCache,
              device_do_topico: str | None = None, agora: float | None = None) -> dict:
    agora = agora if agora is not None else time.time()
    if len(bruto) > MAX_PAYLOAD_BYTES:
        raise TelemetryRejected("payload_grande")
    try:
        msg = json.loads(bruto)
    except (ValueError, UnicodeDecodeError):
        raise TelemetryRejected("json_invalido")
    if not isinstance(msg, dict) or set(msg) != CAMPOS or msg.get("v") != VERSAO:
        raise TelemetryRejected("schema_invalido")

    device_id = msg["device_id"]
    if not isinstance(device_id, str) or not DEVICE_ID_RE.match(device_id):
        raise TelemetryRejected("device_id_invalido")
    if device_do_topico is not None and device_do_topico != device_id:
        raise TelemetryRejected("device_diferente_do_topico")

    esperado = hmac.new(chave_dispositivo(chave_mestra, device_id), _canonico(msg),
                        hashlib.sha256).hexdigest()
    if not isinstance(msg["sig"], str) or not hmac.compare_digest(esperado, msg["sig"]):
        raise TelemetryRejected("assinatura_invalida")

    if not isinstance(msg["ts"], int) or abs(agora - msg["ts"]) > MAX_CLOCK_SKEW_S:
        raise TelemetryRejected("timestamp_fora_da_janela")
    if not isinstance(msg["nonce"], str) or not NONCE_RE.match(msg["nonce"]):
        raise TelemetryRejected("nonce_invalido")

    dados = msg["data"]
    if not isinstance(dados, dict) or not dados or not set(dados) <= set(FAIXAS):
        raise TelemetryRejected("campos_desconhecidos")
    for campo, valor in dados.items():
        minimo, maximo = FAIXAS[campo]
        if (isinstance(valor, bool) or not isinstance(valor, (int, float))
                or not math.isfinite(valor) or not minimo <= valor <= maximo):
            raise TelemetryRejected(f"valor_fora_da_faixa:{campo}")

    if not nonces.registrar(f"{device_id}:{msg['nonce']}", agora):
        raise TelemetryRejected("replay")

    msg["data"] = minimizar_localizacao(dados)
    return msg
