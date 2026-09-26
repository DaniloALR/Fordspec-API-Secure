import json
import ssl
import subprocess
import sys

import pytest

from iot.mqtt_secure_client import contexto_tls
from iot.telemetry import (
    NonceCache, TelemetryRejected, assinar, chave_dispositivo, verificar,
)

MESTRA = b"chave-mestra-de-teste-com-32-bytes!!"
DEVICE = "ranger-demo-001"
AGORA = 1_790_000_000
DADOS = {"velocidade_kmh": 88.5, "rpm": 2500, "lat": -23.561345, "lon": -46.656512}


def _msg(dados=None, device=DEVICE, chave=None, agora=AGORA, nonce=None):
    chave = chave or chave_dispositivo(MESTRA, device)
    return assinar(device, dados or DADOS, chave, agora=agora, nonce=nonce)


def _rejeita(bruto, motivo, **kw):
    with pytest.raises(TelemetryRejected) as exc:
        verificar(bruto, MESTRA, kw.pop("nonces", NonceCache()), agora=AGORA, **kw)
    assert exc.value.motivo.startswith(motivo)


def test_mensagem_valida_e_localizacao_minimizada():
    msg = verificar(_msg(), MESTRA, NonceCache(), device_do_topico=DEVICE, agora=AGORA)
    assert msg["data"]["lat"] == -23.561 and msg["data"]["lon"] == -46.657


def test_adulteracao_detectada():
    m = json.loads(_msg())
    m["data"]["velocidade_kmh"] = 10
    _rejeita(json.dumps(m).encode(), "assinatura_invalida")


def test_chave_de_outro_dispositivo_nao_forja():
    forjada = _msg(device="ranger-vitima-002", chave=chave_dispositivo(MESTRA, DEVICE))
    _rejeita(forjada, "assinatura_invalida")


def test_replay_bloqueado():
    nonces = NonceCache()
    bruto = _msg()
    verificar(bruto, MESTRA, nonces, agora=AGORA)
    _rejeita(bruto, "replay", nonces=nonces)


def test_timestamp_antigo_rejeitado():
    _rejeita(_msg(agora=AGORA - 300), "timestamp_fora_da_janela")


def test_device_diferente_do_topico():
    _rejeita(_msg(), "device_diferente_do_topico", device_do_topico="outro-device")


@pytest.mark.parametrize("dados,motivo", [
    ({"velocidade_kmh": 999}, "valor_fora_da_faixa"),
    ({"rpm": float("nan")}, "valor_fora_da_faixa"),
    ({"rpm": True}, "valor_fora_da_faixa"),
    ({"comando": "unlock_doors"}, "campos_desconhecidos"),
])
def test_dados_invalidos(dados, motivo):
    _rejeita(_msg(dados=dados), motivo)


def test_payload_grande_e_json_invalido():
    _rejeita(b"{" * 5000, "payload_grande")
    _rejeita(b"nao-e-json", "json_invalido")


def test_contexto_tls_seguro():
    ctx = contexto_tls(None, None, None)
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True


@pytest.mark.parametrize("modulo", ["iot.mqtt_secure_client", "scripts.backup_db",
                                    "scripts.simulate_traffic"])
def test_linha_de_comando_inicia(modulo):
    r = subprocess.run([sys.executable, "-m", modulo, "--help"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
