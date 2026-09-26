import argparse
import json
import os
import random
import ssl
import sys
import time
from datetime import datetime, timezone

from iot.telemetry import NonceCache, TelemetryRejected, assinar, chave_dispositivo, verificar

TOPICO_TELEMETRIA = "fordspec/telemetry/{device}/data"
TOPICO_ASSINATURA = "fordspec/telemetry/+/data"
PORTA_TLS = 8883


def log(evento: str, **campos):
    print(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "servico": "fordspec-iot",
                      "evento": evento, **campos}, ensure_ascii=False), flush=True)


def contexto_tls(ca: str | None, cert: str | None, key: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    if cert and key:
        ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


def chave_mestra() -> bytes:
    valor = os.getenv("IOT_HMAC_MASTER_KEY", "")
    if len(valor) < 32:
        sys.exit("IOT_HMAC_MASTER_KEY ausente ou com menos de 32 caracteres.")
    return valor.encode()


def _cliente(client_id: str):
    import paho.mqtt.client as mqtt

    porta = int(os.getenv("MQTT_PORT", str(PORTA_TLS)))
    if porta == 1883:
        sys.exit("Porta 1883 (MQTT sem TLS) não é permitida.")
    c = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                    client_id=client_id, protocol=mqtt.MQTTv311)
    c.tls_set_context(contexto_tls(os.getenv("MQTT_CA"), os.getenv("MQTT_CERT"),
                                   os.getenv("MQTT_KEY")))
    c.tls_insecure_set(False)
    c.reconnect_delay_set(min_delay=1, max_delay=60)
    return c, os.getenv("MQTT_HOST", "localhost"), porta


def publicar(device_id: str, intervalo: float, quantidade: int, ataque: bool = False):
    chave = chave_dispositivo(chave_mestra(), device_id)
    c, host, porta = _cliente(device_id)
    c.connect(host, porta, keepalive=30)
    c.loop_start()
    topico = TOPICO_TELEMETRIA.format(device=device_id)
    ultima = None
    try:
        for _ in range(quantidade):
            dados = {
                "velocidade_kmh": round(random.uniform(0, 140), 1),  # nosec B311
                "rpm": random.randint(800, 4500),  # nosec B311
                "temp_motor_c": round(random.uniform(80, 105), 1),  # nosec B311
                "lat": -23.5613 + random.uniform(-0.01, 0.01),  # nosec B311
                "lon": -46.6565 + random.uniform(-0.01, 0.01),  # nosec B311
            }
            ultima = assinar(device_id, dados, chave)
            c.publish(topico, ultima, qos=1).wait_for_publish(timeout=10)
            log("telemetria_publicada", device_id=device_id)
            time.sleep(intervalo)
        if ataque and ultima:
            c.publish(topico, ultima, qos=1).wait_for_publish(timeout=10)
            forjada = assinar(device_id, {"velocidade_kmh": 0},
                              b"chave-roubada-errada-de-32-bytes!!")
            c.publish(topico, forjada, qos=1).wait_for_publish(timeout=10)
            log("ataque_simulado_publicado", device_id=device_id, tipos=["replay", "forjada"])
    finally:
        c.loop_stop()
        c.disconnect()


def assinar_topico():
    from prometheus_client import Counter, start_http_server

    mensagens = Counter("fordspec_iot_messages_total",
                        "Mensagens de telemetria por resultado.", ["result"])
    for resultado in ("aceita", "assinatura_invalida", "replay", "timestamp_fora_da_janela",
                      "device_diferente_do_topico", "schema_invalido", "json_invalido",
                      "payload_grande", "device_id_invalido", "nonce_invalido",
                      "campos_desconhecidos", "valor_fora_da_faixa"):
        mensagens.labels(result=resultado)
    start_http_server(int(os.getenv("IOT_METRICS_PORT", "9101")))
    mestra = chave_mestra()
    nonces = NonceCache()
    c, host, porta = _cliente(os.getenv("MQTT_CLIENT_ID", "ingest-service"))

    def on_connect(client, userdata, flags, reason_code, properties):
        log("conectado", broker=host, porta=porta, resultado=str(reason_code))
        client.subscribe(TOPICO_ASSINATURA, qos=1)

    def on_message(client, userdata, message):
        device = message.topic.split("/")[2]
        try:
            msg = verificar(message.payload, mestra, nonces, device_do_topico=device)
            mensagens.labels(result="aceita").inc()
            log("telemetria_aceita", device_id=msg["device_id"], dados=msg["data"])
        except TelemetryRejected as exc:
            mensagens.labels(result=exc.motivo.split(":")[0]).inc()
            log("telemetria_rejeitada", nivel="WARNING", device_topico=device,
                motivo=exc.motivo)

    c.on_connect = on_connect
    c.on_message = on_message
    c.connect(host, porta, keepalive=30)
    c.loop_forever()


def main():
    p = argparse.ArgumentParser(description="Cliente MQTT seguro para telemetria FordSpec")
    sub = p.add_subparsers(dest="modo", required=True)
    pub = sub.add_parser("publish")
    pub.add_argument("--device", required=True)
    pub.add_argument("--intervalo", type=float, default=5.0)
    pub.add_argument("--quantidade", type=int, default=10)
    pub.add_argument("--ataque", action="store_true",
                     help="ao final, envia um replay e uma mensagem forjada (teste de alertas)")
    sub.add_parser("subscribe")
    args = p.parse_args()
    if args.modo == "publish":
        publicar(args.device, args.intervalo, args.quantidade, args.ataque)
    else:
        assinar_topico()


if __name__ == "__main__":
    main()
