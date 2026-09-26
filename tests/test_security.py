import json
import logging
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from sqlalchemy import text

from app.core.config import InsecureConfigError, load_settings, settings
from app.db.database import engine
from app.routers.specs import _celula_csv_segura, _nome_arquivo_seguro
from app.security import data_privacy
from app.security.audit import logger as security_logger
from app.security.auth import ALGORITHM
from tests.conftest import VERSAO, auth_header, login, novo_client

SPEC = {"brand": "Ford", "model": "Ranger", "version": VERSAO, "attributes": ["Potência"]}


def _token_manual(**sobrescrever) -> str:
    agora = datetime.now(timezone.utc)
    payload = {"sub": "administrador", "role": "administrador", "ver": 0, "type": "access",
               "iss": settings.jwt_issuer, "aud": settings.jwt_audience, "iat": agora,
               "nbf": agora, "exp": agora + timedelta(minutes=5), "jti": "x" * 32}
    payload.update(sobrescrever)
    segredo = payload.pop("_secret", settings.jwt_secret)
    return jwt.encode(payload, segredo, algorithm=ALGORITHM)


class _Coletor(logging.Handler):
    def __init__(self):
        super().__init__()
        self.registros: list[dict] = []

    def emit(self, record):
        self.registros.append(json.loads(record.getMessage()))


@pytest.fixture
def logs():
    h = _Coletor()
    security_logger.addHandler(h)
    yield h.registros
    security_logger.removeHandler(h)


class TestJWT:
    def test_sem_token_401(self, client):
        assert client.post("/v1/specs", json=SPEC).status_code == 401

    def test_token_tem_claims_obrigatorias(self, client):
        tokens = login(client, "brigadista")
        claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
        for c in ("iss", "aud", "iat", "nbf", "exp", "jti", "sub", "role", "ver", "type"):
            assert c in claims
        exp = claims["exp"] - claims["iat"]
        assert exp == settings.access_token_minutes * 60

    def test_alg_none_rejeitado(self, client):
        token = jwt.encode({"sub": "administrador", "role": "administrador"}, None,
                           algorithm="none")
        r = client.get("/v1/admin/users", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401

    def test_assinatura_com_outro_segredo_rejeitada(self, client):
        token = _token_manual(_secret="segredo-do-atacante-com-32-caracteres!!")
        r = client.get("/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401

    def test_token_expirado_rejeitado(self, client):
        passado = datetime.now(timezone.utc) - timedelta(hours=1)
        token = _token_manual(iat=passado, nbf=passado, exp=passado + timedelta(minutes=1))
        assert client.get("/v1/auth/me",
                          headers={"Authorization": f"Bearer {token}"}).status_code == 401

    def test_audiencia_errada_rejeitada(self, client):
        token = _token_manual(aud="outra-aplicacao")
        assert client.get("/v1/auth/me",
                          headers={"Authorization": f"Bearer {token}"}).status_code == 401

    def test_refresh_nao_serve_como_access(self, client):
        tokens = login(client, "gestor")
        r = client.get("/v1/auth/me",
                       headers={"Authorization": f"Bearer {tokens['refresh_token']}"})
        assert r.status_code == 401

    def test_rotacao_e_deteccao_de_reuso_do_refresh(self, client):
        t1 = login(client, "gestor")
        r = client.post("/v1/auth/refresh", json={"refresh_token": t1["refresh_token"]})
        assert r.status_code == 200
        t2 = r.json()
        assert t2["refresh_token"] != t1["refresh_token"]
        r = client.post("/v1/auth/refresh", json={"refresh_token": t1["refresh_token"]})
        assert r.status_code == 401
        assert client.get("/v1/auth/me", headers=auth_header(t2)).status_code == 401

    def test_logout_revoga_sessoes(self, client):
        tokens = login(client, "brigadista")
        h = auth_header(tokens)
        assert client.post("/v1/auth/logout", headers=h).status_code == 204
        assert client.get("/v1/auth/me", headers=h).status_code == 401

    def test_senha_acima_de_72_bytes_nao_gera_500(self, client):
        r = client.post("/v1/auth/login", json={"username": "gestor", "password": "é" * 40})
        assert r.status_code == 422


class TestLogin:
    def test_mensagem_generica(self, client):
        r1 = client.post("/v1/auth/login", json={"username": "gestor", "password": "errada123"})
        r2 = client.post("/v1/auth/login", json={"username": "naoexiste", "password": "errada123"})
        assert r1.status_code == r2.status_code == 401
        assert r1.json()["message"] == r2.json()["message"] == "Credenciais inválidas."

    def test_lockout_e_desbloqueio(self, client, headers):
        adm = headers["administrador"]
        client.post("/v1/admin/users", headers=adm, json={
            "username": "vitima.lockout", "password": "SenhaForte-12345", "role": "brigadista"})
        atacante = novo_client("10.0.0.66")
        for _ in range(settings.login_max_failures):
            atacante.post("/v1/auth/login",
                          json={"username": "vitima.lockout", "password": "chute-errado"})
        r = novo_client("10.0.0.67").post(
            "/v1/auth/login", json={"username": "vitima.lockout", "password": "SenhaForte-12345"})
        assert r.status_code == 401
        users = client.get("/v1/admin/users", headers=adm).json()
        assert next(u for u in users if u["username"] == "vitima.lockout")["locked"] is True
        assert client.post("/v1/admin/users/vitima.lockout/unlock", headers=adm).status_code == 200
        login(novo_client("10.0.0.68"), "vitima.lockout", "SenhaForte-12345")

    def test_brute_force_gera_alerta(self, logs):
        c = novo_client("10.9.9.9")
        for _ in range(5):
            c.post("/v1/auth/login", json={"username": "naoexiste", "password": "x" * 8})
        alertas = [r for r in logs if r.get("evento") == "brute_force_suspeito"]
        assert alertas and alertas[-1]["nivel"] == "CRITICAL"


MATRIZ = [
    ("brigadista", "GET", "/v1/attributes", 200),
    ("brigadista", "GET", f"/v1/specs/export?version={VERSAO}", 403),
    ("brigadista", "GET", "/v1/admin/users", 403),
    ("brigadista", "GET", "/v1/admin/audit", 403),
    ("gestor", "GET", f"/v1/specs/export?version={VERSAO}", 200),
    ("gestor", "GET", "/v1/admin/audit", 200),
    ("gestor", "GET", "/v1/admin/users", 403),
    ("gestor", "GET", "/v1/admin/audit/verify", 403),
    ("administrador", "GET", "/v1/admin/users", 200),
    ("administrador", "GET", "/v1/admin/permissions/report", 200),
    ("administrador", "GET", "/v1/admin/audit/verify", 200),
]


class TestRBAC:
    @pytest.mark.parametrize("perfil,metodo,rota,esperado", MATRIZ)
    def test_matriz_de_permissoes(self, client, headers, perfil, metodo, rota, esperado):
        assert client.request(metodo, rota, headers=headers[perfil]).status_code == esperado

    @pytest.mark.parametrize("perfil", ["brigadista", "gestor", "administrador"])
    def test_todos_os_perfis_geram_ficha(self, client, headers, perfil):
        assert client.post("/v1/specs", json=SPEC, headers=headers[perfil]).status_code == 201

    def test_troca_de_perfil_invalida_tokens_imediatamente(self, client, headers):
        adm = headers["administrador"]
        client.post("/v1/admin/users", headers=adm, json={
            "username": "gestor.temp", "password": "SenhaForte-12345", "role": "gestor"})
        h = auth_header(login(client, "gestor.temp", "SenhaForte-12345"))
        assert client.get(f"/v1/specs/export?version={VERSAO}", headers=h).status_code == 200
        r = client.patch("/v1/admin/users/gestor.temp/role", headers=adm,
                         json={"role": "brigadista"})
        assert r.status_code == 200
        assert client.get(f"/v1/specs/export?version={VERSAO}", headers=h).status_code == 401

    def test_nao_remove_ultimo_administrador(self, client, headers):
        r = client.patch("/v1/admin/users/administrador/role", headers=headers["administrador"],
                         json={"role": "brigadista"})
        assert r.status_code == 409

    def test_mass_assignment_bloqueado(self, client, headers):
        corpo = {**SPEC, "role": "administrador"}
        r = client.post("/v1/specs", json=corpo, headers=headers["brigadista"])
        assert r.status_code == 422

    def test_perfil_invalido_rejeitado(self, client, headers):
        r = client.post("/v1/admin/users", headers=headers["administrador"], json={
            "username": "x.root", "password": "SenhaForte-12345", "role": "root"})
        assert r.status_code == 422


class TestBOLA:
    def test_brigadista_nao_le_ficha_de_outro(self, client, headers):
        adm = headers["administrador"]
        client.post("/v1/admin/users", headers=adm, json={
            "username": "brigadista.b", "password": "SenhaForte-12345", "role": "brigadista"})
        dono = headers["brigadista"]
        outro = auth_header(login(client, "brigadista.b", "SenhaForte-12345"))
        ficha = client.post("/v1/specs", json=SPEC, headers=dono).json()["id"]
        assert client.get(f"/v1/specs/{ficha}", headers=dono).status_code == 200
        assert client.get(f"/v1/specs/{ficha}", headers=outro).status_code == 404
        assert client.get(f"/v1/specs/{ficha}", headers=headers["gestor"]).status_code == 200

    def test_id_malformado_rejeitado(self, client, headers):
        r = client.get("/v1/specs/1%20OR%201=1", headers=headers["gestor"])
        assert r.status_code == 422


class TestValidacao:
    @pytest.mark.parametrize("versao", [
        "' OR 1=1 --", "Raptor; DROP TABLE spec_value", "<script>alert(1)</script>",
        "$(whoami)", "a" * 121,
    ])
    def test_payloads_maliciosos_422(self, client, headers, versao):
        r = client.post("/v1/specs", headers=headers["brigadista"],
                        json={**SPEC, "version": versao})
        assert r.status_code == 422

    def test_erro_de_validacao_nao_ecoa_entrada(self, client, headers):
        r = client.post("/v1/specs", headers=headers["brigadista"],
                        json={**SPEC, "version": "<script>alert(1)</script>"})
        assert "<script>" not in r.text

    def test_excesso_de_atributos(self, client, headers):
        r = client.post("/v1/specs", headers=headers["brigadista"],
                        json={**SPEC, "attributes": ["Potência"] * 51})
        assert r.status_code == 422

    def test_curinga_like_nao_lista_tudo(self, client, headers):
        r = client.get("/v1/vehicles?brand=%25", headers=headers["brigadista"])
        assert r.status_code == 200 and r.json() == []

    def test_export_bloqueia_header_injection(self, client, headers):
        r = client.get("/v1/specs/export?version=Limited%0d%0aSet-Cookie:x=1",
                       headers=headers["gestor"])
        assert r.status_code == 422

    def test_nome_arquivo_e_celula_csv_seguros(self):
        assert _nome_arquivo_seguro("Ford", "../..", 'a"b') == "ficha_Ford_.._.._a_b.csv"
        assert _celula_csv_segura("=HYPERLINK(\"x\")").startswith("'")
        assert _celula_csv_segura("250") == "250"


class TestHardening:
    def test_headers_de_seguranca_e_trace_id(self, client):
        r = client.get("/")
        for h in ("Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options",
                  "Content-Security-Policy", "Referrer-Policy", "X-Request-ID",
                  "Cross-Origin-Resource-Policy"):
            assert h in r.headers
        assert r.headers["Content-Security-Policy"].startswith("default-src 'none'")

    def test_rate_limit_login(self):
        c = novo_client("10.1.1.1")
        codigos = [c.post("/v1/auth/login",
                          json={"username": "gestor", "password": "errada123"}).status_code
                   for _ in range(settings.rate_limit_login + 1)]
        assert codigos[-1] == 429
        r = c.post("/v1/auth/login", json={"username": "gestor", "password": "errada123"})
        assert "Retry-After" in r.headers

    def test_body_grande_413(self, client, headers):
        corpo = {**SPEC, "version": "x" * (settings.max_body_bytes + 10)}
        r = client.post("/v1/specs", json=corpo, headers=headers["brigadista"])
        assert r.status_code == 413

    def test_body_grande_sem_content_length_413(self, client, headers):
        def chunks():
            for _ in range(settings.max_body_bytes // 1000 + 2):
                yield b"x" * 1000
        h = {**headers["brigadista"], "Content-Type": "application/json"}
        r = client.post("/v1/specs", content=chunks(), headers=h)
        assert r.status_code == 413

    def test_host_nao_confiavel(self, client):
        assert client.get("/", headers={"Host": "evil.example.com"}).status_code == 400

    def test_erro_500_generico(self, headers, monkeypatch):
        from app.routers import specs

        def explode(*a, **kw):
            raise RuntimeError("detalhe interno: senha do banco")
        monkeypatch.setattr(specs.spec_service, "generate", explode)
        c = novo_client(raise_server_exceptions=False)
        r = c.post("/v1/specs", json=SPEC, headers=headers["brigadista"])
        assert r.status_code == 500
        assert "senha do banco" not in r.text and "Traceback" not in r.text

    def test_producao_exige_segredos(self, monkeypatch):
        monkeypatch.setenv("APP_ENV", "production")
        monkeypatch.delenv("JWT_SECRET", raising=False)
        with pytest.raises(InsecureConfigError):
            load_settings()


class TestCriptografia:
    def test_email_cifrado_no_banco_e_mascarado_na_api(self, client, headers):
        with engine.connect() as conn:
            bruto = conn.execute(text(
                "SELECT email FROM app_user WHERE username='gestor'")).scalar_one()
        assert bruto.startswith("gAAAAA") and "@" not in bruto
        users = client.get("/v1/admin/users", headers=headers["administrador"]).json()
        email = next(u["email"] for u in users if u["username"] == "gestor")
        assert email == "g****r@fordspec.local"

    def test_rotacao_de_chave(self):
        antiga = data_privacy.construir_cifrador(["chave-antiga-" + "a" * 32])
        token_antigo = antiga.encrypt(b"dado pessoal").decode()
        nova = data_privacy.construir_cifrador(["chave-nova-" + "b" * 32,
                                                "chave-antiga-" + "a" * 32])
        assert nova.decrypt(token_antigo.encode()) == b"dado pessoal"
        rotacionado = nova.rotate(token_antigo.encode())
        so_nova = data_privacy.construir_cifrador(["chave-nova-" + "b" * 32])
        assert so_nova.decrypt(rotacionado) == b"dado pessoal"

    def test_adulteracao_detectada(self):
        token = data_privacy.criptografar("segredo")
        adulterado = token[:-5] + ("A" if token[-5] != "A" else "B") + token[-4:]
        with pytest.raises(Exception):
            data_privacy.descriptografar(adulterado)

    def test_pseudonimizacao(self, client, headers):
        a = data_privacy.pseudonimizar("brigadista")
        assert a == data_privacy.pseudonimizar("brigadista") and a.startswith("ANON_")
        client.post("/v1/specs", json=SPEC, headers=headers["brigadista"])
        with engine.connect() as conn:
            donos = {r[0] for r in conn.execute(text("SELECT requested_by FROM spec_request"))}
        assert a in donos and "brigadista" not in donos


class TestObservabilidade:
    def test_log_estruturado_sem_segredos(self, client, logs):
        client.post("/v1/auth/login",
                    json={"username": "gestor", "password": "SenhaQueNaoPodeVazar1"})
        texto = json.dumps(logs)
        assert "SenhaQueNaoPodeVazar1" not in texto
        falha = next(r for r in logs if r.get("evento") == "login_falha")
        for campo in ("ts", "nivel", "tipo", "trace_id", "ip", "usuario"):
            assert campo in falha

    def test_trace_id_correlaciona_logs(self, client, logs):
        r = client.post("/v1/auth/login", json={"username": "gestor", "password": "errada123"},
                        headers={"X-Request-ID": "teste-correlacao-0001"})
        assert r.headers["X-Request-ID"] == "teste-correlacao-0001"
        assert {x["tipo"] for x in logs if x["trace_id"] == "teste-correlacao-0001"} >= {
            "seguranca", "acesso"}

    def test_cadeia_de_auditoria_detecta_adulteracao(self, client, headers):
        adm = headers["administrador"]
        assert client.get("/v1/admin/audit/verify", headers=adm).json()["integra"] is True
        with engine.begin() as conn:
            alvo, original = conn.execute(text(
                "SELECT id, actor FROM audit_event ORDER BY id LIMIT 1")).one()
            conn.execute(text("UPDATE audit_event SET actor='apagando-rastros' WHERE id=:i"),
                         {"i": alvo})
        try:
            r = client.get("/v1/admin/audit/verify", headers=adm).json()
            assert r["integra"] is False and r["registro_adulterado"] == alvo
        finally:
            with engine.begin() as conn:
                conn.execute(text("UPDATE audit_event SET actor=:a WHERE id=:i"),
                             {"a": original, "i": alvo})

    def test_gestor_ve_apenas_proprias_acoes(self, client, headers):
        eventos = client.get("/v1/admin/audit", headers=headers["gestor"]).json()
        assert eventos and {e["actor"] for e in eventos} == {"gestor"}

    def test_metricas_prometheus(self, client):
        client.post("/v1/auth/login", json={"username": "gestor", "password": "errada123"})
        corpo = client.get("/metrics").text
        assert "fordspec_auth_login_failures_total" in corpo
        assert "fordspec_http_requests_total" in corpo
