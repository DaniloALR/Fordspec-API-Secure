"""Fixtures: banco SQLite temporário semeado, segredos de teste e clientes por perfil."""
import os
import tempfile

# Configura o ambiente ANTES de importar a aplicação (config é lida no import).
_TMP = tempfile.mkdtemp(prefix="fordspec-test-")
os.environ.update({
    "APP_ENV": "test",
    "DATABASE_URL": f"sqlite:///{os.path.join(_TMP, 'test.db')}",
    "SEED_PASSWORD_BRIGADISTA": "Brigadista-Teste-2026",
    "SEED_PASSWORD_GESTOR": "Gestor-Teste-2026",
    "SEED_PASSWORD_ADMINISTRADOR": "Admin-Teste-2026",
    "LOG_FILE": "",
})

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.db.database import engine  # noqa: E402
from app.main import app  # noqa: E402
from app.security.audit import monitor  # noqa: E402
from app.security.auth import denylist  # noqa: E402
from app.security.protection import limiter  # noqa: E402
from seed import seed_database  # noqa: E402

SENHAS = {
    "brigadista": "Brigadista-Teste-2026",
    "gestor": "Gestor-Teste-2026",
    "administrador": "Admin-Teste-2026",
}
VERSAO = "Limited 3.0L V6 26MY"


@pytest.fixture(scope="session", autouse=True)
def _banco():
    seed_database.run()
    yield


@pytest.fixture(autouse=True)
def _reset_estado():
    """Isola os testes: rate limit, monitor, denylist e lockouts de conta."""
    limiter.limpar()
    monitor.limpar()
    denylist.limpar()
    with engine.begin() as conn:
        conn.execute(text("UPDATE app_user SET failed_attempts=0, locked_until=NULL"))
    yield


def novo_client(ip: str = "testclient", **kw) -> TestClient:
    return TestClient(app, client=(ip, 50000), **kw)


@pytest.fixture
def client():
    return novo_client()


def login(client: TestClient, username: str, senha: str | None = None) -> dict:
    r = client.post("/v1/auth/login",
                    json={"username": username, "password": senha or SENHAS[username]})
    assert r.status_code == 200, r.text
    return r.json()


def auth_header(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


@pytest.fixture
def headers(client):
    """Headers Authorization por perfil: headers['gestor'] etc."""
    return {role: auth_header(login(client, role)) for role in SENHAS}
