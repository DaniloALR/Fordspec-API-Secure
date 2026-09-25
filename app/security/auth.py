"""Autenticação: hash de senha (bcrypt) e JWT seguro (PyJWT).

Sprint 3:
- python-jose (CVE-2024-33663/33664) substituído por PyJWT.
- Claims obrigatórias: iss, aud, iat, nbf, exp, jti, sub, type, ver.
- Algoritmo fixo (HS256) na validação — bloqueia `alg: none` e algorithm confusion.
- Refresh token com rotação: cada uso revoga o jti anterior; reuso é detectado.
- `ver` (token_version do usuário) invalida todos os tokens após troca de perfil,
  desativação ou logout global.
"""
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.core.config import settings

ALGORITHM = "HS256"
BCRYPT_MAX_BYTES = 72

ROLES = ("brigadista", "gestor", "administrador")

REQUIRED_CLAIMS = ["exp", "iat", "nbf", "iss", "aud", "sub", "jti", "type", "role", "ver"]

# Hash fixo usado quando o usuário não existe: o tempo de resposta fica igual ao
# de um usuário válido, evitando enumeração de contas por timing.
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password-timing", bcrypt.gensalt()).decode()


def hash_password(senha: str) -> str:
    return bcrypt.hashpw(senha.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(senha: str, senha_hash: str | None) -> bool:
    dados = senha.encode("utf-8")
    if len(dados) > BCRYPT_MAX_BYTES:
        return False
    # sempre executa o bcrypt (mesmo sem usuário) para tempo de resposta constante
    ok = bcrypt.checkpw(dados, (senha_hash or _DUMMY_HASH).encode("utf-8"))
    return ok and senha_hash is not None


class TokenDenylist:
    """jti revogados até expirarem. Em produção: Redis com TTL (ver documento)."""

    def __init__(self):
        self._itens: dict[str, float] = {}
        self._lock = threading.Lock()

    def revogar(self, jti: str, exp: float):
        with self._lock:
            self._itens[jti] = exp
            agora = time.time()
            for k in [k for k, v in self._itens.items() if v < agora]:
                del self._itens[k]

    def revogado(self, jti: str) -> bool:
        with self._lock:
            return jti in self._itens

    def limpar(self):
        with self._lock:
            self._itens.clear()


denylist = TokenDenylist()


def _create_token(subject: str, role: str, version: int, token_type: str,
                  delta: timedelta) -> str:
    agora = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "role": role,
        "ver": version,
        "type": token_type,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": agora,
        "nbf": agora,
        "exp": agora + delta,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def create_access_token(subject: str, role: str, version: int = 0) -> str:
    return _create_token(subject, role, version, "access",
                         timedelta(minutes=settings.access_token_minutes))


def create_refresh_token(subject: str, role: str, version: int = 0) -> str:
    return _create_token(subject, role, version, "refresh",
                         timedelta(days=settings.refresh_token_days))


class RevokedTokenError(jwt.InvalidTokenError):
    def __init__(self, payload: dict):
        super().__init__("Token revogado.")
        self.payload = payload


def decode_token(token: str, expected_type: str = "access") -> dict:
    """Valida assinatura, algoritmo, emissor, audiência, validade, tipo e revogação.

    Lança jwt.InvalidTokenError (ou subclasse) em qualquer falha; RevokedTokenError
    carrega o payload para permitir detectar reuso de refresh token.
    """
    payload = jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[ALGORITHM],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
        options={"require": REQUIRED_CLAIMS},
        leeway=5,
    )
    if payload["type"] != expected_type:
        raise jwt.InvalidTokenError("Tipo de token inválido.")
    if denylist.revogado(payload["jti"]):
        raise RevokedTokenError(payload)
    return payload


def revoke_token(payload: dict):
    denylist.revogar(payload["jti"], float(payload["exp"]))
