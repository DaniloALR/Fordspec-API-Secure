"""Controle de acesso por perfil (RBAC) — Brigadista, Gestor, Administrador.

Sprint 3:
- Matriz de permissões explícita (menor privilégio); rotas exigem permissões,
  não nomes de perfil.
- O perfil vem do BANCO a cada requisição, não do token: rebaixar/desativar um
  usuário tem efeito imediato. `ver` do token precisa bater com `token_version`.
"""
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models import AppUser
from app.observability import metrics
from app.security.audit import contexto_var, log_evento_seguranca
from app.security.auth import decode_token

bearer = HTTPBearer(auto_error=False)

_BRIGADISTA = {"catalog:read", "spec:create", "spec:read_own"}
_GESTOR = _BRIGADISTA | {"spec:read_any", "spec:export", "audit:read"}
_ADMINISTRADOR = _GESTOR | {"user:read", "user:manage", "audit:verify"}

PERMISSIONS: dict[str, frozenset[str]] = {
    "brigadista": frozenset(_BRIGADISTA),
    "gestor": frozenset(_GESTOR),
    "administrador": frozenset(_ADMINISTRADOR),
}


def _nao_autorizado(detalhe: str, motivo: str):
    metrics.TOKEN_REJECTED.labels(reason=motivo).inc()
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detalhe,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(cred: HTTPAuthorizationCredentials = Depends(bearer),
                     db: Session = Depends(get_db)) -> dict:
    if cred is None:
        raise _nao_autorizado("Credenciais não fornecidas.", "ausente")
    try:
        payload = decode_token(cred.credentials, expected_type="access")
    except jwt.ExpiredSignatureError:
        raise _nao_autorizado("Token inválido ou expirado.", "expirado")
    except jwt.InvalidTokenError:
        log_evento_seguranca("token_invalido", detalhe="assinatura/claims inválidas")
        raise _nao_autorizado("Token inválido ou expirado.", "invalido")

    user = db.query(AppUser).filter(AppUser.username == payload["sub"]).first()
    if not user or not user.is_active or user.token_version != payload["ver"]:
        raise _nao_autorizado("Token inválido ou expirado.", "sessao_invalidada")
    ctx = contexto_var.get()
    if ctx is not None:
        ctx["usuario"] = user.username
    return {"sub": user.username, "role": user.role, "jti": payload["jti"]}


def has_permission(user: dict, permissao: str) -> bool:
    return permissao in PERMISSIONS.get(user["role"], frozenset())


def require_permission(permissao: str):
    def checker(user: dict = Depends(get_current_user)) -> dict:
        if not has_permission(user, permissao):
            metrics.AUTHZ_DENIED.labels(permission=permissao).inc()
            log_evento_seguranca("acesso_negado", detalhe=permissao,
                                 usuario=user["sub"], perfil=user["role"])
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permissão insuficiente para esta operação.",
            )
        return user
    return checker
