from fastapi import APIRouter, Request, HTTPException, Depends
from app.security.auth import (
    hash_password, verify_password, create_access_token, create_refresh_token,
    decode_token,
)
from app.security.rbac import get_current_user
from app.security.validation import LoginIn
from app.security.audit import log_auditoria, log_evento_seguranca, monitor
from jose import JWTError

router = APIRouter(prefix="/v1/auth", tags=["auth"])

USERS = {
    "analista":  {"senha_hash": hash_password("senha-analista"), "role": "analista"},
    "curador":   {"senha_hash": hash_password("senha-curador"),  "role": "curador"},
    "admin":     {"senha_hash": hash_password("senha-admin"),    "role": "admin"},
}


@router.post("/login", summary="Autentica e retorna access + refresh token")
def login(payload: LoginIn, request: Request):
    ip = request.client.host if request.client else "unknown"
    user = USERS.get(payload.username)
    if not user or not verify_password(payload.password, user["senha_hash"]):
        # monitora tentativas repetidas (possível brute force)
        monitor.registrar_falha(ip)
        log_evento_seguranca("login_falha", ip, f"usuario={payload.username}")
        # mensagem genérica — não revela se o usuário existe
        raise HTTPException(status_code=401, detail="Credenciais inválidas.")
    monitor.resetar(ip)
    log_auditoria(payload.username, "login", "/v1/auth/login")
    return {
        "access_token": create_access_token(payload.username, user["role"]),
        "refresh_token": create_refresh_token(payload.username, user["role"]),
        "token_type": "bearer",
        "role": user["role"],
    }


@router.post("/refresh", summary="Renova o access token a partir do refresh token")
def refresh(body: dict):
    token = body.get("refresh_token", "")
    try:
        payload = decode_token(token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Token inválido.")
        return {
            "access_token": create_access_token(payload["sub"], payload["role"]),
            "token_type": "bearer",
        }
    except JWTError:
        raise HTTPException(status_code=401, detail="Refresh token inválido ou expirado.")


@router.get("/me", summary="Retorna o usuário autenticado")
def me(user: dict = Depends(get_current_user)):
    return user
