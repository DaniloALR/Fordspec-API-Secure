from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.security.rbac import PERMISSIONS, get_current_user
from app.security.validation import LoginIn, RefreshIn
from app.services.auth_service import AuthService

router = APIRouter(prefix="/v1/auth", tags=["auth"])
auth_service = AuthService()


@router.post("/login", summary="Autentica e retorna access + refresh token")
def login(payload: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    return auth_service.login(db, payload.username, payload.password, ip)


@router.post("/refresh", summary="Rotaciona o refresh token e emite novo par de tokens")
def refresh(body: RefreshIn, db: Session = Depends(get_db)):
    return auth_service.refresh(db, body.refresh_token)


@router.post("/logout", status_code=204,
             summary="Encerra todas as sessões do usuário (revoga access e refresh)")
def logout(user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    auth_service.logout(db, user["sub"])


@router.get("/me", summary="Retorna o usuário autenticado e suas permissões")
def me(user: dict = Depends(get_current_user)):
    return {"sub": user["sub"], "role": user["role"],
            "permissions": sorted(PERMISSIONS[user["role"]])}
