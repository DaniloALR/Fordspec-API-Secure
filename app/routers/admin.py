from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.security.audit import verificar_cadeia
from app.security.rbac import PERMISSIONS, has_permission, require_permission
from app.security.validation import RoleUpdateIn, UserCreateIn
from app.services.auth_service import UserService

router = APIRouter(prefix="/v1/admin", tags=["admin & auditoria"])
user_service = UserService()

USERNAME_PATH = Path(..., min_length=3, max_length=40, pattern=r"^[a-zA-Z0-9_.@-]+$")


@router.get("/users", summary="Lista usuários (e-mail mascarado) — administrador")
def list_users(db: Session = Depends(get_db),
               _: dict = Depends(require_permission("user:read"))):
    return user_service.list_users(db)


@router.post("/users", status_code=201, summary="Cria usuário — administrador")
def create_user(body: UserCreateIn, db: Session = Depends(get_db),
                admin: dict = Depends(require_permission("user:manage"))):
    return user_service.create(db, admin["sub"], body.username, body.password,
                               body.role, body.email)


@router.patch("/users/{username}/role", summary="Altera o perfil (alteração crítica)")
def change_role(body: RoleUpdateIn, username: str = USERNAME_PATH,
                db: Session = Depends(get_db),
                admin: dict = Depends(require_permission("user:manage"))):
    return user_service.change_role(db, admin["sub"], username, body.role)


@router.post("/users/{username}/deactivate", summary="Desativa usuário e revoga sessões")
def deactivate(username: str = USERNAME_PATH, db: Session = Depends(get_db),
               admin: dict = Depends(require_permission("user:manage"))):
    return user_service.deactivate(db, admin["sub"], username)


@router.post("/users/{username}/unlock", summary="Desbloqueia conta após lockout")
def unlock(username: str = USERNAME_PATH, db: Session = Depends(get_db),
           admin: dict = Depends(require_permission("user:manage"))):
    return user_service.unlock(db, admin["sub"], username)


@router.get("/permissions/report",
            summary="Auditoria de permissões: matriz perfil × permissão e usuários")
def permissions_report(db: Session = Depends(get_db),
                       _: dict = Depends(require_permission("user:read"))):
    return user_service.permissions_report(db, PERMISSIONS)


@router.get("/audit", summary="Trilha de auditoria (gestor vê só as próprias ações)")
def audit(limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db),
          user: dict = Depends(require_permission("audit:read"))):
    actor = None if has_permission(user, "audit:verify") else user["sub"]
    return user_service.audit_events(db, limit, actor)


@router.get("/audit/verify", summary="Verifica a integridade da cadeia de auditoria")
def audit_verify(db: Session = Depends(get_db),
                 _: dict = Depends(require_permission("audit:verify"))):
    return verificar_cadeia(db)
