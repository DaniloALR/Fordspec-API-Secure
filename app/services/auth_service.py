"""Serviços de autenticação e gestão de usuários (camada de serviço)."""
from datetime import datetime, timedelta, timezone

import jwt
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    AuthenticationFailed, InvalidRefreshToken, LastAdministrator, UserAlreadyExists,
    UserNotFound,
)
from app.db.models import AppUser
from app.observability import metrics
from app.repositories.repositories import AuditRepository, UserRepository
from app.security.audit import log_evento_seguranca, monitor, registrar_auditoria
from app.security.auth import (
    RevokedTokenError, create_access_token, create_refresh_token, decode_token,
    hash_password, revoke_token, verify_password,
)
from app.security.data_privacy import mascarar_email, pseudonimizar


def _agora():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _par_de_tokens(user: AppUser) -> dict:
    return {
        "access_token": create_access_token(user.username, user.role, user.token_version),
        "refresh_token": create_refresh_token(user.username, user.role, user.token_version),
        "token_type": "bearer",  # tipo do token (RFC 6750), não senha  # nosec B105
        "expires_in": settings.access_token_minutes * 60,
        "role": user.role,
    }


class AuthService:
    def __init__(self):
        self.users = UserRepository()

    def login(self, db: Session, username: str, password: str, ip: str) -> dict:
        user = self.users.get_by_username(db, username)
        bloqueado = bool(user and user.locked_until and user.locked_until > _agora())
        # verify_password roda sempre (mesmo sem usuário) → tempo constante
        senha_ok = verify_password(password, user.password_hash if user else None)

        if not user or not senha_ok or bloqueado or not user.is_active:
            motivo = ("usuario_inexistente" if not user else
                      "conta_bloqueada" if bloqueado else
                      "conta_inativa" if not user.is_active else "senha_incorreta")
            self._registrar_falha(db, user, username, ip, motivo)
            raise AuthenticationFailed()

        user.failed_attempts = 0
        user.locked_until = None
        self.users.save(db)
        monitor.resetar(ip)
        metrics.LOGIN_SUCCESS.labels(role=user.role).inc()
        registrar_auditoria(db, user.username, "login_sucesso", "/v1/auth/login")
        return _par_de_tokens(user)

    def _registrar_falha(self, db, user, username, ip, motivo):
        metrics.LOGIN_FAILURES.labels(reason=motivo).inc()
        monitor.registrar_falha(ip)
        # usuário inexistente pode ser uma senha digitada no campo errado: pseudonimiza
        ident = user.username if user else pseudonimizar(username)
        log_evento_seguranca("login_falha", ip, motivo, usuario=ident)
        if user and motivo == "senha_incorreta":
            user.failed_attempts += 1
            if user.failed_attempts >= settings.login_max_failures:
                user.locked_until = _agora() + timedelta(minutes=settings.lockout_minutes)
                user.failed_attempts = 0
                metrics.ACCOUNT_LOCKOUTS.inc()
                log_evento_seguranca("conta_bloqueada", ip, nivel="CRITICAL",
                                     usuario=user.username,
                                     detalhe=f"{settings.login_max_failures} falhas; "
                                             f"bloqueio de {settings.lockout_minutes} min")
                registrar_auditoria(db, "sistema", "conta_bloqueada", user.username)
            self.users.save(db)

    def refresh(self, db: Session, refresh_token: str) -> dict:
        try:
            payload = decode_token(refresh_token, expected_type="refresh")
        except RevokedTokenError as exc:
            # refresh já usado sendo reapresentado = token provavelmente roubado:
            # invalida TODAS as sessões do usuário.
            metrics.REFRESH_REUSE.inc()
            user = self.users.get_by_username(db, exc.payload["sub"])
            if user:
                user.token_version += 1
                self.users.save(db)
            log_evento_seguranca("refresh_token_reutilizado", nivel="CRITICAL",
                                 usuario=exc.payload["sub"],
                                 detalhe="todas as sessões do usuário foram revogadas")
            raise InvalidRefreshToken()
        except jwt.InvalidTokenError:
            metrics.TOKEN_REJECTED.labels(reason="refresh_invalido").inc()
            raise InvalidRefreshToken()

        user = self.users.get_by_username(db, payload["sub"])
        if not user or not user.is_active or user.token_version != payload["ver"]:
            raise InvalidRefreshToken()
        revoke_token(payload)  # rotação: o refresh usado não vale mais
        return _par_de_tokens(user)

    def logout(self, db: Session, username: str):
        """Logout global: incrementa token_version, invalidando access e refresh."""
        user = self.users.get_by_username(db, username)
        if user:
            user.token_version += 1
            self.users.save(db)
            registrar_auditoria(db, username, "logout", "/v1/auth/logout")


class UserService:
    def __init__(self):
        self.users = UserRepository()
        self.audit = AuditRepository()

    @staticmethod
    def to_out(u: AppUser) -> dict:
        return {
            "username": u.username,
            "role": u.role,
            "email": mascarar_email(u.email) if u.email else None,
            "is_active": u.is_active,
            "locked": bool(u.locked_until and u.locked_until > _agora()),
            "updated_at": u.updated_at.isoformat() if u.updated_at else None,
        }

    def list_users(self, db: Session) -> list[dict]:
        return [self.to_out(u) for u in self.users.list_all(db)]

    def permissions_report(self, db: Session, permissions: dict) -> dict:
        """Auditoria de permissões: quem tem acesso a quê (rotina periódica)."""
        users = self.users.list_all(db)
        return {
            "gerado_em": _agora().isoformat(),
            "matriz": {r: sorted(p) for r, p in permissions.items()},
            "usuarios": [
                {"username": u.username, "role": u.role, "is_active": u.is_active,
                 "permissoes": sorted(permissions.get(u.role, []))}
                for u in users
            ],
            "resumo": {r: sum(1 for u in users if u.role == r and u.is_active)
                       for r in permissions},
        }

    def create(self, db: Session, actor: str, username: str, password: str,
               role: str, email: str | None) -> dict:
        if self.users.get_by_username(db, username):
            raise UserAlreadyExists(username)
        user = self.users.add(db, AppUser(
            username=username, password_hash=hash_password(password),
            role=role, email=email,
        ))
        metrics.CRITICAL_CHANGES.labels(action="usuario_criado").inc()
        registrar_auditoria(db, actor, "usuario_criado", f"{username} role={role}")
        return self.to_out(user)

    def change_role(self, db: Session, actor: str, username: str, role: str) -> dict:
        user = self._get(db, username)
        antigo = user.role
        if antigo == "administrador" and role != "administrador":
            self._garantir_outro_admin(db)
        user.role = role
        user.token_version += 1  # tokens antigos (com o perfil antigo) deixam de valer
        self.users.save(db)
        metrics.CRITICAL_CHANGES.labels(action="alteracao_perfil").inc()
        log_evento_seguranca("alteracao_perfil", nivel="WARNING", usuario=username,
                             detalhe=f"{antigo} -> {role} por {actor}")
        registrar_auditoria(db, actor, "alteracao_perfil", f"{username}: {antigo}->{role}")
        return self.to_out(user)

    def deactivate(self, db: Session, actor: str, username: str) -> dict:
        user = self._get(db, username)
        if user.role == "administrador":
            self._garantir_outro_admin(db)
        user.is_active = False
        user.token_version += 1
        self.users.save(db)
        metrics.CRITICAL_CHANGES.labels(action="usuario_desativado").inc()
        registrar_auditoria(db, actor, "usuario_desativado", username)
        return self.to_out(user)

    def unlock(self, db: Session, actor: str, username: str) -> dict:
        user = self._get(db, username)
        user.locked_until = None
        user.failed_attempts = 0
        self.users.save(db)
        registrar_auditoria(db, actor, "usuario_desbloqueado", username)
        return self.to_out(user)

    def audit_events(self, db: Session, limit: int, actor: str | None = None) -> list[dict]:
        return [
            {"id": e.id, "ts": e.ts.isoformat(), "actor": e.actor, "action": e.action,
             "resource": e.resource, "ip": e.ip, "trace_id": e.trace_id, "hash": e.hash}
            for e in self.audit.list_recent(db, limit, actor)
        ]

    def _get(self, db, username) -> AppUser:
        user = self.users.get_by_username(db, username)
        if not user:
            raise UserNotFound(username)
        return user

    def _garantir_outro_admin(self, db):
        if self.users.count_active_by_role(db, "administrador") <= 1:
            raise LastAdministrator()
