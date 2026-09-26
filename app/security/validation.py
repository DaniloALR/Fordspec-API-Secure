import re
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.security.auth import BCRYPT_MAX_BYTES, ROLES

MAX_TEXT_LEN = 120
MAX_ATTRS = 50

SAFE_TEXT = re.compile(r"^[\w\sÀ-ÿ.,()/+\-]{1,120}$", re.UNICODE)
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.@-]{3,40}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[a-zA-Z]{2,}$")

INJECTION_PATTERNS = re.compile(
    r"(--|;|/\*|\*/|<script|</script|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|"
    r"\bDELETE\b|\bUPDATE\b|\bOR\b\s+\d+=\d+|xp_|\$\(|`|\|\||&&)",
    re.IGNORECASE,
)


def sanitizar_texto(valor: str, campo: str) -> str:
    valor = valor.strip()
    if not valor:
        raise ValueError(f"{campo} não pode ser vazio.")
    if len(valor) > MAX_TEXT_LEN:
        raise ValueError(f"{campo} excede o tamanho máximo ({MAX_TEXT_LEN}).")
    if INJECTION_PATTERNS.search(valor):
        raise ValueError(f"{campo} contém caracteres ou padrões não permitidos.")
    if not SAFE_TEXT.match(valor):
        raise ValueError(f"{campo} contém caracteres inválidos.")
    return valor


def _validar_senha_forte(v: str) -> str:
    if len(v.encode("utf-8")) > BCRYPT_MAX_BYTES:
        raise ValueError(f"Senha excede {BCRYPT_MAX_BYTES} bytes.")
    if len(v) < 12 or not re.search(r"[A-Za-z]", v) or not re.search(r"\d", v):
        raise ValueError("Senha deve ter ao menos 12 caracteres, com letras e números.")
    return v


class _Estrito(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SecureSpecRequestIn(_Estrito):
    brand: str = Field(..., examples=["Ford"])
    model: str = Field(..., examples=["Ranger"])
    version: str = Field(..., examples=["Limited 3.0L V6 26MY"])
    attributes: list[str] | None = Field(default=None, max_length=MAX_ATTRS)

    @field_validator("brand", "model", "version")
    @classmethod
    def _val_textos(cls, v, info):
        return sanitizar_texto(v, info.field_name)

    @field_validator("attributes")
    @classmethod
    def _val_attrs(cls, v):
        if v is None:
            return v
        if len(v) > MAX_ATTRS:
            raise ValueError(f"Máximo de {MAX_ATTRS} atributos por requisição.")
        return [sanitizar_texto(a, "attribute") for a in v]


class LoginIn(_Estrito):
    username: str = Field(..., min_length=3, max_length=40)
    password: str = Field(..., min_length=6, max_length=72)

    @field_validator("username")
    @classmethod
    def _val_user(cls, v):
        if not USERNAME_RE.match(v):
            raise ValueError("Usuário contém caracteres inválidos.")
        return v

    @field_validator("password")
    @classmethod
    def _val_pwd(cls, v):
        if len(v.encode("utf-8")) > BCRYPT_MAX_BYTES:
            raise ValueError(f"Senha excede {BCRYPT_MAX_BYTES} bytes.")
        return v


class RefreshIn(_Estrito):
    refresh_token: str = Field(..., min_length=20, max_length=2048)


class UserCreateIn(_Estrito):
    username: str = Field(..., min_length=3, max_length=40)
    password: str = Field(..., min_length=12, max_length=72)
    role: str = Field(..., examples=["brigadista"])
    email: str | None = Field(default=None, max_length=254)

    @field_validator("username")
    @classmethod
    def _val_user(cls, v):
        if not USERNAME_RE.match(v):
            raise ValueError("Usuário contém caracteres inválidos.")
        return v

    @field_validator("password")
    @classmethod
    def _val_pwd(cls, v):
        return _validar_senha_forte(v)

    @field_validator("role")
    @classmethod
    def _val_role(cls, v):
        if v not in ROLES:
            raise ValueError(f"Perfil deve ser um de: {', '.join(ROLES)}.")
        return v

    @field_validator("email")
    @classmethod
    def _val_email(cls, v):
        if v is not None and not EMAIL_RE.match(v):
            raise ValueError("E-mail inválido.")
        return v


class RoleUpdateIn(_Estrito):
    role: str

    @field_validator("role")
    @classmethod
    def _val_role(cls, v):
        if v not in ROLES:
            raise ValueError(f"Perfil deve ser um de: {', '.join(ROLES)}.")
        return v
