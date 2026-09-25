import re
from pydantic import BaseModel, Field, field_validator

MAX_TEXT_LEN = 120
MAX_ATTRS = 50

SAFE_TEXT = re.compile(r"^[\w\sÀ-ÿ.,()/+\-]{1,120}$", re.UNICODE)

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


class SecureSpecRequestIn(BaseModel):
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


class LoginIn(BaseModel):
    username: str = Field(..., min_length=3, max_length=40)
    password: str = Field(..., min_length=6, max_length=72)

    @field_validator("username")
    @classmethod
    def _val_user(cls, v):
        if not re.match(r"^[a-zA-Z0-9_.@-]+$", v):
            raise ValueError("Usuário contém caracteres inválidos.")
        return v
