import base64
import hashlib
import hmac

from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy.types import Text, TypeDecorator

from app.core.config import settings


def _derivar_chave(segredo: str) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"fordspec-data-encryption-v1")
    return base64.urlsafe_b64encode(hkdf.derive(segredo.encode("utf-8")))


def construir_cifrador(segredos: list[str]) -> MultiFernet:
    return MultiFernet([Fernet(_derivar_chave(s)) for s in segredos])


_cifrador = construir_cifrador(settings.data_enc_keys)


def criptografar(texto: str) -> str:
    return _cifrador.encrypt(texto.encode("utf-8")).decode("ascii")


def descriptografar(token: str) -> str:
    return _cifrador.decrypt(token.encode("ascii")).decode("utf-8")


def recriptografar(token: str) -> str:
    return _cifrador.rotate(token.encode("ascii")).decode("ascii")


class EncryptedString(TypeDecorator):
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return None if value is None else criptografar(value)

    def process_result_value(self, value, dialect):
        return None if value is None else descriptografar(value)


def pseudonimizar(identificador: str) -> str:
    h = hmac.new(settings.pseudo_salt.encode("utf-8"),
                 identificador.encode("utf-8"), hashlib.sha256).hexdigest()
    return "ANON_" + h[:16]


def mascarar_email(email: str) -> str:
    if "@" not in email:
        return "****"
    user, dom = email.split("@", 1)
    if len(user) <= 2:
        return "*" * len(user) + "@" + dom
    return user[0] + "*" * (len(user) - 2) + user[-1] + "@" + dom
