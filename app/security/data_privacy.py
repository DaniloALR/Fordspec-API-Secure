import os
import hashlib
import base64
from cryptography.fernet import Fernet

_secret = os.getenv("DATA_ENC_KEY", "chave-de-dados-trocar-em-producao-32b")
_key = base64.urlsafe_b64encode(hashlib.sha256(_secret.encode()).digest())
_fernet = Fernet(_key)

PSEUDO_SALT = os.getenv("PSEUDO_SALT", "salt-pseudonimizacao").encode()


def criptografar(texto: str) -> str:
    return _fernet.encrypt(texto.encode()).decode()


def descriptografar(token: str) -> str:
    return _fernet.decrypt(token.encode()).decode()


def pseudonimizar(identificador: str) -> str:
    h = hashlib.sha256(PSEUDO_SALT + identificador.encode()).hexdigest()
    return "ANON_" + h[:16]


def mascarar_email(email: str) -> str:
    if "@" not in email:
        return "****"
    user, dom = email.split("@", 1)
    if len(user) <= 2:
        return "*" * len(user) + "@" + dom
    return user[0] + "*" * (len(user) - 2) + user[-1] + "@" + dom
