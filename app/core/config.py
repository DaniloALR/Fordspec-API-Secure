"""Configuração centralizada e gestão de segredos.

Todos os segredos vêm de variáveis de ambiente (ou de um arquivo .env local,
nunca versionado). Em produção (APP_ENV=production) a aplicação NÃO sobe se um
segredo estiver ausente ou fraco — elimina o antigo fallback hardcoded.
Em desenvolvimento, gera um segredo aleatório uma única vez (.dev-secrets.json,
ignorado pelo git); em teste (APP_ENV=test), gera segredos efêmeros.
"""
import json
import logging
import os
import secrets
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()

_log = logging.getLogger("fordspec.config")

MIN_SECRET_LEN = 32


class InsecureConfigError(RuntimeError):
    pass


def _env_list(name: str, default: str) -> list[str]:
    return [v.strip() for v in os.getenv(name, default).split(",") if v.strip()]


DEV_SECRETS_FILE = os.getenv("DEV_SECRETS_FILE", ".dev-secrets.json")


def _segredo_dev(name: str) -> str:
    """Gera o segredo uma vez e o reaproveita (arquivo local, fora do git).

    Sem isso, seed e API teriam chaves diferentes e os dados cifrados ficariam
    ilegíveis após cada reinício.
    """
    dados = {}
    if os.path.exists(DEV_SECRETS_FILE):
        with open(DEV_SECRETS_FILE, encoding="utf-8") as f:
            dados = json.load(f)
    if name not in dados:
        dados[name] = secrets.token_urlsafe(48)
        with open(DEV_SECRETS_FILE, "w", encoding="utf-8") as f:
            json.dump(dados, f, indent=2)
        _log.warning("%s não definido: segredo de DEV gerado em %s.", name, DEV_SECRETS_FILE)
    return dados[name]


def _secret(name: str, is_prod: bool) -> str:
    valor = os.getenv(name, "")
    if len(valor) >= MIN_SECRET_LEN:
        return valor
    if is_prod:
        raise InsecureConfigError(
            f"{name} ausente ou com menos de {MIN_SECRET_LEN} caracteres (produção)."
        )
    if os.getenv("APP_ENV") == "test":
        return secrets.token_urlsafe(48)
    return _segredo_dev(name)


@dataclass(frozen=True)
class Settings:
    app_env: str
    jwt_secret: str
    data_enc_keys: list[str]
    hmac_secret: str
    pseudo_salt: str
    metrics_token: str | None
    jwt_issuer: str = "fordspec-api"
    jwt_audience: str = "fordspec-clients"
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    allowed_origins: list[str] = field(default_factory=list)
    allowed_hosts: list[str] = field(default_factory=list)
    max_body_bytes: int = 16_384
    rate_limit_default: int = 60
    rate_limit_login: int = 5
    rate_limit_refresh: int = 10
    login_max_failures: int = 5
    lockout_minutes: int = 15
    log_file: str | None = None

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def docs_enabled(self) -> bool:
        return not self.is_production


def load_settings() -> Settings:
    app_env = os.getenv("APP_ENV", "development")
    is_prod = app_env == "production"

    # DATA_ENC_KEYS aceita várias chaves separadas por vírgula (rotação):
    # a primeira cifra, todas decifram.
    enc_keys = _env_list("DATA_ENC_KEYS", "")
    if not enc_keys or any(len(k) < MIN_SECRET_LEN for k in enc_keys):
        enc_keys = [_secret("DATA_ENC_KEYS", is_prod)]

    metrics_token = os.getenv("METRICS_TOKEN") or None
    if is_prod and not metrics_token:
        raise InsecureConfigError("METRICS_TOKEN é obrigatório em produção.")

    return Settings(
        app_env=app_env,
        jwt_secret=_secret("JWT_SECRET", is_prod),
        data_enc_keys=enc_keys,
        hmac_secret=_secret("HMAC_SECRET", is_prod),
        pseudo_salt=_secret("PSEUDO_SALT", is_prod),
        metrics_token=metrics_token,
        access_token_minutes=int(os.getenv("ACCESS_TOKEN_MINUTES", "15")),
        refresh_token_days=int(os.getenv("REFRESH_TOKEN_DAYS", "7")),
        allowed_origins=_env_list(
            "ALLOWED_ORIGINS", "https://app.fordspec.local,http://localhost:8081"
        ),
        allowed_hosts=_env_list(
            "ALLOWED_HOSTS", "localhost,127.0.0.1,testserver,api,*.fordspec.local"
        ),
        max_body_bytes=int(os.getenv("MAX_BODY_BYTES", "16384")),
        rate_limit_default=int(os.getenv("RATE_LIMIT_DEFAULT", "60")),
        rate_limit_login=int(os.getenv("RATE_LIMIT_LOGIN", "5")),
        rate_limit_refresh=int(os.getenv("RATE_LIMIT_REFRESH", "10")),
        login_max_failures=int(os.getenv("LOGIN_MAX_FAILURES", "5")),
        lockout_minutes=int(os.getenv("LOCKOUT_MINUTES", "15")),
        log_file=os.getenv("LOG_FILE") or None,
    )


settings = load_settings()
