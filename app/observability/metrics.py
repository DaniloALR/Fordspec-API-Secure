from prometheus_client import CollectorRegistry, Counter, Histogram

registry = CollectorRegistry(auto_describe=True)

HTTP_REQUESTS = Counter(
    "fordspec_http_requests_total", "Requisições HTTP por rota, método e status.",
    ["method", "route", "status"], registry=registry,
)
HTTP_LATENCY = Histogram(
    "fordspec_http_request_duration_seconds", "Latência das requisições HTTP.",
    ["method", "route"], registry=registry,
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)
LOGIN_FAILURES = Counter(
    "fordspec_auth_login_failures_total", "Falhas de login.", ["reason"], registry=registry,
)
LOGIN_SUCCESS = Counter(
    "fordspec_auth_login_success_total", "Logins bem-sucedidos.", ["role"], registry=registry,
)
ACCOUNT_LOCKOUTS = Counter(
    "fordspec_auth_account_lockouts_total", "Contas bloqueadas por excesso de falhas.",
    registry=registry,
)
BRUTE_FORCE_ALERTS = Counter(
    "fordspec_security_brute_force_alerts_total", "Alertas de brute force por IP.",
    registry=registry,
)
TOKEN_REJECTED = Counter(
    "fordspec_auth_token_rejected_total", "Tokens rejeitados (inválido/expirado/revogado).",
    ["reason"], registry=registry,
)
REFRESH_REUSE = Counter(
    "fordspec_auth_refresh_reuse_total", "Reuso de refresh token revogado (possível roubo).",
    registry=registry,
)
AUTHZ_DENIED = Counter(
    "fordspec_authz_denied_total", "Acessos negados por RBAC/objeto.", ["permission"],
    registry=registry,
)
RATE_LIMITED = Counter(
    "fordspec_rate_limited_total", "Requisições bloqueadas por rate limit.", ["rule"],
    registry=registry,
)
INPUT_REJECTED = Counter(
    "fordspec_input_rejected_total", "Entradas rejeitadas pela validação.", ["route"],
    registry=registry,
)
PAYLOAD_TOO_LARGE = Counter(
    "fordspec_payload_too_large_total", "Corpos de requisição acima do limite.",
    registry=registry,
)
CRITICAL_CHANGES = Counter(
    "fordspec_critical_changes_total", "Alterações críticas (usuários/perfis).", ["action"],
    registry=registry,
)
SPECS_GENERATED = Counter(
    "fordspec_specs_generated_total", "Fichas técnicas geradas.", registry=registry,
)


for _r in ("senha_incorreta", "usuario_inexistente", "conta_bloqueada", "conta_inativa"):
    LOGIN_FAILURES.labels(reason=_r)
for _r in ("ausente", "expirado", "invalido", "sessao_invalidada", "refresh_invalido"):
    TOKEN_REJECTED.labels(reason=_r)
for _r in ("login", "refresh", "default"):
    RATE_LIMITED.labels(rule=_r)
for _a in ("usuario_criado", "alteracao_perfil", "usuario_desativado"):
    CRITICAL_CHANGES.labels(action=_a)
for _p in ("catalog:read", "spec:create", "spec:read_own", "spec:read_any", "spec:export",
           "audit:read", "user:read", "user:manage", "audit:verify"):
    AUTHZ_DENIED.labels(permission=_p)
for _p in ("brigadista", "gestor", "administrador"):
    LOGIN_SUCCESS.labels(role=_p)
