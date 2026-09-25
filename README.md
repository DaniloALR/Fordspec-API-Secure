# FordSpec AI — API (Desafio 01 · Arquitetura & Web Services · Sprint 3 DevSecOps)

API REST de **Inteligência Competitiva Automotiva**. Recebe `Marca + Modelo + Versão + atributos` e devolve uma **ficha técnica padronizada** a partir de uma **base curada** com **regras determinísticas** (zero alucinação). Campos inexistentes saem como `ND`.

> **Sprint 3 (Cybersecurity/DevSecOps):** documento de entrega em
> [`docs_seguranca/SPRINT3_DevSecOps.md`](docs_seguranca/SPRINT3_DevSecOps.md): pipeline, segurança
> em código e infraestrutura, observabilidade/resposta a incidentes e compliance.

---

## Grupo 

| Nome | RM |
|------|----|
| Danilo Affonso Luz Rios | 554791 |
| Thiago Feltrin Geraldes | 555805 |
| Lucca Natario do Vale | 95688 |

## Arquitetura (SOA — serviços independentes)

```
                       API Gateway (FastAPI / prefixo /v1)
                                    │
        ┌──────────────┬────────────┴───────────┬──────────────┐
        ▼              ▼                         ▼              ▼
 catalog-service  vehicle-service          spec-service   export-service
 (dicionário de   (base curada de          (monta a       (exporta no
  atributos)       veículos)                ficha)          formato BASE)
        └──────────────┴────────────┬───────────┴──────────────┘
                                    ▼
                            PostgreSQL / SQLite
```

### Separação de camadas (3 camadas isoladas)
```
routers/        → APRESENTAÇÃO (HTTP, validação de entrada, status codes)
services/       → SERVIÇO      (regra de negócio determinística)
repositories/   → DADOS        (única camada que acessa o ORM)
db/             → modelos + conexão
```

---

## Como executar

```bash
# 1. dependências (inclui ferramentas de teste e segurança)
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

# 2. (opcional) configuração — sem .env, em dev os segredos são gerados em .dev-secrets.json
cp .env.example .env

# 3. popular a base curada e criar os usuários brigadista / gestor / administrador
#    (senhas vêm de SEED_PASSWORD_<PERFIL> ou são geradas e exibidas uma única vez)
python -m seed.seed_database

# 4. subir a API
uvicorn app.main:app --reload

# 5. documentação interativa (desligada quando APP_ENV=production)
#    Swagger UI : http://localhost:8000/docs
```

> Se houver um `fordspec.db` da Sprint 2, apague-o antes do passo 3: o schema mudou
> (tabelas `app_user` e `audit_event` e a coluna `spec_request.requested_by`). Em
> PostgreSQL, use `alembic upgrade head`.

Ambiente completo (Postgres + MQTT/TLS + Prometheus/Grafana/Loki): `docker compose up -d --build`
(ver seção 5 do documento da Sprint 3).

---

## Endpoints (contrato REST)

Todas as rotas `/v1/*` (exceto `/v1/auth/login` e `/v1/auth/refresh`) exigem `Authorization: Bearer <access_token>`.

| Método | Rota | Função | Perfis |
|--------|------|--------|--------|
| `POST` | `/v1/auth/login` | Autentica (access 15 min + refresh 7 dias) | — |
| `POST` | `/v1/auth/refresh` | Rotaciona o refresh token | — |
| `POST` | `/v1/auth/logout` | Encerra todas as sessões | todos |
| `GET`  | `/v1/auth/me` | Usuário e permissões | todos |
| `GET`  | `/v1/attributes` | Dicionário de atributos (14 categorias / 262 itens) | todos |
| `GET`  | `/v1/vehicles?brand=&model=` | Versões disponíveis na base curada | todos |
| `POST` | `/v1/specs` | Gera a ficha padronizada (201) | todos |
| `GET`  | `/v1/specs/{id}` | Metadados de uma ficha | dono · gestor · administrador |
| `GET`  | `/v1/specs/export?version=` | Exporta no formato BASE (CSV) | gestor · administrador |
| `GET`  | `/v1/admin/audit` | Trilha de auditoria (gestor vê só as próprias ações) | gestor · administrador |
| `GET/POST/PATCH` | `/v1/admin/users…` | Gestão de usuários e perfis | administrador |
| `GET`  | `/v1/admin/permissions/report` | Auditoria de permissões | administrador |
| `GET`  | `/v1/admin/audit/verify` | Integridade da cadeia de auditoria | administrador |
| `GET`  | `/metrics` | Métricas Prometheus (token em produção) | — |

### Exemplo — gerar ficha
```bash
TOKEN=$(curl -s -X POST http://localhost:8000/v1/auth/login -H "Content-Type: application/json" \
  -d '{"username":"brigadista","password":"<senha>"}' | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -X POST http://localhost:8000/v1/specs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "brand": "Ford",
    "model": "Ranger",
    "version": "Limited 3.0L V6 26MY",
    "attributes": ["Potência", "Torque", "Polegadas"]
  }'
```

### Resposta (formato padronizado — sempre igual)
```json
{
  "id": "a1b2c3...",
  "vehicle": { "brand": "Ford", "model": "Ranger", "version": "Limited 3.0L V6 26MY" },
  "generated_at": "2026-05-22T10:00:00Z",
  "total_attributes": 3,
  "items": [
    { "attribute": "Potência", "category": "Engine & Transmission", "value": "250", "unit": "cv", "status": "confirmed", "source": "Ford data sheet BASE (curado)" },
    { "attribute": "Torque", "category": "Engine & Transmission", "value": "600", "unit": "Nm", "status": "confirmed", "source": "..." }
  ]
}
```

### Erros padronizados
| Situação | Status | `error` |
|----------|--------|---------|
| Versão não existe na base | 422 | `version_not_found` |
| Atributo fora do dicionário | 400 | `invalid_attribute` |
| Ficha não encontrada (ou de outro usuário) | 404 | (HTTP padrão) |
| Sem token / token inválido, expirado ou revogado | 401 | — |
| Perfil sem permissão | 403 | — |
| Entrada inválida | 422 | `validation_error` |
| Corpo acima de 16 KB | 413 | `payload_too_large` |
| Excesso de requisições | 429 | `rate_limited` (+ `Retry-After`) |

```json
{ "error": "version_not_found",
  "message": "Versão 'Raptr' não encontrada na base curada para Ford Ranger.",
  "status": 422 }
```

---

## Banco de dados

| Tabela | Papel |
|--------|-------|
| `attribute` | Dicionário mestre (14 categorias / 262 atributos) — garante formato único |
| `vehicle_version` | Base curada (marca/modelo/versão) |
| `spec_value` | Valor de cada atributo por versão, com `status` e `source` (rastreável) |
| `spec_request` | Registro de cada ficha gerada (dono pseudonimizado) |
| `app_user` | Usuários, perfil, hash bcrypt, e-mail **cifrado**, lockout, `token_version` |
| `audit_event` | Trilha de auditoria com hash encadeado |

**Migrações:** versionadas com Alembic (`alembic revision --autogenerate` / `alembic upgrade head`). Ver `migrations/`.

---

## Testes

```bash
pytest -v --cov=app --cov=iot     # 81 testes: contrato, JWT, RBAC, BOLA, validação,
                                  # rate limit, criptografia, logs, IoT e backup
pip-audit -r requirements.txt     # SCA
bandit -r app iot scripts seed -ll -ii   # SAST
```

O pipeline [`.github/workflows/devsecops.yml`](.github/workflows/devsecops.yml) roda esses
testes e scanners, além de Gitleaks, Semgrep, Checkov, Trivy, SBOM e OWASP ZAP, em cada push/PR.

---

## Como esta API conversa com as outras disciplinas

- **Cybersecurity** → JWT seguro, RBAC Brigadista/Gestor/Administrador, criptografia local, pipeline DevSecOps, observabilidade e LGPD ([documento](docs_seguranca/SPRINT3_DevSecOps.md)).
- **Mobile/IoT** → o app React Native consome `/v1/attributes`, `/v1/vehicles` e `/v1/specs` (com Bearer token); a telemetria entra por MQTT/TLS (`iot/`).
- **IA/ML** → camada de matching de sinônimos antes do `catalog-service`.
- **Testing/QA** → `tests/` é executado como gate no pipeline.
