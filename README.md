# FordSpec AI — API (Desafio 01 · Arquitetura & Web Services)

API REST de **Inteligência Competitiva Automotiva**. Recebe `Marca + Modelo + Versão + atributos` e devolve uma **ficha técnica padronizada** a partir de uma **base curada** com **regras determinísticas** (zero alucinação). Campos inexistentes saem como `ND`.

> Validação oficial do desafio: a ficha da **Ford Ranger Raptor** é entregue corretamente (ver `test_aceitacao_raptor.py`).

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
# 1. dependências
pip install -r requirements.txt

# 2. (opcional) banco Postgres — senão usa SQLite local
export DATABASE_URL="postgresql+psycopg2://user:pass@localhost/fordspec"

# 3. popular base curada a partir do data sheet BASE da Ford
python -m seed.seed_database

# 4. subir a API
uvicorn app.main:app --reload

# 5. abrir documentação interativa
#    Swagger UI : http://localhost:8000/docs
#    ReDoc      : http://localhost:8000/redoc
```

---

## Endpoints (contrato REST)

| Método | Rota | Função | Status |
|--------|------|--------|--------|
| `GET`  | `/v1/attributes` | Dicionário de atributos (14 categorias / 262 itens) | 200 |
| `GET`  | `/v1/vehicles?brand=&model=` | Versões disponíveis na base curada | 200 |
| `POST` | `/v1/specs` | Gera a ficha padronizada | 201 |
| `GET`  | `/v1/specs/{id}` | Metadados de uma ficha gerada | 200 / 404 |
| `GET`  | `/v1/specs/export?version=` | Exporta no formato BASE (CSV) | 200 |

### Exemplo — gerar ficha
```bash
curl -X POST http://localhost:8000/v1/specs \
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
| Ficha não encontrada | 404 | (HTTP padrão) |

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
| `spec_request` | Registro de cada ficha gerada |

**Migrações:** versionadas com Alembic (`alembic revision --autogenerate` / `alembic upgrade head`). Ver `migrations/`.

---

## Testes

```bash
python test_api.py               # endpoints + regra ND + erros
python test_aceitacao_raptor.py  # teste de aceitação oficial (Ranger Raptor 5/5)
```

---

## Como esta API conversa com as outras disciplinas

- **Cybersecurity** → adiciona JWT/RBAC, rate limit e validação sobre estes endpoints.
- **Mobile/IoT** → o app React Native consome `/v1/attributes`, `/v1/vehicles` e `/v1/specs`.
- **IA/ML** → camada de matching de sinônimos antes do `catalog-service`.
- **Testing/QA** → o teste de aceitação da Raptor é o critério de "solução operando corretamente".
