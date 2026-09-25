# Migrações de Banco de Dados (Alembic)

Controle de versão do schema — atende a rubrica "Controle de migrações" (7%).

## Configuração

`alembic.ini` (raiz) aponta para `app.db.models.Base`. O `env.py` importa o
metadata para autogeração:

```python
from app.db.database import Base
from app.db import models  # registra as tabelas
target_metadata = Base.metadata
```

## Comandos

```bash
# inicializar (uma vez)
alembic init migrations

# gerar migração a partir das mudanças nos modelos
alembic revision --autogenerate -m "cria attribute, vehicle_version, spec_value"

# aplicar
alembic upgrade head

# reverter a última
alembic downgrade -1
```

## Migração inicial (referência)

A primeira migração cria as 4 tabelas:

| Revisão | Descrição |
|---------|-----------|
| `0001_initial` | `attribute`, `vehicle_version`, `spec_value`, `spec_request` |

Cada alteração futura de schema gera uma nova revisão versionada e rastreável
no controle de versão (Git), garantindo reprodutibilidade entre ambientes
(dev → staging → produção).
