# Threat Model (STRIDE) — FordSpec AI · revisão Sprint 3

Análise de ameaças da API de Inteligência Competitiva pelo método STRIDE.
A revisão completa por componente (API, IoT, dados, ML, pipeline), com status e riscos
residuais, está em [SPRINT3_DevSecOps.md, seção 4.1](SPRINT3_DevSecOps.md#41-revisão-final-dos-riscos-stride).

| Categoria STRIDE | Ameaça no contexto FordSpec | Mitigação (Sprint 2 → Sprint 3) |
|---|---|---|
| **S**poofing | Atacante se passa por brigadista/gestor para gerar ou exportar fichas; veículo falso publica telemetria | JWT com segredo obrigatório, algoritmo fixo e `aud/iss/jti` obrigatórios; rotação de refresh com detecção de reuso; lockout; mTLS + HMAC por dispositivo no MQTT |
| **T**ampering | Alteração de payload em trânsito; injeção em campos; imagem ou dependência adulterada | Validação por allowlist + `extra=forbid`; escape de LIKE; TLS/HSTS; HMAC na telemetria; SCA + Trivy + cosign + deploy por digest |
| **R**epudiation | Usuário nega ter feito uma alteração crítica (troca de perfil, exportação) | Auditoria persistida com hash encadeado (`/v1/admin/audit/verify`), `trace_id`, IP e usuário em todos os logs |
| **I**nformation Disclosure | Exposição de dados pessoais, localização, stack trace, segredos no Git; BOLA; scraping da base curada | E-mail cifrado (MultiFernet), pseudonimização, localização truncada, 500 genérico, 422 sem eco, Gitleaks, secrets como arquivo, verificação de dono, catálogo autenticado |
| **D**enial of Service | Flood, corpo gigante, flood MQTT | Rate limit por rota (login 5/min), 413 inclusive chunked, limites de recursos no k8s e HPA, limites do broker |
| **E**levation of Privilege | Brigadista executa ação de gestor/administrador; mass assignment; perfil antigo em token válido; escape do container | Matriz de permissões lida do banco + `token_version`; `extra=forbid`; não-root, read-only, drop ALL, PSA restricted |

## Superfície de ataque mapeada
- **Entradas do usuário** (marca/modelo/versão/atributos, query params do export) → validadas e sanitizadas.
- **Autenticação** (login/refresh/logout) → rate limit, lockout, monitoramento de brute force e reuso de token.
- **Endpoints privilegiados** (export, `/v1/admin/*`) → RBAC Brigadista/Gestor/Administrador.
- **Dados em repouso** (usuários, fichas, backups) → cifrados e pseudonimizados.
- **Telemetria IoT** (MQTT) → somente TLS, mTLS, ACL por dispositivo, mensagens assinadas.
- **Cadeia de suprimentos** (dependências, imagem, pipeline) → SCA, SAST, secret scanning, Trivy, SBOM, cosign.

## Riscos residuais e recomendações
- Rate limit e denylist de tokens em memória → migrar para Redis com várias réplicas.
- HS256 com segredo compartilhado → RS256/ES256 com chave no KMS/Vault quando outros serviços precisarem validar tokens.
- MFA para gestor/administrador.
- Logs em armazenamento imutável (WORM) para reforçar o não repúdio.
