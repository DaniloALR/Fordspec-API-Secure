# Threat Model (STRIDE) — FordSpec AI

Análise de ameaças da API de Inteligência Competitiva, usando o método STRIDE.
Cada ameaça é mapeada à mitigação implementada e ao bloco da rubrica correspondente.

| Categoria STRIDE | Ameaça no contexto FordSpec | Mitigação implementada | Bloco |
|---|---|---|---|
| **S**poofing (falsificação de identidade) | Atacante se passa por analista para gerar/exportar fichas | Autenticação JWT com assinatura forte e expiração curta | 2 |
| **T**ampering (adulteração) | Alteração de payload em trânsito; injeção em campos | Validação/sanitização + HMAC de integridade + HTTPS/TLS | 1, 3 |
| **R**epudiation (repúdio) | Usuário nega ter feito uma alteração crítica | Trilha de auditoria (quem, quando, o quê) em log estruturado | 5 |
| **I**nformation Disclosure (vazamento) | Exposição de dados de cliente/lead ou stack trace | Criptografia em repouso, anonimização, erros genéricos, sem dados sensíveis em log | 1, 4 |
| **D**enial of Service (negação de serviço) | Scraping massivo ou flood derruba a API | Rate limiting/throttling + limite de tamanho de payload | 1, 3 |
| **E**levation of Privilege (elevação de privilégio) | Analista tenta executar ação de admin/curador | RBAC: verificação de papel antes de cada rota crítica | 2 |

## Superfície de ataque mapeada
- **Entradas do usuário** (marca/modelo/versão/atributos) → validadas e sanitizadas.
- **Autenticação** (login/refresh) → monitorada contra brute force.
- **Endpoints privilegiados** (export, edição de dicionário) → restritos por RBAC.
- **Dados em repouso** (se houver dados de cliente do Desafio 02) → criptografados.
- **Comunicação** app ↔ API → TLS + CORS allow-list + HMAC.

## Riscos residuais e recomendações
- Rate limit em memória → migrar para Redis em produção (escala horizontal).
- Secret HS256 em ambiente → migrar para RS256 com chaves gerenciadas (KMS/Vault).
- Usuários em memória (demo) → mover para tabela com hash bcrypt no BD.
