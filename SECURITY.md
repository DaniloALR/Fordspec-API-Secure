# Política de Segurança — FordSpec AI

## Versões suportadas

| Versão | Suporte de segurança |
|--------|----------------------|
| 2.x (Sprint 3, DevSecOps) | ✅ |
| 1.x (Sprint 2) | ❌ (dependências com CVEs conhecidas) |

## Como reportar uma vulnerabilidade

**Não abra issue pública.** Use o recurso *Private vulnerability reporting* do GitHub
(aba **Security → Report a vulnerability**) informando:

- componente afetado (API, app mobile, broker MQTT, pipeline);
- passos para reproduzir e impacto esperado;
- se houver, o `X-Request-ID` da requisição.

| Etapa | Prazo |
|-------|-------|
| Confirmação de recebimento | 2 dias úteis |
| Triagem e classificação (CVSS) | 5 dias úteis |
| Correção de severidade Crítica/Alta | 7 / 30 dias |
| Correção de severidade Média/Baixa | próxima sprint |

Incidentes envolvendo dados pessoais seguem o plano de resposta descrito em
[docs_seguranca/SPRINT3_DevSecOps.md](docs_seguranca/SPRINT3_DevSecOps.md#34-plano-de-resposta-a-incidentes),
incluindo comunicação à ANPD e aos titulares quando exigido pela LGPD (art. 48).

## Controles automatizados

Todo push/PR passa pelo pipeline [`.github/workflows/devsecops.yml`](.github/workflows/devsecops.yml):
Gitleaks, Semgrep, Bandit, pip-audit, Dependency Review, pytest (segurança), Checkov,
Trivy, SBOM, OWASP ZAP e deploy com imagem assinada (cosign).
