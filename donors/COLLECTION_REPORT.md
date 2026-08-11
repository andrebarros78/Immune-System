# Relatório de Coleta OSS — Sistema Imunológico

Data da coleta: 2026-08-11

## Resultado

- Doadores registrados: **44**
- Doadores coletados e com licença verificada: **44**
- Rejeitados: **0**
- Política: **Open Source Only**
- Submodules: **0**
- Forks usados como dependência: **0**
- Histórico `.git` upstream incorporado: **0**

## Modelo de coleta

### Snapshot limpo

Aplicado apenas a peças pequenas ou diretamente reutilizáveis. O checkout do upstream é limitado, o diretório `.git` é removido, a origem é fixada por commit e o conteúdo recebe hash SHA-256 de árvore.

### Cápsula pinada

Aplicada a serviços e projetos grandes. O repositório não recebe o monorepo inteiro. A cápsula mantém:

- `DONOR.json` com commit imutável, função e modo de uso;
- `UPSTREAM_LICENSE.txt` verificado;
- `UPSTREAM_README.txt` preservado;
- URL de arquivo de origem correspondente ao commit;
- hashes da licença e documentação.

Isso mantém as peças externas substituíveis e impede que o núcleo do Sistema Imunológico fique acoplado ao histórico ou à arquitetura dos doadores.

## Doadores no cofre

OPA, Conftest, Temporal, NATS/JetStream, agentgateway, FastMCP, SWE-ReX, Podman, osquery, psutil, watchdog, OpenTelemetry Collector, Jaeger, Alertmanager, Uptime Kuma, restic, Litestream, Schemathesis, Hypothesis, Playwright, Locust, Toxiproxy, Testcontainers Python, Trivy, Syft, OSV-Scanner, ORT, ScanCode Toolkit, OpenSSF Scorecard, SOPS, age, Cosign, Gitleaks, Ollama, llama.cpp, OpenHands Software Agent SDK, HolmesGPT, mini-swe-agent, Microsoft Agent Framework, Promptfoo, Inspect AI, Qdrant, Hatchet e StackStorm.

## Fronteira soberana

Nenhuma peça acima substitui ou governa:

- IMUNE-DNA;
- Núcleo Soberano;
- Supervisor;
- PolicyGuard;
- promoção/rollback;
- critério MISSION_PROVEN.

Todas são doadores subordinados e devem passar pelo laboratório antes de integração operacional.

## Arquivos de controle

- `donors/registry.json` — inventário declarativo.
- `donors/LOCK.json` — commits resolvidos e evidências da coleta.
- `donors/DONOR_INTAKE_POLICY.md` — política soberana de entrada.
- `scripts/collect_donors.py` — coletor fail-closed para licença/origem.
- `.github/workflows/collect-donors.yml` — execução automática da coleta.
- `donors/collected/<id>/` — cápsulas e snapshots limpos.
