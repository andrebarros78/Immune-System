# ADR-0004 — Cognição e Skills sem autoridade operacional

## Estado
Aceito para a Fase 4.

## Decisão

A cognição do Sistema Imunológico é um subsistema de **proposta**, nunca de execução.

A cadeia obrigatória é:

`evidência → CognitiveCore → ProviderManager/Skill context → proposta → CognitiveCoordinator → PolicyGuard → fila durável → Worker → Executor → evidência`.

Nenhum Provider, modelo de IA, agente doador ou Skill recebe referência direta a `WorkerRunner`, `SafeExecutor`, `PrivilegedExecutor`, shell, subprocesso, privilégio do host ou ferramenta material.

### Providers

- Providers são substituíveis e implementam somente `propose()`.
- O adapter HTTP compatível com OpenAI/Ollama envia contexto estruturado e **não envia tools/functions**.
- Observações externas são marcadas `UNTRUSTED_DATA` e ficam separadas da fronteira soberana do sistema.
- Provider pago é ignorado sem identidade `provider:paid` e orçamento explícito.
- Falha, timeout ou ausência de IA cai para `DeterministicNoAIProvider`, que não propõe ações materiais.

### Memória

- Todo aprendizado nasce `QUARANTINED`.
- Cognição só recupera memória `PROMOTED`.
- Promoção exige identidade `memory:promote`, evidências completas, validação independente e reprodutibilidade.
- Conteúdo é protegido por SHA-256 e adulteração falha fechada.

### Skills

- Skills de doadores usam a porta existente `immune_lab.admission`.
- Registro começa `QUARANTINED`, `authority=none`, `executable=false`.
- Aprovação exige as seis evidências do laboratório: origem, licença, segurança, funcionalidade, isolamento e rollback.
- Mesmo aprovadas permanecem `authority=adapter-only` e `executable=false`.
- Suspensão ou retirada remove imediatamente a elegibilidade cognitiva.

### Ponte para ação

`CognitiveCoordinator` não executa. Ele somente:

1. verifica estado da missão;
2. verifica Skill referenciada;
3. submete cada proposta ao `PolicyGuard` com identidade `cognition:authorize`;
4. rejeita custo, desativação de segurança, segredo ou irreversibilidade conforme o DNA;
5. coloca apenas decisões permitidas na fila durável da Fase 2;
6. deixa a execução real para os Workers e Executors comprovados na Fase 3.

Mudanças materiais continuam criando checkpoint no Executor da Fase 3; cognição não pode declarar checkpoint válido por conta própria.

## Consequências

- Prompt injection pode influenciar uma recomendação, mas não concede autoridade.
- Um Provider malicioso ainda encontra `PolicyGuard`, Worker Manifest, allowlist, checkpoint, timeout e rollback antes de qualquer efeito material.
- O sistema continua funcional sem IA.
- Agentes OSS coletados permanecem em quarentena até evidência real; a Fase 4 não falsifica aprovação de HolmesGPT, OpenHands, mini-swe-agent ou qualquer outro doador.

## Critério de prova

`PHASE4_PROVEN` exige regressão das Fases 2 e 3, testes adversariais de Provider/IA/memória/Skills, integração HTTP local, modo sem IA, gate financeiro, prompt injection tratado como dado, cognição sem execução direta e E2E `IA → PolicyGuard → fila → Worker`.
