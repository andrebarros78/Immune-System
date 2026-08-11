# ADR-0006 — Diagnóstico causal e correção governada

## Estado
Aceito para a Fase 6.

## Contexto
A Fase 5 produz sinais, anomalias, evidências e mapa de dependências. Isso não é suficiente para autorreparo seguro: um sintoma pode desaparecer sem que a causa raiz tenha sido identificada, e uma correção pode terminar com código de saída zero mas ainda produzir um estado funcional incorreto.

## Decisão
O Sistema Imunológico mantém uma cadeia causal própria e durável:

`Sinal → Incidente → Hipóteses concorrentes → Evidências → Testes discriminantes → Causa raiz → Correção candidata → Laboratório → PolicyGuard → Worker/Executor → Validação → Recuperação/Regressão → Aceite ou Rollback`.

### 1. Incidentes
Sinais correlacionados pela Fase 5 são anexados ao mesmo incidente. O sinal original é preservado como evidência com integridade verificável.

### 2. Hipóteses concorrentes
Nenhuma hipótese recebe autoridade por confiança textual ou por origem em IA. A hipótese candidata só pode virar `ROOT_CAUSE` quando:
- possui evidência líquida de suporte;
- possui pelo menos um teste discriminante positivo;
- hipóteses concorrentes foram enfraquecidas por evidência ou teste discriminante.

`SYMPTOM_DISAPPEARED` não é resultado aceito para confirmar causa raiz.

### 3. Tentativas e progresso
Cada tentativa registra estratégia, teste, resultado, evidência e progresso mensurável. Três repetições da mesma estratégia sem progresso colocam o diagnóstico em `STALLED`; repetir novamente a mesma estratégia é recusado e deve ser substituído.

### 4. Correção
Uma correção só pode ser planejada após `ROOT_CAUSE_CONFIRMED`. O planejador não executa comandos. A correção passa pelo `PolicyGuard`, entra na fila durável e é executada pelo Worker da Fase 3.

### 5. Laboratório e checkpoint
Antes do efeito material, o laboratório cria checkpoint independente. O Executor Seguro continua criando seu próprio checkpoint para a execução. Isso fornece duas camadas de recuperação:
- falha de processo: rollback do Executor;
- processo com sucesso técnico mas efeito funcional inválido: rollback do Validation Engine.

### 6. Validação e resolução
Incidente só pode chegar a `RESOLVED` após:
- validação funcional da correção;
- evidência de validação íntegra;
- recuperação verificada;
- regressões verificadas.

## Limites
A Fase 6 não concede execução direta à cognição, IA ou doadores. Ela também não declara `MISSION_PROVEN` do produto completo. A remediação continua subordinada ao IMUNE-DNA, ao PolicyGuard, aos Workers e aos checkpoints soberanos.
