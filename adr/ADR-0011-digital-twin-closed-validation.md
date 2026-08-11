# ADR-0011 — Validação Integral por Digital Twin Fechado

## Estado
Aceito para homologação do Sistema Imunológico V1.

## Decisão
A validação adicional do produto será executada em um Digital Twin operacional dentro de sandbox virtual fechada.

O Twin representa serviços, dependências, configuração, falhas, IA, release, relógio e ações materiais como estado virtual. A autoridade soberana continua nos componentes reais do Core; somente o atuador físico é substituído por `TwinActuator`, incapaz de acessar processo, SO ou rede.

## Isolamento obrigatório
O `ExternalEffectGuard` é fail-closed e bloqueia antes do efeito:
- sockets e `socket.create_connection`;
- `urllib.request.urlopen`;
- `subprocess.run` e `subprocess.Popen`;
- `os.system`;
- escritas via `open`/`io.open` fora da raiz temporária da sandbox;
- escape de path do próprio Twin.

O cenário operacional normal deve terminar com zero violações. Tentativas adversariais deliberadas são aceitas apenas quando comprovadamente bloqueadas antes do efeito.

## Escopo de prova
`IMMUNE_SYSTEM_V1_CLOSED_DIGITAL_TWIN_INTEGRAL_VALIDATION`

A prova inclui regressões das Fases 2–10 e cenários integrados de descoberta, diagnóstico causal, correção virtual, validação semântica, rollback, aprendizagem controlada, modo sem IA, observabilidade, Supervisor, Watchdog, backup/restore, atualização segura, reinício/retomada, isolamento de 32 sistemas e auditoria.

## Não-alegação
`DIGITAL_TWIN_PROVEN` comprova a execução controlada e reproduzível do produto no gêmeo digital fechado. Não é evidência de uma instalação física específica nem de efeitos reais sobre sistemas externos.
