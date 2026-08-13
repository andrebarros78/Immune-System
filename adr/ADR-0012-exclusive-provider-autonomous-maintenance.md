# ADR-0012 â€” CogniÃ§Ã£o exclusiva, provedor substituÃ­vel e manutenÃ§Ã£o autÃ´noma

**Estado:** aprovado e implementado em 13/08/2026.

## DecisÃ£o

O Sistema ImunolÃ³gico possui uma camada cognitiva prÃ³pria, exclusiva e independente dos sistemas protegidos. Nenhum provedor, modelo ou API faz parte da identidade arquitetural do produto.

A seleÃ§Ã£o de IA ocorre somente por `ProviderRuntimeConfig -> ProviderManager -> Adapter`. O provedor atual Ã© configuraÃ§Ã£o operacional e pode ser substituÃ­do sem alterar o nÃºcleo, PolicyGuard, Workers, memÃ³ria, aprendizagem, diagnÃ³stico ou contratos.

A credencial do provedor Ã© referenciada somente por variÃ¡vel de ambiente com namespace `IMMUNE_`. Segredos inline em configuraÃ§Ã£o sÃ£o rejeitados. O estado pÃºblico informa apenas se a credencial estÃ¡ presente, nunca seu valor.

## Fronteira de exclusividade

- `owner_scope` obrigatÃ³rio: `immune-core`.
- agentes cognitivos internos podem consultar o Provider Manager;
- sistemas protegidos nÃ£o recebem acesso ao Provider Manager, modelo, contexto ou credencial;
- Workers executores nÃ£o recebem o provedor cognitivo;
- IA somente propÃµe; PolicyGuard autoriza; Worker executa; validador prova;
- aprendizado cognitivo comeÃ§a em quarentena e sÃ³ pode ser promovido apÃ³s evidÃªncia, identidade de validador e validaÃ§Ã£o independente reproduzÃ­vel.

## Autonomia operacional

O `AutonomousMaintenanceController` fecha o ciclo interno de observaÃ§Ã£o, proposta cognitiva, autorizaÃ§Ã£o, execuÃ§Ã£o limitada, validaÃ§Ã£o e aprendizagem. Tarefas sÃ£o reivindicadas por missÃ£o, impedindo um Worker de consumir trabalho de outra missÃ£o.

O `AutonomousUpdateAgent` nÃ£o realiza autoatualizaÃ§Ã£o irrestrita. Ele somente pode ativar release previamente verificada e autorizada; o `ReleaseManager` mantÃ©m backup, health check e rollback automÃ¡tico.

Sem IA disponÃ­vel, o sistema entra em modo degradado determinÃ­stico e nÃ£o concede novas aÃ§Ãµes Ã  camada cognitiva.

## Provedor atual

`config/provider-runtime.json` contÃ©m a seleÃ§Ã£o operacional atual. Esta informaÃ§Ã£o nÃ£o cria dependÃªncia arquitetural e pode ser trocada por configuraÃ§Ã£o.
