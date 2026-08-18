# ADR-0015 — Sovereign Brain Fortress: sete anéis de contenção

**Estado:** ACCEPTED
**Data:** 2026-08-18
**Escopo de prova:** `SOVEREIGN_BRAIN_FORTRESS_V1_CLOSED_LAB`

## Contexto

O Sistema Imunológico já separava cognição, PolicyGuard, Gateway, execução, memória e evidência. Essa separação lógica não era suficiente para uma fronteira de soberania máxima: o pacote `immune_core` ainda possuía transporte HTTP do provider, subprocesso de Worker e servidor HTTP de apresentação. Alguns caminhos também aceitavam fatos de autorização calculados pelo chamador.

A Fortaleza do Cérebro transforma essa separação em contenção física de código e autoridade. O objetivo não é alegar invulnerabilidade absoluta. O objetivo operacional é: **o comprometimento isolado de Provider, Adapter, Gateway, Worker, memória ou banco não pode adquirir soberania sobre o Core nem produzir ação material sem uma cadeia de autorização independente**.

## Decisão

A arquitetura passa a possuir sete anéis concêntricos e uma fundação de Root of Trust:

1. **SOVEREIGN_CORE** — contratos, estado soberano, raciocínio e decisão. Zero rede, zero subprocesso, zero adapter, zero credencial externa e zero listener HTTP.
2. **MEMORY_AUDIT_VAULT** — memória promovida com atestação independente e audit ledger com selos externos assinados.
3. **POLICY_AUTHORITY** — deriva fatos de autorização de fontes soberanas e emite capability criptográfica one-shot, ligada a missão, sistema, ação, parâmetros e checkpoint.
4. **EXECUTION_PROVIDER_SANDBOX** â€” `immune_execution_broker` possui subprocesso fora do Core e exige sandbox descartÃ¡vel para execuÃ§Ã£o nÃ£o confiÃ¡vel; `immune_provider_proxy` possui transporte externo, DLP, quarentena de prompt injection e credencial do provider. No closed-lab, Worker/Adapter usam `network=none`, limite de PIDs, CPU/memÃ³ria, root read-only, tmpfs, `cap-drop ALL`, `no-new-privileges`, nÃ£o-heranÃ§a de secrets e teardown comprovado.
5. **IMMUNE_GATEWAY_DMZ** — ingress assinado com nonce/anti-replay; egress só consome capability exata e valida política/checkpoint declarados pelo adapter, nunca booleans do chamador.
6. **ADAPTERS** â€” allowlist de aÃ§Ãµes e risco pertence ao adapter homologado; adapter nÃ£o recebe soberania. Manifesto assinado, digest SHA-256 do artefato/imagem, sandbox descartÃ¡vel e rede deny-by-default sÃ£o gates obrigatÃ³rios para Adapter nÃ£o confiÃ¡vel.
7. **EXTERNAL_WORLD** — nenhuma confiança implícita.

**Fundação — ROOT_OF_TRUST:** manifesto de arquivos críticos, geração monotônica e assinatura externa. Falha de assinatura, hash ou rollback de geração resulta em `CONTAINED_READ_ONLY`.

## Fronteira do Core

O gate estático reprova imports de rede, subprocesso e pacotes externos de execução/transporte dentro de `immune_core`. Implementações concretas foram movidas para:

- `immune_execution_broker/`
- `immune_provider_proxy/`
- `immune_presentation/`

O Core conserva somente contratos/protocolos necessários à coordenação.

## Capabilities materiais

`EgressRequest` não aceita `checkpoint_valid`, `recovery_verified`, `material_change` ou `irreversible` fornecidos pelo solicitante.

Fluxo obrigatório:

`ActionIntent → SovereignPolicyAuthority → PolicyGuard → one-use ActionCapability → GatewayEgress → Adapter`

A capability possui TTL curto, JTI persistido contra replay e binding criptográfico a:

- mission_id;
- system_id;
- action;
- SHA-256 dos parâmetros;
- checkpoint_id.

## Memória e auditoria

Memória continua quarantine-first e somente é promovida após evidência validada, validação independente e reprodução. A promoção recebe selo criptográfico independente.

O audit ledger continua hash-chained e recebe checkpoints externos assinados. Uma reescrita do SQLite que recalculasse a história interna diverge do selo externo e é detectada.

## Provider

O modelo externo continua sendo apenas mecanismo de proposta. Endpoint, chave e HTTP pertencem ao `immune_provider_proxy`. Dados passam por DLP e conteúdo com marcadores de prompt injection é substituído por `QUARANTINED_UNTRUSTED_INSTRUCTION` antes do transporte.

Nenhuma ferramenta ou autoridade material é oferecida ao modelo.

### Attestation da prova live

A prova live do provider pode ser reutilizada sem nova chamada somente quando uma attestation externa confirma simultaneamente: o run e o job live anteriores como `success` pela API pÃºblica do GitHub; o commit baseline exato; e `git diff` zero em toda a superfÃ­cie do Provider Proxy. Qualquer alteraÃ§Ã£o no cÃ³digo, contrato, configuraÃ§Ã£o ou smoke do provider invalida essa attestation e exige um novo live smoke. Isso evita autoinduÃ§Ã£o de rate-limit sem transformar indisponibilidade externa em bypass de seguranÃ§a.

## Boot e Root of Trust

O closed-lab utiliza `ExternalHMACRootKey`, criado apenas para a prova e fora do Core. Isso prova o protocolo de attestation, tamper detection e rollback protection.

**Implantação física exige backend hardware-backed (TPM/HSM ou equivalente) e uma prova própria do host.** O closed-lab não declara TPM do PC atual como comprovado.

## Aceite

`BRAIN_FORTRESS_PROVEN` somente pode ser emitido quando, no mesmo commit:

- sete anéis e fronteiras estáticas passam;
- suíte completa passa;
- Fases 1–10 permanecem PROVEN;
- Digital Twin permanece PROVEN;
- testes adversariais da fortaleza passam;
- Provider proof passa pelo Proxy: live fresco quando a superfÃ­cie mudou, ou attestation externa imutÃ¡vel quando a superfÃ­cie Ã© byte-identical a um live proof jÃ¡ confirmado;
- sandbox OS descartÃ¡vel de Worker/Adapter passa no runner fechado e alimenta o gate Fortress do mesmo job;
- `config/gateway-runtime.json` possui zero sistemas reais anexados durante a prova;
- efeitos externos sobre sistemas existentes = 0.

A implantação em qualquer sistema físico permanece uma missão separada e exige Root of Trust hardware-backed e evidência daquele host.
