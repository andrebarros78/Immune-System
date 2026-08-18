# Sovereign Brain Fortress â€” Estado Oficial

**Estado: BRAIN_FORTRESS_PROVEN**

Escopo: `SOVEREIGN_BRAIN_FORTRESS_V1_CLOSED_LAB`.

Commit tÃ©cnico endurecido comprovado: `ea28c1b1755fabfef912f92272c7950316f31335`.

## EvidÃªncia GitHub Actions â€” prova tÃ©cnica endurecida

- Fortress run `32154652997` â€” `success`.
  - `Seven Rings + Core + Recovery` â€” job `95768816895` â€” `success`.
  - `Provider Proof Attestation` â€” job `95769023275` â€” `success`.
  - `Provider Proof Accepted` â€” job `95769081824` â€” `success`.
  - `BRAIN_FORTRESS_PROVEN` â€” job `95769116431` â€” `success`.
- Mission Integral run `32154653079` â€” `success`.
  - `Core + Recovery + Digital Twin` â€” job `95768816656` â€” `success`.
  - `Provider Proof Attestation` â€” job `95769028222` â€” `success`.
  - `Provider Proof Accepted` â€” job `95769099422` â€” `success`.
  - `MISSION_PROVEN` â€” job `95769142792` â€” `success`.

O job GLM foi deliberadamente `skipped` nesta prova porque a superfÃ­cie do Provider Proxy permaneceu byte a byte idÃªntica ao commit `f5d15f5f4bf01654bdfc7040ed22bbb98cee8afa`. A attestation consultou o GitHub e confirmou o run externo `32136856684` e o job live `95710280924` como `success`. Se qualquer arquivo da superfÃ­cie do provider mudar, a attestation deixa de ser reutilizÃ¡vel e um novo live smoke passa a ser obrigatÃ³rio.

## Provas atuais

- regressÃ£o completa local: `229/229`;
- subtestes adversariais parametrizados: `9`;
- Fases 1â€“10: PROVEN no runner integral;
- Digital Twin: PROVEN, 7 cenÃ¡rios;
- Brain Fortress gate local: `88/88` checks;
- testes Fortress: `31`;
- Root Manifest generation: `3`;
- arquivos crÃ­ticos cobertos: `42`;
- protected systems attached durante a prova: `0`;
- efeitos externos nos sistemas existentes: `0`;
- first-party secret scan: `0` achados.

## Sete anÃ©is

1. **SOVEREIGN_CORE** â€” zero rede, subprocesso, adapter, credencial externa, painel HTTP e control-plane; scanner AST tambÃ©m bloqueia rotas indiretas de processo/FFI/transporte e aliases perigosos.
2. **MEMORY_AUDIT_VAULT** â€” promoÃ§Ã£o de memÃ³ria selada e audit checkpoints externos assinados; adulteraÃ§Ã£o Ã© detectada.
3. **POLICY_AUTHORITY** â€” fatos derivados de estado soberano e capability criptogrÃ¡fica one-shot ligada a missÃ£o, sistema, aÃ§Ã£o, parÃ¢metros e checkpoint.
4. **EXECUTION_PROVIDER_SANDBOX** â€” Execution Broker e Provider Proxy fora do Core. Worker nÃ£o confiÃ¡vel usa sandbox descartÃ¡vel com `network=none`, `pids-limit=1`, 128 MiB, 0.5 CPU, root read-only, tmpfs efÃªmero, `cap-drop ALL`, `no-new-privileges` e zero secrets herdados no closed-lab.
5. **IMMUNE_GATEWAY_DMZ** â€” ingress assinado/anti-replay e egress capability-gated; booleans de autorizaÃ§Ã£o do chamador nÃ£o existem no contrato material.
6. **ADAPTERS** â€” manifesto assinado, capability allowlist, binding ao SHA-256 da imagem, sandbox descartÃ¡vel e rede deny-by-default no closed-lab.
7. **EXTERNAL_WORLD** â€” nenhuma confianÃ§a implÃ­cita; sistemas reais permanecem desconectados durante a prova.

## Ataques explicitamente comprovados

- provider comprometido tentando autoridade de execuÃ§Ã£o;
- prompt injection antes do transporte;
- Gateway com capability forjada/replay;
- Adapter tentando expansÃ£o de capability/aÃ§Ã£o/imagem;
- Worker tentando executÃ¡vel fora da allowlist;
- sandbox tentando rede, child-process, escrita no root e leitura de secret;
- memory poisoning e adulteraÃ§Ã£o do selo;
- reescrita do audit ledger;
- identidade/capability expirada, wrong-scope e replay;
- tamper conjunto de ConstituiÃ§Ã£o + PolicyGuard + manifesto sem a root externa;
- assinatura/root key invÃ¡lida ou ausente â†’ `CONTAINED_READ_ONLY`;
- comprometimento combinado provider+gateway e adapter+worker sem aquisiÃ§Ã£o de soberania.

## Root of Trust e limite da prova

A raiz de confianÃ§a utilizada no closed-lab Ã© externa e efÃªmera (`ExternalHMACRootKey`). O runtime atesta antes de criar/abrir o SQLite soberano e contÃ©m falha em `CONTAINED_READ_ONLY`.

Uma implantaÃ§Ã£o fÃ­sica somente pode entrar em `OPERATIONAL` com RootKeyProvider hardware-backed/TPM/HSM equivalente, processos/identidades separados, firewall/IPC prÃ³prios e evidÃªncia especÃ­fica daquele host. Esta prova nÃ£o declara TPM fÃ­sico deste PC como comprovado e nÃ£o usa nenhum sistema existente como alvo.
