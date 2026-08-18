# Sistema ImunolÃ³gico V1.1.1 â€” Sovereign Brain Fortress Hardening

**Estado: V1_1_1_CONSOLIDATED_PROVEN**

Base preservada e imutÃ¡vel: `v1.1.0`.

Escopo: `SOVEREIGN_BRAIN_FORTRESS_V1_CLOSED_LAB`.

Tag alvo imutÃ¡vel: `v1.1.1`.

## ConteÃºdo da patch release

- sete anÃ©is concÃªntricos preservados e revalidados;
- boundary scanner do Sovereign Core ampliado contra rotas indiretas de processo, rede, FFI, loader dinÃ¢mico e aliases;
- provas explÃ­citas de comprometimento duplo `provider+gateway` e `adapter+worker`;
- sandbox OS descartÃ¡vel para Worker e Adapter no runner fechado;
- `network=none`, `pids-limit`, memÃ³ria/CPU limitadas, root read-only, tmpfs, `cap-drop ALL` e `no-new-privileges` validados por `docker inspect` e por processo malicioso real;
- segredo nÃ£o Ã© herdado pelo sandbox e injeÃ§Ã£o de variÃ¡vel secret-like Ã© rejeitada antes da criaÃ§Ã£o do container;
- Adapter Manifest assinado e imagem executada vinculada ao SHA-256 assinado;
- Root Manifest ampliado para 42 arquivos crÃ­ticos, generation 3;
- tamper conjunto ConstituiÃ§Ã£o + PolicyGuard + manifesto comprovado contra raiz externa;
- root key ausente/assinatura invÃ¡lida continuam fail-closed antes do estado soberano;
- token/capability expirado, wrong-scope e replay bloqueados;
- provider live attestation reutilizÃ¡vel somente se a superfÃ­cie do provider for byte-identical e GitHub confirmar externamente o run/job live anterior como `success`;
- qualquer mudanÃ§a na superfÃ­cie do Provider Proxy invalida a attestation e exige live smoke novo;
- workflows `BRAIN_FORTRESS_PROVEN` e `MISSION_PROVEN` acoplados e com jobs finais explicitamente executados, nunca aceitos apenas por status agregado com job final `skipped`.

## Prova tÃ©cnica anterior ao commit documental

Commit: `ea28c1b1755fabfef912f92272c7950316f31335`.

- Fortress run `32154652997` â€” success;
- `BRAIN_FORTRESS_PROVEN` job `95769116431` â€” success;
- Mission Integral run `32154653079` â€” success;
- `MISSION_PROVEN` job `95769142792` â€” success;
- regressÃ£o local: 229/229 + 9 subtestes;
- Brain Fortress gate local: 88/88;
- testes Fortress: 31;
- protected systems attached: 0;
- external effects: 0.

## Provider proof

A Ãºltima prova live utilizada como baseline Ã© o GitHub run `32136856684`, commit `f5d15f5f4bf01654bdfc7040ed22bbb98cee8afa`, job `GLM Live via Provider Proxy` `95710280924` â€” success.

A superfÃ­cie pinada Ã©:

- `immune_provider_proxy/`;
- `immune_core/providers.py`;
- `immune_core/provider_runtime.py`;
- `config/provider-live-test.json`;
- `config/provider-runtime.json`;
- `scripts/provider_live_smoke.py`.

A release somente aceita reutilizaÃ§Ã£o se `git diff` dessa superfÃ­cie for zero e a API pÃºblica do GitHub confirmar o run, commit, workflow e job esperados.

## Regra da tag

`v1.1.1` somente pode ser criada no commit documental final quando, nesse mesmo SHA:

1. `BRAIN_FORTRESS_PROVEN - Seven Ring Isolated Validation` terminar `success`;
2. o job final `BRAIN_FORTRESS_PROVEN` terminar `success`;
3. `MISSION_PROVEN - Integral Isolated Validation` terminar `success`;
4. o job final `MISSION_PROVEN` terminar `success`;
5. sandbox OS, Root of Trust, Fases 1â€“10, Digital Twin e provider proof estiverem verdes.

`v1.0.0`, `v1.0.1` e `v1.1.0` sÃ£o histÃ³ricos e nÃ£o podem ser movidos.

## Fronteira de implantaÃ§Ã£o

Esta release prova a Fortaleza integral em closed-lab/CI sem sistemas reais anexados. ImplantaÃ§Ã£o fÃ­sica continua sendo missÃ£o separada e exige Root of Trust hardware-backed e prova especÃ­fica do host conforme `runbooks/BRAIN-FORTRESS-DEPLOYMENT.md`.
