# Sovereign Brain Fortress — Estado Oficial

**Estado: BRAIN_FORTRESS_PROVEN**

Escopo: `SOVEREIGN_BRAIN_FORTRESS_V1_CLOSED_LAB`.

Commit técnico provado: `3c3421f88ed1c113e7d09a8f33911f3992f71f35`.

## Evidência GitHub Actions em main

- Fortress run: `32135967148` — `success`.
  - Seven Rings + Core + Recovery — job `95707241288` — `success`.
  - GLM Live via Provider Proxy — job `95707387323` — `success`.
  - BRAIN_FORTRESS_PROVEN — job `95708736176` — `success`.
- Mission Integral run: `32135967165` — `success`.
  - Core + Recovery + Digital Twin — job `95707241686` — `success`.
  - GLM Live - Isolated — job `95707417498` — `success`.
  - MISSION_PROVEN — job `95708795704` — `success`.

## Provas da cadeia

- regressão completa: 215/215;
- Fases 1–10: PROVEN;
- Digital Twin: 50/50 checks, 7 cenários;
- Brain Fortress: 63/63 checks, 17 testes adversariais;
- Phase 9 endurance: zero falhas;
- Phase 10 endurance determinístico: zero degradações;
- Core static boundary: zero violações;
- protected systems attached durante a prova: 0;
- efeitos externos nos sistemas existentes: 0.

## Sete anéis

1. SOVEREIGN_CORE — zero rede, subprocesso, adapter, credencial externa, painel HTTP e control-plane.
2. MEMORY_AUDIT_VAULT — promoção de memória selada e audit checkpoints externos assinados.
3. POLICY_AUTHORITY — fatos derivados de estado soberano e capability criptográfica one-shot.
4. EXECUTION_PROVIDER_SANDBOX — execução, Provider Proxy e control-plane fora do Core.
5. IMMUNE_GATEWAY_DMZ — ingress assinado/anti-replay e egress capability-gated.
6. ADAPTERS — allowlist e política de risco pertencem ao adapter homologado.
7. EXTERNAL_WORLD — nenhuma confiança implícita.

Fundação: Root of Trust com manifesto assinado e proteção contra rollback de geração. Falha de attestation resulta em `CONTAINED_READ_ONLY` antes da abertura do estado soberano.

## Limite da prova

A raiz de confiança utilizada no closed-lab é externa e efêmera. Uma implantação física somente pode entrar em modo `OPERATIONAL` com backend RootKeyProvider hardware-backed/TPM/HSM equivalente e evidência específica daquele host. Esta prova não declara TPM físico deste PC como comprovado.

O `MISSION_PROVEN` anterior permanece preservado. `BRAIN_FORTRESS_PROVEN` acrescenta a prova de contenção e soberania dos sete anéis.
