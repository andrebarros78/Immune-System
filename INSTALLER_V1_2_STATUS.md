# SISTEMA IMUNOLÃ“GICO â€” WINDOWS INSTALLER v1.2.0 â€” STATUS OFICIAL

**Data da prova:** 21/08/2026
**Branch:** `installer/v1.2.0`
**Core congelado:** `v1.1.1`
**Core commit:** `d4750b24336d9b88663473d2db32a796e419e46f`
**MissÃ£o:** `BUILD_WINDOWS_INSTALLER_HOST_PROOF`
**Estado:** `MISSION_PROVEN`

## 1. Resultado executivo

O instalador Windows do Sistema ImunolÃ³gico foi construÃ­do e provado em host Windows real.

Fluxo real executado ponta a ponta:

1. limpeza controlada de resÃ­duos first-party;
2. instalaÃ§Ã£o limpa;
3. self-test do host;
4. reparo sobre instalaÃ§Ã£o existente;
5. self-test pÃ³s-reparo;
6. desinstalaÃ§Ã£o preservando evidÃªncias/dados;
7. validaÃ§Ã£o da remoÃ§Ã£o de serviÃ§os e regras de firewall;
8. reinstalaÃ§Ã£o final;
9. self-test final independente;
10. verificaÃ§Ã£o independente do Root of Trust.

Resultado final: `PASS`.

## 2. EvidÃªncia principal

Arquivos canÃ´nicos:

- `installer/evidence/HOST_INSTALL_PROOF.log`
- `installer/evidence/HOST_INSTALL_PROOF.json`

Resultado registrado:

```text
HOST_INSTALL_PROOF=PASS
final_state=CONTAINED_READ_ONLY
root_attested=true
protected_systems=0
```

## 3. SeguranÃ§a fÃ­sica / Root of Trust

Comprovado no host real:

```text
SECURE_BOOT=True
TPM_PRESENT=True
TPM_READY=True
ROOT_ATTESTED=True
ROOT_VERIFY=PASS
```

O Root of Trust usa chave nÃ£o exportÃ¡vel apoiada pelo `Microsoft Platform Crypto Provider` e assinatura do manifesto do payload.

## 4. ServiÃ§os instalados

Oito serviÃ§os foram comprovados em `Running` e `Auto`, executados como `NT AUTHORITY\LocalService` e com Service SID restrito:

- `SistemaImuneCore`
- `SistemaImuneVault`
- `SistemaImunePolicy`
- `SistemaImuneExecution`
- `SistemaImuneGateway`
- `SistemaImuneProvider`
- `SistemaImuneAdapter`
- `SistemaImuneWatchdog`

## 5. Firewall e separaÃ§Ã£o de autoridade

Regras outbound `Block` foram comprovadas para os componentes que nÃ£o podem possuir autoridade direta de rede:

- Core
- Vault
- Policy
- Execution
- Adapter
- Watchdog

Gateway e Provider permanecem como fronteiras designadas para conectividade controlada.

## 6. InstalaÃ§Ã£o sem anexaÃ§Ã£o

A prova foi executada com a opÃ§Ã£o obrigatÃ³ria `NÃ£o anexar agora`.

Estado final comprovado:

```text
contract.state=UNATTACHED
mode_initial=CONTAINED_READ_ONLY
protected_systems=0
adapter=null
material_action_without_homologation=PROHIBITED
```

Isso prova que **instalar nÃ£o equivale a anexar** e que nenhuma varredura ou alteraÃ§Ã£o de sistema externo Ã© iniciada automaticamente.

## 7. Reparo

O reparo foi comprovado sobre instalaÃ§Ã£o existente. Foram corrigidos e testados:

- quiesce de serviÃ§os;
- espera pela saÃ­da real dos processos first-party;
- manutenÃ§Ã£o temporÃ¡ria de ACL apenas dentro dos caminhos canÃ´nicos do produto;
- recriaÃ§Ã£o determinÃ­stica de serviÃ§os;
- reaplicaÃ§Ã£o de ACLs restritas por Service SID;
- estabilizaÃ§Ã£o/retry do SCM;
- preservaÃ§Ã£o do System Contract;
- self-test pÃ³s-reparo.

Resultado:

```text
REPAIR EXIT_CODE=0
SELFTEST[REPAIR]=INSTALLER_SELF_TEST=PASS
```

## 8. DesinstalaÃ§Ã£o e reinstalaÃ§Ã£o

DesinstalaÃ§Ã£o comprovada:

```text
UNINSTALL_PRESERVE_DATA EXIT_CODE=0
install_root_exists=false
services=MISSING
firewall_rules=false
data_root_exists=true
```

ReinstalaÃ§Ã£o final comprovada:

```text
REINSTALL_FINAL EXIT_CODE=0
SELFTEST[REINSTALL_FINAL]=INSTALLER_SELF_TEST=PASS
```

## 9. Integridade do instalador

Instalador gerado:

```text
installer/dist/Sistema-Imunologico-Setup.exe
```

SHA-256 da build usada na prova:

```text
3c5b3552fcf67f4d5c54a1a3c372a40e2135b91a1a5f3ecd6b89d06a8f7c9202
```

O payload embutido possui manifesto SHA-256 e Ã© validado antes da instalaÃ§Ã£o.

### Authenticode

A prova registra:

```text
authenticode_status=NotSigned
```

Portanto, **a instalaÃ§Ã£o tÃ©cnica e a integridade criptogrÃ¡fica interna estÃ£o provadas**, mas uma assinatura Authenticode publicamente confiÃ¡vel para distribuiÃ§Ã£o comercial ainda exige um certificado de code-signing confiÃ¡vel por terceiros. Este ponto nÃ£o Ã© mascarado como concluÃ­do.

## 10. RegressÃ£o do Core

ApÃ³s a implementaÃ§Ã£o do instalador:

```text
229 passed
9 subtests passed
```

O Core `v1.1.1` permaneceu imutÃ¡vel.

## 11. Escopo do MISSION_PROVEN

`MISSION_PROVEN` aplica-se Ã  missÃ£o:

```text
BUILD_WINDOWS_INSTALLER_HOST_PROOF
```

EstÃ¡ provado que o Sistema ImunolÃ³gico pode ser instalado, validado, reparado, desinstalado e reinstalado em Windows real, mantendo o Core congelado, Root of Trust fÃ­sico, serviÃ§os separados, firewall de contenÃ§Ã£o e estado `UNATTACHED/CONTAINED_READ_ONLY` quando nenhum alvo Ã© escolhido.

**NÃ£o estÃ¡ sendo declarado que um sistema externo especÃ­fico foi homologado ou promovido a `OPERATIONAL`.** Isso exige selecionar um alvo real e executar a missÃ£o de anexaÃ§Ã£o/homologaÃ§Ã£o correspondente.

## 12. Estado canÃ´nico

```text
WINDOWS_INSTALLER_VERSION=1.2.0
CORE_VERSION=v1.1.1
CORE_COMMIT=d4750b24336d9b88663473d2db32a796e419e46f
BUILD_WINDOWS_INSTALLER_HOST_PROOF=MISSION_PROVEN
ROOT_ATTESTED=true
HOST_SELF_TEST=PASS
INSTALL=PASS
REPAIR=PASS
UNINSTALL=PASS
REINSTALL=PASS
PROTECTED_SYSTEMS=0
FINAL_STATE=CONTAINED_READ_ONLY
TARGET_ATTACHMENT=NOT_REQUESTED
PUBLIC_AUTHENTICODE=NOT_PROVEN
```
