# DONOR INTAKE POLICY — Open Source Only

## Regra soberana

Todo componente externo é apenas uma peça doadora. Nenhum doador substitui o núcleo soberano, o Supervisor, o IMUNE-DNA, o PolicyGuard, a promoção/rollback ou o critério MISSION_PROVEN.

## Proibições

- Não usar submodules Git.
- Não usar forks como dependência estrutural.
- Não preservar `.git` do upstream em snapshots incorporados.
- Não importar código sem licença Open Source explícita.
- Não aceitar licença `source-available`, BSL, SSPL não aprovada como OSS, licença comercial ou código sem licença.
- Não importar secrets, credenciais, artefatos de CI ou histórico desnecessário.
- Não copiar monorepos inteiros quando somente uma biblioteca, binário ou protocolo for necessário.

## Classes de doação

1. `library` — dependência de código pinada e usada via Adapter.
2. `service` — executável/daemon OSS subordinado ao núcleo.
3. `tool` — ferramenta de teste, segurança, diagnóstico ou build.
4. `protocol` — padrão aberto usado na integração.
5. `architecture` — somente conceitos/padrões; não incorpora runtime.
6. `vendor-source` — snapshot de fonte incorporado somente quando tecnicamente necessário.

## Porta de entrada

Para cada doador registrar obrigatoriamente:

- nome e função;
- repositório upstream;
- licença OSS;
- commit pinado;
- modo de uso;
- razão técnica;
- fronteira de autoridade;
- método de aquisição;
- checksum do artefato quando aplicável;
- dependências e vulnerabilidades conhecidas;
- decisão de laboratório.

## Regra de limpeza

Snapshots de fonte, quando autorizados, devem ser obtidos de commit imutável, extraídos sem `.git`, mantidos em namespace próprio e acompanhados da licença upstream e de `DONOR.yaml`.

## Regra de atualização

Atualização de doador é uma nova entrada de laboratório. Nunca seguir automaticamente `main`, `master` ou `latest` em produção.

## Regra de rejeição

Se licença, origem, integridade ou fronteira de autoridade não puderem ser comprovadas, o componente permanece fora do Sistema Imunológico.
