# Brain Fortress — Gate de implantação física

A prova `BRAIN_FORTRESS_PROVEN` do repositório é deliberadamente executada sem sistemas reais anexados. Para implantar o Sistema Imunológico em um host físico, os seguintes gates adicionais são obrigatórios e fail-closed.

## Antes do modo OPERATIONAL

1. Secure Boot/boot chain do host validado conforme a plataforma.
2. RootKeyProvider hardware-backed disponível e marcado `hardware_backed=true`.
3. Chave raiz privada não exportável pelo processo do Core.
4. Manifesto soberano assinado cobre todos os arquivos listados em `config/brain-root-critical-files.json` e os adapters autorizados daquele host.
5. Generation do manifesto não é inferior à última geração selada.
6. `FortressBootGate.attest(..., require_hardware_backed=true)` retorna `OPERATIONAL`.
7. Conta/processo do Core não possui acesso direto de rede nem capacidade de subprocesso.
8. Provider Proxy, Execution Broker, Gateway e adapters executam em identidades/processos separados e com privilégio mínimo.
9. Firewall do Core é deny-by-default; somente IPC explicitamente definido pelo deployment é permitido.
10. Secret/Provider credentials existem apenas no broker/proxy apropriado, nunca no Core.
11. Audit seal externo e Memory Vault possuem chaves separadas.
12. Recovery/rollback do host é testado antes de anexar o primeiro sistema protegido.

## Falha em qualquer gate

Estado obrigatório: `CONTAINED_READ_ONLY`.

Nesse estado o cérebro pode preservar evidência e diagnóstico offline, mas não pode emitir capability material nem conectar-se a sistemas protegidos.

## Prova de host

Cada implantação física deve gerar evidência própria contendo pelo menos:

- identidade do host e versão;
- backend hardware-backed e attestation pública, sem material secreto;
- hash/assinatura/generation do manifesto;
- separação efetiva dos processos/anéis;
- regras de firewall/IPC verificadas;
- rollback/recovery drill;
- ataque de replay/capability forjada;
- ataque de provider/adapter/worker comprometido;
- resultado final do boot gate.

A prova de laboratório não substitui essa prova física.
