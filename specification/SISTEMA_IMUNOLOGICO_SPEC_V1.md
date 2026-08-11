
# Sistema Imunológico — Baseline normativa executável v1.0

**Fonte canônica:** `SISTEMA_IMUNOLOGICO_ESPECIFICACAO_DETALHADA(2).md`  
**SHA-256 da fonte:** `d912a3b7410be88579b33be4fb266c72ca7dc15fc5550206747b7b7eef3327f5`  
**Data:** 11/08/2026

Este arquivo é a baseline normativa usada pelos contratos executáveis da Fase 1.
Ele não reduz a especificação detalhada: requisitos e decisões devem ser rastreados
ao documento fonte pelo `specification/SOURCE_MANIFEST.json`.

## Definição oficial

O Sistema Imunológico é um produto independente e tecnologicamente adaptável,
com autonomia operacional ampla dentro de sua missão. Descobre ambientes,
aprende tecnologias desconhecidas por fontes verificáveis, cria as capacidades
necessárias, diagnostica e corrige falhas, valida os resultados e continua
trabalhando para manter cada sistema autorizado saudável e operacional.

## Princípios normativos

1. **Independência:** sistemas protegidos entram por contratos, conectores e adapters.
2. **Núcleo soberano:** autoridade, permissão, isolamento, aplicação, rollback e aceite permanecem no núcleo próprio.
3. **Autonomia governada:** autonomia existe somente dentro de missão, escopo, políticas, custo e risco autorizados.
4. **Prova antes da conclusão:** compilar, iniciar ou produzir saída parcial não prova correção.
5. **Reversibilidade:** mudanças materiais exigem recuperação verificável proporcional ao risco.
6. **Isolamento:** sistema, missão, incidente, tentativa e Worker possuem fronteiras independentes.
7. **Aprendizagem controlada:** conhecimento só é promovido após evidência, teste, versionamento e possibilidade de reversão.
8. **Tecnologia substituível:** IA, bancos, observabilidade e peças OSS são subordinados a contratos estáveis.
9. **Menor caminho completo:** reutilizar tecnologia comprovada e construir somente lacunas.
10. **Verdade operacional:** fato, hipótese, decisão, estimativa e pendência não podem ser confundidos.

## Separação de autoridade

Pensar, autorizar, executar e validar são funções separadas. IA e Skills podem
propor, mas não autorizam nem executam por conta própria. PolicyGuard autoriza
dentro da política; Workers executam no escopo; validadores produzem evidência;
o Motor de Aceite só emite prova quando os contratos forem satisfeitos.

## Regra Open Source Only

Decisão explícita posterior do responsável do produto: componentes doadores do
Sistema Imunológico devem ser **somente Open Source**, com licença explícita,
origem pinada e auditável. Software proprietário, source-available não-OSS ou
dependência que exija serviço proprietário não pode ser promovido como doador.

## Loop operacional

OBSERVAR → ENTENDER → DECIDIR → DELEGAR → ACOMPANHAR → VALIDAR → APRENDER → CONTINUAR.

Para correção técnica: INSPECIONAR → REPRODUZIR → COLETAR EVIDÊNCIA → ISOLAR →
IDENTIFICAR CAUSA → CORRIGIR → TESTAR CORREÇÃO → TESTAR REGRESSÕES → TESTAR
INTEGRAÇÃO → TESTAR RECUPERAÇÃO → AUDITAR → SALVAR CHECKPOINT → PROCURAR NOVA FALHA → CONTINUAR.

## MISSION_PROVEN

`MISSION_PROVEN` só pode existir para escopo explícito quando resultado observável,
testes relevantes, regressão, recuperação e segurança proporcionais ao risco,
evidências e ausência de bloqueio crítico estiverem comprovados. Pendências
opcionais devem estar separadas do escopo aceito.

## Intervenção humana por exceção

Escalar somente para gasto/contratação, criação de conta, credencial pessoal
inexistente, MFA/CAPTCHA/confirmação física, compromisso jurídico, comunicação
externa, regra de negócio, ação irreversível sem recuperação ou bloqueio real
após rotas técnicas distintas permitidas.
