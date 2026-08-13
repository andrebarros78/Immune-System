# Runtime cognitivo do Sistema ImunolÃ³gico

## Regra

A IA Ã© uma dependÃªncia substituÃ­vel e exclusiva do `immune-core`. Nunca compartilhar chave, contexto, cota ou Provider Manager com sistema protegido ou outro projeto.

## ConfiguraÃ§Ã£o

Arquivo padrÃ£o: `config/provider-runtime.json`.

Troca de provedor: altere somente o perfil de configuraÃ§Ã£o (`endpoint`, `model`, `api_key_env`, opÃ§Ãµes compatÃ­veis e prioridade). O nÃºcleo nÃ£o deve conter nome de modelo ou fornecedor.

A credencial nunca deve ser gravada no repositÃ³rio. O perfil aponta apenas para o nome de uma variÃ¡vel de ambiente `IMMUNE_*`. A variÃ¡vel deve ser injetada somente no processo/serviÃ§o do Sistema ImunolÃ³gico.

## Estado sem credencial

O sistema continua operacional em modo degradado determinÃ­stico para monitoramento, runbooks aprovados, contenÃ§Ã£o, memÃ³ria, supervisÃ£o, backup e recuperaÃ§Ã£o. CogniÃ§Ã£o externa permanece indisponÃ­vel atÃ© a credencial existir.

## Autoridade

IA -> proposta
PolicyGuard -> autorizaÃ§Ã£o
Worker -> execuÃ§Ã£o
Validador -> evidÃªncia
Aprendizagem -> promoÃ§Ã£o somente apÃ³s prova independente
