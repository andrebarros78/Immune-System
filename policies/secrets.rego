package immune.secrets

default decision := "PERMITIR"

decision := "BLOQUEAR" if { input.exposes_secret == true }
decision := "BLOQUEAR" if { input.logs_plaintext_secret == true }
decision := "BLOQUEAR" if { input.prompt_contains_unredacted_secret == true }
