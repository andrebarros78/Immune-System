package immune.destructive

default decision := "PERMITIR"

decision := "EXIGIR_CHECKPOINT" if {
  input.material_change == true
  input.checkpoint_valid != true
}

decision := "EXIGIR_APROVAÇÃO_HUMANA" if {
  input.irreversible == true
  input.recovery_verified != true
}

decision := "BLOQUEAR" if { input.disables_security_control == true }
