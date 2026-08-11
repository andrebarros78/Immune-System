package immune.checkpoint

default decision := "PERMITIR"

decision := "EXIGIR_CHECKPOINT" if {
  input.material_change == true
  input.checkpoint_valid != true
}

decision := "BLOQUEAR" if {
  input.checkpoint_required == true
  input.recovery_procedure_defined != true
}
