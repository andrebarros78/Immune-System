package immune.authority

default decision := "BLOQUEAR"

decision := "PERMITIR" if {
  input.mission_authorized == true
  input.system_authorized == true
  input.requester_authorized == true
  input.scope_ok == true
  not input.restrictions_required
}

decision := "PERMITIR_COM_RESTRIÇÕES" if {
  input.mission_authorized == true
  input.system_authorized == true
  input.requester_authorized == true
  input.scope_ok == true
  input.restrictions_required == true
}
