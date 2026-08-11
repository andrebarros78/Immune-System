package immune.donor

default decision := "BLOQUEAR"

decision := "PERMITIR_COM_RESTRIÇÕES" if {
  input.open_source == true
  input.license_verified == true
  input.origin_pinned == true
  input.artifact_hash_verified == true
  input.security_scanned == true
  input.laboratory_approved == true
  input.authority == "adapter-only"
}
