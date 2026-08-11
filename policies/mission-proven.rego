package immune.mission

default mission_proven := false

mission_proven if {
  input.scope_explicit == true
  input.observable_result_achieved == true
  input.relevant_tests_passed == true
  input.regression_validated == true
  input.recovery_validated == true
  input.security_validated == true
  input.evidence_preserved == true
  input.no_critical_blocker == true
  input.independent_audit_passed == true
}
