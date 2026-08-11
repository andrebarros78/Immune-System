package immune.financial

default decision := "PERMITIR"

decision := "EXIGIR_APROVAÇÃO_HUMANA" if { input.new_cost == true }
decision := "EXIGIR_APROVAÇÃO_HUMANA" if { input.purchase == true }
decision := "EXIGIR_APROVAÇÃO_HUMANA" if { input.subscription == true }
decision := "EXIGIR_APROVAÇÃO_HUMANA" if { input.trial_with_billing_risk == true }
decision := "EXIGIR_APROVAÇÃO_HUMANA" if { input.commercial_license == true }
