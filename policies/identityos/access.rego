package identityos.access

default allow = false

allow {
  input.action == "application.login"
  input.application.status == "ACTIVE"
  input.token.claims.organization_id == input.application.organization_id
  input.token.claims.application_id == input.application.application_id
  has_application_access_role
}

decision := {"allow": allow, "reasons": reasons} {
  reasons := [reason | deny[reason]]
}

deny["application is not active"] {
  input.action == "application.login"
  input.application.status != "ACTIVE"
}

deny["token organization does not match application organization"] {
  input.action == "application.login"
  input.token.claims.organization_id != input.application.organization_id
}

deny["token application does not match requested application"] {
  input.action == "application.login"
  input.token.claims.application_id != input.application.application_id
}

deny["APPLICATION_USER role is required"] {
  input.action == "application.login"
  not has_application_access_role
}

has_role(role) {
  input.token.claims.realm_access.roles[_] == role
}

has_application_access_role {
  has_role("APPLICATION_USER")
}

has_application_access_role {
  has_role("APPLICATION_SUPER_ADMIN")
}
