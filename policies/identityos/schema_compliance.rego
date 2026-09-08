package identityos.schema_compliance

default allow = false

sensitive_fields := {
  "aadhaar",
  "aadhar",
  "pan",
  "passport",
  "voter_id",
  "driving_license",
  "biometric",
  "date_of_birth",
  "dob",
  "address",
}

login_allowed_fields := {
  "username",
  "email",
  "mobile",
  "password",
  "otp",
}

allow {
  count(deny) == 0
}

decision := {"allow": allow, "reasons": reasons, "sensitiveFields": requested_sensitive_fields} {
  reasons := [reason | deny[reason]]
}

requested_field_names[field_name] {
  field := input.schema.fields[_]
  field_name := lower(field.name)
}

requested_sensitive_fields[field_name] {
  field := input.schema.fields[_]
  sensitive_field(field)
  field_name := field_name_for(field)
}

sensitive_schema_fields[field] {
  field := input.schema.fields[_]
  sensitive_field(field)
}

deny["schema type must be REGISTRATION or LOGIN"] {
  not valid_schema_type
}

deny["login schema cannot collect sensitive personal data"] {
  upper(input.schema.type) == "LOGIN"
  count(requested_sensitive_fields) > 0
}

deny["login schema contains fields outside basic authentication fields"] {
  upper(input.schema.type) == "LOGIN"
  field_name := requested_field_names[_]
  not login_allowed_fields[field_name]
}

deny[reason] {
  upper(input.schema.type) == "REGISTRATION"
  field := sensitive_schema_fields[_]
  not field_has_consent(field)
  reason := sprintf("sensitive field %q requires explicit consent", [field_name_for(field)])
}

deny[reason] {
  upper(input.schema.type) == "REGISTRATION"
  field := sensitive_schema_fields[_]
  not field_has_purpose(field)
  reason := sprintf("sensitive field %q requires a declared processing purpose", [field_name_for(field)])
}

deny[reason] {
  upper(input.schema.type) == "REGISTRATION"
  field := sensitive_schema_fields[_]
  not field_has_retention(field)
  reason := sprintf("sensitive field %q requires a retention period", [field_name_for(field)])
}

deny[reason] {
  upper(input.schema.type) == "REGISTRATION"
  field := sensitive_schema_fields[_]
  days := retention_days_for_field(field)
  days > 365
  reason := sprintf("sensitive field %q retention must be 365 days or less for demo DPDP policy", [field_name_for(field)])
}

deny[reason] {
  upper(input.schema.type) == "REGISTRATION"
  field := sensitive_schema_fields[_]
  not field_has_justification(field)
  reason := sprintf("sensitive field %q requires justification", [field_name_for(field)])
}

valid_schema_type {
  upper(input.schema.type) == "REGISTRATION"
}

valid_schema_type {
  upper(input.schema.type) == "LOGIN"
}

has_text(value) {
  trim(value, " ") != ""
}

field_name_for(field) = name {
  name := lower(field.name)
}

sensitive_field(field) {
  sensitive_fields[field_name_for(field)]
}

sensitive_field(field) {
  field.dpdp.sensitive == true
}

sensitive_field(field) {
  lower(field.type) == "gov-id"
}

sensitive_field(field) {
  lower(field.type) == "address"
}

field_has_consent(field) {
  field.dpdp.consentRequired == true
}

field_has_purpose(field) {
  has_text(field.dpdp.purpose)
}

field_has_retention(field) {
  field.dpdp.retentionDays > 0
}

retention_days_for_field(field) = days {
  days := field.dpdp.retentionDays
}

field_has_justification(field) {
  has_text(field.dpdp.justification)
}
