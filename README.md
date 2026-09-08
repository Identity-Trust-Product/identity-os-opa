# Identity OS OPA Policy Pack

This folder runs Open Policy Agent locally for Identity OS policy-governance trials.

## Start OPA

```powershell
cd backend/identity-os-opa
Copy-Item .env.example .env
docker compose up -d
```

OPA API:

```text
http://localhost:8181
```

## Policy Location

Policies are mounted from:

```text
backend/identity-os-opa/policies
```

The starter policy is:

```text
identityos/access.rego
```

The DPDP schema compliance demo policy is:

```text
identityos/schema_compliance.rego
```

It exposes:

```text
data.identityos.access.decision
```

## Direct OPA Test

```powershell
Invoke-RestMethod -Method Post `
  -Uri "http://localhost:8181/v1/data/identityos/access/decision" `
  -ContentType "application/json" `
  -Body '{
    "input": {
      "action": "application.login",
      "token": {
        "claims": {
          "organization_id": "org_03db05edc099",
          "application_id": "app_716d1fe7a98f",
          "realm_access": { "roles": ["APPLICATION_USER"] }
        }
      },
      "application": {
        "organization_id": "org_03db05edc099",
        "application_id": "app_716d1fe7a98f",
        "status": "ACTIVE"
      }
    }
  }'
```

Expected decision:

```json
{
  "result": {
    "allow": true,
    "reasons": []
  }
}
```

## DPDP Schema Compliance Test

Allowed schema:

```powershell
Invoke-RestMethod -Method Post `
  -Uri "http://localhost:8181/v1/data/identityos/schema_compliance/decision" `
  -ContentType "application/json" `
  -Body '{
    "input": {
      "schema": {
        "type": "REGISTRATION",
        "fields": [
          { "name": "email" },
          { "name": "username" },
          { "name": "password" }
        ]
      },
      "application": {
        "purpose": "account_creation"
      },
      "consent": {
        "required": false
      },
      "retention": {
        "days": 180
      }
    }
  }'
```

Denied schema:

```powershell
Invoke-RestMethod -Method Post `
  -Uri "http://localhost:8181/v1/data/identityos/schema_compliance/decision" `
  -ContentType "application/json" `
  -Body '{
    "input": {
      "schema": {
        "type": "REGISTRATION",
        "fields": [
          { "name": "email" },
          { "name": "aadhaar" },
          { "name": "date_of_birth" }
        ]
      },
      "application": {
        "purpose": ""
      },
      "consent": {
        "required": false
      },
      "retention": {}
    }
  }'
```

Expected deny reasons:

```json
{
  "result": {
    "allow": false,
    "reasons": [
      "sensitive fields require explicit consent",
      "sensitive fields require a declared processing purpose",
      "sensitive fields require a retention period"
    ],
    "sensitiveFields": ["aadhaar", "date_of_birth"]
  }
}
