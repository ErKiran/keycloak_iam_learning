# SCIM Department Mapping Debug

Debug logging is enabled in Docker Compose with:

```text
SCIM_DEBUG=true
```

Rebuild/restart the app:

```sh
docker compose up --build app
```

Watch the SCIM decision trail:

```sh
docker compose logs -f app
```

Create a user with the top-level department field:

```sh
curl -X POST http://localhost:3001/scim/v2/Users \
  -H 'Authorization: Bearer local-scim-token' \
  -H 'Content-Type: application/scim+json' \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "it.user@example.com",
    "name": { "givenName": "IT", "familyName": "User" },
    "emails": [{ "value": "it.user@example.com", "primary": true }],
    "department": "Information Technology",
    "active": true
  }'
```

Create a user with the Enterprise User extension:

```sh
curl -X POST http://localhost:3001/scim/v2/Users \
  -H 'Authorization: Bearer local-scim-token' \
  -H 'Content-Type: application/scim+json' \
  -d '{
    "schemas": [
      "urn:ietf:params:scim:schemas:core:2.0:User",
      "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    ],
    "userName": "finance.user@example.com",
    "name": { "givenName": "Finance", "familyName": "User" },
    "emails": [{ "value": "finance.user@example.com", "primary": true }],
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
      "department": "Finance"
    },
    "active": true
  }'
```

Expected debug milestones:

```text
[SCIM DEBUG] department extracted
[SCIM DEBUG] department rule resolved
[SCIM DEBUG] department sync start
[SCIM DEBUG] ensure group with role start
[SCIM DEBUG] assign client role to group success
[SCIM DEBUG] add user to group success
[SCIM DEBUG] department sync complete
```

If it fails, the failing log line includes the Keycloak HTTP status and response body.
