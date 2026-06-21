# Docker Bootstrap

This Docker setup starts the Node app, Keycloak, and Caddy.

## Start

```sh
docker compose up --build
```

Open the app at:

```text
http://localhost:8090
```

Keycloak admin console:

```text
http://localhost:8090/admin
```

Admin login:

```text
admin / admin
```

## Demo Users

All demo users use the password:

```text
password
```

| Username | Role |
| --- | --- |
| developer | Developer |
| teller | Teller |
| customer | balance:read, transfer:write |

## Realm Import

The bootstrap realm file is:

```text
keycloak/minilab-realm.json
```

It creates the `minilab` realm, the `web-app` OIDC client, the `user-lookup` service client, client roles, composite roles, UMA transfer authorization settings, and the default users.

If you edit the realm JSON after Keycloak has already started, recreate the Keycloak volume so the import runs again:

```sh
docker compose down -v
docker compose up --build
```
