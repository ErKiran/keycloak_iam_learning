# Docker Compose

Start the app and Keycloak:

```sh
docker compose up --build
```

URLs:

```text
App:      http://localhost:3001
Keycloak: http://localhost:8081
```

The app uses this callback URL:

```text
http://localhost:3001/callback
```

If Keycloak shows `Invalid parameter: redirect_uri`, it has already imported an older realm from the existing Docker volume. Reset the volume once:

```sh
docker compose down -v
docker compose up --build
```
