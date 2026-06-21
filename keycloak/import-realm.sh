#!/usr/bin/env bash
set -euo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
APP_BASE_URL="${APP_BASE_URL:-http://localhost:3000}"
REALM_NAME="${REALM_NAME:-minilab}"
REALM_FILE="${REALM_FILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/minilab-realm.json}"
KCADM_BIN="${KCADM_BIN:-kcadm.sh}"
RESET_REALM="${RESET_REALM:-0}"

tmp_realm="$(mktemp)"
trap 'rm -f "$tmp_realm"' EXIT

node - "$REALM_FILE" "$tmp_realm" "$APP_BASE_URL" <<'NODE'
const fs = require("fs");

const [inputFile, outputFile, appBaseUrl] = process.argv.slice(2);
const realm = JSON.parse(fs.readFileSync(inputFile, "utf8"));
const webApp = realm.clients.find((client) => client.clientId === "web-app");

if (!webApp) {
  throw new Error("web-app client not found in realm file");
}

webApp.redirectUris = [`${appBaseUrl}/callback`];
webApp.webOrigins = [appBaseUrl];

fs.writeFileSync(outputFile, `${JSON.stringify(realm, null, 2)}\n`);
NODE

echo "Logging into Keycloak at ${KEYCLOAK_URL}"
"$KCADM_BIN" config credentials \
  --server "$KEYCLOAK_URL" \
  --realm master \
  --user "$KEYCLOAK_ADMIN" \
  --password "$KEYCLOAK_ADMIN_PASSWORD"

if "$KCADM_BIN" get "realms/${REALM_NAME}" >/dev/null 2>&1; then
  if [ "$RESET_REALM" = "1" ]; then
    echo "Deleting existing realm ${REALM_NAME}"
    "$KCADM_BIN" delete "realms/${REALM_NAME}"
  else
    echo "Realm ${REALM_NAME} already exists. Re-run with RESET_REALM=1 to replace it."
    exit 1
  fi
fi

echo "Importing realm ${REALM_NAME}"
"$KCADM_BIN" create realms -f "$tmp_realm"

echo
echo "Imported ${REALM_NAME}"
echo "App callback: ${APP_BASE_URL}/callback"
echo "Client ID: web-app"
echo "Client secret: local-dev-secret"
echo "Users: developer / password, teller / password, customer / password"
