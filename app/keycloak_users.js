const axios = require("axios");
const querystring = require("querystring");
const {
  KEYCLOAK_BASE_URL,
  KEYCLOAK_REALM,
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CLIENT_SECRET,
  tokenEndpoint,
} = require("../helper");

function normalize(value) {
  return String(value || "").trim().toLowerCase();
}

function candidateIdentities(username, email) {
  const set = new Set();
  const u = normalize(username);
  const e = normalize(email);

  if (u) set.add(u);
  if (e) {
    set.add(e);
    const local = e.split("@")[0];
    if (local) set.add(local);
  }

  return [...set];
}

async function getAdminAccessToken() {
  const clientId = process.env.KEYCLOAK_USER_LOOKUP_CLIENT_ID || KEYCLOAK_CLIENT_ID;
  const clientSecret = process.env.KEYCLOAK_USER_LOOKUP_CLIENT_SECRET || KEYCLOAK_CLIENT_SECRET;

  let response;
  try {
    response = await axios.post(
      tokenEndpoint,
      querystring.stringify({
        grant_type: "client_credentials",
        client_id: clientId,
        client_secret: clientSecret,
      }),
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        timeout: 10000,
      }
    );
  } catch (err) {
    const status = err?.response?.status;
    if (status === 401 || status === 403) {
      throw new Error(
        `Keycloak token request denied for lookup client '${clientId}'. Check client secret and enable Service Accounts.`
      );
    }
    throw err;
  }

  const accessToken = response?.data?.access_token;
  if (!accessToken) {
    throw new Error("Unable to obtain Keycloak admin access token for user lookup");
  }

  return accessToken;
}

function findExactUserMatch(users, username, email) {
  const probes = candidateIdentities(username, email);
  return users.find((user) => {
    const uname = normalize(user?.username);
    const uemail = normalize(user?.email);
    return probes.includes(uname) || probes.includes(uemail);
  });
}

async function lookupUsersByQuery(accessToken, queryKey, queryValue) {
  const base = `${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users`;
  let response;
  try {
    response = await axios.get(base, {
      headers: { Authorization: `Bearer ${accessToken}` },
      params: { [queryKey]: queryValue, exact: true, max: 20 },
      timeout: 10000,
    });
  } catch (err) {
    const status = err?.response?.status;
    if (status === 403) {
      const permissionError = new Error(
        "Keycloak lookup client is missing permission to read users. Grant realm-management view-users (or query-users)."
      );
      permissionError.code = "KEYCLOAK_LOOKUP_FORBIDDEN";
      throw permissionError;
    }
    throw err;
  }

  return Array.isArray(response.data) ? response.data : [];
}

function getTargetClientIds() {
  const configured = String(
    process.env.KEYCLOAK_ROLE_SOURCE_CLIENT_IDS ||
    process.env.KEYCLOAK_ROLE_SOURCE_CLIENT_ID ||
    process.env.KEYCLOAK_RESOURCE_SERVER_ID ||
    KEYCLOAK_CLIENT_ID ||
    ""
  )
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

  return [...new Set(configured)];
}

function shouldIncludeRealmRoles() {
  return String(process.env.KEYCLOAK_INCLUDE_REALM_ROLES || "false").toLowerCase() === "true";
}

async function getClientUuidByClientId(accessToken, clientId) {
  const clientsUrl = `${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients`;
  const clientsResponse = await axios.get(clientsUrl, {
    headers: { Authorization: `Bearer ${accessToken}` },
    params: { clientId, max: 2 },
    timeout: 10000,
  });

  const clients = Array.isArray(clientsResponse.data) ? clientsResponse.data : [];
  return clients[0]?.id || null;
}

async function fetchClientRolesForUser(accessToken, userId, clientUuid) {
  const clientRoleUrl = `${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users/${userId}/role-mappings/clients/${clientUuid}/composite`;
  const clientResponse = await axios.get(clientRoleUrl, {
    headers: { Authorization: `Bearer ${accessToken}` },
    timeout: 10000,
  });

  return Array.isArray(clientResponse.data)
    ? clientResponse.data.map((role) => role.name).filter(Boolean)
    : [];
}

async function fetchRealmRolesForUser(accessToken, userId) {
  const realmRoleUrl = `${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users/${userId}/role-mappings/realm/composite`;
  const realmResponse = await axios.get(realmRoleUrl, {
    headers: { Authorization: `Bearer ${accessToken}` },
    timeout: 10000,
  });

  return Array.isArray(realmResponse.data)
    ? realmResponse.data.map((role) => role.name).filter(Boolean)
    : [];
}

async function fetchAllCompositeRoleMappings(accessToken, userId) {
  const allCompositeUrl = `${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users/${userId}/role-mappings/composite`;
  const response = await axios.get(allCompositeUrl, {
    headers: { Authorization: `Bearer ${accessToken}` },
    timeout: 10000,
  });

  return Array.isArray(response.data) ? response.data : [];
}

async function keycloakUserExists({ username, email }) {
  const accessToken = await getAdminAccessToken();
  const probes = candidateIdentities(username, email);

  for (const probe of probes) {
    const byUsername = await lookupUsersByQuery(accessToken, "username", probe);
    if (findExactUserMatch(byUsername, username, email)) return true;

    if (probe.includes("@")) {
      const byEmail = await lookupUsersByQuery(accessToken, "email", probe);
      if (findExactUserMatch(byEmail, username, email)) return true;
    }
  }

  return false;
}

/**
 * Fetch a Keycloak user by username or email and return role names.
 * By default this reads client roles only. Realm roles are optional via env.
 */
async function getUserRolesFromKeycloak({ username, email }) {
  const accessToken = await getAdminAccessToken();
  const probes = candidateIdentities(username, email);

  let foundUser = null;

  // Try to find user by each probe
  for (const probe of probes) {
    const byUsername = await lookupUsersByQuery(accessToken, "username", probe);
    foundUser = findExactUserMatch(byUsername, username, email);
    if (foundUser) break;

    if (probe.includes("@")) {
      const byEmail = await lookupUsersByQuery(accessToken, "email", probe);
      foundUser = findExactUserMatch(byEmail, username, email);
      if (foundUser) break;
    }
  }

  if (!foundUser) {
    console.warn(`[Keycloak] User not found for username=${username}, email=${email}`);
    return [];
  }

  console.log(`[Keycloak] Found user: ${foundUser.id} (${foundUser.username || foundUser.email})`);

  try {
    const userId = foundUser.id;
    const allRoles = [];
    const targetClientIds = getTargetClientIds();

    for (const targetClientId of targetClientIds) {
      try {
        console.log(`[Keycloak] Looking up client UUID for clientId=${targetClientId}`);
        const clientUuid = await getClientUuidByClientId(accessToken, targetClientId);

        if (!clientUuid) {
          console.warn(`[Keycloak] Client not found for clientId=${targetClientId}`);
          continue;
        }

        console.log(`[Keycloak] Found client UUID: ${clientUuid} for clientId=${targetClientId}`);
        const clientRoles = await fetchClientRolesForUser(accessToken, userId, clientUuid);
        console.log(`[Keycloak] Client roles for ${targetClientId}: ${clientRoles.join(", ") || "none"}`);
        allRoles.push(...clientRoles);
      } catch (clientErr) {
        if (clientErr?.response?.status === 403) {
          throw new Error(
            "Keycloak lookup client is missing permission to read client roles. Grant realm-management view-users and view-clients."
          );
        }
        if (clientErr?.response?.status !== 404) {
          console.warn(`[Keycloak] Could not fetch client roles for ${targetClientId}: ${clientErr.message}`);
        }
      }
    }

    if (shouldIncludeRealmRoles()) {
      try {
        const realmRoles = await fetchRealmRolesForUser(accessToken, userId);
        console.log(`[Keycloak] Realm roles found: ${realmRoles.join(", ") || "none"}`);
        allRoles.push(...realmRoles);
      } catch (realmErr) {
        if (realmErr?.response?.status !== 404) {
          console.warn(`[Keycloak] Could not fetch realm roles: ${realmErr.message}`);
        }
      }
    }

    // Fallback for composite inheritance edge cases:
    // When roles are inherited via realm composite, per-client lookups can still appear empty.
    if (allRoles.length === 0) {
      try {
        const effectiveMappings = await fetchAllCompositeRoleMappings(accessToken, userId);
        const fallbackClientRoles = effectiveMappings
          .filter((role) => role?.clientRole === true)
          .map((role) => role?.name)
          .filter(Boolean);

        const fallbackRealmRoles = shouldIncludeRealmRoles()
          ? effectiveMappings
              .filter((role) => role?.clientRole !== true)
              .map((role) => role?.name)
              .filter(Boolean)
          : [];

        if (fallbackClientRoles.length > 0 || fallbackRealmRoles.length > 0) {
          console.log(
            `[Keycloak] Fallback effective mappings used. Client roles: ${fallbackClientRoles.join(", ") || "none"}; Realm roles: ${fallbackRealmRoles.join(", ") || "none"}`
          );
          allRoles.push(...fallbackClientRoles, ...fallbackRealmRoles);
        }
      } catch (fallbackErr) {
        if (fallbackErr?.response?.status !== 404) {
          console.warn(`[Keycloak] Could not fetch fallback effective composite mappings: ${fallbackErr.message}`);
        }
      }
    }

    const uniqueRoles = [...new Set(allRoles)];
    console.log(`[Keycloak] Total unique roles for user: ${uniqueRoles.join(", ") || "none"}`);
    return uniqueRoles;
  } catch (err) {
    const status = err?.response?.status;
    if (status === 403) {
      throw new Error(
        "Keycloak lookup client is missing permission to read user roles. Grant realm-management view-users, query-users, and view-realm-scopes."
      );
    }
    console.error("[Keycloak] Error fetching user roles:", err.message);
    return [];
  }
}

module.exports = {
  keycloakUserExists,
  getUserRolesFromKeycloak,
};
