const axios = require("axios");
const querystring = require("querystring");
const {
  KEYCLOAK_BASE_URL,
  KEYCLOAK_REALM,
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CLIENT_SECRET,
  tokenEndpoint,
} = require("../helper");

async function getAdminAccessToken() {
  const clientId = process.env.KEYCLOAK_USER_LOOKUP_CLIENT_ID || KEYCLOAK_CLIENT_ID;
  const clientSecret = process.env.KEYCLOAK_USER_LOOKUP_CLIENT_SECRET || KEYCLOAK_CLIENT_SECRET;

  const response = await axios.post(
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

  const accessToken = response?.data?.access_token;
  if (!accessToken) {
    throw new Error("Unable to obtain Keycloak admin access token for group management");
  }

  return accessToken;
}

function groupsBaseUrl() {
  return `${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/groups`;
}

function usersBaseUrl() {
  return `${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users`;
}

async function authHeaders() {
  const accessToken = await getAdminAccessToken();
  return { Authorization: `Bearer ${accessToken}` };
}

async function searchKeycloakGroups({ search, first = 0, max = 1000 } = {}) {
  const headers = await authHeaders();
  const response = await axios.get(groupsBaseUrl(), {
    headers,
    params: {
      first,
      max,
      briefRepresentation: false,
      ...(search ? { search } : {}),
    },
    timeout: 10000,
  });

  return Array.isArray(response.data) ? response.data : [];
}

async function getKeycloakGroupById(groupId) {
  const headers = await authHeaders();
  const response = await axios.get(`${groupsBaseUrl()}/${encodeURIComponent(groupId)}`, {
    headers,
    timeout: 10000,
  });

  return response.data;
}

async function getKeycloakGroupMembers(groupId) {
  const headers = await authHeaders();
  const response = await axios.get(`${groupsBaseUrl()}/${encodeURIComponent(groupId)}/members`, {
    headers,
    params: { max: 1000 },
    timeout: 10000,
  });

  return Array.isArray(response.data) ? response.data : [];
}

async function getKeycloakUserGroups(userId) {
  const headers = await authHeaders();
  const response = await axios.get(`${usersBaseUrl()}/${encodeURIComponent(userId)}/groups`, {
    headers,
    params: { briefRepresentation: false, max: 1000 },
    timeout: 10000,
  });

  return Array.isArray(response.data) ? response.data : [];
}

async function findKeycloakGroupByName(name) {
  const groups = await searchKeycloakGroups({ search: name });
  const normalized = String(name || "").trim().toLowerCase();
  return groups.find((group) => String(group.name || "").trim().toLowerCase() === normalized) || null;
}

async function getClientUuidByClientId(clientId) {
  const headers = await authHeaders();
  const response = await axios.get(`${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients`, {
    headers,
    params: { clientId, max: 2 },
    timeout: 10000,
  });

  const clients = Array.isArray(response.data) ? response.data : [];
  return clients[0]?.id || null;
}

async function getClientRole(clientUuid, roleName) {
  const headers = await authHeaders();
  const response = await axios.get(
    `${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${encodeURIComponent(clientUuid)}/roles/${encodeURIComponent(roleName)}`,
    {
      headers,
      timeout: 10000,
    }
  );

  return response.data;
}

async function assignClientRoleToGroup(groupId, roleName, clientId = KEYCLOAK_CLIENT_ID) {
  const clientUuid = await getClientUuidByClientId(clientId);
  if (!clientUuid) {
    throw new Error(`Keycloak client not found: ${clientId}`);
  }

  const role = await getClientRole(clientUuid, roleName);
  const headers = await authHeaders();
  await axios.post(
    `${groupsBaseUrl()}/${encodeURIComponent(groupId)}/role-mappings/clients/${encodeURIComponent(clientUuid)}`,
    [role],
    {
      headers,
      timeout: 10000,
    }
  );
}

async function ensureKeycloakGroupWithClientRole(groupName, roleName, clientId = KEYCLOAK_CLIENT_ID) {
  let group = await findKeycloakGroupByName(groupName);
  if (!group) {
    group = await createKeycloakGroup({ name: groupName });
  }

  await assignClientRoleToGroup(group.id, roleName, clientId);
  return group;
}

async function createKeycloakGroup(group) {
  const headers = await authHeaders();
  const response = await axios.post(groupsBaseUrl(), group, {
    headers,
    timeout: 10000,
  });

  const location = response.headers?.location || "";
  const groupId = location.split("/").filter(Boolean).pop();
  if (!groupId) {
    throw new Error("Keycloak created the group but did not return a Location header");
  }

  return getKeycloakGroupById(groupId);
}

async function updateKeycloakGroup(groupId, group) {
  const headers = await authHeaders();
  await axios.put(`${groupsBaseUrl()}/${encodeURIComponent(groupId)}`, group, {
    headers,
    timeout: 10000,
  });

  return getKeycloakGroupById(groupId);
}

async function deleteKeycloakGroup(groupId) {
  const headers = await authHeaders();
  await axios.delete(`${groupsBaseUrl()}/${encodeURIComponent(groupId)}`, {
    headers,
    timeout: 10000,
  });
}

async function addUserToKeycloakGroup(userId, groupId) {
  const headers = await authHeaders();
  await axios.put(`${usersBaseUrl()}/${encodeURIComponent(userId)}/groups/${encodeURIComponent(groupId)}`, null, {
    headers,
    timeout: 10000,
  });
}

async function removeUserFromKeycloakGroup(userId, groupId) {
  const headers = await authHeaders();
  await axios.delete(`${usersBaseUrl()}/${encodeURIComponent(userId)}/groups/${encodeURIComponent(groupId)}`, {
    headers,
    timeout: 10000,
  });
}

module.exports = {
  searchKeycloakGroups,
  getKeycloakGroupById,
  getKeycloakGroupMembers,
  getKeycloakUserGroups,
  findKeycloakGroupByName,
  ensureKeycloakGroupWithClientRole,
  createKeycloakGroup,
  updateKeycloakGroup,
  deleteKeycloakGroup,
  addUserToKeycloakGroup,
  removeUserFromKeycloakGroup,
};
