const axios = require("axios");
const querystring = require("querystring");
const {
  KEYCLOAK_BASE_URL,
  KEYCLOAK_REALM,
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CLIENT_SECRET,
  tokenEndpoint,
} = require("../helper");

function isScimDebugEnabled() {
  return String(process.env.SCIM_DEBUG || "").toLowerCase() === "true";
}

function scimDebug(step, details = {}) {
  if (!isScimDebugEnabled()) return;
  console.log(`[SCIM DEBUG] ${step}`, details);
}

function keycloakErrorDetails(err) {
  return {
    message: err?.message,
    status: err?.response?.status,
    data: err?.response?.data,
  };
}

async function getAdminAccessToken() {
  const clientId = process.env.KEYCLOAK_USER_LOOKUP_CLIENT_ID || KEYCLOAK_CLIENT_ID;
  const clientSecret = process.env.KEYCLOAK_USER_LOOKUP_CLIENT_SECRET || KEYCLOAK_CLIENT_SECRET;
  scimDebug("keycloak token request", { clientId });

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

  scimDebug("keycloak token received", { clientId });
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
  scimDebug("search groups request", { search, first, max });
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

  scimDebug("search groups response", {
    search,
    count: Array.isArray(response.data) ? response.data.length : 0,
    names: Array.isArray(response.data) ? response.data.map((group) => group.name) : [],
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
  scimDebug("user groups request", { userId });
  const response = await axios.get(`${usersBaseUrl()}/${encodeURIComponent(userId)}/groups`, {
    headers,
    params: { briefRepresentation: false, max: 1000 },
    timeout: 10000,
  });

  scimDebug("user groups response", {
    userId,
    groups: Array.isArray(response.data)
      ? response.data.map((group) => ({ id: group.id, name: group.name, path: group.path }))
      : [],
  });
  return Array.isArray(response.data) ? response.data : [];
}

async function findKeycloakGroupByName(name) {
  const groups = await searchKeycloakGroups({ search: name });
  const normalized = String(name || "").trim().toLowerCase();
  const group = groups.find((item) => String(item.name || "").trim().toLowerCase() === normalized) || null;
  scimDebug("find group by name", { name, found: group ? { id: group.id, name: group.name, path: group.path } : null });
  return group;
}

async function getClientUuidByClientId(clientId) {
  const headers = await authHeaders();
  scimDebug("client lookup request", { clientId });
  const response = await axios.get(`${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients`, {
    headers,
    params: { clientId, max: 2 },
    timeout: 10000,
  });

  const clients = Array.isArray(response.data) ? response.data : [];
  const clientUuid = clients[0]?.id || null;
  scimDebug("client lookup response", { clientId, clientUuid });
  return clientUuid;
}

async function getClientRole(clientUuid, roleName) {
  const headers = await authHeaders();
  scimDebug("client role lookup request", { clientUuid, roleName });
  const response = await axios.get(
    `${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${encodeURIComponent(clientUuid)}/roles/${encodeURIComponent(roleName)}`,
    {
      headers,
      timeout: 10000,
    }
  );

  scimDebug("client role lookup response", {
    clientUuid,
    roleName,
    role: response.data ? { id: response.data.id, name: response.data.name } : null,
  });
  return response.data;
}

async function assignClientRoleToGroup(groupId, roleName, clientId = KEYCLOAK_CLIENT_ID) {
  scimDebug("assign client role to group start", { groupId, roleName, clientId });
  const clientUuid = await getClientUuidByClientId(clientId);
  if (!clientUuid) {
    throw new Error(`Keycloak client not found: ${clientId}`);
  }

  const role = await getClientRole(clientUuid, roleName);
  const headers = await authHeaders();
  try {
    await axios.post(
      `${groupsBaseUrl()}/${encodeURIComponent(groupId)}/role-mappings/clients/${encodeURIComponent(clientUuid)}`,
      [role],
      {
        headers,
        timeout: 10000,
      }
    );
    scimDebug("assign client role to group success", { groupId, roleName, clientId, clientUuid });
  } catch (err) {
    scimDebug("assign client role to group failed", { groupId, roleName, clientId, ...keycloakErrorDetails(err) });
    throw err;
  }
}

async function ensureKeycloakGroupWithClientRole(groupName, roleName, clientId = KEYCLOAK_CLIENT_ID) {
  scimDebug("ensure group with role start", { groupName, roleName, clientId });
  let group = await findKeycloakGroupByName(groupName);
  if (!group) {
    scimDebug("group missing, creating", { groupName });
    group = await createKeycloakGroup({ name: groupName });
    scimDebug("group created", { groupName, groupId: group.id });
  }

  await assignClientRoleToGroup(group.id, roleName, clientId);
  scimDebug("ensure group with role complete", { groupName, groupId: group.id, roleName, clientId });
  return group;
}

async function createKeycloakGroup(group) {
  const headers = await authHeaders();
  scimDebug("create group request", { group });
  const response = await axios.post(groupsBaseUrl(), group, {
    headers,
    timeout: 10000,
  });

  const location = response.headers?.location || "";
  const groupId = location.split("/").filter(Boolean).pop();
  if (!groupId) {
    throw new Error("Keycloak created the group but did not return a Location header");
  }

  scimDebug("create group response", { groupId, location });
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
  scimDebug("add user to group request", { userId, groupId });
  try {
    await axios.put(`${usersBaseUrl()}/${encodeURIComponent(userId)}/groups/${encodeURIComponent(groupId)}`, null, {
      headers,
      timeout: 10000,
    });
    scimDebug("add user to group success", { userId, groupId });
  } catch (err) {
    scimDebug("add user to group failed", { userId, groupId, ...keycloakErrorDetails(err) });
    throw err;
  }
}

async function removeUserFromKeycloakGroup(userId, groupId) {
  const headers = await authHeaders();
  scimDebug("remove user from group request", { userId, groupId });
  try {
    await axios.delete(`${usersBaseUrl()}/${encodeURIComponent(userId)}/groups/${encodeURIComponent(groupId)}`, {
      headers,
      timeout: 10000,
    });
    scimDebug("remove user from group success", { userId, groupId });
  } catch (err) {
    scimDebug("remove user from group failed", { userId, groupId, ...keycloakErrorDetails(err) });
    throw err;
  }
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
