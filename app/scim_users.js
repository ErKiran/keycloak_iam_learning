const express = require("express");
const {
  getKeycloakUserById,
  searchKeycloakUsers,
  countKeycloakUsers,
  createKeycloakUser,
  updateKeycloakUser,
  deleteKeycloakUser,
} = require("./keycloak_users");
const {
  getKeycloakUserGroups,
  ensureKeycloakGroupWithClientRole,
  addUserToKeycloakGroup,
  removeUserFromKeycloakGroup,
} = require("./keycloak_groups");

const router = express.Router();

const USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
const LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
const ENTERPRISE_USER_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const DEPARTMENT_GROUP_RULES = [
  {
    department: "information technology",
    groupName: "Developer",
    roleName: "Developer",
  },
  {
    department: "finance",
    groupName: "Finance",
    roleName: "Teller",
  },
];

function scimLocation(req, id) {
  return `${req.protocol}://${req.get("host")}/scim/v2/Users/${encodeURIComponent(id)}`;
}

function groupLocation(req, id) {
  return `${req.protocol}://${req.get("host")}/scim/v2/Groups/${encodeURIComponent(id)}`;
}

function keycloakGroupToScimMembership(req, group) {
  return {
    value: group.id,
    display: group.name || group.path || group.id,
    $ref: groupLocation(req, group.id),
  };
}

function keycloakToScimUser(req, user, groups = []) {
  const department = keycloakDepartment(user);
  const emails = [];
  if (user.email) {
    emails.push({
      value: user.email,
      primary: true,
      type: "work",
    });
  }

  return {
    schemas: [USER_SCHEMA],
    id: user.id,
    userName: user.username,
    name: {
      givenName: user.firstName || "",
      familyName: user.lastName || "",
    },
    active: user.enabled !== false,
    emails,
    ...(department ? { department } : {}),
    ...(department ? { [ENTERPRISE_USER_SCHEMA]: { department } } : {}),
    groups: groups.map((group) => keycloakGroupToScimMembership(req, group)),
    meta: {
      resourceType: "User",
      created: user.createdTimestamp ? new Date(user.createdTimestamp).toISOString() : undefined,
      location: scimLocation(req, user.id),
    },
  };
}

function keycloakDepartment(user = {}) {
  const value = user.attributes?.department;
  if (Array.isArray(value)) return value[0] || "";
  return value || "";
}

function scimDepartment(scimUser = {}) {
  const enterprise = scimUser[ENTERPRISE_USER_SCHEMA];
  return scimUser.department ?? enterprise?.department;
}

function departmentRule(department) {
  const normalized = String(department || "").trim().toLowerCase();
  return DEPARTMENT_GROUP_RULES.find((rule) => rule.department === normalized) || null;
}

async function keycloakToScimUserWithGroups(req, user) {
  const groups = await getKeycloakUserGroups(user.id);
  return keycloakToScimUser(req, user, groups);
}

function firstEmail(scimUser = {}) {
  if (typeof scimUser.email === "string") return scimUser.email;
  if (Object.prototype.hasOwnProperty.call(scimUser, "emails") && scimUser.emails?.length === 0) return null;
  if (!Array.isArray(scimUser.emails)) return undefined;

  const primary = scimUser.emails.find((email) => email?.primary);
  return (primary || scimUser.emails[0])?.value;
}

function scimToKeycloakUser(scimUser = {}, existing = {}) {
  const name = scimUser.name || {};
  const email = firstEmail(scimUser);
  const department = scimDepartment(scimUser);
  const attributes = { ...(existing.attributes || {}) };

  if (department !== undefined) {
    attributes.department = department ? [String(department)] : [];
  }

  return {
    ...existing,
    username: scimUser.userName ?? existing.username,
    email: email !== undefined ? email : existing.email,
    firstName: Object.prototype.hasOwnProperty.call(name, "givenName") ? name.givenName : existing.firstName,
    lastName: Object.prototype.hasOwnProperty.call(name, "familyName") ? name.familyName : existing.lastName,
    enabled: typeof scimUser.active === "boolean" ? scimUser.active : existing.enabled ?? true,
    attributes,
  };
}

function scimError(res, status, detail, scimType) {
  return res.status(status).type("application/scim+json").json({
    schemas: [ERROR_SCHEMA],
    status: String(status),
    ...(scimType ? { scimType } : {}),
    detail,
  });
}

function parseFilter(filter) {
  if (!filter) return {};

  const match = String(filter).match(/^\s*(userName|emails\.value)\s+eq\s+"([^"]+)"\s*$/i);
  if (!match) {
    const err = new Error('Only simple filters like userName eq "alice" or emails.value eq "alice@example.com" are supported');
    err.status = 400;
    err.scimType = "invalidFilter";
    throw err;
  }

  return match[1].toLowerCase() === "username"
    ? { username: match[2] }
    : { email: match[2] };
}

function setPath(user, path, value) {
  switch (String(path || "").toLowerCase()) {
    case "username":
      user.userName = value;
      break;
    case "name.givenname":
      user.name = { ...(user.name || {}), givenName: value };
      break;
    case "name.familyname":
      user.name = { ...(user.name || {}), familyName: value };
      break;
    case "active":
      user.active = value;
      break;
    case "department":
      user.department = value;
      user[ENTERPRISE_USER_SCHEMA] = { ...(user[ENTERPRISE_USER_SCHEMA] || {}), department: value };
      break;
    case ENTERPRISE_USER_SCHEMA.toLowerCase():
      if (value && typeof value === "object" && Object.prototype.hasOwnProperty.call(value, "department")) {
        user.department = value.department;
        user[ENTERPRISE_USER_SCHEMA] = { ...(user[ENTERPRISE_USER_SCHEMA] || {}), department: value.department };
        break;
      }
      throw Object.assign(new Error(`Unsupported PATCH path: ${path}`), { status: 400, scimType: "invalidPath" });
    case `${ENTERPRISE_USER_SCHEMA.toLowerCase()}.department`:
      user.department = value;
      user[ENTERPRISE_USER_SCHEMA] = { ...(user[ENTERPRISE_USER_SCHEMA] || {}), department: value };
      break;
    case "emails":
      user.emails = Array.isArray(value) ? value : [value];
      break;
    case "emails.value":
    case 'emails[type eq "work"].value':
      user.emails = [{ value, primary: true, type: "work" }];
      break;
    default: {
      const err = new Error(`Unsupported PATCH path: ${path}`);
      err.status = 400;
      err.scimType = "invalidPath";
      throw err;
    }
  }
}

function removePath(user, path) {
  switch (String(path || "").toLowerCase()) {
    case "name.givenname":
      user.name = { ...(user.name || {}), givenName: null };
      break;
    case "name.familyname":
      user.name = { ...(user.name || {}), familyName: null };
      break;
    case "emails":
    case "emails.value":
    case 'emails[type eq "work"].value':
      user.emails = [];
      break;
    case "department":
      user.department = null;
      user[ENTERPRISE_USER_SCHEMA] = { ...(user[ENTERPRISE_USER_SCHEMA] || {}), department: null };
      break;
    case `${ENTERPRISE_USER_SCHEMA.toLowerCase()}.department`:
      user.department = null;
      user[ENTERPRISE_USER_SCHEMA] = { ...(user[ENTERPRISE_USER_SCHEMA] || {}), department: null };
      break;
    default: {
      const err = new Error(`Unsupported remove path: ${path}`);
      err.status = 400;
      err.scimType = "invalidPath";
      throw err;
    }
  }
}

async function syncDepartmentGroup(userId, department) {
  const nextRule = departmentRule(department);
  const managedGroups = new Set(DEPARTMENT_GROUP_RULES.map((rule) => rule.groupName.toLowerCase()));
  const currentGroups = await getKeycloakUserGroups(userId);

  for (const group of currentGroups) {
    const groupName = String(group.name || "").trim().toLowerCase();
    if (managedGroups.has(groupName) && groupName !== String(nextRule?.groupName || "").toLowerCase()) {
      await removeUserFromKeycloakGroup(userId, group.id);
    }
  }

  if (!nextRule) return;

  const targetGroup = await ensureKeycloakGroupWithClientRole(nextRule.groupName, nextRule.roleName);
  const alreadyMember = currentGroups.some((group) => group.id === targetGroup.id);
  if (!alreadyMember) {
    await addUserToKeycloakGroup(userId, targetGroup.id);
  }
}

function applyPatchOperations(scimUser, operations = []) {
  if (!Array.isArray(operations)) {
    const err = new Error("PATCH requires an Operations array");
    err.status = 400;
    err.scimType = "invalidSyntax";
    throw err;
  }

  const next = JSON.parse(JSON.stringify(scimUser));

  for (const operation of operations) {
    const op = String(operation.op || "").toLowerCase();
    if (op === "add" || op === "replace") {
      if (operation.path) {
        setPath(next, operation.path, operation.value);
      } else if (operation.value && typeof operation.value === "object") {
        Object.entries(operation.value).forEach(([path, value]) => setPath(next, path, value));
      } else {
        const err = new Error("PATCH add/replace requires a path or object value");
        err.status = 400;
        err.scimType = "invalidSyntax";
        throw err;
      }
      continue;
    }

    if (op === "remove") {
      removePath(next, operation.path);
      continue;
    }

    const err = new Error(`Unsupported PATCH operation: ${operation.op}`);
    err.status = 400;
    err.scimType = "invalidSyntax";
    throw err;
  }

  return next;
}

async function handleKeycloakError(res, err) {
  const status = err?.response?.status;

  if (status === 404) {
    return scimError(res, 404, "User not found");
  }

  if (status === 409) {
    return scimError(res, 409, "User already exists", "uniqueness");
  }

  if (status === 400) {
    return scimError(res, 400, err?.response?.data?.errorMessage || "Invalid user request", "invalidValue");
  }

  if (status === 401 || status === 403) {
    return scimError(res, status, "Keycloak admin client is not authorized to manage users");
  }

  return scimError(res, err.status || 500, err.message || "SCIM request failed", err.scimType);
}

router.use((req, res, next) => {
  res.type("application/scim+json");

  if (process.env.SCIM_BEARER_TOKEN) {
    const expected = `Bearer ${process.env.SCIM_BEARER_TOKEN}`;
    if (req.get("authorization") !== expected) {
      return scimError(res, 401, "Missing or invalid SCIM bearer token");
    }
  }

  next();
});

router.get("/Users", async (req, res) => {
  try {
    const startIndex = Math.max(parseInt(req.query.startIndex, 10) || 1, 1);
    const count = Math.min(Math.max(parseInt(req.query.count, 10) || 100, 1), 1000);
    const query = parseFilter(req.query.filter);
    const users = await searchKeycloakUsers({ first: startIndex - 1, max: count, ...query });
    const totalResults = await countKeycloakUsers(query);

    return res.json({
      schemas: [LIST_SCHEMA],
      totalResults,
      startIndex,
      itemsPerPage: users.length,
      Resources: await Promise.all(users.map((user) => keycloakToScimUserWithGroups(req, user))),
    });
  } catch (err) {
    return handleKeycloakError(res, err);
  }
});

router.post("/Users", async (req, res) => {
  try {
    console.log("Create user request body:", JSON.stringify(req.body, null, 2));
    if (!req.body?.userName) {
      return scimError(res, 400, "userName is required", "invalidValue");
    }

    const created = await createKeycloakUser(scimToKeycloakUser(req.body));
    await syncDepartmentGroup(created.id, scimDepartment(req.body));
    const scimUser = await keycloakToScimUserWithGroups(req, await getKeycloakUserById(created.id));
    return res.status(201).set("Location", scimUser.meta.location).json(scimUser);
  } catch (err) {
    return handleKeycloakError(res, err);
  }
});

router.get("/Users/:id", async (req, res) => {
  try {
    const user = await getKeycloakUserById(req.params.id);
    return res.json(await keycloakToScimUserWithGroups(req, user));
  } catch (err) {
    return handleKeycloakError(res, err);
  }
});

router.put("/Users/:id", async (req, res) => {
  try {
    const schemas = Array.isArray(req.body?.schemas) ? req.body.schemas : [];
    if (schemas.length > 0 && !schemas.includes(USER_SCHEMA)) {
      return scimError(res, 400, "PUT body must use the SCIM User schema", "invalidSyntax");
    }

    if (req.body?.id && req.body.id !== req.params.id) {
      return scimError(res, 400, "Request body id must match the URL id", "invalidValue");
    }

    const existing = await getKeycloakUserById(req.params.id);
    const updated = await updateKeycloakUser(req.params.id, scimToKeycloakUser(req.body, existing));
    await syncDepartmentGroup(req.params.id, scimDepartment(req.body) ?? keycloakDepartment(updated));
    const scimUser = await keycloakToScimUserWithGroups(req, updated);
    return res.set("Location", scimUser.meta.location).json(scimUser);
  } catch (err) {
    return handleKeycloakError(res, err);
  }
});

router.patch("/Users/:id", async (req, res) => {
  try {
    const schemas = Array.isArray(req.body?.schemas) ? req.body.schemas : [];
    if (schemas.length > 0 && !schemas.includes(PATCH_SCHEMA)) {
      return scimError(res, 400, "PATCH body must use the SCIM PatchOp schema", "invalidSyntax");
    }

    const existing = await getKeycloakUserById(req.params.id);
    const patchedScim = applyPatchOperations(keycloakToScimUser(req, existing), req.body?.Operations);
    const updated = await updateKeycloakUser(req.params.id, scimToKeycloakUser(patchedScim, existing));
    await syncDepartmentGroup(req.params.id, scimDepartment(patchedScim));
    return res.json(await keycloakToScimUserWithGroups(req, updated));
  } catch (err) {
    return handleKeycloakError(res, err);
  }
});

router.delete("/Users/:id", async (req, res) => {
  try {
    await deleteKeycloakUser(req.params.id);
    return res.status(204).send();
  } catch (err) {
    return handleKeycloakError(res, err);
  }
});

module.exports = router;
