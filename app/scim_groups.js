const express = require("express");
const {
  searchKeycloakGroups,
  getKeycloakGroupById,
  getKeycloakGroupMembers,
  createKeycloakGroup,
  updateKeycloakGroup,
  deleteKeycloakGroup,
  addUserToKeycloakGroup,
  removeUserFromKeycloakGroup,
} = require("./keycloak_groups");

const router = express.Router();

const GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";

function scimLocation(req, id) {
  return `${req.protocol}://${req.get("host")}/scim/v2/Groups/${encodeURIComponent(id)}`;
}

function userLocation(req, id) {
  return `${req.protocol}://${req.get("host")}/scim/v2/Users/${encodeURIComponent(id)}`;
}

async function keycloakToScimGroup(req, group, includeMembers = true) {
  const members = includeMembers
    ? (await getKeycloakGroupMembers(group.id)).map((member) => ({
        value: member.id,
        display: member.username || member.email || member.id,
        $ref: userLocation(req, member.id),
      }))
    : [];

  return {
    schemas: [GROUP_SCHEMA],
    id: group.id,
    displayName: group.name,
    members,
    meta: {
      resourceType: "Group",
      location: scimLocation(req, group.id),
    },
  };
}

function memberIds(members = []) {
  if (!Array.isArray(members)) return [];
  return members.map((member) => member?.value).filter(Boolean);
}

function scimToKeycloakGroup(scimGroup = {}, existing = {}) {
  return {
    ...existing,
    name: scimGroup.displayName ?? existing.name,
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

  const match = String(filter).match(/^\s*displayName\s+eq\s+"([^"]+)"\s*$/i);
  if (!match) {
    const err = new Error('Only simple filters like displayName eq "Admins" are supported');
    err.status = 400;
    err.scimType = "invalidFilter";
    throw err;
  }

  return { displayName: match[1] };
}

function setPath(group, path, value) {
  switch (String(path || "").toLowerCase()) {
    case "displayname":
      group.displayName = value;
      break;
    case "members":
      group.members = Array.isArray(value) ? value : [value];
      break;
    default: {
      const err = new Error(`Unsupported PATCH path: ${path}`);
      err.status = 400;
      err.scimType = "invalidPath";
      throw err;
    }
  }
}

function memberIdFromPath(path) {
  const match = String(path || "").match(/^members\[value\s+eq\s+"([^"]+)"\]$/i);
  return match?.[1] || null;
}

function applyPatchOperations(scimGroup, operations = []) {
  if (!Array.isArray(operations)) {
    const err = new Error("PATCH requires an Operations array");
    err.status = 400;
    err.scimType = "invalidSyntax";
    throw err;
  }

  const next = JSON.parse(JSON.stringify(scimGroup));
  const memberChanges = [];

  for (const operation of operations) {
    const op = String(operation.op || "").toLowerCase();
    const path = String(operation.path || "").toLowerCase();
    const pathMemberId = memberIdFromPath(operation.path);

    if (op === "add" && (!path || path === "members")) {
      const members = Array.isArray(operation.value) ? operation.value : [operation.value];
      memberChanges.push({ op: "add", members });
      next.members = [...(next.members || []), ...members];
      continue;
    }

    if (op === "replace") {
      if (!operation.path && operation.value && typeof operation.value === "object") {
        Object.entries(operation.value).forEach(([patchPath, value]) => setPath(next, patchPath, value));
        if (Object.prototype.hasOwnProperty.call(operation.value, "members")) {
          memberChanges.push({ op: "replace", members: operation.value.members || [] });
        }
        continue;
      }

      if (path === "members") {
        const members = Array.isArray(operation.value) ? operation.value : [operation.value];
        next.members = members;
        memberChanges.push({ op: "replace", members });
        continue;
      }

      setPath(next, operation.path, operation.value);
      continue;
    }

    if (op === "remove" && pathMemberId) {
      const members = [{ value: pathMemberId }];
      memberChanges.push({ op: "remove", members });
      next.members = (next.members || []).filter((member) => member.value !== pathMemberId);
      continue;
    }

    if (op === "remove" && path === "members") {
      const members = operation.value ? (Array.isArray(operation.value) ? operation.value : [operation.value]) : next.members;
      memberChanges.push({ op: "remove", members });
      next.members = (next.members || []).filter((member) => !memberIds(members).includes(member.value));
      continue;
    }

    const err = new Error(`Unsupported PATCH operation: ${operation.op}`);
    err.status = 400;
    err.scimType = path && path !== "members" ? "invalidPath" : "invalidSyntax";
    throw err;
  }

  return { group: next, memberChanges };
}

async function applyMemberChanges(groupId, currentMembers, changes) {
  for (const change of changes) {
    if (change.op === "add") {
      for (const userId of memberIds(change.members)) {
        await addUserToKeycloakGroup(userId, groupId);
      }
      continue;
    }

    if (change.op === "remove") {
      for (const userId of memberIds(change.members)) {
        await removeUserFromKeycloakGroup(userId, groupId);
      }
      continue;
    }

    if (change.op === "replace") {
      const currentIds = memberIds(currentMembers);
      const nextIds = memberIds(change.members);

      for (const userId of currentIds.filter((id) => !nextIds.includes(id))) {
        await removeUserFromKeycloakGroup(userId, groupId);
      }

      for (const userId of nextIds.filter((id) => !currentIds.includes(id))) {
        await addUserToKeycloakGroup(userId, groupId);
      }
    }
  }
}

async function handleKeycloakError(res, err) {
  const status = err?.response?.status;

  if (status === 404) {
    return scimError(res, 404, "Group not found");
  }

  if (status === 409) {
    return scimError(res, 409, "Group already exists", "uniqueness");
  }

  if (status === 400) {
    return scimError(res, 400, err?.response?.data?.errorMessage || "Invalid group request", "invalidValue");
  }

  if (status === 401 || status === 403) {
    return scimError(res, status, "Keycloak admin client is not authorized to manage groups");
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

router.get("/Groups", async (req, res) => {
  try {
    const startIndex = Math.max(parseInt(req.query.startIndex, 10) || 1, 1);
    const count = Math.min(Math.max(parseInt(req.query.count, 10) || 100, 1), 1000);
    const query = parseFilter(req.query.filter);
    const allGroups = await searchKeycloakGroups({ search: query.displayName });
    const filteredGroups = query.displayName
      ? allGroups.filter((group) => String(group.name || "").toLowerCase() === query.displayName.toLowerCase())
      : allGroups;
    const page = filteredGroups.slice(startIndex - 1, startIndex - 1 + count);

    return res.json({
      schemas: [LIST_SCHEMA],
      totalResults: filteredGroups.length,
      startIndex,
      itemsPerPage: page.length,
      Resources: await Promise.all(page.map((group) => keycloakToScimGroup(req, group, false))),
    });
  } catch (err) {
    return handleKeycloakError(res, err);
  }
});

router.post("/Groups", async (req, res) => {
  try {
    if (!req.body?.displayName) {
      return scimError(res, 400, "displayName is required", "invalidValue");
    }

    const created = await createKeycloakGroup(scimToKeycloakGroup(req.body));
    for (const userId of memberIds(req.body.members)) {
      await addUserToKeycloakGroup(userId, created.id);
    }

    const scimGroup = await keycloakToScimGroup(req, created);
    return res.status(201).set("Location", scimGroup.meta.location).json(scimGroup);
  } catch (err) {
    return handleKeycloakError(res, err);
  }
});

router.get("/Groups/:id", async (req, res) => {
  try {
    const group = await getKeycloakGroupById(req.params.id);
    return res.json(await keycloakToScimGroup(req, group));
  } catch (err) {
    return handleKeycloakError(res, err);
  }
});

router.patch("/Groups/:id", async (req, res) => {
  try {
    const schemas = Array.isArray(req.body?.schemas) ? req.body.schemas : [];
    if (schemas.length > 0 && !schemas.includes(PATCH_SCHEMA)) {
      return scimError(res, 400, "PATCH body must use the SCIM PatchOp schema", "invalidSyntax");
    }

    const existing = await getKeycloakGroupById(req.params.id);
    const currentScimGroup = await keycloakToScimGroup(req, existing);
    const patched = applyPatchOperations(currentScimGroup, req.body?.Operations);
    const updated = await updateKeycloakGroup(req.params.id, scimToKeycloakGroup(patched.group, existing));
    await applyMemberChanges(req.params.id, currentScimGroup.members, patched.memberChanges);

    return res.json(await keycloakToScimGroup(req, updated));
  } catch (err) {
    return handleKeycloakError(res, err);
  }
});

router.delete("/Groups/:id", async (req, res) => {
  try {
    await deleteKeycloakGroup(req.params.id);
    return res.status(204).send();
  } catch (err) {
    return handleKeycloakError(res, err);
  }
});

module.exports = router;
