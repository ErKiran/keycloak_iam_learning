const express = require("express");

const router = express.Router();

const LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
const USER_SCHEMA_ID = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA_ID = "urn:ietf:params:scim:schemas:core:2.0:Group";

const schemas = [
  {
    id: USER_SCHEMA_ID,
    name: "User",
    description: "User account",
    attributes: [
      {
        name: "userName",
        type: "string",
        multiValued: false,
        description: "Unique identifier for the user, typically used by the user to directly authenticate.",
        required: true,
        caseExact: false,
        mutability: "readWrite",
        returned: "default",
        uniqueness: "server",
      },
      {
        name: "name",
        type: "complex",
        multiValued: false,
        description: "The components of the user's real name.",
        required: false,
        mutability: "readWrite",
        returned: "default",
        uniqueness: "none",
        subAttributes: [
          {
            name: "givenName",
            type: "string",
            multiValued: false,
            required: false,
            caseExact: false,
            mutability: "readWrite",
            returned: "default",
            uniqueness: "none",
          },
          {
            name: "familyName",
            type: "string",
            multiValued: false,
            required: false,
            caseExact: false,
            mutability: "readWrite",
            returned: "default",
            uniqueness: "none",
          },
        ],
      },
      {
        name: "active",
        type: "boolean",
        multiValued: false,
        description: "A Boolean value indicating the user's administrative status.",
        required: false,
        mutability: "readWrite",
        returned: "default",
        uniqueness: "none",
      },
      {
        name: "emails",
        type: "complex",
        multiValued: true,
        description: "Email addresses for the user.",
        required: false,
        mutability: "readWrite",
        returned: "default",
        uniqueness: "none",
        subAttributes: [
          {
            name: "value",
            type: "string",
            multiValued: false,
            required: false,
            caseExact: false,
            mutability: "readWrite",
            returned: "default",
            uniqueness: "none",
          },
          {
            name: "type",
            type: "string",
            multiValued: false,
            required: false,
            caseExact: false,
            canonicalValues: ["work"],
            mutability: "readWrite",
            returned: "default",
            uniqueness: "none",
          },
          {
            name: "primary",
            type: "boolean",
            multiValued: false,
            required: false,
            mutability: "readWrite",
            returned: "default",
            uniqueness: "none",
          },
        ],
      },
    ],
  },
  {
    id: GROUP_SCHEMA_ID,
    name: "Group",
    description: "Group",
    attributes: [
      {
        name: "displayName",
        type: "string",
        multiValued: false,
        description: "A human-readable name for the group.",
        required: true,
        caseExact: false,
        mutability: "readWrite",
        returned: "default",
        uniqueness: "server",
      },
      {
        name: "members",
        type: "complex",
        multiValued: true,
        description: "Users that belong to the group.",
        required: false,
        mutability: "readWrite",
        returned: "default",
        uniqueness: "none",
        subAttributes: [
          {
            name: "value",
            type: "string",
            multiValued: false,
            description: "Identifier of the member resource.",
            required: false,
            caseExact: true,
            mutability: "immutable",
            returned: "default",
            uniqueness: "none",
          },
          {
            name: "$ref",
            type: "reference",
            referenceTypes: ["User"],
            multiValued: false,
            required: false,
            mutability: "immutable",
            returned: "default",
            uniqueness: "none",
          },
          {
            name: "display",
            type: "string",
            multiValued: false,
            required: false,
            caseExact: false,
            mutability: "immutable",
            returned: "default",
            uniqueness: "none",
          },
        ],
      },
    ],
  },
];

const resourceTypes = [
  {
    id: "User",
    name: "User",
    endpoint: "/Users",
    description: "User account",
    schema: USER_SCHEMA_ID,
    schemaExtensions: [],
  },
  {
    id: "Group",
    name: "Group",
    endpoint: "/Groups",
    description: "Group",
    schema: GROUP_SCHEMA_ID,
    schemaExtensions: [],
  },
];

function scimLocation(req, path) {
  return `${req.protocol}://${req.get("host")}/scim/v2${path}`;
}

function withMeta(req, resource, resourceType, path) {
  return {
    schemas: [`urn:ietf:params:scim:schemas:core:2.0:${resourceType}`],
    ...resource,
    meta: {
      resourceType,
      location: scimLocation(req, path),
    },
  };
}

function listResponse(resources) {
  return {
    schemas: [LIST_SCHEMA],
    totalResults: resources.length,
    startIndex: 1,
    itemsPerPage: resources.length,
    Resources: resources,
  };
}

function scimError(res, status, detail) {
  return res.status(status).type("application/scim+json").json({
    schemas: [ERROR_SCHEMA],
    status: String(status),
    detail,
  });
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

router.get("/Schemas", (req, res) => {
  const resources = schemas.map((schema) =>
    withMeta(req, schema, "Schema", `/Schemas/${encodeURIComponent(schema.id)}`)
  );
  res.json(listResponse(resources));
});

router.get("/Schemas/:id", (req, res) => {
  const schema = schemas.find((item) => item.id === req.params.id);
  if (!schema) return scimError(res, 404, "Schema not found");

  return res.json(withMeta(req, schema, "Schema", `/Schemas/${encodeURIComponent(schema.id)}`));
});

router.get("/ResourceTypes", (req, res) => {
  const resources = resourceTypes.map((resourceType) =>
    withMeta(req, resourceType, "ResourceType", `/ResourceTypes/${encodeURIComponent(resourceType.id)}`)
  );
  res.json(listResponse(resources));
});

router.get("/ResourceTypes/:id", (req, res) => {
  const resourceType = resourceTypes.find((item) => item.id.toLowerCase() === String(req.params.id).toLowerCase());
  if (!resourceType) return scimError(res, 404, "ResourceType not found");

  return res.json(withMeta(req, resourceType, "ResourceType", `/ResourceTypes/${encodeURIComponent(resourceType.id)}`));
});

module.exports = router;
