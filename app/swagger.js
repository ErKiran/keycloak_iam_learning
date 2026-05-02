function buildOpenApi(req) {
  const baseUrl = process.env.APP_BASE_URL || `${req.protocol}://${req.get("host")}`;

  return {
    openapi: "3.0.3",
    info: {
      title: "Neobank IAM Learning API",
      version: "1.0.0",
      description: "OIDC, SAML, banking demo, and SCIM provisioning endpoints.",
    },
    servers: [{ url: baseUrl }],
    tags: [
      { name: "Auth" },
      { name: "SAML" },
      { name: "Admin" },
      { name: "Banking" },
      { name: "Teller" },
      { name: "SCIM Metadata" },
      { name: "SCIM Users" },
      { name: "SCIM Groups" },
    ],
    components: {
      securitySchemes: {
        SessionCookie: {
          type: "apiKey",
          in: "cookie",
          name: "connect.sid",
        },
        ScimBearerAuth: {
          type: "http",
          scheme: "bearer",
          description: "Required when SCIM_BEARER_TOKEN is configured.",
        },
      },
      schemas: {
        Error: {
          type: "object",
          properties: {
            error: { type: "string" },
            message: { type: "string" },
          },
        },
        TransferRequest: {
          type: "object",
          required: ["to", "amount"],
          properties: {
            to: { type: "string", example: "alice" },
            amount: { type: "number", example: 25 },
          },
        },
        TransferResponse: {
          type: "object",
          properties: {
            ok: { type: "boolean" },
            to: { type: "string" },
            amount: { type: "number" },
            newBalance: { type: "number" },
          },
        },
        ScimError: {
          type: "object",
          properties: {
            schemas: {
              type: "array",
              items: { type: "string" },
              example: ["urn:ietf:params:scim:api:messages:2.0:Error"],
            },
            status: { type: "string", example: "400" },
            scimType: { type: "string", example: "invalidValue" },
            detail: { type: "string" },
          },
        },
        ScimEmail: {
          type: "object",
          properties: {
            value: { type: "string", format: "email" },
            primary: { type: "boolean" },
            type: { type: "string", example: "work" },
          },
        },
        ScimUser: {
          type: "object",
          required: ["userName"],
          properties: {
            schemas: {
              type: "array",
              items: { type: "string" },
              example: ["urn:ietf:params:scim:schemas:core:2.0:User"],
            },
            id: { type: "string", readOnly: true },
            userName: { type: "string", example: "alice" },
            name: {
              type: "object",
              properties: {
                givenName: { type: "string", example: "Alice" },
                familyName: { type: "string", example: "Morgan" },
              },
            },
            active: { type: "boolean", example: true },
            emails: {
              type: "array",
              items: { $ref: "#/components/schemas/ScimEmail" },
            },
            meta: { type: "object", readOnly: true },
          },
        },
        ScimMember: {
          type: "object",
          properties: {
            value: { type: "string", description: "Keycloak user id" },
            display: { type: "string", readOnly: true },
            $ref: { type: "string", readOnly: true },
          },
        },
        ScimGroup: {
          type: "object",
          required: ["displayName"],
          properties: {
            schemas: {
              type: "array",
              items: { type: "string" },
              example: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            },
            id: { type: "string", readOnly: true },
            displayName: { type: "string", example: "Tellers" },
            members: {
              type: "array",
              items: { $ref: "#/components/schemas/ScimMember" },
            },
            meta: { type: "object", readOnly: true },
          },
        },
        ScimPatch: {
          type: "object",
          required: ["Operations"],
          properties: {
            schemas: {
              type: "array",
              items: { type: "string" },
              example: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            },
            Operations: {
              type: "array",
              items: {
                type: "object",
                required: ["op"],
                properties: {
                  op: { type: "string", enum: ["add", "replace", "remove"] },
                  path: { type: "string", example: "active" },
                  value: {},
                },
              },
            },
          },
        },
        ScimListResponse: {
          type: "object",
          properties: {
            schemas: {
              type: "array",
              items: { type: "string" },
              example: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            },
            totalResults: { type: "integer" },
            startIndex: { type: "integer" },
            itemsPerPage: { type: "integer" },
            Resources: { type: "array", items: { type: "object" } },
          },
        },
        ScimSchemaResource: {
          type: "object",
          properties: {
            schemas: {
              type: "array",
              items: { type: "string" },
              example: ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
            },
            id: { type: "string", example: "urn:ietf:params:scim:schemas:core:2.0:User" },
            name: { type: "string", example: "User" },
            description: { type: "string" },
            attributes: { type: "array", items: { type: "object" } },
            meta: { type: "object" },
          },
        },
        ScimResourceType: {
          type: "object",
          properties: {
            schemas: {
              type: "array",
              items: { type: "string" },
              example: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            },
            id: { type: "string", example: "User" },
            name: { type: "string", example: "User" },
            endpoint: { type: "string", example: "/Users" },
            description: { type: "string" },
            schema: { type: "string", example: "urn:ietf:params:scim:schemas:core:2.0:User" },
            schemaExtensions: { type: "array", items: { type: "object" } },
            meta: { type: "object" },
          },
        },
        SamlConfigForm: {
          type: "object",
          properties: {
            configId: { type: "integer" },
            displayName: { type: "string" },
            idpMetadataUrl: { type: "string" },
            idpMetadataXml: { type: "string" },
            spEntityId: { type: "string" },
            ssoUrl: { type: "string" },
            x509Certificate: { type: "string" },
            nameIdFormat: { type: "string" },
            mapEmailClaim: { type: "string" },
            mapFirstNameClaim: { type: "string" },
            mapLastNameClaim: { type: "string" },
          },
        },
      },
    },
    paths: {
      "/": {
        get: {
          tags: ["Auth"],
          summary: "Render login page",
          responses: { 200: { description: "Login page" } },
        },
      },
      "/callback": {
        get: {
          tags: ["Auth"],
          summary: "OIDC authorization-code callback",
          parameters: [{ name: "code", in: "query", required: true, schema: { type: "string" } }],
          responses: {
            302: { description: "Redirects to a dashboard" },
            400: { description: "Missing authorization code" },
            500: { description: "Token exchange failed" },
          },
        },
      },
      "/logout": {
        get: {
          tags: ["Auth"],
          summary: "Destroy local session and redirect to logout",
          responses: { 302: { description: "Redirect" } },
        },
      },
      "/saml/login": {
        get: {
          tags: ["SAML"],
          summary: "Start SAML login",
          responses: { 302: { description: "Redirect to IdP" } },
        },
        post: {
          tags: ["SAML"],
          summary: "Start SAML login or submit a SAML response",
          responses: { 302: { description: "Redirect" } },
        },
      },
      "/saml/acs": {
        post: {
          tags: ["SAML"],
          summary: "SAML assertion consumer service",
          requestBody: {
            content: {
              "application/x-www-form-urlencoded": {
                schema: {
                  type: "object",
                  properties: { SAMLResponse: { type: "string" } },
                },
              },
            },
          },
          responses: {
            302: { description: "Redirect to authorized dashboard" },
            401: { description: "SAML authentication failed" },
            403: { description: "User is not authorized" },
          },
        },
      },
      "/saml/metadata": {
        get: {
          tags: ["SAML"],
          summary: "Return SAML service provider metadata",
          responses: {
            200: {
              description: "SP metadata XML",
              content: { "application/xml": { schema: { type: "string" } } },
            },
          },
        },
      },
      "/dashboard": {
        get: {
          tags: ["Banking"],
          summary: "Render customer dashboard",
          security: [{ SessionCookie: [] }],
          parameters: [{ name: "user", in: "query", schema: { type: "string" } }],
          responses: {
            200: { description: "Dashboard page" },
            302: { description: "Redirect to role-appropriate dashboard" },
            403: { description: "Unauthorized" },
          },
        },
      },
      "/transfer": {
        post: {
          tags: ["Banking"],
          summary: "Create a money transfer",
          security: [{ SessionCookie: [] }],
          requestBody: {
            required: true,
            content: { "application/json": { schema: { $ref: "#/components/schemas/TransferRequest" } } },
          },
          responses: {
            200: {
              description: "Transfer completed",
              content: { "application/json": { schema: { $ref: "#/components/schemas/TransferResponse" } } },
            },
            400: { description: "Invalid input or insufficient funds" },
            401: { description: "Login required" },
            403: { description: "Unauthorized or consent required" },
          },
        },
      },
      "/authorize-transfer": {
        get: {
          tags: ["Banking"],
          summary: "Request UMA/consent authorization for transfer",
          parameters: [
            { name: "to", in: "query", schema: { type: "string" } },
            { name: "amount", in: "query", schema: { type: "number" } },
          ],
          responses: {
            302: { description: "Redirect to authorization flow" },
            403: { description: "Unauthorized" },
          },
        },
      },
      "/resume-transfer": {
        get: {
          tags: ["Banking"],
          summary: "Resume a transfer after consent",
          security: [{ SessionCookie: [] }],
          responses: {
            302: { description: "Redirect to dashboard or success page" },
            403: { description: "Unauthorized" },
          },
        },
      },
      "/transfer-success": {
        get: {
          tags: ["Banking"],
          summary: "Render transfer success page",
          security: [{ SessionCookie: [] }],
          responses: { 200: { description: "Transfer success page" } },
        },
      },
      "/teller": {
        get: {
          tags: ["Teller"],
          summary: "Render teller dashboard",
          security: [{ SessionCookie: [] }],
          responses: { 200: { description: "Teller dashboard" } },
        },
      },
      "/teller/export": {
        get: {
          tags: ["Teller"],
          summary: "Export Keycloak users and roles",
          security: [{ SessionCookie: [] }],
          parameters: [{ name: "format", in: "query", schema: { type: "string", enum: ["json", "csv"] } }],
          responses: {
            200: { description: "User export" },
            500: { description: "Export failed" },
          },
        },
      },
      "/admin/dashboard": {
        get: {
          tags: ["Admin"],
          summary: "Render admin dashboard",
          security: [{ SessionCookie: [] }],
          parameters: [{ name: "configId", in: "query", schema: { type: "integer" } }],
          responses: {
            200: { description: "Admin dashboard" },
            403: { description: "Unauthorized" },
          },
        },
      },
      "/admin/saml": {
        post: {
          tags: ["Admin"],
          summary: "Create or update SAML configuration",
          security: [{ SessionCookie: [] }],
          requestBody: {
            content: {
              "application/x-www-form-urlencoded": { schema: { $ref: "#/components/schemas/SamlConfigForm" } },
            },
          },
          responses: {
            302: { description: "Saved and redirected" },
            400: { description: "Invalid SAML configuration" },
            403: { description: "Unauthorized" },
          },
        },
      },
      "/admin/saml/new": {
        post: {
          tags: ["Admin"],
          summary: "Create a blank SAML configuration",
          security: [{ SessionCookie: [] }],
          responses: { 302: { description: "Redirect to new config" }, 403: { description: "Unauthorized" } },
        },
      },
      "/admin/saml/{id}/use": {
        post: {
          tags: ["Admin"],
          summary: "Set active SAML configuration",
          security: [{ SessionCookie: [] }],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
          responses: { 302: { description: "Redirect" }, 400: { description: "Invalid id" }, 403: { description: "Unauthorized" } },
        },
      },
      "/admin/saml/{id}/toggle": {
        post: {
          tags: ["Admin"],
          summary: "Enable or disable SAML configuration",
          security: [{ SessionCookie: [] }],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
          requestBody: {
            content: {
              "application/x-www-form-urlencoded": {
                schema: {
                  type: "object",
                  properties: { action: { type: "string", enum: ["enable", "disable"] } },
                },
              },
            },
          },
          responses: { 302: { description: "Redirect" }, 400: { description: "Invalid request" }, 403: { description: "Unauthorized" } },
        },
      },
      "/scim/v2/Schemas": {
        get: {
          tags: ["SCIM Metadata"],
          summary: "List supported SCIM schemas",
          security: [{ ScimBearerAuth: [] }],
          responses: {
            200: {
              description: "SCIM schema list",
              content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimListResponse" } } },
            },
          },
        },
      },
      "/scim/v2/Schemas/{id}": {
        get: {
          tags: ["SCIM Metadata"],
          summary: "Get a SCIM schema",
          security: [{ ScimBearerAuth: [] }],
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "string" },
              example: "urn:ietf:params:scim:schemas:core:2.0:User",
            },
          ],
          responses: {
            200: {
              description: "SCIM schema",
              content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimSchemaResource" } } },
            },
            404: { description: "Schema not found" },
          },
        },
      },
      "/scim/v2/ResourceTypes": {
        get: {
          tags: ["SCIM Metadata"],
          summary: "List supported SCIM resource types",
          security: [{ ScimBearerAuth: [] }],
          responses: {
            200: {
              description: "SCIM resource type list",
              content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimListResponse" } } },
            },
          },
        },
      },
      "/scim/v2/ResourceTypes/{id}": {
        get: {
          tags: ["SCIM Metadata"],
          summary: "Get a SCIM resource type",
          security: [{ ScimBearerAuth: [] }],
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "string", enum: ["User", "Group"] },
            },
          ],
          responses: {
            200: {
              description: "SCIM resource type",
              content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimResourceType" } } },
            },
            404: { description: "ResourceType not found" },
          },
        },
      },
      "/scim/v2/Users": {
        get: {
          tags: ["SCIM Users"],
          summary: "List SCIM users",
          security: [{ ScimBearerAuth: [] }],
          parameters: [
            { name: "filter", in: "query", schema: { type: "string", example: 'userName eq "alice"' } },
            { name: "startIndex", in: "query", schema: { type: "integer", default: 1 } },
            { name: "count", in: "query", schema: { type: "integer", default: 100 } },
          ],
          responses: {
            200: { description: "SCIM list response", content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimListResponse" } } } },
            400: { description: "Invalid filter", content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimError" } } } },
          },
        },
        post: {
          tags: ["SCIM Users"],
          summary: "Create SCIM user",
          security: [{ ScimBearerAuth: [] }],
          requestBody: {
            required: true,
            content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimUser" } } },
          },
          responses: {
            201: { description: "Created", content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimUser" } } } },
            400: { description: "Invalid user" },
            409: { description: "User already exists" },
          },
        },
      },
      "/scim/v2/Users/{id}": {
        get: {
          tags: ["SCIM Users"],
          summary: "Get SCIM user",
          security: [{ ScimBearerAuth: [] }],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          responses: {
            200: { description: "SCIM user", content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimUser" } } } },
            404: { description: "Not found" },
          },
        },
        put: {
          tags: ["SCIM Users"],
          summary: "Replace SCIM user",
          description: "Full user update used by SCIM clients such as Okta.",
          security: [{ ScimBearerAuth: [] }],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          requestBody: {
            required: true,
            content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimUser" } } },
          },
          responses: {
            200: { description: "Updated user", content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimUser" } } } },
            400: { description: "Invalid user" },
            404: { description: "Not found" },
          },
        },
        patch: {
          tags: ["SCIM Users"],
          summary: "Patch SCIM user",
          security: [{ ScimBearerAuth: [] }],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          requestBody: {
            required: true,
            content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimPatch" } } },
          },
          responses: {
            200: { description: "Updated user", content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimUser" } } } },
            400: { description: "Invalid patch" },
            404: { description: "Not found" },
          },
        },
        delete: {
          tags: ["SCIM Users"],
          summary: "Delete SCIM user",
          security: [{ ScimBearerAuth: [] }],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          responses: { 204: { description: "Deleted" }, 404: { description: "Not found" } },
        },
      },
      "/scim/v2/Groups": {
        get: {
          tags: ["SCIM Groups"],
          summary: "List SCIM groups",
          security: [{ ScimBearerAuth: [] }],
          parameters: [
            { name: "filter", in: "query", schema: { type: "string", example: 'displayName eq "Tellers"' } },
            { name: "startIndex", in: "query", schema: { type: "integer", default: 1 } },
            { name: "count", in: "query", schema: { type: "integer", default: 100 } },
          ],
          responses: {
            200: { description: "SCIM list response", content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimListResponse" } } } },
          },
        },
        post: {
          tags: ["SCIM Groups"],
          summary: "Create SCIM group",
          security: [{ ScimBearerAuth: [] }],
          requestBody: {
            required: true,
            content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimGroup" } } },
          },
          responses: {
            201: { description: "Created", content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimGroup" } } } },
            400: { description: "Invalid group" },
            409: { description: "Group already exists" },
          },
        },
      },
      "/scim/v2/Groups/{id}": {
        get: {
          tags: ["SCIM Groups"],
          summary: "Get SCIM group",
          security: [{ ScimBearerAuth: [] }],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          responses: {
            200: { description: "SCIM group", content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimGroup" } } } },
            404: { description: "Not found" },
          },
        },
        patch: {
          tags: ["SCIM Groups"],
          summary: "Patch SCIM group",
          security: [{ ScimBearerAuth: [] }],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          requestBody: {
            required: true,
            content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimPatch" } } },
          },
          responses: {
            200: { description: "Updated group", content: { "application/scim+json": { schema: { $ref: "#/components/schemas/ScimGroup" } } } },
            400: { description: "Invalid patch" },
            404: { description: "Not found" },
          },
        },
        delete: {
          tags: ["SCIM Groups"],
          summary: "Delete SCIM group",
          security: [{ ScimBearerAuth: [] }],
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          responses: { 204: { description: "Deleted" }, 404: { description: "Not found" } },
        },
      },
      "/swagger.json": {
        get: {
          tags: ["Admin"],
          summary: "OpenAPI specification",
          responses: { 200: { description: "OpenAPI JSON" } },
        },
      },
      "/docs": {
        get: {
          tags: ["Admin"],
          summary: "Swagger UI",
          responses: { 200: { description: "Swagger UI page" } },
        },
      },
    },
  };
}

function swaggerJson(req, res) {
  res.json(buildOpenApi(req));
}

function swaggerUi(req, res) {
  res.type("html").send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Neobank API Docs</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      window.ui = SwaggerUIBundle({
        url: "/swagger.json",
        dom_id: "#swagger-ui",
        deepLinking: true,
        persistAuthorization: true
      });
    </script>
  </body>
</html>`);
}

module.exports = {
  swaggerJson,
  swaggerUi,
};
