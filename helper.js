const jwt = require("jsonwebtoken");
const axios = require("axios");

function getUserRoles(req) {
  const token = req.session?.tokens?.access_token;
  if (!token) return [];

  const decoded = jwt.decode(token);
  return decoded?.resource_access?.[process.env.KEYCLOAK_CLIENT_ID]?.roles || [];
}

function getUsername(req) {
  return req.session?.user?.username || req.session?.user?.email || null;
}


function requireLogin(req, res, next) {
  if (!req.session?.tokens?.access_token) return res.redirect("/");
  next();
}

async function umaDecision(req, resource, scope) {
  const accessToken = req.session?.tokens?.access_token;
  if (!accessToken) return false;

  const audience = process.env.KEYCLOAK_RESOURCE_SERVER_ID; // bank-api
  const permission = `${resource}#${scope}`;

  try {
    const body = new URLSearchParams();
    body.set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket");
    body.set("audience", audience);
    body.set("response_mode", "decision");
    body.set("permission", permission);

    const resp = await axios.post(tokenEndpoint, body.toString(), {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Bearer ${accessToken}`,
      },
    });

    // decision mode => { result: true }
    return resp.data?.result === true;
  } catch (e) {
    // if not authorized, Keycloak typically returns 403 / access_denied
    return false;
  }
}

function requireUma(resource, scope) {
  return async (req, res, next) => {
    const ok = await umaDecision(req, resource, scope);
    if (!ok) return res.status(403).render("unauthorized");
    next();
  };
}


const {
  KEYCLOAK_BASE_URL,
  KEYCLOAK_REALM,
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CLIENT_SECRET,
  REDIRECT_URI,
} = process.env;

const USERLIST = "userlist:view"
const TRANSFER = "transfer:write"
const READBALANCE = "balance:read"

const authorizeEndpoint = `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/auth`;
const tokenEndpoint = `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`;


module.exports = {getUserRoles, requireLogin, getUsername,  KEYCLOAK_BASE_URL,
  KEYCLOAK_REALM,
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CLIENT_SECRET,
  REDIRECT_URI,
  USERLIST,
  TRANSFER,
  READBALANCE,
  authorizeEndpoint,
  tokenEndpoint,
  umaDecision, requireUma
}