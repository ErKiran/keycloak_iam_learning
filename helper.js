const jwt = require("jsonwebtoken");
const axios = require("axios");

function getUserRoles(req) {
  const token = req.session?.tokens?.access_token;
  if (!token) {
    return Array.isArray(req.session?.user?.roles) ? req.session.user.roles : [];
  }

  const decoded = jwt.decode(token);
  return decoded?.resource_access?.[process.env.KEYCLOAK_CLIENT_ID]?.roles || [];
}

function getUsername(req) {
  return req.session?.user?.username || req.session?.user?.email || null;
}


function requireLogin(req, res, next) {
  if (!req.session?.tokens?.access_token && !req.session?.user) return res.redirect("/");
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
  KEYCLOAK_REALM,
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CLIENT_SECRET,
  REDIRECT_URI,
} = process.env;

const KEYCLOAK_BASE_URL = process.env.KEYCLOAK_BASE_URL || "http://localhost:8080";
const KEYCLOAK_PUBLIC_BASE_URL = process.env.KEYCLOAK_PUBLIC_BASE_URL || KEYCLOAK_BASE_URL;

const USERLIST = "userlist:view"
const TRANSFER = "transfer:write"
const READBALANCE = "balance:read"
const ADMIN_DASHBOARD = "admin:dashboard"
const DEVCONSOLE_SETUP = "admin:developer:console"
const SAML_SETUP = "admin:sso:saml"

function canAccessAdminDashboardFromRoles(roles = []) {
  return (
    roles.includes(ADMIN_DASHBOARD) ||
    roles.includes(DEVCONSOLE_SETUP) ||
    roles.includes(SAML_SETUP) ||
    roles.includes("admin")
  );
}

function isAdminUser(req) {
  return canAccessAdminDashboardFromRoles(getUserRoles(req));
}

/**
 * Centralized dashboard redirect logic based on user roles.
 * Determines which dashboard the user should access.
 * Priority: Admin Dashboard > Teller > Customer Dashboard
 */
function getDashboardRedirect(roles = []) {
  // 1. Admin dashboard for privileged users
  if (canAccessAdminDashboardFromRoles(roles)) {
    return "/admin/dashboard";
  }
  
  // 2. Teller dashboard for users who manage other users
  if (roles.includes(USERLIST)) {
    return "/teller";
  }
  
  // 3. Customer dashboard for balance reader
  if (roles.includes(READBALANCE)) {
    return "/dashboard";
  }
  
  // 4. No suitable role
  return null;
}

const authorizeEndpoint = `${KEYCLOAK_PUBLIC_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/auth`;
const tokenEndpoint = `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`;


module.exports = {getUserRoles, requireLogin, getUsername,  KEYCLOAK_BASE_URL,
  KEYCLOAK_PUBLIC_BASE_URL,
  KEYCLOAK_REALM,
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CLIENT_SECRET,
  REDIRECT_URI,
  USERLIST,
  TRANSFER,
  READBALANCE,
  ADMIN_DASHBOARD,
  DEVCONSOLE_SETUP,
  SAML_SETUP,
  canAccessAdminDashboardFromRoles,
  isAdminUser,
  getDashboardRedirect,
  authorizeEndpoint,
  tokenEndpoint,
  umaDecision, requireUma
}
