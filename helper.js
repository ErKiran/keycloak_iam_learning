const jwt = require("jsonwebtoken");

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

const {
  KEYCLOAK_BASE_URL,
  KEYCLOAK_REALM,
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CLIENT_SECRET,
  REDIRECT_URI,
} = process.env;

const authorizeEndpoint = `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/auth`;
const tokenEndpoint = `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`;


module.exports = {getUserRoles, requireLogin, getUsername,  KEYCLOAK_BASE_URL,
  KEYCLOAK_REALM,
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CLIENT_SECRET,
  REDIRECT_URI,
  authorizeEndpoint,
  tokenEndpoint
}