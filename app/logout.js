const {
  REDIRECT_URI,
  KEYCLOAK_REALM,
  KEYCLOAK_BASE_URL
 } = require("../helper")

function logout(req, res) {
  const idToken = req.session?.tokens?.id_token;

  req.session.destroy(() => {
    const logoutUrl =
      `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/logout` +
      `?post_logout_redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
      (idToken ? `&id_token_hint=${idToken}` : "");

    res.redirect(logoutUrl);
  });
}


module.exports = {logout}