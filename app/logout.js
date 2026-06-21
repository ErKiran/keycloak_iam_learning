const {
  KEYCLOAK_REALM,
  KEYCLOAK_PUBLIC_BASE_URL,
  KEYCLOAK_CLIENT_ID
 } = require("../helper")

function logout(req, res) {
  const idToken = req.session?.tokens?.id_token;
  const appBaseUrl = (process.env.APP_BASE_URL || `${req.protocol}://${req.get("host")}`).replace(/\/$/, "");
  const returnTo = `${appBaseUrl}/`;
  const cookieName = process.env.SESSION_COOKIE_NAME || "connect.sid";

  const params = new URLSearchParams({
    client_id: KEYCLOAK_CLIENT_ID,
    post_logout_redirect_uri: returnTo,
  });

  if (idToken) {
    params.set("id_token_hint", idToken);
  }

  const logoutUrl =
    `${KEYCLOAK_PUBLIC_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/logout?${params.toString()}`;

  res.clearCookie(cookieName, {
    path: "/",
    httpOnly: true,
  });

  if (!req.session) {
    return res.redirect(logoutUrl);
  }

  req.session.destroy(() => {
    res.redirect(logoutUrl);
  });
}


module.exports = {logout}
