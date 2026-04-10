const passport = require("passport");
const { Strategy: SamlStrategy } = require("@node-saml/passport-saml");
const {
  getDashboardRedirect,
  READBALANCE,
} = require("../helper");
const { getActiveSamlConfig } = require("./saml_config_store");
const { keycloakUserExists, getUserRolesFromKeycloak } = require("./keycloak_users");

function resolveBaseUrl(req) {
  return process.env.APP_BASE_URL || `${req.protocol}://${req.get("host")}`;
}

function normalizeCert(cert = "") {
  return cert.replace(/\\n/g, "\n").trim();
}

function toArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function parseRoleList(value) {
  return toArray(value)
    .flatMap((entry) => String(entry || "").split(","))
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function getProfileValue(profile, key, fallback = "") {
  const raw = profile?.[key];
  if (raw === undefined || raw === null) return fallback;
  if (Array.isArray(raw)) return raw[0] || fallback;
  return raw;
}

function buildUserFromSamlProfile(profile, config) {
  const email = getProfileValue(profile, config.mapEmailClaim, "") || getProfileValue(profile, "email", "");
  const firstName = getProfileValue(profile, config.mapFirstNameClaim, "") || getProfileValue(profile, "givenName", "");
  const lastName = getProfileValue(profile, config.mapLastNameClaim, "") || getProfileValue(profile, "sn", "");

  const roles = [
    ...parseRoleList(profile?.roles),
    ...parseRoleList(profile?.role),
    ...parseRoleList(profile?.groups),
    ...parseRoleList(profile?.memberOf),
  ];

  const uniqueRoles = [...new Set(roles)];

  return {
    username: profile?.nameID || email || "saml-user",
    name: [firstName, lastName].filter(Boolean).join(" ") || null,
    email: email || null,
    roles: uniqueRoles,
    authMethod: "saml",
  };
}

function createSamlStrategy(req, config) {
  const callbackUrl = `${resolveBaseUrl(req)}/saml/acs`;
  const expectedAudience =
    String(process.env.SAML_EXPECTED_AUDIENCE || "").trim() || resolveBaseUrl(req);
  const issuer = String(config.spEntityId || "").trim() || expectedAudience;
  const cert = normalizeCert(config.x509Certificate);

  return new SamlStrategy(
    {
      issuer,
      audience: expectedAudience,
      callbackUrl,
      entryPoint: config.ssoUrl,
      idpCert: cert,
      identifierFormat: config.nameIdFormat,
      validateInResponseTo: "never",
      disableRequestedAuthnContext: true,
      acceptedClockSkewMs: 5000,
      signatureAlgorithm: "sha256",
      digestAlgorithm: "sha256",
    },
    (profile, done) => done(null, profile)
  );
}

async function withSamlStrategy(req, res, next, callback, options = {}) {
  const onMissingConfig = options.onMissingConfig;

  try {
    const config = await getActiveSamlConfig();

    if (!config) {
      if (typeof onMissingConfig === "function") {
        return onMissingConfig();
      }
      return res.status(404).send("No active SSO configuration is enabled.");
    }

    if (!config.ssoUrl || !config.spEntityId || !config.x509Certificate) {
      if (typeof onMissingConfig === "function") {
        return onMissingConfig();
      }
      return res.status(400).send("SAML config is incomplete. ssoUrl, spEntityId, and x509Certificate are required.");
    }

    const strategyName = "saml-dynamic";
    passport.use(strategyName, createSamlStrategy(req, config));
    return callback(strategyName, config);
  } catch (err) {
    return next(err);
  }
}

function samlLogin(req, res, next) {
  return withSamlStrategy(
    req,
    res,
    next,
    (strategyName) => passport.authenticate(strategyName, { session: false })(req, res, next),
    { onMissingConfig: () => res.redirect("/") }
  );
}

function samlLoginPost(req, res, next) {
  if (req.body?.SAMLResponse) {
    return samlAcs(req, res, next);
  }
  return samlLogin(req, res, next);
}

function samlAcs(req, res, next) {
  return withSamlStrategy(req, res, next, (strategyName, config) => {
    passport.authenticate(strategyName, { session: false }, (err, profile) => {
      if (err) return next(err);
      if (!profile) return res.status(401).send("SAML authentication failed");

      const user = buildUserFromSamlProfile(profile, config);

      console.log("SAML user authenticated:", user);

      (async () => {
        const exists = await keycloakUserExists({
          username: user.username,
          email: user.email,
        });

        if (!exists) {
          return res.status(403).send("SAML user does not exist in Keycloak realm");
        }

        let keycloakRoles = [];
        try {
          keycloakRoles = await getUserRolesFromKeycloak({
            username: user.username,
            email: user.email,
          });
        } catch (roleErr) {
          console.error("Warning: Could not fetch Keycloak roles:", roleErr.message);
        }

        req.session.user = user;
        req.session.tokens = null;
        req.session.balance = req.session.balance ?? 1000;

        if (keycloakRoles && keycloakRoles.length > 0) {
          req.session.user.roles = keycloakRoles;
        } else if (!Array.isArray(req.session.user.roles) || req.session.user.roles.length === 0) {
          req.session.user.roles = [READBALANCE];
        }

        const redirectUrl = getDashboardRedirect(req.session.user.roles);
        if (!redirectUrl) {
          return res.status(403).send("SAML user does not have any valid roles");
        }

        return res.redirect(redirectUrl);
      })().catch((lookupErr) => {
        console.error("Keycloak user lookup failed:", lookupErr.message);
        return res.status(503).send("Unable to validate SAML user against Keycloak");
      });
    })(req, res, next);
  });
}

function samlMetadata(req, res, next) {
  return withSamlStrategy(req, res, next, (strategyName) => {
    const strategy = passport._strategy(strategyName);
    if (!strategy) return res.status(500).send("SAML strategy could not be initialized");

    const xml = strategy.generateServiceProviderMetadata();
    res.type("application/xml").send(xml);
  });
}

module.exports = {
  samlLogin,
  samlLoginPost,
  samlAcs,
  samlMetadata,
};
