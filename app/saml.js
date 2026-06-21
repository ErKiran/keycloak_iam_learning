const passport = require("passport");
const { Strategy: SamlStrategy } = require("@node-saml/passport-saml");
const { createHash } = require("crypto");
const {
  getDashboardRedirect,
  READBALANCE,
} = require("../helper");
const { getActiveSamlConfig } = require("./saml_config_store");
const { keycloakUserExists, getUserRolesFromKeycloak } = require("./keycloak_users");
const { certificateSummary, normalizeCertificateBundle } = require("./x509_certificate");


function getCertificateSummary(cert = "") {
  const normalizedSummary = certificateSummary(cert);
  const certs = normalizedSummary.certs;
  if (certs.length === 0) {
    return {
      present: false,
      certCount: 0,
      length: 0,
      hasBeginMarker: false,
      hasEndMarker: false,
      fingerprintSha256: "",
      fingerprints: [],
    };
  }

  const primary = certs[0];
  const primaryBody = primary
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "")
    .trim();

  const fingerprints = certs
    .map((entry) => entry
      .replace(/-----BEGIN CERTIFICATE-----/g, "")
      .replace(/-----END CERTIFICATE-----/g, "")
      .replace(/\s+/g, "")
      .trim())
    .filter(Boolean)
    .map((body) => createHash("sha256").update(body).digest("hex"));

  return {
    present: true,
    certCount: certs.length,
    length: certs.join("\n\n").length,
    hasBeginMarker: primary.includes("-----BEGIN CERTIFICATE-----"),
    hasEndMarker: primary.includes("-----END CERTIFICATE-----"),
    bodyLength: primaryBody.length,
    fingerprintSha256: fingerprints[0] || "",
    fingerprints,
    head: primary.slice(0, 40),
    tail: primary.slice(-40),
  };
}

function collectMatchValues(text, regex, max = 10) {
  const output = [];
  let match;

  while ((match = regex.exec(text)) !== null) {
    if (match[1]) output.push(match[1]);
    if (output.length >= max) break;
  }

  return output;
}

function analyzeSamlXml(xml = "") {
  if (!xml) return null;

  const signatureTagCount = (xml.match(/<(?:\w+:)?Signature\b/g) || []).length;
  const digestMethods = [...new Set(collectMatchValues(xml, /<(?:\w+:)?DigestMethod[^>]*Algorithm="([^"]+)"/gi))];
  const signatureMethods = [...new Set(collectMatchValues(xml, /<(?:\w+:)?SignatureMethod[^>]*Algorithm="([^"]+)"/gi))];
  const referenceUris = [...new Set(collectMatchValues(xml, /<(?:\w+:)?Reference[^>]*URI="([^"]+)"/gi))];
  const certSnippets = [...new Set(collectMatchValues(xml, /<(?:\w+:)?X509Certificate[^>]*>([^<]+)<\/(?:\w+:)?X509Certificate>/gi)
    .map((entry) => String(entry).replace(/\s+/g, "").slice(0, 40)))];

  return {
    xmlLength: xml.length,
    xmlSha256: createHash("sha256").update(xml).digest("hex"),
    signatureTagCount,
    hasResponseSignature: /<(?:\w+:)?Response\b(?:(?!<(?:\w+:)?Assertion\b)[\s\S])*?<(?:\w+:)?Signature\b/i.test(xml),
    hasAssertionSignature: /<(?:\w+:)?Assertion[\s\S]*?<(?:\w+:)?Signature\b/i.test(xml),
    issuer: (xml.match(/<(?:\w+:)?Issuer[^>]*>([^<]*)<\/(?:\w+:)?Issuer>/i) || [])[1] || "",
    destination: (xml.match(/Destination="([^"]*)"/i) || [])[1] || "",
    inResponseTo: (xml.match(/InResponseTo="([^"]*)"/i) || [])[1] || "",
    responseId: (xml.match(/<(?:\w+:)?Response[^>]*\sID="([^"]+)"/i) || [])[1] || "",
    assertionId: (xml.match(/<(?:\w+:)?Assertion[^>]*\sID="([^"]+)"/i) || [])[1] || "",
    digestMethods,
    signatureMethods,
    referenceUris,
    certSnippetCount: certSnippets.length,
    certSnippetPreview: certSnippets.slice(0, 3),
    statusCode: (xml.match(/<(?:\w+:)?StatusCode[^>]*Value="([^"]+)"/i) || [])[1] || "",
    nameId: (xml.match(/<(?:\w+:)?NameID[^>]*>([^<]*)<\/(?:\w+:)?NameID>/i) || [])[1] || "",
  };
}

function decodeSamlResponsePreview(samlResponse = "") {
  if (!samlResponse) return null;

  try {
    const xml = Buffer.from(String(samlResponse), "base64").toString("utf8");
    return {
      length: xml.length,
      preview: xml.slice(0, 1200),
      analysis: analyzeSamlXml(xml),
    };
  } catch (err) {
    return {
      error: err.message,
      length: String(samlResponse).length,
    };
  }
}

function resolveBaseUrl(req) {
  return process.env.APP_BASE_URL || `${req.protocol}://${req.get("host")}`;
}

function normalizeCert(cert = "") {
  return normalizeCertificateBundle(String(cert || "").replace(/\\n/g, "\n"));
}

function normalizeCerts(cert = "") {
  const normalized = normalizeCert(String(cert || ""));
  if (!normalized) return [];

  const certBlocks = normalized.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (certBlocks && certBlocks.length > 0) {
    return certBlocks.map((entry) => entry.trim()).filter(Boolean);
  }

  return [normalized];
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
  const baseUrl = resolveBaseUrl(req);
  const callbackUrl = `${baseUrl}/saml/acs`;
  const issuer = String(config.spEntityId || "").trim() || baseUrl;
  const expectedAudience =
    String(process.env.SAML_EXPECTED_AUDIENCE || "").trim() || issuer;
  const certs = normalizeCerts(config.x509Certificate);
  const idpCert = certs.length <= 1 ? (certs[0] || "") : certs;

  return new SamlStrategy(
    {
      issuer,
      audience: expectedAudience,
      callbackUrl,
      entryPoint: config.ssoUrl,
      idpCert,
      identifierFormat: config.nameIdFormat,
      validateInResponseTo: "never",
      disableRequestedAuthnContext: true,
      // Entra signs the Assertion by default, while the outer Response can be unsigned.
      wantAuthnResponseSigned: false,
      wantAssertionsSigned: true,
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
  const responsePreview = decodeSamlResponsePreview(req.body?.SAMLResponse || "");

  return withSamlStrategy(req, res, next, (strategyName, config) => {

    passport.authenticate(strategyName, { session: false }, (err, profile) => {
      if (err) {
        const isSignatureError = String(err?.message || "").toLowerCase().includes("invalid document signature");

        return next(err);
      }

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
