const {
  getUserRoles,
  getUsername,
  canAccessAdminDashboardFromRoles,
  DEVCONSOLE_SETUP,
  SAML_SETUP,
} = require("../helper");
const {
  DEFAULT_NAME_ID_FORMAT,
  listSamlConfigs,
  getSamlConfig,
  getActiveSamlConfig,
  createSamlConfig,
  setSamlConfigEnabled,
  setActiveSamlConfig,
  saveSamlConfig: saveSamlConfigToDb,
} = require("./saml_config_store");
const {
  parseIdpMetadataXml,
  fetchAndParseIdpMetadata,
} = require("./saml_metadata");

function resolveBaseUrl(req) {
  return process.env.APP_BASE_URL || `${req.protocol}://${req.get("host")}`;
}

function canManageSamlFromRoles(roles = []) {
  return (
    roles.includes(SAML_SETUP) ||
    roles.includes(DEVCONSOLE_SETUP) ||
    roles.includes("admin")
  );
}

async function adminDashboard(req, res) {
  const roles = getUserRoles(req);

  if (!canAccessAdminDashboardFromRoles(roles)) {
    return res.status(403).render("unauthorized");
  }

  const samlConfigs = await listSamlConfigs();
  const activeSamlConfig = await getActiveSamlConfig();
  const requestedConfigId = Number(req.query.configId || 0) || null;
  const samlConfig = requestedConfigId
    ? await getSamlConfig(requestedConfigId)
    : activeSamlConfig || samlConfigs[0] || null;

  const appBaseUrl = resolveBaseUrl(req);
  const idpSetup = activeSamlConfig
    ? {
        acsUrl: `${appBaseUrl}/saml/acs`,
        metadataUrl: `${appBaseUrl}/saml/metadata`,
        startLoginUrl: `${appBaseUrl}/saml/login`,
        spEntityId: activeSamlConfig.spEntityId,
        nameIdFormat: activeSamlConfig.nameIdFormat,
        idpEntityId: activeSamlConfig.idpEntityId || "(from IdP metadata if provided)",
      }
    : null;

  return res.render("admin_dashboard", {
    userName: getUsername(req),
    roles,
    samlConfig,
    samlConfigs,
    activeConfigId: activeSamlConfig?.id || null,
    idpSetup,
    canManageSaml: canManageSamlFromRoles(roles),
    saved: req.query.saved === "1",
    saveError: req.query.err || "",
  });
}

async function saveSamlConfig(req, res) {
  const roles = getUserRoles(req);
  if (!canManageSamlFromRoles(roles)) {
    return res.status(403).render("unauthorized");
  }

  const configId = Number(req.body?.configId || 0) || null;
  const displayName = String(req.body?.displayName || "SSO Config").trim();
  let idpMetadataUrl = String(req.body?.idpMetadataUrl || "").trim();
  const idpMetadataXml = String(req.body?.idpMetadataXml || "").trim();
  const spEntityId = String(req.body?.spEntityId || "").trim();
  let ssoUrl = String(req.body?.ssoUrl || "").trim();
  let x509Certificate = String(req.body?.x509Certificate || "").trim();
  const nameIdFormat = String(req.body?.nameIdFormat || DEFAULT_NAME_ID_FORMAT).trim();
  const mapEmailClaim = String(req.body?.mapEmailClaim || "email").trim();
  const mapFirstNameClaim = String(req.body?.mapFirstNameClaim || "firstName").trim();
  const mapLastNameClaim = String(req.body?.mapLastNameClaim || "lastName").trim();
  let idpEntityId = "";
  let metadataSource = "manual";

  try {
    if (idpMetadataXml) {
      const parsed = await parseIdpMetadataXml(idpMetadataXml);
      ssoUrl = String(parsed.ssoUrl || "").trim();
      x509Certificate = String(parsed.x509Certificate || "").trim();
      idpEntityId = parsed.idpEntityId || "";
      metadataSource = "xml";

      if (!idpMetadataUrl) {
        idpMetadataUrl = "inline:xml";
      }
    } else if (idpMetadataUrl) {
      const parsed = await fetchAndParseIdpMetadata(idpMetadataUrl);
      ssoUrl = String(parsed.ssoUrl || "").trim();
      x509Certificate = String(parsed.x509Certificate || "").trim();
      idpEntityId = parsed.idpEntityId || "";
      metadataSource = "url";
    }
  } catch (err) {
    const message = encodeURIComponent(err.message || "Unable to parse metadata");
    return res.redirect(`/admin/dashboard?err=${message}`);
  }

  if (!spEntityId || !ssoUrl || !x509Certificate) {
    return res.status(400).send("Missing required SAML fields. Provide SP entity ID and valid metadata (URL/XML) or manual SSO URL + certificate.");
  }

  await saveSamlConfigToDb({
    displayName,
    idpMetadataUrl,
    metadataSource,
    idpEntityId,
    spEntityId,
    ssoUrl,
    x509Certificate,
    nameIdFormat,
    mapEmailClaim,
    mapFirstNameClaim,
    mapLastNameClaim,
  }, configId);

  return res.redirect(`/admin/dashboard?saved=1${configId ? `&configId=${configId}` : ""}`);
}

async function createNewSamlConfig(req, res) {
  const roles = getUserRoles(req);
  if (!canManageSamlFromRoles(roles)) {
    return res.status(403).render("unauthorized");
  }

  const config = await createSamlConfig();
  return res.redirect(`/admin/dashboard?configId=${config.id}`);
}

async function toggleSamlConfig(req, res) {
  const roles = getUserRoles(req);
  if (!canManageSamlFromRoles(roles)) {
    return res.status(403).render("unauthorized");
  }

  const configId = Number(req.params?.id || 0);
  const action = String(req.body?.action || "").trim();
  if (!configId || (action !== "enable" && action !== "disable")) {
    return res.status(400).send("Invalid SAML config toggle request");
  }

  await setSamlConfigEnabled(configId, action === "enable");
  return res.redirect(`/admin/dashboard?configId=${configId}`);
}

async function useSamlConfig(req, res) {
  const roles = getUserRoles(req);
  if (!canManageSamlFromRoles(roles)) {
    return res.status(403).render("unauthorized");
  }

  const configId = Number(req.params?.id || 0);
  if (!configId) {
    return res.status(400).send("Invalid SAML config id");
  }

  await setActiveSamlConfig(configId);
  return res.redirect(`/admin/dashboard?configId=${configId}`);
}

module.exports = {
  adminDashboard,
  saveSamlConfig,
  createNewSamlConfig,
  toggleSamlConfig,
  useSamlConfig,
};
