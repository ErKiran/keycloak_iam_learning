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

function normalizeUploadedCertificate(file) {
  if (!file?.buffer || !file.buffer.length) return "";

  const text = file.buffer.toString("utf8").trim();
  if (text.includes("-----BEGIN CERTIFICATE-----")) {
    return text;
  }

  const normalized = text.replace(/\s+/g, "");
  if (normalized && /^[A-Za-z0-9+/=]+$/.test(normalized)) {
    return [
      "-----BEGIN CERTIFICATE-----",
      ...(normalized.match(/.{1,64}/g) || []),
      "-----END CERTIFICATE-----",
    ].join("\n");
  }

  const base64 = file.buffer.toString("base64");
  return [
    "-----BEGIN CERTIFICATE-----",
    ...(base64.match(/.{1,64}/g) || []),
    "-----END CERTIFICATE-----",
  ].join("\n");
}

function isSamlDebugEnabled() {
  return String(process.env.SAML_DEBUG || "").toLowerCase() === "true";
}

function samlDebug(step, details = {}) {
  if (!isSamlDebugEnabled()) return;
  console.log(`[SAML DEBUG] ${step}`, details);
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
  const uploadedCertificate = normalizeUploadedCertificate(req.file);
  const nameIdFormat = String(req.body?.nameIdFormat || DEFAULT_NAME_ID_FORMAT).trim();
  const mapEmailClaim = String(req.body?.mapEmailClaim || "email").trim();
  const mapFirstNameClaim = String(req.body?.mapFirstNameClaim || "firstName").trim();
  const mapLastNameClaim = String(req.body?.mapLastNameClaim || "lastName").trim();
  let idpEntityId = "";
  let metadataSource = "manual";

  if (uploadedCertificate) {
    samlDebug("step 2 uploaded certificate received", {
      fileName: req.file?.originalname || "",
      mimeType: req.file?.mimetype || "",
      size: req.file?.size || 0,
      normalizedLength: uploadedCertificate.length,
    });
    x509Certificate = uploadedCertificate;
  }

  try {
    if (idpMetadataXml) {
      samlDebug("step 3 parse metadata xml", {
        source: "xml",
        xmlLength: idpMetadataXml.length,
      });
      const parsed = await parseIdpMetadataXml(idpMetadataXml);
      ssoUrl = String(parsed.ssoUrl || "").trim();
      x509Certificate = String(parsed.x509Certificate || "").trim();
      idpEntityId = parsed.idpEntityId || "";
      metadataSource = "xml";

      if (!idpMetadataUrl) {
        idpMetadataUrl = "inline:xml";
      }
    } else if (idpMetadataUrl) {
      samlDebug("step 3 fetch metadata url", {
        source: "url",
        idpMetadataUrl,
      });
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
    samlDebug("step 4 validation failed", {
      spEntityIdPresent: Boolean(spEntityId),
      ssoUrlPresent: Boolean(ssoUrl),
      x509CertificatePresent: Boolean(x509Certificate),
      uploadedFilePresent: Boolean(req.file),
      idpMetadataUrl,
      metadataSource,
    });
    return res.status(400).send("Missing required SAML fields. Provide SP entity ID and valid metadata (URL/XML), a certificate upload, or manual SSO URL + certificate.");
  }

  samlDebug("step 5 save config", {
    configId,
    displayName,
    idpMetadataUrl,
    metadataSource,
    idpEntityId,
    spEntityId,
    ssoUrl,
    x509CertificateLength: x509Certificate.length,
    uploadedFilePresent: Boolean(req.file),
  });

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
