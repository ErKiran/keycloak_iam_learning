const { get, run, all } = require("./db");
const { randomUUID } = require("crypto");

const DEFAULT_NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

function mapRowToConfig(row) {
  if (!row) return null;
  return {
    id: row.id,
    configUuid: row.config_uuid || null,
    displayName: row.display_name || "",
    idpMetadataUrl: row.idp_metadata_url,
    metadataSource: row.metadata_source,
    idpEntityId: row.idp_entity_id,
    spEntityId: row.sp_entity_id,
    ssoUrl: row.sso_url,
    x509Certificate: row.x509_certificate,
    nameIdFormat: row.name_id_format,
    mapEmailClaim: row.map_email_claim,
    mapFirstNameClaim: row.map_first_name_claim,
    mapLastNameClaim: row.map_last_name_claim,
    isEnabled: row.is_enabled === 1,
    isActive: row.is_active === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

async function listSamlConfigs() {
  const rows = await all("SELECT * FROM saml_configs_multi ORDER BY is_active DESC, updated_at DESC");
  return rows.map(mapRowToConfig);
}

async function getSamlConfig(configId) {
  if (configId) {
    const row = await get("SELECT * FROM saml_configs_multi WHERE id = ?", [configId]);
    return mapRowToConfig(row);
  }

  const row = await get("SELECT * FROM saml_configs_multi WHERE is_active = 1 AND is_enabled = 1 LIMIT 1");
  if (row) return mapRowToConfig(row);

  const fallback = await get("SELECT * FROM saml_configs_multi ORDER BY updated_at DESC LIMIT 1");
  return mapRowToConfig(fallback);
}

async function getActiveSamlConfig() {
  const row = await get("SELECT * FROM saml_configs_multi WHERE is_active = 1 AND is_enabled = 1 LIMIT 1");
  return mapRowToConfig(row);
}

async function createSamlConfig() {
  const now = new Date().toISOString();
  const configUuid = randomUUID();

  const result = await run(
    `
      INSERT INTO saml_configs_multi (
        config_uuid,
        display_name,
        is_enabled,
        is_active,
        created_at,
        updated_at
      )
      VALUES (?, ?, 1, 0, ?, ?)
    `,
    [
      configUuid,
      `SSO Config ${new Date().toLocaleString()}`,
      now,
      now,
    ]
  );

  return getSamlConfig(result.lastID);
}

async function saveSamlConfig(config, configId) {
  const now = new Date().toISOString();

  if (configId) {
    await run(
      `
        UPDATE saml_configs_multi
        SET
          display_name = ?,
          idp_metadata_url = ?,
          metadata_source = ?,
          idp_entity_id = ?,
          sp_entity_id = ?,
          sso_url = ?,
          x509_certificate = ?,
          name_id_format = ?,
          map_email_claim = ?,
          map_first_name_claim = ?,
          map_last_name_claim = ?,
          updated_at = ?
        WHERE id = ?
      `,
      [
        String(config.displayName || "SSO Config").trim(),
        String(config.idpMetadataUrl || "").trim(),
        String(config.metadataSource || "manual").trim(),
        String(config.idpEntityId || "").trim(),
        String(config.spEntityId || "").trim(),
        String(config.ssoUrl || "").trim(),
        String(config.x509Certificate || "").trim(),
        String(config.nameIdFormat || DEFAULT_NAME_ID_FORMAT).trim(),
        String(config.mapEmailClaim || "email").trim(),
        String(config.mapFirstNameClaim || "firstName").trim(),
        String(config.mapLastNameClaim || "lastName").trim(),
        now,
        configId,
      ]
    );

    return getSamlConfig(configId);
  }

  const configUuid = randomUUID();
  const countRow = await get("SELECT COUNT(*) AS total FROM saml_configs_multi");
  const isFirst = Number(countRow?.total || 0) === 0 ? 1 : 0;

  const result = await run(
    `
      INSERT INTO saml_configs_multi (
        config_uuid,
        display_name,
        idp_metadata_url,
        metadata_source,
        idp_entity_id,
        sp_entity_id,
        sso_url,
        x509_certificate,
        name_id_format,
        map_email_claim,
        map_first_name_claim,
        map_last_name_claim,
        is_enabled,
        is_active,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
    `,
    [
      configUuid,
      String(config.displayName || "SSO Config").trim(),
      String(config.idpMetadataUrl || "").trim(),
      String(config.metadataSource || "manual").trim(),
      String(config.idpEntityId || "").trim(),
      String(config.spEntityId || "").trim(),
      String(config.ssoUrl || "").trim(),
      String(config.x509Certificate || "").trim(),
      String(config.nameIdFormat || DEFAULT_NAME_ID_FORMAT).trim(),
      String(config.mapEmailClaim || "email").trim(),
      String(config.mapFirstNameClaim || "firstName").trim(),
      String(config.mapLastNameClaim || "lastName").trim(),
      isFirst,
      now,
      now,
    ]
  );

  return getSamlConfig(result.lastID);
}

async function setSamlConfigEnabled(configId, enabled) {
  await run("UPDATE saml_configs_multi SET is_enabled = ?, updated_at = ? WHERE id = ?", [
    enabled ? 1 : 0,
    new Date().toISOString(),
    configId,
  ]);

  if (!enabled) {
    await run("UPDATE saml_configs_multi SET is_active = 0 WHERE id = ?", [configId]);
  }

  return getSamlConfig(configId);
}

async function setActiveSamlConfig(configId) {
  await run("UPDATE saml_configs_multi SET is_active = 0");
  await run("UPDATE saml_configs_multi SET is_active = 1, is_enabled = 1, updated_at = ? WHERE id = ?", [
    new Date().toISOString(),
    configId,
  ]);

  return getSamlConfig(configId);
}

module.exports = {
  DEFAULT_NAME_ID_FORMAT,
  listSamlConfigs,
  getSamlConfig,
  getActiveSamlConfig,
  createSamlConfig,
  setSamlConfigEnabled,
  setActiveSamlConfig,
  saveSamlConfig,
};
