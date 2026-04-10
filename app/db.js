const fs = require("fs");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();

const dbPath = process.env.SQLITE_PATH || path.join(process.cwd(), "data", "app.db");
fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const db = new sqlite3.Database(dbPath);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(Array.isArray(rows) ? rows : []);
    });
  });
}

async function initDb() {
  await run(`
    CREATE TABLE IF NOT EXISTS saml_configs (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      config_uuid TEXT NOT NULL DEFAULT '',
      idp_metadata_url TEXT NOT NULL,
      metadata_source TEXT NOT NULL DEFAULT 'manual',
      idp_entity_id TEXT NOT NULL DEFAULT '',
      sp_entity_id TEXT NOT NULL,
      sso_url TEXT NOT NULL,
      x509_certificate TEXT NOT NULL,
      name_id_format TEXT NOT NULL,
      map_email_claim TEXT NOT NULL,
      map_first_name_claim TEXT NOT NULL,
      map_last_name_claim TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `);

  await run(
    "ALTER TABLE saml_configs ADD COLUMN metadata_source TEXT NOT NULL DEFAULT 'manual'"
  ).catch(() => null);

  await run(
    "ALTER TABLE saml_configs ADD COLUMN idp_entity_id TEXT NOT NULL DEFAULT ''"
  ).catch(() => null);

  await run(
    "ALTER TABLE saml_configs ADD COLUMN config_uuid TEXT NOT NULL DEFAULT ''"
  ).catch(() => null);

  await run(`
    CREATE TABLE IF NOT EXISTS saml_configs_multi (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      config_uuid TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL DEFAULT '',
      idp_metadata_url TEXT NOT NULL DEFAULT '',
      metadata_source TEXT NOT NULL DEFAULT 'manual',
      idp_entity_id TEXT NOT NULL DEFAULT '',
      sp_entity_id TEXT NOT NULL DEFAULT '',
      sso_url TEXT NOT NULL DEFAULT '',
      x509_certificate TEXT NOT NULL DEFAULT '',
      name_id_format TEXT NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      map_email_claim TEXT NOT NULL DEFAULT 'email',
      map_first_name_claim TEXT NOT NULL DEFAULT 'firstName',
      map_last_name_claim TEXT NOT NULL DEFAULT 'lastName',
      is_enabled INTEGER NOT NULL DEFAULT 1,
      is_active INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `);

  await run(
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_saml_configs_multi_one_active ON saml_configs_multi(is_active) WHERE is_active = 1"
  );

  await run(`
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
    SELECT
      CASE WHEN config_uuid = '' THEN lower(hex(randomblob(16))) ELSE config_uuid END,
      'Default SSO',
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
      1,
      1,
      updated_at,
      updated_at
    FROM saml_configs
    WHERE EXISTS (SELECT 1 FROM saml_configs)
      AND NOT EXISTS (SELECT 1 FROM saml_configs_multi)
  `).catch(() => null);
}

module.exports = {
  db,
  dbPath,
  run,
  get,
  all,
  initDb,
};
