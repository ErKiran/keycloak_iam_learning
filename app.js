require("dotenv").config();
const express = require("express");
const path = require("path");
const passport = require("passport");
const multer = require("multer");

const session = require("express-session");
const { transfer, authorizeTransfer, transferSuccess, resumeTransfer } = require("./app/transfer");
const { dashboard } = require("./app/dashboard");
const {
  adminDashboard,
  saveSamlConfig,
  createNewSamlConfig,
  toggleSamlConfig,
  useSamlConfig,
} = require("./app/admin");
const { samlLogin, samlLoginPost, samlAcs, samlMetadata } = require("./app/saml");
const { initDb } = require("./app/db");
const {tellerDashboard, exportUsers} = require("./app/teller")
const { requireLogin } = require("./helper");
const { login, callback } = require("./app/login");
const { logout } = require("./app/logout");
const scimUsers = require("./app/scim_users");
const scimGroups = require("./app/scim_groups");
const scimMetadata = require("./app/scim_metadata");
const { swaggerJson, swaggerUi } = require("./app/swagger");
const ssf = require("./app/ssf");

const app = express();
const upload = multer({ storage: multer.memoryStorage() });
app.use(express.json({
  type:["application/json", "application/scim+json"]
}));
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true },
  })
);
app.use(passport.initialize());

// ✅ EJS setup
app.set("view engine", "ejs");
app.set("views", path.join(process.cwd(), "views"));

const PORT = process.env.PORT || 3000;

app.get("/", login);
app.get("/docs", swaggerUi);
app.get("/swagger.json", swaggerJson);
app.use(ssf);
app.get("/saml/login", samlLogin);
app.post("/saml/login", samlLoginPost);
app.post("/saml/acs", samlAcs);
app.get("/saml/metadata", samlMetadata);
app.use("/scim/v2", scimMetadata);
app.use("/scim/v2", scimUsers);
app.use("/scim/v2", scimGroups);
app.post('/transfer', transfer)
app.get("/callback", callback);

app.get("/authorize-transfer", authorizeTransfer)

app.get("/callback", callback);

app.get("/dashboard", requireLogin, dashboard)
app.get("/admin/dashboard", requireLogin, adminDashboard)
app.post("/admin/saml", requireLogin, upload.single("x509CertificateFile"), saveSamlConfig)
app.post("/admin/saml/new", requireLogin, createNewSamlConfig)
app.post("/admin/saml/:id/use", requireLogin, useSamlConfig)
app.post("/admin/saml/:id/toggle", requireLogin, toggleSamlConfig)

app.get("/teller", requireLogin, tellerDashboard);

app.get("/teller/export", requireLogin, exportUsers);

app.get("/logout", logout);

app.get("/resume-transfer", requireLogin, resumeTransfer)

app.get("/transfer-success", requireLogin, transferSuccess);

app.use((err, req, res, next) => {
  const debugValue = String(process.env.SAML_DEBUG || "").toLowerCase();
  const samlDebugEnabled =
    debugValue === "true" ||
    debugValue === "1" ||
    debugValue === "yes" ||
    (!debugValue && String(process.env.NODE_ENV || "").toLowerCase() !== "production");

  if (samlDebugEnabled && req?.originalUrl?.startsWith("/saml")) {
    console.error("[SAML DEBUG] unhandled error", {
      method: req.method,
      path: req.originalUrl,
      host: req.get("host"),
      message: err?.message || String(err),
      stack: err?.stack || "",
      bodyKeys: Object.keys(req.body || {}),
      hasSamlResponse: Boolean(req.body?.SAMLResponse),
      relayState: req.body?.RelayState || "",
    });
  }

  if (res.headersSent) return next(err);
  return res.status(500).send("Internal Server Error");
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`App running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Failed to initialize SQLite:", err.message);
    process.exit(1);
  });
