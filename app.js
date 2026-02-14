require("dotenv").config();
const express = require("express");
const axios = require("axios");
const querystring = require("querystring");
const path =require("path");

const session = require("express-session");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true },
  })
);

// ✅ EJS setup
app.set("view engine", "ejs");
app.set("views", path.join(process.cwd(), "views"));

const {
  PORT,
  KEYCLOAK_BASE_URL,
  KEYCLOAK_REALM,
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CLIENT_SECRET,
  REDIRECT_URI,
} = process.env;

const authorizeEndpoint = `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/auth`;
const tokenEndpoint = `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`;


// ------------------------------
// 1️⃣ Visual Login Page
// ------------------------------
app.get("/", (req, res) => {
  const authUrl =
    `${authorizeEndpoint}?` +
    querystring.stringify({
      client_id: KEYCLOAK_CLIENT_ID,
      response_type: "code",
      scope: "openid profile email",
      redirect_uri: REDIRECT_URI,
    });

 res.render("login",{authUrl})
});



app.get("/authorize-transfer", (req, res) => {
  const { to, amount } = req.query;
  req.session.pendingTransfer = { to, amount };

  const authUrl =
    `${authorizeEndpoint}?` +
    querystring.stringify({
      client_id: KEYCLOAK_CLIENT_ID,
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      scope: "openid transfer:write",
      prompt: "consent",
    });

  return res.redirect(authUrl);
});




// ------------------------------
// 2️⃣ Callback (Realistic Token Request)
// ------------------------------
app.get("/callback", async (req, res) => {
  const { code } = req.query;

  if (!code) {
    return res.status(400).send("Missing authorization code");
  }

  console.log("code\t", code)

  try {
    const tokenResponse = await axios.post(
      tokenEndpoint,
      querystring.stringify({
        grant_type: "authorization_code",
        code: code,
        redirect_uri: REDIRECT_URI,
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          // Real-world: client authentication via Basic Auth header
          Authorization:
            "Basic " +
            Buffer.from(
              `${KEYCLOAK_CLIENT_ID}:${KEYCLOAK_CLIENT_SECRET}`
            ).toString("base64"),
        },
      }
    );

 const tokens = tokenResponse.data;

// Store tokens in session
req.session.tokens = tokens;

// Decode ID token just for display (not verifying signature here)
const decoded = tokens.id_token ? jwt.decode(tokens.id_token) : null;

req.session.user = {
  username: decoded?.preferred_username || decoded?.email || "user",
  name: decoded?.name || null,
  email: decoded?.email || null,
};

// Default mock balance
req.session.balance = req.session.balance ?? 1000;

// Keep old behavior if you want to debug
if (req.query.raw === "1") {
  return res.json(tokens);
}

if (req.session.pendingTransfer) {
  req.session.transferAllowed = true;
}

return res.redirect("/dashboard");

  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).send("Token exchange failed");
  }
});


app.post("/transfer", (req, res) => {
  if (!req.session?.tokens?.access_token) {
    return res.status(401).json({ error: "LOGIN_REQUIRED" });
  }

  // Consent gate (lab-style)
  if (!req.session.transferAllowed) {
    return res.status(403).json({ error: "CONSENT_REQUIRED" });
  }

  const { to, amount } = req.body || {};
  const amt = Number(amount);

  if (!to || !Number.isFinite(amt) || amt <= 0) {
    return res.status(400).json({ error: "Provide valid recipient and amount" });
  }

  const bal = Number(req.session.balance ?? 1000);
  if (amt > bal) {
    return res.status(400).json({ error: "INSUFFICIENT_FUNDS" });
  }

  const newBal = bal - amt;
  req.session.balance = newBal;

  // One-time step-up (optional): require consent again for next transfer
  req.session.transferAllowed = false;
  req.session.pendingTransfer = null;

  return res.json({
    ok: true,
    to,
    amount: amt,
    newBalance: newBal,
    note: "Mock transfer executed.",
  });
});

app.get("/consent-status", (req, res) => {
  res.json({
    loggedIn: !!req.session?.tokens?.access_token,
    transferAllowed: !!req.session.transferAllowed,
    pendingTransfer: req.session.pendingTransfer || null,
    balance: Number(req.session.balance ?? 1000),
  });
});


function requireLogin(req, res, next) {
  if (!req.session?.tokens?.access_token) return res.redirect("/");
  next();
}

app.get("/dashboard", requireLogin, (req, res) => {
  const u = req.session.user || {};
  const balance = Number(req.session.balance ?? 1000);

  res.render("dashboard", {
    userName: u.name || u.username || "user",
    balance,
  });
});


app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});


app.listen(PORT, () => {
  console.log(`App running on http://localhost:${PORT}`);
});
