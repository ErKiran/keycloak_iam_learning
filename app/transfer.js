const { getUserRoles, authorizeEndpoint, getUsername } = require("../helper");
const querystring = require("querystring")


const { getOrInitBalance, setBalance } = require("./store");

function transfer(req, res) {
  if (!req.session?.tokens?.access_token) {
    return res.status(401).json({ error: "LOGIN_REQUIRED" });
  }

  const roles = getUserRoles(req);
  if (!roles.includes("customer")) {
    return res.status(403).json({ error: "UNAUTHORIZED_ACTION" });
  }

  const { to, amount } = req.body || {};
  const amt = Number(amount);

  if (!to || !Number.isFinite(amt) || amt <= 0) {
    return res.status(400).json({ error: "INVALID_INPUT" });
  }

  // Consent gate
  if (!req.session.transferAllowed) {
    req.session.pendingTransfer = { to, amount: amt };
    return res.status(403).json({ error: "CONSENT_REQUIRED" });
  }

  const username = getUsername(req);
  if (!username) return res.status(401).json({ error: "LOGIN_REQUIRED" });

  const bal = getOrInitBalance(username);
  if (amt > bal) {
    req.session.transferAllowed = false;
    req.session.pendingTransfer = null;
    return res.status(400).json({ error: "INSUFFICIENT_FUNDS", balance: bal });
  }

  const newBal = bal - amt;

  setBalance(username, newBal);

  // one-time step-up
  req.session.transferAllowed = false;
  req.session.pendingTransfer = null;

  return res.json({ ok: true, to, amount: amt, newBalance: newBal });
}

function resumeTransfer(req, res) {
  // Must have a pending transfer and have just passed consent
  if (!req.session?.transferAllowed || !req.session?.pendingTransfer) {
    return res.redirect("/dashboard");
  }

  const roles = getUserRoles(req);
  if (!roles.includes("customer")) {
    req.session.transferAllowed = false;
    req.session.pendingTransfer = null;
    return res.status(403).render("unauthorized");
  }

  const { to, amount } = req.session.pendingTransfer;
  const amt = Number(amount);

  const bal = Number(req.session.balance ?? 1000);

  if (!to || !Number.isFinite(amt) || amt <= 0) {
    req.session.transferAllowed = false;
    req.session.pendingTransfer = null;
    return res.redirect("/dashboard");
  }

  if (amt > bal) {
    req.session.transferAllowed = false;
    req.session.pendingTransfer = null;
    return res.redirect("/dashboard?err=INSUFFICIENT_FUNDS");
  }

  const newBal = bal - amt;
  req.session.balance = newBal;

  // one-time step-up
  req.session.transferAllowed = false;
  req.session.pendingTransfer = null;

  return res.redirect(`/transfer-success?to=${to}&amount=${amt}&balance=${newBal}`)
}

function authorizeTransfer(req, res) {

  const roles = getUserRoles(req)

  // If user isn't eligible to transfer, don't even ask for consent
  if (!roles.includes("customer")) {
    return res.status(403).render("unauthorized"); // your EJS template
  }

  const { to, amount } = req.query;
  req.session.pendingTransfer = { to, amount };

  const authUrl =
    `${authorizeEndpoint}?` +
    querystring.stringify({
      client_id: process.env.KEYCLOAK_CLIENT_ID,
      response_type: "code",
      redirect_uri: process.env.REDIRECT_URI,
      scope: "openid transfer:write",
      prompt: "consent",
    });

  return res.redirect(authUrl);
};

function transferSuccess(req, res) {
  const { to, amount, balance } = req.query;

  res.render("transfer_success", {
    to: to || "recipient",
    amount: amount || "0",
    balance: balance || String(req.session.balance ?? 0),
  });
};


module.exports= {transfer, authorizeTransfer, transferSuccess, resumeTransfer}