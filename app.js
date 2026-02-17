require("dotenv").config();
const express = require("express");
const path = require("path");

const session = require("express-session");
const { transfer, authorizeTransfer, transferSuccess, resumeTransfer } = require("./app/transfer");
const { dashboard } = require("./app/dashboard");
const {tellerDashboard, tellerViewCustomer} = require("./app/teller")
const { requireLogin } = require("./helper");
const { login, callback } = require("./app/login");
const { logout } = require("./app/logout");

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
} = process.env;

app.get("/", login);
app.post('/transfer', transfer)
app.get("/callback", callback);

app.get("/authorize-transfer", authorizeTransfer)

app.get("/callback", callback);

app.get("/dashboard", requireLogin, dashboard)

app.get("/teller", requireLogin, tellerDashboard);

app.get("/teller/users/:username", requireLogin, tellerViewCustomer);

app.get("/logout", logout);

app.get("/resume-transfer", requireLogin, resumeTransfer)

app.get("/transfer-success", requireLogin, transferSuccess);

app.listen(PORT, () => {
  console.log(`App running on http://localhost:${PORT}`);
});
