const { getUserRoles, getUsername } = require("../helper");

const { getOrInitBalance } = require("./store");

function dashboard(req, res) {
    const roles = getUserRoles(req, res)

    if (roles.includes("teller") && !req.query.user) {
        return res.redirect("/teller")
    }

    // allow customer + teller to view the dashboard UI
    if (!roles.includes("customer") && !roles.includes("teller")) {
        return res.status(403).render("unauthorized");
    }

    const username = getUsername(req);
    const balance = getOrInitBalance(username);

    res.render("dashboard", {
        userName: username,
        balance,
        roles,              // pass roles into UI (optional)
        viewingUser: req.query.user || null, // optional
    });
}

module.exports = { dashboard }