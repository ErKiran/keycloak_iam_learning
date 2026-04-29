const {
    getUserRoles,
    getUsername,
    READBALANCE,
    USERLIST,
    getDashboardRedirect,
} = require("../helper");

const { getOrInitBalance } = require("./store");

function dashboard(req, res) {
    const roles = getUserRoles(req, res)
    
    // Centralized redirect: determine which dashboard user should access
    const dashboardRedirect = getDashboardRedirect(roles);
    
    // If user doesn't have any valid role, deny access
    if (!dashboardRedirect) {
        return res.status(403).render("unauthorized");
    }
    
    // If user should access a different dashboard, redirect them
    // Exception: Tellers can view customer details if a user param is provided
    if (dashboardRedirect !== "/dashboard" && !(roles.includes(USERLIST) && req.query.user)) {
        return res.redirect(dashboardRedirect);
    }

    // User is authorized for customer dashboard (or teller viewing customer details)
    const username = req.query.user || getUsername(req);
    const balance = getOrInitBalance(username);

    res.render("dashboard", {
        userName: username,
        balance,
        roles,              // pass roles into UI (optional)
        viewingUser: req.query.user || null, // optional
    });
}

module.exports = { dashboard }