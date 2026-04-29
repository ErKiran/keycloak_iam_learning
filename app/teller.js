const { getUserRolesFromKeycloak, getAllKeycloakUsers } = require("./keycloak_users");

async function tellerDashboard(req, res)  {
  try {
    const users = await getAllKeycloakUsers();
    res.render("teller", { customers: users });
  } catch (err) {
    console.error("Error fetching users:", err.message);
    res.render("teller", { customers: [], error: "Failed to load users from Keycloak" });
  }
}

async function exportUsers(req, res) {
  try {
    const format = req.query.format || "json"; // 'json' or 'csv'
    const users = [];

    // Fetch all users from Keycloak
    const keycloakUsers = await getAllKeycloakUsers();

    // Fetch user data with roles
    for (const customer of keycloakUsers) {
      try {
        const roles = await getUserRolesFromKeycloak({
          username: customer.username,
          email: customer.email,
        });

        users.push({
          username: customer.username,
          email: customer.email || "",
          role: roles.length > 0 ? roles.join(", ") : "No roles assigned",
        });
      } catch (err) {
        console.error(`Error fetching roles for ${customer.username}:`, err.message);
        users.push({
          username: customer.username,
          email: customer.email || "",
          role: "Error retrieving roles",
        });
      }
    }

    if (format === "csv") {
      // Export as CSV
      const csvHeader = "Username,Email,Role\n";
      const csvRows = users
        .map((user) => `"${user.username}","${user.email}","${user.role}"`)
        .join("\n");
      const csvContent = csvHeader + csvRows;

      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", 'attachment; filename="users.csv"');
      res.send(csvContent);
    } else {
      // Export as JSON
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", 'attachment; filename="users.json"');
      res.json(users);
    }
  } catch (err) {
    console.error("Error exporting users:", err.message);
    res.status(500).json({ error: "Failed to export users", message: err.message });
  }
}

module.exports = {tellerDashboard, exportUsers}