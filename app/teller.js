// Mock customer directory for demo purposes (you can expand)
const MOCK_CUSTOMERS = [
  { username: "alice", name: "Alice Carter" },
  { username: "bob", name: "Bob Miller" },
  { username: "charlie", name: "Charlie Singh" },
];

function tellerDashboard(req, res)  {
  res.render("teller", { customers: MOCK_CUSTOMERS });
}

function tellerViewCustomer(req, res) {
  const user = MOCK_CUSTOMERS.find(u => u.username === req.params.username);
  if (!user) return res.status(404).send("User not found");

  res.render("teller_user", { user });
}

module.exports = {tellerDashboard, tellerViewCustomer}