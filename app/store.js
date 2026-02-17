// store.js
const balances = new Map();

function getOrInitBalance(username) {
    console.log("balances", balances)
  if (!balances.has(username)) {
    balances.set(username, 1000);
  }

  console.log("balances 2", balances)
  return balances.get(username);
}

function setBalance(username, value) {
  balances.set(username, value);
}

module.exports = {
  getOrInitBalance,
  setBalance,
};
