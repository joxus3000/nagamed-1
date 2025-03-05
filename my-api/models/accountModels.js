const db = require("../config/db");

exports.createAccount = async (email, hashedPassword, role) => {
  const [result] = await db.query(
    "INSERT INTO Account (email, password, role) VALUES (?, ?, ?)",
    [email, hashedPassword, role]
  );
  return result.insertId;
};

exports.findAccountByEmail = async (email) => {
  const [users] = await db.query("SELECT * FROM Account WHERE email = ?", [email]);
  return users.length ? users[0] : null;
};

exports.updatePassword = async (email, hashedPassword) => {
  const [result] = await db.query(
    "UPDATE Account SET password = ? WHERE email = ?",
    [hashedPassword, email]
  );
  return result.affectedRows;
};

exports.getAllUsers = async () => {
  const [users] = await db.query("SELECT account_id, email, role FROM Account");
  return users;
};
