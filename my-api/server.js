require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();

// ✅ Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// ✅ Database Connection
const dbConfig = {
  host: process.env.DB_HOST || "127.0.0.1",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "jednikko",
  database: process.env.DB_NAME || "ClinicDB",  // ✅ Ensure this matches .env
  port: process.env.DB_PORT || 3307,
};

let db;
async function connectDB() {
  try {
    db = await mysql.createPool(dbConfig);
    console.log("✅ Connected to MySQL Database");
  } catch (error) {
    console.error("❌ Database Connection Error:", error.message);
    process.exit(1);
  }
}
connectDB();

// ✅ JWT Secret Key
const JWT_SECRET = "your_jwt_secret";

// ✅ Hashing Function
async function hashPassword(password) {
  return await bcrypt.hash(password, 10);
}

// 📌 REGISTER API
app.post("/register", async (req, res) => {
  try {
    console.log("🟢 Incoming Data:", req.body);

    const { email, password, role } = req.body;
    if (!email || !password || !role) {
      return res.status(400).json({ error: "Email, password, and role are required" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await db.query(
      "INSERT INTO Account (email, password, role) VALUES (?, ?, ?)",
      [email, hashedPassword, role]
    );

    console.log("✅ Insert Result:", result);

    res.json({ message: "✅ Account created", account_id: result.insertId });
  } catch (err) {
    console.error("❌ Register Error:", err.message);
    res.status(500).json({ error: "Internal server error", details: err.message });
  }
});

app.get("/users", async (req, res) => {
  try {
    const [users] = await db.query("SELECT account_id, email, role FROM Account"); // Exclude password for security
    res.json({ users });
  } catch (err) {
    console.error("❌ Error fetching users:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});


// 🔑 LOGIN API
app.post("/login", async (req, res) => {
  try {
    console.log("🟢 Incoming Login Data:", req.body);

    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    // ✅ Search in `Account` table by email
    const [users] = await db.query("SELECT * FROM Account WHERE email = ?", [email]);

    if (users.length === 0) {
      console.error("❌ User not found:", email);
      return res.status(400).json({ error: "User not found" });
    }

    const user = users[0];

    console.log("🟢 Found User:", user);

    // ✅ Compare hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.error("❌ Password Mismatch");
      return res.status(400).json({ error: "Invalid credentials" });
    }

    // ✅ Generate JWT token
    const token = jwt.sign(
      { account_id: user.account_id, role: user.role },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ message: "✅ Login successful", token });
  } catch (err) {
    console.error("❌ Login Error:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.put("/forgot-password", async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      return res.status(400).json({ error: "Email and new password are required" });
    }

    // Hash the new password before storing it
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const [result] = await db.query("UPDATE Account SET password = ? WHERE email = ?", [hashedPassword, email]);

    if (result.affectedRows === 0) {
      return res.status(400).json({ error: "User not found" });
    }

    res.json({ message: "✅ Password reset successful" });
  } catch (err) {
    console.error("❌ Forgot Password Error:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});
 

// 📌 ADD APPOINTMENT
app.post("/appointments", async (req, res) => {
  try {
    console.log("🟢 Booking Appointment:", req.body);

    const { patient_id, doctor_id, clinic_id, appointment_date_time, status } = req.body;
    if (!patient_id || !doctor_id || !clinic_id || !appointment_date_time || !status) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const [result] = await db.query(
      "INSERT INTO Appointment (patient_id, doctor_id, clinic_id, appointment_date_time, status) VALUES (?, ?, ?, ?, ?)",
      [patient_id, doctor_id, clinic_id, appointment_date_time, status]
    );

    res.json({ message: "✅ Appointment booked", appointment_id: result.insertId });
  } catch (err) {
    console.error("❌ Book Appointment Error:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});


// Patients GET APPOINTMENTS
app.get("/appointments/:patient_id", async (req, res) => {
  try {
    const { patient_id } = req.params;
    const [appointments] = await db.query("SELECT * FROM Appointment WHERE patient_id = ?", [patient_id]);
    res.json({ appointments });
  } catch (err) {
    console.error("❌ Error fetching appointments:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Doctors GET APPOINTMENTS
app.get("/appointments", async (req, res) => {
  try {
    const [appointments] = await db.query("SELECT * FROM Appointment");
    res.json({ appointments });
  } catch (err) {
    console.error("❌ Error fetching appointments:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get appointment that corresponds to doctor_id
app.get("/appointments/:doctor_id", async (req, res) => {
  try {
    const { doctor_id } = req.params;
    const [appointments] = await db.query("SELECT * FROM Appointment WHERE doctor_id = ?", [doctor_id]);
    res.json({ appointments });
  } catch (err) {
    console.error("❌ Error fetching appointments:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});
// 🌟 Start Server
const PORT = 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
