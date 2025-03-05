const db = require("../config/db");

exports.createAppointment = async (req, res) => {
  try {
    const { patient_id, doctor_id, clinic_id, appointment_date_time, status } = req.body;
    if (!patient_id || !doctor_id || !clinic_id || !appointment_date_time || !status) {
      return res.status(400).json({ error: "All fields are required" });
    }
    
    const [result] = await db.query(
      "INSERT INTO Appointment (patient_id, doctor_id, clinic_id, appointment_date_time, status) VALUES (?, ?, ?, ?, ?)",
      [patient_id, doctor_id, clinic_id, appointment_date_time, status]
    );
    res.json({ message: "Appointment booked", appointment_id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
};

exports.getAppointments = async (req, res) => {
  try {
    const [appointments] = await db.query("SELECT * FROM Appointment");
    res.json({ appointments });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
};