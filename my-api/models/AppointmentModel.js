const db = require("../config/db");

exports.createAppointment = async (patient_id, doctor_id, clinic_id, appointment_date_time, status) => {
  const [result] = await db.query(
    "INSERT INTO Appointment (patient_id, doctor_id, clinic_id, appointment_date_time, status) VALUES (?, ?, ?, ?, ?)",
    [patient_id, doctor_id, clinic_id, appointment_date_time, status]
  );
  return result.insertId;
};

exports.getAppointmentsByPatient = async (patient_id) => {
  const [appointments] = await db.query(
    "SELECT * FROM Appointment WHERE patient_id = ?",
    [patient_id]
  );
  return appointments;
};

exports.getAppointmentsByDoctor = async (doctor_id) => {
  const [appointments] = await db.query(
    "SELECT * FROM Appointment WHERE doctor_id = ?",
    [doctor_id]
  );
  return appointments;
};

exports.getAllAppointments = async () => {
  const [appointments] = await db.query("SELECT * FROM Appointment");
  return appointments;
};
