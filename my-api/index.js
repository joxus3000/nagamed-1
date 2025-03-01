const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Test Route
app.get("/", (req, res) => {
  res.send("Hello from Node.js API!");
});

// Sample Route (GET Request)
app.get("/api/data", (req, res) => {
  res.json({ message: "This is a sample API response" });
});

// Sample Route (POST Request)
app.post("/api/post", (req, res) => {
  const { name } = req.body;
  res.json({ message: `Hello, ${name}!` });
});

// Start the Server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
