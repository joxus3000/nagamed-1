const express = require("express");
const accountController = require("../controllers/accountController");

const router = express.Router();

// User Registration
router.post("/register", accountController.register);

// User Login
router.post("/login", accountController.login);

// Get All Users
router.get("/users", accountController.getUsers);

// Forgot Password
router.put("/forgot-password", accountController.forgotPassword);

module.exports = router;