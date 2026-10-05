const express = require("express");
const {
  registerUser,
  loginUser,
  getMe,
  logoutUser,
  refreshAccessToken,
} = require("../controllers/authController");
const validateUser = require("../middleware/validateUser");
const verifyToken = require("../middleware/authMiddleware");
const router = express.Router();

// POST /api/auth/register
router.post("/register", validateUser, registerUser);
router.post("/login", loginUser);
router.get("/me", verifyToken, getMe);
router.post("/logout", verifyToken, logoutUser);
router.post("/refresh", refreshAccessToken);

module.exports = router;
