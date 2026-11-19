const express = require("express");
const {
  detectIdor,
  detectMassAssignment,
} = require("../middleware/detection/userAbuseDetector");
const detectDataExposure = require("../middleware/detection/dataExposureDetector");

const router = express.Router();
router.use(detectDataExposure);

const {
  getUsers,
  getUserById,
  updateUser,
  deleteUser,
} = require("../controllers/userController");
const verifyToken = require("../middleware/authMiddleware");

// const {protect}=require("../middleware/authMiddleware");
// router.post("/login",loginUser);

const reqruireAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Access denied: Admin only" });
  }
  next();
};

router.get("/", verifyToken, reqruireAdmin, getUsers);
router.get("/:id", verifyToken, detectIdor, getUserById);
router.put("/:id", verifyToken, detectIdor, detectMassAssignment, updateUser);
router.delete("/:id", verifyToken, detectIdor, deleteUser);
module.exports = router;
