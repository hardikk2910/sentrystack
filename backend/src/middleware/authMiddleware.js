const jwt = require("jsonwebtoken");
const BlacklistedToken = require("../models/BlacklistedToken");

const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const blacklisted = await BlacklistedToken.findOne({ token });
    if (blacklisted) {
      return res.status(401).json({ error: "Token has been logged out" });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Attach the decoded user information to the request object
    next();
  } catch (err) {
    console.error("Error verifying token:", err.message);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

module.exports = verifyToken;
