const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const BlacklistedToken = require("../models/BlacklistedToken");
const RefreshToken = require("../models/RefreshToken");
const crypto = require("crypto");

// HELPER: creates a refresh token, saves it, returns the raw token
const generateRefreshToken = async (user) => {
  const refreshToken = jwt.sign(
    { id: user._id, jti: crypto.randomUUID() }, // jti makes each token unique
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "7d" },
  );

  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days from now

  await RefreshToken.create({
    token: refreshToken,
    userId: user._id,
    expiresAt,
  });

  return refreshToken;
};

// POST /api/auth/refresh
const refreshAccessToken = async (req, res) => {
  try {
    // const { refreshToken } = req.body;
    const { refreshToken } = req.cookies; // Get refresh token from cookies

    if (!refreshToken) {
      return res.status(400).json({ error: "Refresh token is required" });
    }

    // Check if the refresh token exists in the database(not revoked/logged out, not expired thanks to TTL
    // const storedToken = await RefreshToken.findOne({ token: refreshToken });
    // if (!storedToken) {
    //   return res
    //     .status(401)
    //     .json({ error: "Invalid or expired refresh token" });
    // }
    const storedToken = await RefreshToken.findOneAndDelete({
      token: refreshToken,
    });
    if (!storedToken) {
      return res
        .status(401)
        .json({ error: "Invalid or expired refresh token" });
    }
    // Verify its signature/expiry too (defense in depth, in case DB and JWT ever disagree
    let decoded;

    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch (err) {
      // await storedToken.deleteOne(); // Remove the invalid token from DB
      return res
        .status(401)
        .json({ error: "Invalid or expired refresh token" });
    }
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(401).json({ error: "User no longer exists" });
    }

    // // ROTATION: delete the old refresh token, issue a new one
    // await storedToken.deleteOne();
    const newRefreshToken = await generateRefreshToken(user);

    const newAccessToken = await jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
    );

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({ token: newAccessToken });
  } catch (err) {
    console.error("Error refreshing access token:", err);
    res.status(500).json({ error: "Server error" });
  }
};
//GET /api/auth/me
const getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json(user);
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ message: error.message });
  }
};

// POST /api/auth/register
const registerUser = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res
        .status(409)
        .json({ error: "Username or email already in use" });
    }

    const newUser = new User({
      username,
      email,
      password,
    });
    await newUser.save();

    // ACCESS TOKEN
    const token = jwt.sign(
      { id: newUser._id, role: newUser.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
    );

    // REFRESH TOKEN
    const refreshToken = await generateRefreshToken(newUser);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: false, // set to true only when served over HTTPS (production)
      sameSite: "lax", // 'lax' is fine for localhost dev; revisit for prod
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days, matches your refresh token's JWT expiry
    });

    res.status(201).json({
      message: "User registered successfully",
      token,
      // refreshToken,
      user: {
        id: newUser._id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
};

// POST /api/auth/login
const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // ACCESS TOKEN
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
    );

    // REFRESH TOKEN
    const refreshToken = await generateRefreshToken(user);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: false, // set to true only when served over HTTPS (production)
      sameSite: "lax", // 'lax' is fine for localhost dev; revisit for prod
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days, matches your refresh token's JWT expiry
    });
    res.status(200).json({
      message: "Login successful",
      token,
      // refreshToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
};

// POST /api/auth/logout
const logoutUser = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader.split(" ")[1];

    // req.user.exp is the token's expiry (in seconds since epoch), set by jwt.verify in verifytoken
    const expiresAt = new Date(req.user.exp * 1000); // Convert to milliseconds
    await BlacklistedToken.create({ token, expiresAt });

    // Also revoke the refresh token, if the client sends one
    const { refreshToken } = req.cookies; // Get refresh token from cookies
    if (refreshToken) {
      await RefreshToken.deleteOne({ token: refreshToken });
    }

    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
    });

    res.status(200).json({ message: "Logged out successfully" });
  } catch (err) {
    console.error("Error logging out", err);
    res.status(500).json({ message: err.message });
  }
};

module.exports = {
  registerUser,
  loginUser,
  getMe,
  logoutUser,
  refreshAccessToken,
};
