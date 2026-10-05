const User = require("../models/User");

//get all users
const getUsers = async (req, res) => {
  try {
    const users = await User.find();
    // const users = await User.find().select("-password");
    // const user = await User.findById(req.params.id).select('-password');
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

//GET SINGLE USER BY ID
const getUserById = async (req, res) => {
  try {
    // const user = await User.findById(req.params.id);
    const user = await User.findById(req.params.id).select("-password");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // VULNERABILITY: This check is commented out, which means that any authenticated user can access any other user's data by ID.
    // This could lead to unauthorized access to sensitive information.
    // It is important to ensure that only the user themselves or an admin can access this information.
    // if (req.user.role !== "admin" && req.user.id !== user._id.toString()) {
    //   return res.status(403).json({ message: "Access denied" });
    // }

    res.status(200).json(user);
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ message: error.message });
  }
};

//UPDATE USER A USER
const updateUser = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const user = await User.findById(req.params.id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    // VULNERABILITY: This check is commented out, which means that any authenticated user can access any other user's data by ID.
    // This could lead to unauthorized access to sensitive information.
    // It is important to ensure that only the user themselves or an admin can access this information.

    // if (req.user.role !== "admin" && req.user.id !== user._id.toString()) {
    //   return res.status(403).json({ message: "Access denied" });
    // }
    if (username) user.username = username;
    if (email) user.email = email;
    if (password) user.password = password;

    const updatedUser = await user.save();
    res.status(200).json(updatedUser);
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ message: error.message });
  }
};

// DELETE A USER
const deleteUser = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // VULNERABILITY: This check is commented out, which means that any authenticated user can access any other user's data by ID.
    // This could lead to unauthorized access to sensitive information.
    // It is important to ensure that only the user themselves or an admin can access this information.

    // if (req.user.role !== "admin" && req.user.id !== user._id.toString()) {
    //   return res.status(403).json({ message: "Access denied" });
    // }

    await user.deleteOne();

    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ message: error.message });
  }
};

module.exports = {
  getUsers,
  getUserById,
  updateUser,
  deleteUser,
};
