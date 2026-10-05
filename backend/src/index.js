const express = require("express");
const dotenv = require("dotenv");
const connectDB = require("./config/db");
const cors = require("cors");
const cookieParser = require("cookie-parser");

const userRoutes = require("./routes/UserRoutes");
const authRoutes = require("./routes/auth");

dotenv.config();

const app = express();

//Middleware
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  }),
);
app.use(cookieParser());
app.use(express.json());
app.use("/api/users", userRoutes);
app.use("/api/auth", authRoutes);

// Connect to MongoDB
connectDB();

//Basic health check route
app.get("/", (req, res) => {
  res.json({ message: "SentryStack API is running..." });
});

const PORT = process.env.PORT || 5001;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
