// src/server.js
require("dotenv").config();

const path = require("path");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

// =============================================================================
// App
// =============================================================================
const app = express();

// -----------------------------------------------------------------------------
/** CORS: allow your production client + localhost (dev) */
const allowlist = [process.env.CLIENT_URL, "http://localhost:5173"].filter(Boolean);
app.use(
  cors({
    origin(origin, cb) {
      // allow same-origin/no-origin (curl, health checks), and allowlisted origins
      if (!origin || allowlist.includes(origin)) return cb(null, true);
      return cb(new Error("Not allowed by CORS"));
    },
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// -----------------------------------------------------------------------------
/** Static assets (note: server file is in /src, public is one level up) */
app.use("/pdf", express.static(path.join(__dirname, "../public/pdf")));

// -----------------------------------------------------------------------------
/** JWT secret (don’t crash if missing so Render can boot) */
const secret_key = process.env.SECRET_KEY || "";
if (!secret_key) {
  console.warn("WARNING: SECRET_KEY is not set. JWT routes will fail without it.");
}

// =============================================================================
// MongoDB (optional)
// =============================================================================
const connectDB = require("./db"); // your existing connect function

if (process.env.MONGO_URI) {
  connectDB().catch((err) => {
    console.error("MongoDB connection failed:", err?.message || err);
    process.exit(1);
  });
} else {
  console.warn("MONGO_URI not set — skipping Mongo connection.");
}

// =============================================================================
/** User model (used by auth routes; will require a real DB connection) */
const User =
  mongoose.models.User ||
  mongoose.model(
    "User",
    new mongoose.Schema({
      username: { type: String, required: true, unique: true },
      password: { type: String, required: true },
      email: { type: String, required: true, unique: true },
    })
  );

// =============================================================================
// Auth helpers
// =============================================================================
const authenticateJWT = (req, res, next) => {
  if (!secret_key) return res.status(500).json({ error: "Server misconfigured (no SECRET_KEY)" });

  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Authorization header is missing" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, secret_key, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.userID = decoded.userID;
    next();
  });
};

// =============================================================================
// Routes
// =============================================================================

app.post("/register", async (req, res) => {
  if (!process.env.MONGO_URI) {
    return res.status(503).json({ error: "Database not configured" });
  }

  const { username, password, email } = req.body;
  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) return res.status(400).json({ error: "Username or email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, email });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Error in /register:", error);
    res.status(500).json({ error: "Failed to register user" });
  }
});

app.post("/login", async (req, res) => {
  if (!process.env.MONGO_URI) {
    return res.status(503).json({ error: "Database not configured" });
  }
  if (!secret_key) return res.status(500).json({ error: "Server misconfigured (no SECRET_KEY)" });

  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { userID: user._id, username: user.username, email: user.email },
      secret_key,
      { expiresIn: "1h" }
    );

    res.json({ token, userID: user._id });
  } catch (error) {
    console.error("Error in /login:", error);
    res.status(500).json({ error: "Failed to log in" });
  }
});

app.get("/getUser", authenticateJWT, async (req, res) => {
  if (!process.env.MONGO_URI) {
    return res.status(503).json({ error: "Database not configured" });
  }

  try {
    const user = await User.findById(req.userID).select("username email");
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ username: user.username, email: user.email });
  } catch (error) {
    console.error("Error fetching user details:", error);
    res.status(500).json({ error: "Failed to fetch user details" });
  }
});

// -----------------------------------------------------------------------------
/** Health + simple test */
app.get("/health", (_req, res) => res.status(200).json({ message: "API is healthy" }));
app.get("/", (_req, res) => res.send("Hello! this is Jaturaput's World!"));
app.get("/api", (_req, res) => res.json({ fruits: ["apple", "orange", "banana"] }));

// =============================================================================
// SendGrid email route
// =============================================================================
const sgMail = require("@sendgrid/mail");
if (process.env.SENDGRID_API_KEY) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
} else {
  console.warn("SENDGRID_API_KEY not set — /api/contact/send will fail.");
}

app.post("/api/contact/send", async (req, res) => {
  const { to, subject, body, replyTo } = req.body || {};
  if (!to || !subject || !body) return res.status(400).json({ error: "Missing fields" });
  if (!process.env.SENDGRID_API_KEY) return res.status(503).json({ error: "Email not configured" });
  if (!process.env.MAIL_FROM) return res.status(503).json({ error: "MAIL_FROM not configured" });

  try {
    await sgMail.send({
      to,
      from: process.env.MAIL_FROM, // must be a verified sender in SendGrid
      subject,
      text: body,
      replyTo: replyTo || undefined,
    });
    res.json({ ok: true });
  } catch (err) {
    console.error("SendGrid error:", err.response?.body || err);
    res.status(500).json({ error: "mail_failed", details: err.response?.body });
  }
});

// =============================================================================
// Start server (use Render's PORT)
// =============================================================================
const PORT = process.env.PORT || 8081;
app.listen(PORT, () => {
  console.log(`Server started on http://localhost:${PORT}`);
});
