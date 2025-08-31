// src/server.js

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const connectDB = require("./db"); // Import the connectDB function
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const path = require("path");
//====================================================================================================
// Initialize app
const app = express();
//====================================================================================================
// Connect to MongoDB
connectDB();
//====================================================================================================
// Middleware
const corsOptions = {
    origin: process.env.CLIENT_URL || "http://localhost:5173",
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const secret_key = process.env.SECRET_KEY;

if (!secret_key) {
    throw new Error("SECRET_KEY is not defined in the environment variables.");
}

//====================================================================================================
// Serve static files from 'public' folder WITHOUT including /public/ in URL
app.use('/pdf', express.static(path.join(__dirname, 'public/pdf')));

//====================================================================================================
// User Schema and Model
const mongoose = require("mongoose");
const User = mongoose.model(
    "User",
    new mongoose.Schema({
        username: { type: String, required: true, unique: true },
        password: { type: String, required: true },
        email: { type: String, required: true, unique: true },
    })
);

// Middleware to Authenticate JWT
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ error: "Authorization header is missing" });
    }

    const token = authHeader.split(" ")[1];
    jwt.verify(token, secret_key, (err, decoded) => {
        if (err) {
            return res.status(403).json({ error: "Invalid token" });
        }

        req.userID = decoded.userID;
        next();
    });
};

// Routes
app.post("/register", async (req, res) => {
    const { username, password, email } = req.body;

    try {
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.status(400).json({ error: "Username or email already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword, email });
        await newUser.save();

        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        console.error("Error in /register endpoint:", error);
        res.status(500).json({ error: "Failed to register user" });
    }
});

app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign(
            { userID: user._id, username: user.username, email: user.email },
            secret_key,
            { expiresIn: "1h" }
        );

        res.json({ token, userID: user._id });
    } catch (error) {
        console.error("Error in /login endpoint:", error);
        res.status(500).json({ error: "Failed to log in" });
    }
});

app.get("/getUser", authenticateJWT, async (req, res) => {
    try {
        const userID = req.userID;

        const user = await User.findById(userID).select("username email");
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json({ username: user.username, email: user.email });
    } catch (error) {
        console.error("Error fetching user details:", error);
        res.status(500).json({ error: "Failed to fetch user details" });
    }
});

//====================================================================================================
// Health Check
app.get("/health", (req, res) => {
    res.status(200).json({ message: "API is healthy" });
});

// Root and Test Endpoints
app.get("/", (req, res) => {
    res.send("Hello! this is Jaturaput's World!");
});

app.get("/api", (req, res) => {
    res.json({ fruits: ["apple", "orange", "banana"] });
});



/**/
const sgMail = require("@sendgrid/mail");
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

app.post("/api/contact/send", async (req, res) => {
  const { to, subject, body, replyTo } = req.body || {};
  if (!to || !subject || !body) return res.status(400).json({ error: "Missing fields" });
  try {
    await sgMail.send({
      to,
      from: process.env.MAIL_FROM,       // verified sender in SendGrid
      subject,
      text: body,
      replyTo: replyTo || undefined,
    });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "mail_failed" });
  }
});





//====================================================================================================
// Start the Server
app.listen(8081, () => {
    console.log("Server started on http://localhost:8081");
});













