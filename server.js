require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const User = require("./models/User.model");
const jwt = require("jsonwebtoken");
const twilio = require("twilio");
const cors = require("cors");
const path = require("path");
const { createLogger, format, transports } = require("winston");
const morgan = require("morgan");

const app = express();
const apiRouter = express.Router();

const PORT = process.env.PORT || 9090;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// Winston Logger Configuration
const logger = createLogger({
  level: "info",
  format: format.combine(
    format.timestamp(),
    format.json()
  ),
  transports: [
    new transports.File({ filename: "error.log", level: "error" }),
    new transports.File({ filename: "combined.log" }),
    new transports.Console({
      format: process.env.NODE_ENV === "production" ? format.json() : format.simple(),
    }),
  ],
});

// Middleware
app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "frontend")));

// Morgan HTTP logging
app.use(
  morgan("combined", {
    stream: { write: (message) => logger.info(message.trim()) },
  })
);

// Authentication middleware
const authenticate = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token) {
    logger.warn("Access denied: No token provided");
    return res.status(401).json({ message: "Access denied. No token provided." });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    logger.info(`Authenticated user: ${req.user.email}`);
    next();
  } catch (error) {
    logger.error("Invalid token access attempt", { error: error.message });
    return res.status(400).json({ message: "Invalid token." });
  }
};

const TWILLIO_SID = process.env.TWILLIO_SID;
const TWILLIO_TOKEN = process.env.TWILLIO_TOKEN;
const TWILLIO_NUM = process.env.TWILLIO_NUM;

const twilioClient = twilio(TWILLIO_SID, TWILLIO_TOKEN);

// Routes
apiRouter.post("/register", async (req, res) => {
  try {
    const { name, email, password, phoneNumber } = req.body;
    logger.info(`Registration attempt for email: ${email}`);

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      logger.warn("Registration failed: Email already in use");
      return res.status(400).json({ message: "Email already in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString("hex");

    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      verificationToken,
      phoneNumber,
    });

    const verificationLink = `${BASE_URL}/verify/${verificationToken}`;
    logger.info(`User created: ${email}, Verification link: ${verificationLink}`);

    res.status(201).json({
      message: "User registered. Please check your email for verification.",
    });
  } catch (error) {
    logger.error("Error during registration", { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

apiRouter.post("/verify/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const { consent, marketing } = req.body;

    logger.info(`Verification attempt with token: ${token}`);
    const user = await User.findOne({ verificationToken: token });

    if (!user) {
      logger.warn("Verification failed: Invalid or expired token");
      return res.status(404).json({ message: "Invalid or expired token." });
    }

    if (!consent || consent == "0") {
      logger.warn("Verification failed: Consent not given");
      return res
        .status(400)
        .json({ message: "You must provide consent to proceed." });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.marketingConsent = marketing == "1" ? true : false;
    user.consentGiven = consent == "1" ? true : false;
    await user.save();

    logger.info(`User verified successfully: ${user.email}`);
    res.status(200).json({
      message: "Thank you for your consent! You can now log in.",
    });
  } catch (error) {
    logger.error("Error during verification", { error: error.message });
    res
      .status(500)
      .json({ error: "An error occurred while processing your request." });
  }
});

apiRouter.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    logger.info(`Login attempt for email: ${email}`);
    const user = await User.findOne({ email });
    if (!user) {
      logger.warn("Login failed: Invalid email");
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      logger.warn("Login failed: Invalid password");
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign(
      { id: user._id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    logger.info(`User logged in successfully: ${email}`);
    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    logger.error("Error during login", { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Send-Message Route
apiRouter.post("/send-message", async (req, res) => {
  const { phoneNumber } = req.body;

  if (!phoneNumber) {
    logger.warn('Send-message failed: Missing "phoneNumber" in request body');
    return res
      .status(400)
      .send({ error: 'Missing "phoneNumber" in request body.' });
  }

  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    const verificationToken = crypto.randomBytes(32).toString("hex");

    const user = await User.create([{ phoneNumber, verificationToken }], {
      session,
    });

    const message = `Please give us your consent by following this link: ${BASE_URL}/verify/${verificationToken}`;
    logger.info("Generated message", { message });

    let messageResponse = null;

    if (process.env.NODE_ENV === "production") {
      messageResponse = await twilioClient.messages.create({
        body: message,
        from: TWILLIO_NUM,
        to: `+${phoneNumber}`,
      });
    } else {
      logger.info("Message sending skipped in development environment.");
    }

    await session.commitTransaction();
    session.endSession();

    logger.info("Message sent successfully and user added", {
      user: user[0],
      messageResponse: messageResponse || "Message not sent (development mode)",
    });
    res.status(200).send({
      success: true,
      message: "User added and message sent successfully!",
      data: {
        user: user[0],
        twilioResponse:
          messageResponse || "Message not sent (development mode)",
      },
    });
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    logger.error("Error during send-message", { error: error.message });

    res.status(500).send({
      success: false,
      error: error.message,
    });
  }
});

// Remaining Routes and App Initialization
app.use("/API", apiRouter);

app.use((req, res) => {
  logger.warn(`404 error: URL not found ${req.originalUrl}`);
  res.status(404).render("404", { title: "Page Not Found", baseUrl: BASE_URL });
});

const DB_URL = process.env.DB_URL;
mongoose
  .connect(DB_URL)
  .then(() => {
    logger.info("Connected to the database");
    app.listen(PORT, () => {
      logger.info(`Server is running at ${BASE_URL}`);
    });
  })
  .catch((error) => {
    logger.error("Database connection error", { error: error.message });
  });
