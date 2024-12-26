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

const app = express();
const apiRouter = express.Router();

const PORT = process.env.PORT || 9090;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`; // Fallback to localhost if not defined

app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "frontend")));

// Authentication middleware
const authenticate = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token)
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    return res.status(400).json({ message: "Invalid token." });
  }
};

const TWILLIO_SID = process.env.TWILLIO_SID;
const TWILLIO_TOKEN = process.env.TWILLIO_TOKEN;
const TWILLIO_NUM = process.env.TWILLIO_NUM;

const twilioClient = twilio(TWILLIO_SID, TWILLIO_TOKEN);

apiRouter.post("/register", async (req, res) => {
  try {
    const { name, email, password, phoneNumber } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "Email already in use" });

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
    console.log(verificationLink);

    res.status(201).json({
      message: "User registered. Please check your email for verification.",
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

apiRouter.post("/verify/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const { consent, marketing } = req.body;

    const user = await User.findOne({ verificationToken: token });
    if (!user) {
      return res.status(404).json({ message: "Invalid or expired token." });
    }

    if (!consent || consent == "0") {
      return res
        .status(400)
        .json({ message: "You must provide consent to proceed." });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.marketingConsent = marketing == "1" ? true : false;
    user.consentGiven = consent == "1" ? true : false;
    await user.save();

    res.status(200).json({
      message: "Thank you for your consent! You can now log in.",
    });
  } catch (error) {
    res
      .status(500)
      .json({ error: "An error occurred while processing your request." });
  }
});

apiRouter.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ message: "Invalid email or password" });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid)
      return res.status(400).json({ message: "Invalid email or password" });

    const token = jwt.sign(
      { id: user._id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      },
    );
 
    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

apiRouter.post("/send-message", async (req, res) => {
  const { phoneNumber } = req.body;

  if (!phoneNumber) {
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
    // console.log(message);

    let messageResponse = null;

    if (process.env.NODE_ENV === "production") {
      messageResponse = await twilioClient.messages.create({
        body: message,
        from: TWILLIO_NUM,
        to: `+${phoneNumber}`,
      });
    } else {
      console.log("Message sending skipped in development environment.");
    }

    await session.commitTransaction();
    session.endSession();

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

    res.status(500).send({
      success: false,
      error: error.message,
    });
  }
});

apiRouter.get("/dashboard", authenticate, (req, res) => {
  res.json({ message: "This is protected dashboard data.", user: req.user });
});

app.use("/API", apiRouter);

app.get("/login", (req, res) => {
  res.render("index", { baseUrl: BASE_URL });
});

app.get("/dashboard", (req, res) => {
  res.render("dashboard", { baseUrl: BASE_URL });
});

app.get("/verify/:token", async (req, res) => {
  try {
    const { token } = req.params;

    const user = await User.findOne({ verificationToken: token });
    if (!user) {
      return res
        .status(404)
        .render("invalid-token", {
          title: "Invalid or Expired Token",
          baseUrl: BASE_URL,
        });
    }

    res.render("verify", { token, baseUrl: BASE_URL });
  } catch (error) {
    res
      .status(500)
      .send("<h1>An error occurred while processing your request.</h1>");
  }
});

app.use((req, res) => {
  res.status(404).render("404", { title: "Page Not Found", baseUrl: BASE_URL });
});

const DB_URL = process.env.DB_URL;
mongoose
  .connect(DB_URL)
  .then(() => {
    console.log("Connected!");

    app.listen(PORT, () => {
      console.log(`Server is running at ${BASE_URL}`);
    });
  })
  .catch(() => {
    console.log("Error happened connecting to database!");
  });
