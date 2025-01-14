// Environment and Package Imports
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
const WebSocket = require("ws");
const { LibreLinkUpClient } = require("@diakem/libre-link-up-api-client");
const BitlyClient = require("bitly").BitlyClient;
const axios = require("axios");
const { LibreViewClient, processGlucoseData } = require("./libre.js");

// Constants and Environment Variables
const PORT = process.env.PORT || 9090;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const BITLY_API = process.env.BITLY_API;
const SERVER_2_WS_URL =
  "wss://af829a6a-bf37-46af-be69-2490e65e1a5d-00-2gn9zyi2n3qvf.pike.replit.dev/user";
const TWILLIO_SID = process.env.TWILLIO_SID;
const TWILLIO_TOKEN = process.env.TWILLIO_TOKEN;
const TWILLIO_NUM = process.env.TWILLIO_NUM;
const DB_URL = process.env.DB_URL;

// Initialize Express and Clients
const app = express();
const apiRouter = express.Router();
const bitly = new BitlyClient(BITLY_API);
const twilioClient = twilio(TWILLIO_SID, TWILLIO_TOKEN);

const logger = createLogger({
  level: "info",
  format: format.combine(format.timestamp(), format.json()),
  transports: [
    new transports.File({ filename: "error.log", level: "error" }),
    new transports.File({ filename: "combined.log" }),
    new transports.Console({
      format:
        process.env.NODE_ENV === "production" ? format.json() : format.simple(),
    }),
  ],
});

app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "frontend")));
app.use(
  morgan("combined", {
    stream: { write: (message) => logger.info(message.trim()) },
  })
);

const authenticate = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token) {
    logger.warn("Access denied: No token provided");
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    logger.info(`Authenticated user: ${req.user.email}`);
    next();
  } catch (error) {
    logger.error("Invalid token access attempt", { error: error.message });
    if (error.name === "TokenExpiredError") {
      return res
        .status(401)
        .json({ message: "Token expired. Please log in again." });
    }
    return res.status(400).json({
      message:
        error.name === "JsonWebTokenError"
          ? "Malformed token. Access denied."
          : "Invalid token.",
    });
  }
};

// Utility Functions
async function sendLoginDataToServer(name, processedData, phoneNumber = "") {
  if(!phoneNumber){
    return;
  }
  const ws = new WebSocket(SERVER_2_WS_URL);
  // console.log("ASDSAD" + processedData);
  ws.on("open", () => {
    const message = { event: "user_login", phoneNumber, name, processedData};
    ws.send(JSON.stringify(message));
    console.log("Login data sent to Server 2:", message);
    ws.close();
  });

  ws.on("error", (error) => console.error("WebSocket error:", error));
}

async function sendConsetAvailable(phoneNumber) {
  const ws = new WebSocket(SERVER_2_WS_URL);

  ws.on("open", () => {
    const message = { event: "user_consent", phoneNumber };
    ws.send(JSON.stringify(message));
    console.log("Login data sent to Server 2:", message);
    ws.close();
  });

  ws.on("error", (error) => console.error("WebSocket error:", error));
}

async function libreLogin(email, password) {
  const client = new LibreViewClient();
  
  const loginData = await client.login(email, password);
  
  // console.log(loginData)
  return client;
}

async function getUserData(client) {
  const connectionsData = await client.getConnections();
  if (!connectionsData.length) {
    throw new Error("No connections found");
  }
  
  const patientId = connectionsData[0].patientId;
  const glucoseMeasurement = connectionsData[0];
  const cgmData = await client.getCGMData(patientId);
  // console.log(glucoseMeasurement)
  
  const { fullName: userName, combinedReadings: processedData } = processGlucoseData(
    glucoseMeasurement,
    cgmData.graphData
  );
  
    // console.log("Processed Historical Readings:", processedData);
// 
    return {userName, processedData};
}

// API Routes
apiRouter.get("/dashboard", authenticate, async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      user: req.user,
      message: "Dashboard data fetched successfully",
    });
  } catch (error) {
    logger.error("Error fetching dashboard data", { error: error.message });
    res.status(500).json({
      success: false,
      message: "Failed to fetch dashboard data. Please try again later.",
    });
  }
});

apiRouter.get("/lookup-phone", async (req, res) => {
  try {
    const { phoneNumber } = req.query;
    if (!phoneNumber) {
      logger.warn('Lookup failed: Missing "phoneNumber" in query parameters');
      return res
        .status(400)
        .json({ error: 'Missing "phoneNumber" in query parameters.' });
    }

    const normalizedPhoneNumber = phoneNumber.trim().startsWith("+")
      ? phoneNumber.trim()
      : `+${phoneNumber.trim()}`;
    const user = await User.findOne({ phoneNumber: normalizedPhoneNumber });

    if (!user) {
      logger.warn(`No user found with phone number: ${normalizedPhoneNumber}`);
      return res
        .status(404)
        .json({ success: false, message: "User not found." });
    }

    res.status(200).json({
      success: true,
      data: {
        phoneNumber: user.phoneNumber,
        hasConsented: user.consentGiven || false,
        isLoggedIn: !!(user.email && user.password),
        email: user.email || null,
      },
    });
  } catch (error) {
    logger.error("Error during phone number lookup", { error: error.message });
    res.status(500).json({
      success: false,
      error: "An error occurred while looking up the phone number.",
    });
  }
});

apiRouter.get("/user_libre", async (req, res) => {
  try {
    const { username, password } = req.query;
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: 'Missing "username" or "password" in request parameters.',
      });
    }

    const { read } = LibreLinkUpClient({
      username,
      password,
      clientVersion: "4.9.0",
    });

    const libreData = await read();
    res.status(200).json({ success: true, data: libreData });
  } catch (error) {
    logger.error("Error retrieving LibreLinkUp data", { error: error.message });
    res.status(401).json({ success: false, error: error.message });
  }
});

apiRouter.post("/register", async (req, res) => {
  try {
    const { name, email, password, phoneNumber } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
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
    user.marketingConsent = marketing == "1";
    user.consentGiven = consent == "1";
    await user.save();
    await sendConsetAvailable(user.phoneNumber);

    res.status(200).json({
      message: "Thank you for your consent! You can now log in.",
      phoneNumber: user.phoneNumber,
    });
  } catch (error) {
    logger.error("Error during verification", { error: error.message });
    res
      .status(500)
      .json({ error: "An error occurred while processing your request." });
  }
});

apiRouter.post("/login", async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { email, password, phoneNumber } = req.body;
    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required",
        missingFields: { email: !email, password: !password },
      });
    }

    
    const client = await libreLogin(email, password);
    
    const {userName : userName, processedData : processedData} = await getUserData(client);

    let user;
    if (phoneNumber) {
      const formattedPhoneNumber = phoneNumber.startsWith("+")
      ? phoneNumber
      : `+${phoneNumber}`;
      user = await User.findOne({ phoneNumber: formattedPhoneNumber });
      
      if (user) {
        if (!user.email || !user.password) {
          await User.updateOne(
            { phoneNumber: formattedPhoneNumber },
            { email, password, loggedIn: true },
            { session }
          );
        }
      } else {
        const verificationToken = crypto.randomBytes(8).toString("hex");
        const newUser = await User.create(
          [
            {
              phoneNumber: formattedPhoneNumber,
              email,
              password,
              verificationToken,
              lastLogin: new Date(),
            },
          ],
          { session }
        );
        user = newUser[0];
      }
    }
    const token = jwt.sign(
      {
        email,
        name: userName,
        phoneNumber: user?.phoneNumber,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    // console.log(processedData)
    await sendLoginDataToServer(userName, processedData, user?.phoneNumber || "");
    await session.commitTransaction();

    res.status(200).json({
      message: "Login successful",
      token,
      processedData,
      phoneNumber: user?.phoneNumber,
    });
  } catch (error) {
    await session.abortTransaction();
    logger.error("Error during login:", error.message);
    res
      .status(500)
      .json({ message: "Internal server error. Please try again later." });
  } finally {
    session.endSession();
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
    const formattedPhoneNumber = phoneNumber.startsWith("+")
      ? phoneNumber
      : `+${phoneNumber}`;
    let user = await User.findOne({ phoneNumber: formattedPhoneNumber });

    if (user && user.consentGiven) {
      if (user.loggedIn) {
        const token = jwt.sign(
          {
            email: user.email,
            phoneNumber: user.phoneNumber,
            name: user.name,
          },
          process.env.JWT_SECRET,
          { expiresIn: "1h" }
        );

        await session.commitTransaction();
        return res.status(200).send({
          success: true,
          message: "User already registered and logged in",
          isLoggedIn: true,
          token,
          user: {
            email: user.email,
            phoneNumber: user.phoneNumber,
            name: user.name,
          },
        });
      }

      const longUrl = `${BASE_URL}/login?phoneNumber=${encodeURIComponent(
        formattedPhoneNumber
      )}`;
      let shortUrl = longUrl;
      try {
        const response = await bitly.shorten(longUrl);
        shortUrl = response.link;
      } catch (bitlyError) {
        logger.error("Failed to shorten login URL", {
          error: bitlyError.message,
        });
      }

      const message = `You are not logged in. Please log in using this link: ${shortUrl}`;
      let messageResponse = null;

      if (process.env.NODE_ENV === "production") {
        messageResponse = await twilioClient.messages.create({
          body: message,
          from: `${TWILLIO_NUM}`,
          to: formattedPhoneNumber,
        });
      }

      await session.commitTransaction();
      return res.status(200).send({
        success: true,
        message: "Login link sent successfully!",
        needsLogin: true,
        data: {
          user,
          loginUrl: shortUrl,
          twilioResponse:
            messageResponse || "Message not sent (development mode)",
        },
      });
    }

    if (!user) {
      const verificationToken = crypto.randomBytes(8).toString("hex");
      const newUser = await User.create(
        [{ phoneNumber: formattedPhoneNumber, verificationToken }],
        { session }
      );
      user = newUser[0];
    }

    const longUrl = `${BASE_URL}/verify/${user.verificationToken}`;
    let shortUrl = longUrl;

    try {
      const response = await bitly.shorten(longUrl);
      shortUrl = response.link;
    } catch (bitlyError) {
      logger.error("Failed to shorten URL", { error: bitlyError.message });
    }

    const message = `Please give us your consent by following this link: ${shortUrl}`;
    let messageResponse = null;

    if (process.env.NODE_ENV === "production") {
      messageResponse = await twilioClient.messages.create({
        body: message,
        from: `${TWILLIO_NUM}`,
        to: formattedPhoneNumber,
      });
    }

    await session.commitTransaction();
    res.status(200).send({
      success: true,
      message: "Consent link sent successfully!",
      needsConsent: true,
      data: {
        user,
        twilioResponse:
          messageResponse || "Message not sent (development mode)",
      },
    });
  } catch (error) {
    await session.abortTransaction();
    logger.error("Error during send-message", { error: error.message });
    res.status(500).send({
      success: false,
      error: error.message,
    });
  } finally {
    session.endSession();
  }
});

// View Routes
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
      logger.warn("Invalid or expired token access attempted");
      return res.status(404).render("invalid-token", {
        title: "Invalid or Expired Token",
        baseUrl: BASE_URL,
      });
    }

    res.render("verify", { token, baseUrl: BASE_URL });
  } catch (error) {
    logger.error("Error during token verification", { error: error.message });
    res
      .status(500)
      .send("<h1>An error occurred while processing your request.</h1>");
  }
});

// 404 Handler
app.use((req, res) => {
  logger.warn(`404 error: URL not found ${req.originalUrl}`);
  res.status(404).render("404", { title: "Page Not Found", baseUrl: BASE_URL });
});

// Database Connection and Server Start
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
