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
const { LibreLinkUpClient } = require('@diakem/libre-link-up-api-client');
const BitlyClient = require("bitly").BitlyClient;
const axios = require("axios");



const app = express();
const apiRouter = express.Router();

const PORT = process.env.PORT || 9090;
const bitly = new BitlyClient("d626687a18a237ac4277100c14d987ef6c4b8768"); // Store token in environment variables
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const SERVER_2_WS_URL = "wss://af829a6a-bf37-46af-be69-2490e65e1a5d-00-2gn9zyi2n3qvf.pike.replit.dev/user";


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

async function sendLoginDataToServer( name) {
  const ws = new WebSocket(SERVER_2_WS_URL);

  ws.on("open", () => {
      const message = {
          event: "user_login",
          // phoneNumber: phoneNumber,
          name: name,
      };

      ws.send(JSON.stringify(message));
      console.log("Login data sent to Server 2:", message);
      ws.close();
  });

  ws.on("error", (error) => {
      console.error("WebSocket error:", error);
  });
}

async function sendConsetAvailable(phoneNumber) {
  const ws = new WebSocket(SERVER_2_WS_URL);

  ws.on("open", () => {
      const message = {
          event: "user_consent",
          phoneNumber: phoneNumber,
      };

      ws.send(JSON.stringify(message));
      console.log("Login data sent to Server 2:", message);
      ws.close();
  });

  ws.on("error", (error) => {
      console.error("WebSocket error:", error);
  });
}

const LIBRE_BASE_URL = "https://api.libreview.io";

// Utility to login via Libre API
async function libreLogin(email, password) {
  let baseUrl = process.env.LIBRE_BASE_URL || "https://api.libreview.io";
  const loginPayload = { email, password };
  const headers = {
      "accept-encoding": "gzip",
      "cache-control": "no-cache",
      connection: "Keep-Alive",
      "content-type": "application/json",
      product: "llu.android",
      version: "4.12.0",
  };

  try {
      // Attempt login
      let response = await axios.post(`${baseUrl}/llu/auth/login`, loginPayload, { headers });

      // Handle region redirection
      if (response.data?.data?.redirect) {
          const region = response.data.data.region;
          baseUrl = `https://api-${region}.libreview.io`;
          response = await axios.post(`${baseUrl}/llu/auth/login`, loginPayload, { headers });
      }

      // Check for authentication error
      if (response.data?.status === 2 && response.data?.error?.message === "notAuthenticated") {
          return { status: 401, message: "Invalid email or password" }; // Return a response-like object
      }

      // Extract and return relevant data
      const data = response.data.data;
      const jwtToken = data.authTicket.token;
      const userId = data.user.id;
      const accountId = crypto.createHash("sha256").update(userId).digest("hex");

      headers["Authorization"] = `Bearer ${jwtToken}`;
      headers["Account-Id"] = accountId;

      return { status: 200, jwtToken, accountId, headers, baseUrl }; // Return success response
  } catch (error) {
      console.error("Error during Libre login:", error.message);
      return { status: 500, message: "Internal server error during login" }; // Return server error response
  }
}

// Utility to get user data from Libre API
async function getUserData(headers, baseUrl) {
    const connectionsUrl = `${baseUrl}/llu/connections`;

    const response = await axios.get(connectionsUrl, { headers });
    if (response.status === 200 && response.data.data.length > 0) {
        const connection = response.data.data[0];
        const patientId = connection.patientId;
        const glucoseMeasurement = connection.glucoseMeasurement;
        const name = `${connection.firstName} ${connection.lastName}`;
        return { patientId, glucoseMeasurement, name };
    } else {
        throw new Error("No connections found or failed to fetch connections.");
    }
}


const authenticate = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token) {
    logger.warn("Access denied: No token provided");
    return res.status(401).json({ message: "Access denied. No token provided." });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);

    // Additional checks can be implemented here, e.g., user roles or permissions
    req.user = verified;
    logger.info(`Authenticated user: ${req.user.email}`);
    next();
  } catch (error) {
    logger.error("Invalid token access attempt", { error: error.message });
    
    // More detailed error messages (optional)
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token expired. Please log in again." });
    } else if (error.name === "JsonWebTokenError") {
      return res.status(400).json({ message: "Malformed token. Access denied." });
    } else {
      return res.status(400).json({ message: "Invalid token." });
    }
  }
};

const TWILLIO_SID = process.env.TWILLIO_SID;
const TWILLIO_TOKEN = process.env.TWILLIO_TOKEN;
const TWILLIO_NUM = process.env.TWILLIO_NUM;

const twilioClient = twilio(TWILLIO_SID, TWILLIO_TOKEN);

// Routes
apiRouter.get("/dashboard",authenticate, async (req, res) => {
  try {
    const user = req.user;

    res.status(200).json({
      success: true,
      user,
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

apiRouter.get("/user", async (req, res) => {
  try {
    const { phoneNumber } = req.query;

    if (!phoneNumber) {
      logger.warn('Get user failed: Missing "phoneNumber" in query parameters');
      return res.status(400).json({ error: 'Missing "phoneNumber" in query parameters.' });
    }

    logger.info(`Fetching user data for phone number: ${phoneNumber}`);

    const user = await User.findOne({ phoneNumber });

    if (!user) {
      logger.warn(`No user found with phone number: ${phoneNumber}`);
      return res.status(404).json({success: false, message: "User not found." });
    }

    logger.info(`User data retrieved successfully for phone number: ${phoneNumber}`, { user });
    res.status(200).json({ success: true, user });
  } catch (error) {
    logger.error("Error retrieving user by phone number", { error: error.message });
    res.status(500).json({ success: false, error: "An error occurred while fetching the user data." });
  }
});

apiRouter.get('/user_libre', async (req, res) => {
  try {
    // Extract username and password from the request
    const { username, password } = req.query; // Use req.body if the data is sent via POST or PUT

    // Validate that both username and password are provided
    if (!username || !password) {
      logger.warn('Missing username or password in request');
      return res.status(400).json({
        success: false,
        error: 'Missing "username" or "password" in request parameters.',
      });
    }

    logger.info('Initializing LibreLinkUp client with provided credentials');

    // Initialize the LibreLinkUp client
    const { read } = LibreLinkUpClient({
      username,
      password,
      clientVersion: '4.9.0',
    });

    // Call the read function to fetch data
    const libreData = await read();

    logger.info('LibreLinkUp data retrieved successfully', { libreData });

    // Return LibreLinkUp data
    res.status(200).json({
      success: true,
      data: libreData,
    });
  } catch (error) {
    logger.error('Error retrieving LibreLinkUp data', { error: error.message });
    res.status(401).json({
      success: false,
      error: error.message,
    });
  }
});


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
    const verificationToken = crypto.randomBytes(4).toString("hex");

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
    sendConsetAvailable(user.phoneNumber);

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

      // Step 1: Login via Libre API
      const loginResult = await libreLogin(email, password);

      if (loginResult.status === 401) {
          logger.warn("Login failed: Invalid email or password");
          return res.status(401).json({ message: loginResult.message });
      }

      if (loginResult.status === 500) {
          logger.error("Error during Libre login:", loginResult.message);
          return res.status(500).json({ message: "Internal server error. Please try again later." });
      }

      // Step 2: Get user data
      const { jwtToken, accountId, headers, baseUrl } = loginResult;
      const userData = await getUserData(headers, baseUrl);

      // Step 3: Generate a local JWT for your app session
      const token = jwt.sign(
          { email, accountId, libreJwt: jwtToken, glucoseData: userData.glucoseMeasurement, name: userData.name },
          process.env.JWT_SECRET,
          { expiresIn: "1h" }
      );

      sendLoginDataToServer(userData.name)

      logger.info(`User logged in successfully: ${email}`);
      res.status(200).json({
          message: "Login successful",
          token,
          userData,
      });
  } catch (error) {
      logger.error("Error during login:", error.message);
      res.status(500).json({ message: "Internal server error. Please try again later." });
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

    const longUrl = `${BASE_URL}/verify/${verificationToken}`;

    // Shorten the URL
    let shortUrl = longUrl;
    try {
      const response = await bitly.shorten(longUrl);
      shortUrl = response.link;
      logger.info("URL shortened successfully", { shortUrl });
    } catch (bitlyError) {
      logger.error("Failed to shorten URL", { error: bitlyError.message });
    }

    const message = `Please give us your consent by following this link: ${shortUrl}`;
    logger.info("Generated message", { message });

    let messageResponse = null;

    if (process.env.NODE_ENV === "production") {
      const formattedPhoneNumber = phoneNumber.startsWith('+') ? phoneNumber : `+${phoneNumber}`;
      messageResponse = await twilioClient.messages.create({
        body: message,
        from: `+13059306829`, 
        to: `${formattedPhoneNumber}`,
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

// Routes and App Start (No Changes Beyond Logging)
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
