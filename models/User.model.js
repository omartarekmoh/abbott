const mongoose = require("mongoose");

const userSchema = mongoose.Schema(
  {
    phoneNumber: {
      type: String,
      required: [true, "Please enter a phone number"],
      unique: true,
    },
    name: {
      type: String,
      default: "Anonymous",
    },
    email: {
      type: String,
      sparse: true,
      match: [/.+@.+\..+/, "Please enter a valid email"],
    },
    password: {
      type: String,
    },
    loggedIn: {
      type: Boolean,
      default: false, // Default is false; set to true on successful login
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    verificationToken: {
      type: String,
    },
    consentGiven: {
      type: Boolean,
      default: false,
    },
    marketingConsent: {
      type: Boolean,
      default: false,
    },
    lastLogin: {
      type: Date,
    },
  },
  {
    timestamps: true,
  }
);

const User = mongoose.model("User", userSchema);

// Ensure the phoneNumber is indexed as unique
User.init().then(() => {
  mongoose.connection.db
    .collection("users")
    .createIndex({ phoneNumber: 1 }, { unique: true })
    .then(() => console.log("Unique index created on phoneNumber"))
    .catch((err) => console.error("Error creating index on phoneNumber:", err));
});

module.exports = User;
 