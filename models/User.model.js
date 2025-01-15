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
      default: false,
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
    state: {
      type: String,
      enum: ["awaiting_details", "completed", "new"], // Add more states if needed
      default: "new",
    },
    details: {
      type: String, // Changed from Map to String
      default: "", // Default to an empty string
    },
  },
  {
    timestamps: true, // Automatically adds createdAt and updatedAt timestamps
  }
);

const User = mongoose.model("User", userSchema);

module.exports = User;
