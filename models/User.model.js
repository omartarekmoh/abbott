const mongoose = require("mongoose");

const userSchema = mongoose.Schema(
  {
    phoneNumber: {
      type: String,
      required: [true, "Please enter a phone number"],
      unique: true,
      // match: [/^\+?[1-9]\d{1,14}$/, "Please enter a valid phone number"], // Example regex for E.164 format
    },
    name: {
      type: String,
      default: "Anonymous",
    },
    email: {
      type: String,
      unique: true,
      sparse: true,
      match: [/.+@.+\..+/, "Please enter a valid email"],
    },
    password: {
      type: String,
      minlength: [6, "Password must be at least 6 characters long"],
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    verificationToken: {
      type: String,
    },
    // New fields for consent
    consentGiven: {
      type: Boolean,
      default: false, // Default to false until user provides consent
    },
    marketingConsent: {
      type: Boolean,
      default: false, // Default to false; user can opt-in to receive marketing
    },
    consentGivenAt: {
      type: Date, // Timestamp of when consent was provided
    },
    marketingConsentAt: {
      type: Date, // Timestamp of when marketing consent was provided (if applicable)
    },
    // Additional metadata (optional)
    lastLogin: {
      type: Date, // Timestamp of the last login
    },
  },
  {
    timestamps: true, // Automatically add createdAt and updatedAt timestamps
  }
);

const User = mongoose.model("User", userSchema);

// Ensure the sparse unique index is created
User.init().then(() => {
  mongoose.connection.db
    .collection("users")
    .createIndex({ email: 1 }, { unique: true, sparse: true });
});

module.exports = User;
