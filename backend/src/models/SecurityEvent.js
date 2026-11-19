const mongoose = require("mongoose");

const securityEventSchema = new mongoose.Schema(
  {
    // What was detected (one per vulnerability category + the standout feature)
    type: {
      type: String,
      required: true,
      enum: [
        "BRUTE_FORCE_LOGIN",
        "NOSQL_INJECTION_ATTEMPT",
        "IDOR_ATTEMPT",
        "MASS_ASSIGNMENT_ATTEMPT",
        "DATA_EXPOSURE_ENUMERATION",
        "CORS_ABUSE",
        "ERROR_PROBING",
        "REFRESH_TOKEN_REUSE",
        "TOKEN_FAMILY_REVOKED",
      ],
      index: true,
    },
    severity: {
      type: String,
      required: true,
      enum: ["low", "medium", "high", "critical"],
      index: true,
    },

    // Who / where it came from
    ip: { type: String },
    userAgent: { type: String },
    origin: { type: String },

    // Which account is involved (all optional: not every event has an authenticated user)
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
    targetUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    attemptedIdentifier: { type: String }, // e.g. the email used in a failed login

    // What was requested
    method: { type: String },
    path: { type: String },

    // Free-form evidence specific to each detection (matched payload, counts, jti, etc.)
    details: { type: mongoose.Schema.Types.Mixed },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

// Common SOC-style query: "recent events of a type, newest first"
securityEventSchema.index({ type: 1, createdAt: -1 });

module.exports = mongoose.model("SecurityEvent", securityEventSchema);
