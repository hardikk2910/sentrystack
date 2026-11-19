const mongoose = require("mongoose");

// One record per refresh token that has been rotated away.
// If one of these jtis is ever presented again, the token was stolen and replayed.
const usedRefreshTokenSchema = new mongoose.Schema({
  jti: {
    type: String,
    required: true,
    unique: true,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true,
  },
  rotatedAt: {
    type: Date,
    default: Date.now,
  },
  // Same expiry as the original token; after that the JWT itself is dead, so we can forget it
  expiresAt: {
    type: Date,
    required: true,
  },
});

usedRefreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model("UsedRefreshToken", usedRefreshTokenSchema);
