const { logSecurityEvent } = require("../../utils/securityLogger");

// Origins that are legitimately allowed to call the API
const TRUSTED_ORIGINS = ["http://localhost:5173"];

// Dedupe: one alert per origin per minute, so a noisy page doesn't flood the log
const WINDOW_MS = 60 * 1000;
const lastAlert = new Map(); // origin -> timestamp

function detectCorsAbuse(req, res, next) {
  const origin = req.get("origin");

  if (origin && !TRUSTED_ORIGINS.includes(origin)) {
    const now = Date.now();
    if (!lastAlert.has(origin) || now - lastAlert.get(origin) > WINDOW_MS) {
      lastAlert.set(origin, now);

      // Credentialed cross-origin requests are the dangerous case
      const hasCredentials = Boolean(
        req.get("cookie") || req.get("authorization"),
      );

      logSecurityEvent({
        type: "CORS_ABUSE",
        severity: hasCredentials ? "high" : "medium",
        req,
        details: {
          untrustedOrigin: origin,
          credentialed: hasCredentials,
          isPreflight: req.method === "OPTIONS",
          note: "Request from an origin outside the trusted list",
        },
      });
    }
  }

  next();
}

module.exports = detectCorsAbuse;
