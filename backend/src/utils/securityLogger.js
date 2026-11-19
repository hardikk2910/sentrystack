const SecurityEvent = require("../models/SecurityEvent");

/**
 * Record a security event. Fire-and-forget: never throws, never blocks the request.
 */
async function logSecurityEvent({
  type,
  severity,
  req,
  userId,
  targetUserId,
  attemptedIdentifier,
  details,
}) {
  try {
    const event = {
      type,
      severity,
      userId,
      targetUserId,
      attemptedIdentifier,
      details,
    };

    if (req) {
      event.ip = req.ip;
      event.userAgent = req.get("user-agent");
      event.origin = req.get("origin");
      event.method = req.method;
      event.path = req.originalUrl;
    }

    // Attacker-controlled IDs may not be valid ObjectIds; keep them as evidence in details instead of losing the event
    const OBJECT_ID = /^[a-f\d]{24}$/i;
    for (const field of ["userId", "targetUserId"]) {
      if (event[field] !== undefined && !OBJECT_ID.test(String(event[field]))) {
        event.details = {
          ...(event.details || {}),
          [`${field}Raw`]: String(event[field]).slice(0, 100),
        };
        delete event[field];
      }
    }

    await SecurityEvent.create(event);

    console.warn(
      `[SECURITY][${severity.toUpperCase()}] ${type}`,
      details || "",
    );
  } catch (err) {
    console.error("Failed to write SecurityEvent:", err.message);
  }
}

module.exports = { logSecurityEvent };
