const { logSecurityEvent } = require("../../utils/securityLogger");

const WINDOW_MS = 60 * 1000; // sliding window per IP
const THRESHOLD = 10; // failed logins in the window before alerting

// ip -> { count, identifiers:Set, firstSeen, alerted }
const attempts = new Map();

// Purge stale entries so the Map doesn't grow forever
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of attempts) {
    if (now - entry.firstSeen > WINDOW_MS) attempts.delete(ip);
  }
}, WINDOW_MS).unref();

function detectBruteForce(req, res, next) {
  // Evaluate AFTER the response, so we know whether the login failed
  res.on("finish", () => {
    if (res.statusCode !== 400 && res.statusCode !== 401) return;

    const now = Date.now();
    const ip = req.ip;

    let entry = attempts.get(ip);
    if (!entry || now - entry.firstSeen > WINDOW_MS) {
      entry = {
        count: 0,
        identifiers: new Set(),
        firstSeen: now,
        alerted: false,
      };
      attempts.set(ip, entry);
    }

    entry.count++;

    // Only track plain strings (an injected object like {$regex:..} is the NoSQLi detector's job)
    const identifier =
      typeof req.body?.email === "string" ? req.body.email : null;
    if (identifier) entry.identifiers.add(identifier);

    if (entry.count >= THRESHOLD && !entry.alerted) {
      entry.alerted = true;
      logSecurityEvent({
        type: "BRUTE_FORCE_LOGIN",
        severity: "high",
        req,
        attemptedIdentifier: identifier,
        details: {
          failedAttempts: entry.count,
          distinctIdentifiers: entry.identifiers.size,
          windowSeconds: WINDOW_MS / 1000,
          pattern:
            entry.identifiers.size > 3
              ? "credential stuffing / username enumeration"
              : "password guessing against few accounts",
        },
      });
    }
  });

  next();
}

module.exports = detectBruteForce;
