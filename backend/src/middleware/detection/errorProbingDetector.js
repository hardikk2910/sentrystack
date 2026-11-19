const { logSecurityEvent } = require("../../utils/securityLogger");

const LEAK_PATTERNS = [
  { name: "stack_trace", re: /\bat\s+[\w.<>$ ]+\s+\(.*:\d+:\d+\)/ },
  { name: "file_path", re: /node_modules|\/Users\/|\/home\/|[A-Z]:\\/ },
  {
    name: "mongo_internals",
    re: /CastError|ValidationError|MongoServerError|MongooseError|BSONError/,
  },
];

// Dedupe: one alert per IP+path every 30s so repeated probing doesn't flood the log
const WINDOW_MS = 30 * 1000;
const lastAlert = new Map();

function detectErrorProbing(req, res, next) {
  const originalJson = res.json.bind(res);

  res.json = (body) => {
    try {
      const text = JSON.stringify(body ?? null);
      const leaks = LEAK_PATTERNS.filter((p) => p.re.test(text)).map(
        (p) => p.name,
      );
      if (body && typeof body === "object" && "stack" in body)
        leaks.push("stack_field");

      const isServerError = res.statusCode >= 500;

      if (leaks.length > 0 || isServerError) {
        const key = `${req.ip}|${req.path}`;
        const now = Date.now();
        if (!lastAlert.has(key) || now - lastAlert.get(key) > WINDOW_MS) {
          lastAlert.set(key, now);
          logSecurityEvent({
            type: "ERROR_PROBING",
            severity: leaks.length > 0 ? "high" : "medium",
            req,
            userId: req.user && req.user.id,
            details: {
              statusCode: res.statusCode,
              leakedInternals: leaks,
              note:
                leaks.length > 0
                  ? "Error response exposed internal details"
                  : "Server error triggered (possible malformed-input probing)",
            },
          });
        }
      }
    } catch (err) {
      console.error("errorProbingDetector error:", err.message);
    }
    return originalJson(body);
  };

  next();
}

module.exports = detectErrorProbing;
