const { logSecurityEvent } = require("../../utils/securityLogger");

const BCRYPT_PATTERN = /^\$2[aby]\$\d{2}\$/;
const SENSITIVE_KEYS = ["password", "passwordHash", "refreshToken"];

// Walk the response body and count sensitive fields / hash-looking values
function scan(value, state = { records: 0, fields: new Set() }) {
  if (Array.isArray(value)) {
    value.forEach((v) => scan(v, state));
  } else if (value && typeof value === "object") {
    let hit = false;
    for (const [k, v] of Object.entries(value)) {
      if (SENSITIVE_KEYS.includes(k)) {
        state.fields.add(k);
        hit = true;
      } else if (typeof v === "string" && BCRYPT_PATTERN.test(v)) {
        state.fields.add(k);
        hit = true;
      } else if (v && typeof v === "object") {
        scan(v, state);
      }
    }
    if (hit) state.records++;
  }
  return state;
}

function detectDataExposure(req, res, next) {
  const originalJson = res.json.bind(res);

  res.json = (body) => {
    try {
      const { records, fields } = scan(
        JSON.parse(JSON.stringify(body ?? null)),
      );
      if (records > 0) {
        logSecurityEvent({
          type: "DATA_EXPOSURE_ENUMERATION",
          severity: records > 1 ? "critical" : "high", // bulk leak is worse
          req,
          userId: req.user && req.user.id,
          details: {
            recordsExposed: records,
            sensitiveFields: [...fields],
            statusCode: res.statusCode,
            note: "Response contained password hash / sensitive fields",
          },
        });
      }
    } catch (err) {
      console.error("dataExposureDetector error:", err.message);
    }
    return originalJson(body);
  };

  next();
}

module.exports = detectDataExposure;
