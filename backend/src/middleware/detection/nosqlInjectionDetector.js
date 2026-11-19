const { logSecurityEvent } = require("../../utils/securityLogger");

// Walk the body and collect any MongoDB operator keys ($regex, $ne, $gt, $where ...)
function findOperators(value, path = "body", found = []) {
  if (value && typeof value === "object") {
    for (const key of Object.keys(value)) {
      const childPath = `${path}.${key}`;
      if (key.startsWith("$")) {
        found.push({ path: childPath, operator: key, value: value[key] });
      }
      findOperators(value[key], childPath, found);
    }
  }
  return found;
}

function detectNoSqlInjection(req, res, next) {
  const findings = findOperators(req.body);

  // Also flag non-string email/password even without a $ key (e.g. arrays/objects)
  const typeAnomalies = ["email", "password"].filter(
    (f) =>
      req.body && req.body[f] !== undefined && typeof req.body[f] !== "string",
  );

  if (findings.length > 0 || typeAnomalies.length > 0) {
    logSecurityEvent({
      type: "NOSQL_INJECTION_ATTEMPT",
      severity: "high",
      req,
      details: {
        operators: findings.map((f) => ({
          field: f.path,
          operator: f.operator,
          // Truncate payload; never store password-field values
          value: f.path.includes("password")
            ? "[redacted]"
            : String(JSON.stringify(f.value)).slice(0, 100),
        })),
        nonStringFields: typeAnomalies,
      },
    });
  }

  next();
}

module.exports = detectNoSqlInjection;
