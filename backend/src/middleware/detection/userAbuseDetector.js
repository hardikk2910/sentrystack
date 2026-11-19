const { logSecurityEvent } = require("../../utils/securityLogger");

// Non-admin touching another user's record via /:id
function detectIdor(req, res, next) {
  const caller = req.user; // set by verifyToken
  const targetId = req.params.id;

  if (caller && caller.role !== "admin" && caller.id !== targetId) {
    logSecurityEvent({
      type: "IDOR_ATTEMPT",
      severity: req.method === "GET" ? "medium" : "high", // writes/deletes are worse than reads
      req,
      userId: caller.id,
      targetUserId: targetId,
      details: {
        callerRole: caller.role,
        action: req.method,
        note: "Non-admin accessed another user's object by ID",
      },
    });
  }

  next();
}

// 'role' present in an update body
function detectMassAssignment(req, res, next) {
  const caller = req.user;

  if (req.body && Object.prototype.hasOwnProperty.call(req.body, "role")) {
    const isSelf = caller && caller.id === req.params.id;
    logSecurityEvent({
      type: "MASS_ASSIGNMENT_ATTEMPT",
      severity: caller && caller.role !== "admin" ? "critical" : "medium",
      req,
      userId: caller && caller.id,
      targetUserId: req.params.id,
      details: {
        callerRole: caller && caller.role,
        attemptedRole: String(req.body.role).slice(0, 30),
        selfEscalation: isSelf,
        note: "Privileged field 'role' included in update request",
      },
    });
  }

  next();
}

module.exports = { detectIdor, detectMassAssignment };
