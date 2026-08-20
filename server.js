const express = require("express");

const app = express();
app.use(express.json());

const SHA_RE = /^[0-9a-f]{40}$/;
const EXPECTED_PERMISSIONS = {
  contents: "read",
  packages: "write",
  "id-token": "none",
};

function evaluate(body) {
  const violations = new Set();

  const target = body && body.target;
  const event = body && body.event;
  const ref = body && body.ref;
  const workflow = (body && body.workflow) || {};
  const image = (body && body.image) || {};

  // --- Rule 1: permissions must be exactly least privilege, no extras ---
  const perms = workflow.permissions || {};
  const permKeys = Object.keys(perms);
  const expectedKeys = Object.keys(EXPECTED_PERMISSIONS);
  const hasExtraKey = permKeys.some((k) => !expectedKeys.includes(k));
  const matchesExpected = expectedKeys.every(
    (k) => perms[k] === EXPECTED_PERMISSIONS[k]
  );
  if (hasExtraKey || !matchesExpected) {
    violations.add("EXCESS_PERMISSION");
  }

  // --- Rule 2: pull_request must never use pull_request_target ---
  if (workflow.trigger === "pull_request_target") {
    violations.add("UNSAFE_PR_TRIGGER");
  }

  // --- Rule 2b: tests must pass, matrix complete, failFast false ---
  if (
    workflow.testsPassed !== true ||
    workflow.matrixComplete !== true ||
    workflow.failFast !== false
  ) {
    violations.add("TESTS_INCOMPLETE");
  }

  // --- Rule 3: third-party actions must be pinned to a full commit SHA ---
  const actions = Array.isArray(workflow.actions) ? workflow.actions : [];
  for (const action of actions) {
    const owner = action && action.owner;
    const ref_ = action && action.ref;
    if (owner !== "actions") {
      if (typeof ref_ !== "string" || !SHA_RE.test(ref_)) {
        violations.add("MUTABLE_ACTION");
      }
    }
  }

  // --- Rule 4: image hardening ---
  if (image.multiStage !== true) violations.add("SINGLE_STAGE_IMAGE");
  if (image.runsAsRoot !== false) violations.add("ROOT_RUNTIME");
  if (!["none", "buildkit"].includes(image.secretMode)) {
    violations.add("SECRET_IN_LAYER");
  }
  if (image.criticalVulnerabilities !== 0) violations.add("CRITICAL_CVE");
  if (image.digestPinned !== true) violations.add("UNPINNED_IMAGE");

  // --- Rule 5: production requires push to main + approval ---
  if (target === "production") {
    if (event !== "push" || ref !== "refs/heads/main") {
      violations.add("INVALID_PRODUCTION_REF");
    }
    if (workflow.environmentApproval !== true) {
      violations.add("APPROVAL_REQUIRED");
    }
  }

  const decision = violations.size === 0 ? "promote" : "block";
  return { decision, violations: Array.from(violations) };
}

app.post("/release-gate", (req, res) => {
  try {
    const result = evaluate(req.body || {});
    res.status(200).json(result);
  } catch (err) {
    res.status(400).json({ decision: "block", violations: ["MALFORMED_REQUEST"] });
  }
});

// Simple health check, handy for Render and for sanity-checking deploys.
app.get("/", (_req, res) => {
  res.status(200).send("release-gate service is up");
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`release-gate listening on port ${PORT}`);
  });
}

module.exports = { app, evaluate };
