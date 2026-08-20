const assert = require("assert");
const { evaluate } = require("../server.js");

function basePayload(overrides = {}) {
  return {
    target: "preview",
    event: "pull_request",
    ref: "refs/heads/feature/x",
    workflow: {
      trigger: "pull_request",
      permissions: { contents: "read", packages: "write", "id-token": "none" },
      testsPassed: true,
      matrixComplete: true,
      failFast: false,
      actions: [{ owner: "actions", name: "checkout", ref: "v4" }],
    },
    image: {
      multiStage: true,
      runsAsRoot: false,
      secretMode: "none",
      criticalVulnerabilities: 0,
      digestPinned: true,
    },
    ...overrides,
  };
}

let passed = 0;
let failed = 0;

function check(name, fn) {
  try {
    fn();
    console.log(`PASS: ${name}`);
    passed++;
  } catch (err) {
    console.error(`FAIL: ${name}`);
    console.error(err.message);
    failed++;
  }
}

check("safe preview PR -> promote", () => {
  const r = evaluate(basePayload());
  assert.strictEqual(r.decision, "promote");
  assert.deepStrictEqual(r.violations, []);
});

check("safe production push -> promote", () => {
  const r = evaluate(
    basePayload({
      target: "production",
      event: "push",
      ref: "refs/heads/main",
      workflow: {
        ...basePayload().workflow,
        trigger: "push",
        environmentApproval: true,
      },
    })
  );
  assert.strictEqual(r.decision, "promote");
  assert.deepStrictEqual(r.violations, []);
});

check("extra permission scope -> EXCESS_PERMISSION", () => {
  const p = basePayload();
  p.workflow.permissions = { ...p.workflow.permissions, actions: "write" };
  const r = evaluate(p);
  assert.strictEqual(r.decision, "block");
  assert.ok(r.violations.includes("EXCESS_PERMISSION"));
});

check("pull_request_target -> UNSAFE_PR_TRIGGER", () => {
  const p = basePayload();
  p.workflow.trigger = "pull_request_target";
  const r = evaluate(p);
  assert.ok(r.violations.includes("UNSAFE_PR_TRIGGER"));
});

check("failFast true -> TESTS_INCOMPLETE", () => {
  const p = basePayload();
  p.workflow.failFast = true;
  const r = evaluate(p);
  assert.ok(r.violations.includes("TESTS_INCOMPLETE"));
});

check("unpinned third-party action -> MUTABLE_ACTION", () => {
  const p = basePayload();
  p.workflow.actions.push({ owner: "docker", name: "build-push-action", ref: "v5" });
  const r = evaluate(p);
  assert.ok(r.violations.includes("MUTABLE_ACTION"));
});

check("pinned third-party action -> no MUTABLE_ACTION", () => {
  const p = basePayload();
  p.workflow.actions.push({
    owner: "docker",
    name: "build-push-action",
    ref: "a".repeat(40),
  });
  const r = evaluate(p);
  assert.ok(!r.violations.includes("MUTABLE_ACTION"));
});

check("single stage image -> SINGLE_STAGE_IMAGE", () => {
  const p = basePayload();
  p.image.multiStage = false;
  const r = evaluate(p);
  assert.ok(r.violations.includes("SINGLE_STAGE_IMAGE"));
});

check("root runtime -> ROOT_RUNTIME", () => {
  const p = basePayload();
  p.image.runsAsRoot = true;
  const r = evaluate(p);
  assert.ok(r.violations.includes("ROOT_RUNTIME"));
});

check("secret via ARG -> SECRET_IN_LAYER", () => {
  const p = basePayload();
  p.image.secretMode = "arg";
  const r = evaluate(p);
  assert.ok(r.violations.includes("SECRET_IN_LAYER"));
});

check("secret via buildkit -> allowed", () => {
  const p = basePayload();
  p.image.secretMode = "buildkit";
  const r = evaluate(p);
  assert.ok(!r.violations.includes("SECRET_IN_LAYER"));
});

check("critical CVEs present -> CRITICAL_CVE", () => {
  const p = basePayload();
  p.image.criticalVulnerabilities = 2;
  const r = evaluate(p);
  assert.ok(r.violations.includes("CRITICAL_CVE"));
});

check("not digest pinned -> UNPINNED_IMAGE", () => {
  const p = basePayload();
  p.image.digestPinned = false;
  const r = evaluate(p);
  assert.ok(r.violations.includes("UNPINNED_IMAGE"));
});

check("production off main -> INVALID_PRODUCTION_REF", () => {
  const p = basePayload({
    target: "production",
    event: "push",
    ref: "refs/heads/release",
  });
  p.workflow.trigger = "push";
  p.workflow.environmentApproval = true;
  const r = evaluate(p);
  assert.ok(r.violations.includes("INVALID_PRODUCTION_REF"));
});

check("production without approval -> APPROVAL_REQUIRED", () => {
  const p = basePayload({
    target: "production",
    event: "push",
    ref: "refs/heads/main",
  });
  p.workflow.trigger = "push";
  p.workflow.environmentApproval = false;
  const r = evaluate(p);
  assert.ok(r.violations.includes("APPROVAL_REQUIRED"));
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
