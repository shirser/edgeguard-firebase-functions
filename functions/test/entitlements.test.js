const test = require("node:test");
const assert = require("node:assert/strict");

// Requiring lib/index.js runs admin.initializeApp() once; requires npm run
// build to have produced lib/ from src/ first (source of truth stays src).
const {
  getEffectiveUserEntitlements,
  getTurnCredentials,
  isUserEntitlementsExpired,
} = require("../lib/index.js");
const admin = require("firebase-admin");

const db = admin.firestore();

function entitlementsRef(uid) {
  return db.collection("userEntitlements").doc(uid);
}

function timestampInMillis(millis) {
  return admin.firestore.Timestamp.fromMillis(millis);
}

// A complete, valid document -- individual tests override only the field(s)
// they care about, so every test stays focused on the one rule it exercises
// instead of restating the full shape each time.
function validDoc(overrides = {}) {
  const now = admin.firestore.Timestamp.now();
  return {
    schemaVersion: 1,
    plan: "premium",
    subscriptionStatus: "active",
    maxCameras: 5,
    maxHomeDevices: 5,
    maxConcurrentLiveSessions: 2,
    turnAccessAllowed: true,
    source: "manual",
    validUntil: null,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

test.afterEach(async () => {
  const snap = await db.collection("userEntitlements").listDocuments();
  await Promise.all(snap.map((ref) => ref.delete()));
});

// --- 1. no document -> Free defaults -----------------------------------

test("getEffectiveUserEntitlements: no document returns Free defaults", async () => {
  const result = await getEffectiveUserEntitlements("uid-no-doc", db);

  assert.deepEqual(result, {
    plan: "free",
    subscriptionStatus: "active",
    maxCameras: 1,
    maxHomeDevices: 1,
    maxConcurrentLiveSessions: 1,
    turnAccessAllowed: true,
  });
});

// --- 2/3. active Premium (no validUntil / future validUntil) -----------

test("getEffectiveUserEntitlements: active Premium with validUntil null returns Premium", async () => {
  const uid = "uid-premium-no-expiry";
  await entitlementsRef(uid).set(validDoc());

  const result = await getEffectiveUserEntitlements(uid, db);

  assert.equal(result.plan, "premium");
  assert.equal(result.subscriptionStatus, "active");
  assert.equal(result.maxCameras, 5);
  assert.equal(result.maxHomeDevices, 5);
  assert.equal(result.maxConcurrentLiveSessions, 2);
  assert.equal(result.turnAccessAllowed, true);
});

test("getEffectiveUserEntitlements: active Premium with a future validUntil returns Premium", async () => {
  const uid = "uid-premium-future-expiry";
  await entitlementsRef(uid).set(
    validDoc({ validUntil: timestampInMillis(Date.now() + 60 * 60 * 1000) })
  );

  const result = await getEffectiveUserEntitlements(uid, db);

  assert.equal(result.plan, "premium");
  assert.equal(result.maxCameras, 5);
});

// --- 4/5. expired -> Free ------------------------------------------------

test("getEffectiveUserEntitlements: Premium with a past validUntil returns Free", async () => {
  const uid = "uid-premium-expired-by-date";
  await entitlementsRef(uid).set(
    validDoc({ validUntil: timestampInMillis(Date.now() - 60 * 60 * 1000) })
  );

  const result = await getEffectiveUserEntitlements(uid, db);

  assert.equal(result.plan, "free");
  assert.equal(result.maxCameras, 1);
  assert.equal(result.turnAccessAllowed, true);
});

test("getEffectiveUserEntitlements: subscriptionStatus expired returns Free regardless of validUntil", async () => {
  const uid = "uid-status-expired";
  await entitlementsRef(uid).set(
    validDoc({ subscriptionStatus: "expired", validUntil: null })
  );

  const result = await getEffectiveUserEntitlements(uid, db);

  assert.equal(result.plan, "free");
  assert.equal(result.maxCameras, 1);
});

// --- 6. blocked -> TURN denied, limits zeroed -----------------------------

test("getEffectiveUserEntitlements: blocked zeroes all limits and denies TURN", async () => {
  const uid = "uid-blocked";
  await entitlementsRef(uid).set(
    validDoc({ subscriptionStatus: "blocked", turnAccessAllowed: true, maxCameras: 5 })
  );

  const result = await getEffectiveUserEntitlements(uid, db);

  assert.equal(result.subscriptionStatus, "blocked");
  assert.equal(result.maxCameras, 0);
  assert.equal(result.maxHomeDevices, 0);
  assert.equal(result.maxConcurrentLiveSessions, 0);
  assert.equal(result.turnAccessAllowed, false);
});

// --- 7. explicit TURN deny on an otherwise-active document survives ------

test("getEffectiveUserEntitlements: active document with turnAccessAllowed false denies TURN", async () => {
  const uid = "uid-active-turn-denied";
  await entitlementsRef(uid).set(validDoc({ turnAccessAllowed: false }));

  const result = await getEffectiveUserEntitlements(uid, db);

  assert.equal(result.subscriptionStatus, "active");
  assert.equal(result.turnAccessAllowed, false);
  // The rest of the stored grant is otherwise honored -- only TURN is denied.
  assert.equal(result.maxCameras, 5);
});

// --- 8/9. corrupt: negative / fractional limit ----------------------------

test("getEffectiveUserEntitlements: negative limit is treated as a corrupt document -> Free", async () => {
  const uid = "uid-negative-limit";
  await entitlementsRef(uid).set(validDoc({ maxCameras: -1 }));

  const result = await getEffectiveUserEntitlements(uid, db);

  assert.deepEqual(result, {
    plan: "free",
    subscriptionStatus: "active",
    maxCameras: 1,
    maxHomeDevices: 1,
    maxConcurrentLiveSessions: 1,
    turnAccessAllowed: true,
  });
});

test("getEffectiveUserEntitlements: fractional limit is treated as a corrupt document -> Free", async () => {
  const uid = "uid-fractional-limit";
  await entitlementsRef(uid).set(validDoc({ maxConcurrentLiveSessions: 1.5 }));

  const result = await getEffectiveUserEntitlements(uid, db);

  assert.equal(result.plan, "free");
  assert.equal(result.maxConcurrentLiveSessions, 1);
});

// --- 10. unknown plan -> Free ----------------------------------------------

test("getEffectiveUserEntitlements: unknown plan is treated as a corrupt document -> Free", async () => {
  const uid = "uid-unknown-plan";
  await entitlementsRef(uid).set(validDoc({ plan: "ultra" }));

  const result = await getEffectiveUserEntitlements(uid, db);

  assert.equal(result.plan, "free");
});

// --- 11. unknown schemaVersion -> Free --------------------------------------

test("getEffectiveUserEntitlements: unknown schemaVersion is treated as a corrupt document -> Free", async () => {
  const uid = "uid-unknown-schema-version";
  await entitlementsRef(uid).set(validDoc({ schemaVersion: 2 }));

  const result = await getEffectiveUserEntitlements(uid, db);

  assert.equal(result.plan, "free");
});

// --- 12. invalid validUntil type -> Free ------------------------------------

test("getEffectiveUserEntitlements: non-Timestamp validUntil is treated as a corrupt document -> Free", async () => {
  const uid = "uid-invalid-valid-until-type";
  await entitlementsRef(uid).set(validDoc({ validUntil: "2099-01-01" }));

  const result = await getEffectiveUserEntitlements(uid, db);

  assert.equal(result.plan, "free");
});

// --- createdAt/updatedAt: required, must be a Firestore Timestamp ----------

test("getEffectiveUserEntitlements: missing createdAt is treated as a corrupt document -> Free", async () => {
  const uid = "uid-missing-created-at";
  const doc = validDoc();
  delete doc.createdAt;
  await entitlementsRef(uid).set(doc);

  const result = await getEffectiveUserEntitlements(uid, db);

  assert.deepEqual(result, {
    plan: "free",
    subscriptionStatus: "active",
    maxCameras: 1,
    maxHomeDevices: 1,
    maxConcurrentLiveSessions: 1,
    turnAccessAllowed: true,
  });
});

test("getEffectiveUserEntitlements: missing updatedAt is treated as a corrupt document -> Free", async () => {
  const uid = "uid-missing-updated-at";
  const doc = validDoc();
  delete doc.updatedAt;
  await entitlementsRef(uid).set(doc);

  const result = await getEffectiveUserEntitlements(uid, db);

  assert.equal(result.plan, "free");
});

test("getEffectiveUserEntitlements: createdAt of the wrong type is treated as a corrupt document -> Free", async () => {
  const uid = "uid-invalid-created-at-type";
  await entitlementsRef(uid).set(validDoc({ createdAt: Date.now() }));

  const result = await getEffectiveUserEntitlements(uid, db);

  assert.equal(result.plan, "free");
});

test("getEffectiveUserEntitlements: updatedAt of the wrong type is treated as a corrupt document -> Free", async () => {
  const uid = "uid-invalid-updated-at-type";
  await entitlementsRef(uid).set(validDoc({ updatedAt: "2099-01-01" }));

  const result = await getEffectiveUserEntitlements(uid, db);

  assert.equal(result.plan, "free");
});

// --- validUntil boundary: exactly "now" counts as expired, not active ------
//
// getEffectiveUserEntitlements itself always uses the real clock (a
// Firestore round-trip between setting the document and reading it back
// makes it impossible to land validUntil and Date.now() on the exact same
// millisecond from the outside), so the deterministic boundary check below
// exercises the same isExpired() rule directly with an injected `now` --
// same pattern as index.ts's buildTurnCredentialsResponse(nowSeconds).

test("isUserEntitlementsExpired: validUntil exactly equal to now is expired (<=, not <)", () => {
  const nowMillis = 1_800_000_000_000;
  const stored = {
    subscriptionStatus: "active",
    validUntil: timestampInMillis(nowMillis),
  };

  assert.equal(isUserEntitlementsExpired(stored, nowMillis), true);
});

test("isUserEntitlementsExpired: validUntil one millisecond in the future is active", () => {
  const nowMillis = 1_800_000_000_000;
  const stored = {
    subscriptionStatus: "active",
    validUntil: timestampInMillis(nowMillis + 1),
  };

  assert.equal(isUserEntitlementsExpired(stored, nowMillis), false);
});

test("getEffectiveUserEntitlements: validUntil in the past (end-to-end via the emulator) returns Free", async () => {
  const uid = "uid-valid-until-just-past";
  await entitlementsRef(uid).set(validDoc({ validUntil: timestampInMillis(Date.now() - 1) }));

  const result = await getEffectiveUserEntitlements(uid, db);

  assert.equal(result.plan, "free");
  assert.equal(result.maxCameras, 1);
});

// A few additional corruption rules not explicitly numbered in the spec but
// covered by the same "Corrupt document" section of docs/USER_ENTITLEMENTS.md.

test("getEffectiveUserEntitlements: unknown subscriptionStatus is treated as a corrupt document -> Free", async () => {
  const uid = "uid-unknown-status";
  await entitlementsRef(uid).set(validDoc({ subscriptionStatus: "pending" }));

  assert.equal((await getEffectiveUserEntitlements(uid, db)).plan, "free");
});

test("getEffectiveUserEntitlements: unknown source is treated as a corrupt document -> Free", async () => {
  const uid = "uid-unknown-source";
  await entitlementsRef(uid).set(validDoc({ source: "referral" }));

  assert.equal((await getEffectiveUserEntitlements(uid, db)).plan, "free");
});

test("getEffectiveUserEntitlements: missing required field is treated as a corrupt document -> Free", async () => {
  const uid = "uid-missing-field";
  const doc = validDoc();
  delete doc.turnAccessAllowed;
  await entitlementsRef(uid).set(doc);

  assert.equal((await getEffectiveUserEntitlements(uid, db)).plan, "free");
});

// --- 13/14. getTurnCredentials enforcement ----------------------------------

const CAMERA_ID = "camera-entitlements-test";
const OWNER_UID = "home-owner-entitlements-uid";
const CAMERA_AUTH_UID = "camera-auth-entitlements-uid";

function claimRef() {
  return db.collection("cameraClaims").doc(CAMERA_ID);
}

function fakeRequest(data, uid) {
  return {
    data,
    auth: uid ? { uid, token: {}, rawToken: "" } : undefined,
    rawRequest: {},
    acceptsStreaming: false,
  };
}

test.afterEach(async () => {
  await claimRef().delete();
  delete process.env.TURN_REST_SECRET;
});

test("getTurnCredentials: does not issue credentials when TURN access is denied (blocked)", async () => {
  process.env.TURN_REST_SECRET = "entitlements-test-secret";
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });
  await entitlementsRef(OWNER_UID).set(validDoc({ subscriptionStatus: "blocked" }));

  await assert.rejects(
    getTurnCredentials.run(fakeRequest({ cameraDeviceId: CAMERA_ID, purpose: "LIVE_VIEW" }, OWNER_UID)),
    (err) => err.code === "permission-denied" && err.message === "TURN_ACCESS_DENIED"
  );
});

test("getTurnCredentials: does not issue credentials when turnAccessAllowed is explicitly false", async () => {
  process.env.TURN_REST_SECRET = "entitlements-test-secret";
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });
  await entitlementsRef(OWNER_UID).set(validDoc({ turnAccessAllowed: false }));

  await assert.rejects(
    getTurnCredentials.run(fakeRequest({ cameraDeviceId: CAMERA_ID, purpose: "LIVE_VIEW" }, OWNER_UID)),
    (err) => err.code === "permission-denied" && err.message === "TURN_ACCESS_DENIED"
  );
});

test("getTurnCredentials: a missing entitlements document does not break an existing Free user", async () => {
  process.env.TURN_REST_SECRET = "entitlements-test-secret";
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });
  // Deliberately no userEntitlements/{OWNER_UID} document at all.

  const response = await getTurnCredentials.run(
    fakeRequest({ cameraDeviceId: CAMERA_ID, purpose: "LIVE_VIEW" }, OWNER_UID)
  );

  assert.equal(response.iceServers.length, 1);
  assert.match(response.iceServers[0].username, new RegExp(`^\\d+:${OWNER_UID}$`));
});

// --- 15. secret/credentials never appear in warning/error logs -------------
// firebase-functions/logger writes via the *original* console.debug/info/
// log/warn/error functions captured at module load (UNPATCHED_CONSOLE in
// firebase-functions/lib/logger/common.js), so patching console.* here
// would not intercept it -- but those original functions still write
// through process.stdout/stderr's own .write() at call time, so patching
// that (and restoring it immediately after) does. No new dependency, no
// shared test infrastructure -- self-contained in this one test.
async function captureStdio(fn) {
  const originalStdoutWrite = process.stdout.write.bind(process.stdout);
  const originalStderrWrite = process.stderr.write.bind(process.stderr);
  const lines = [];
  process.stdout.write = (chunk, ...args) => {
    lines.push(String(chunk));
    return originalStdoutWrite(chunk, ...args);
  };
  process.stderr.write = (chunk, ...args) => {
    lines.push(String(chunk));
    return originalStderrWrite(chunk, ...args);
  };
  try {
    await fn();
  } finally {
    process.stdout.write = originalStdoutWrite;
    process.stderr.write = originalStderrWrite;
  }
  return lines.join("\n");
}

test("logs: TURN secret and issued credentials never appear in warning/error logs for a denied request", async () => {
  const secret = "must-never-be-logged-secret";
  process.env.TURN_REST_SECRET = secret;
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });
  await entitlementsRef(OWNER_UID).set(validDoc({ turnAccessAllowed: false }));

  const output = await captureStdio(async () => {
    await assert.rejects(
      getTurnCredentials.run(fakeRequest({ cameraDeviceId: CAMERA_ID, purpose: "LIVE_VIEW" }, OWNER_UID)),
      (err) => err.code === "permission-denied"
    );
  });

  assert.ok(!output.includes(secret), "raw TURN_REST_SECRET value must never be logged");
});

test("logs: corrupt entitlements document warning never contains the uid", async () => {
  const uid = "uid-corrupt-log-check-no-uid";
  await entitlementsRef(uid).set(validDoc({ plan: "ultra" }));

  const output = await captureStdio(async () => {
    await getEffectiveUserEntitlements(uid, db);
  });

  assert.ok(output.includes("USER_ENTITLEMENTS_CORRUPT_DOCUMENT_FALLBACK_FREE"), "the warning should still fire");
  assert.ok(!output.includes(uid), "the uid must never appear in the corrupt-document warning");
});

test("logs: corrupt entitlements document warning never leaks raw document field values", async () => {
  const uid = "uid-corrupt-log-check-no-data";
  const suspiciousValue = "sh0uld-never-appear-in-logs";
  await entitlementsRef(uid).set(validDoc({ plan: suspiciousValue }));

  const output = await captureStdio(async () => {
    await getEffectiveUserEntitlements(uid, db);
  });

  // plan is invalid so classification stops at INVALID_PLAN -- only that
  // fixed reason code (and, if present/safe, schemaVersion) may appear,
  // never the actual invalid value that was stored.
  assert.ok(output.includes("INVALID_PLAN"), "the fixed corruption-reason enum value should be logged");
  assert.ok(!output.includes(suspiciousValue), "raw corrupt field values must never be logged");
  assert.ok(!output.includes(uid), "the uid must never appear in the corrupt-document warning either");
});
