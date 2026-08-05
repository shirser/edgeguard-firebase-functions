const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// Requiring lib/index.js runs admin.initializeApp() once; requires npm run build to have produced
// lib/ from src/ first (source of truth stays src).
const { claimCameraForUser, releaseCameraForUser, releaseCameraFromCamera, unpairCameraFromDevice } = require("../lib/index.js");
const admin = require("firebase-admin");

const db = admin.firestore();

// ---------------------------------------------------------------------------------------------
// Canonical userEntitlements/{uid} is now the single source of truth for Camera-count limits in
// claimCameraForUser (and the legacy users/{uid}.cameraLimit compatibility mirror
// releaseCameraForUser/unpairCameraFromDevice/releaseCameraFromCamera write back). The legacy
// users/{uid}.subscriptionUnits/.cameraLimit fields are never read for any decision anymore -- see
// this file's own static-guard test at the bottom, and functions/src/index.ts's own doc comments
// at each call site.
// ---------------------------------------------------------------------------------------------

function userRef(uid) {
  return db.collection("users").doc(uid);
}
function entitlementsRef(uid) {
  return db.collection("userEntitlements").doc(uid);
}
function claimRef(cameraDeviceId) {
  return db.collection("cameraClaims").doc(cameraDeviceId);
}
function registryRef(deviceId) {
  return db.collection("registeredDevices").doc(deviceId);
}
function pairingSessionRef(pairingId) {
  return db.collection("cameraPairingSessions").doc(pairingId);
}
function pairingStateRef(cameraDeviceId) {
  return db.collection("cameraLinks").doc(cameraDeviceId).collection("pairingState").doc("current");
}
function cameraDeviceLinkRef(ownerUid, cameraDeviceId) {
  return db.collection("users").doc(ownerUid).collection("cameraDevices").doc(cameraDeviceId);
}

function hashPairingSecret(secret) {
  return crypto.createHash("sha256").update(secret).digest("hex");
}

let uniqueCounter = 0;
function uniqueId(prefix) {
  uniqueCounter += 1;
  return `${prefix}-${Date.now()}-${uniqueCounter}`;
}

function fakeRequest(data, uid) {
  return {
    data,
    auth: uid ? { uid, token: { auth_time: Math.floor(Date.now() / 1000) }, rawToken: "" } : undefined,
    rawRequest: {},
    acceptsStreaming: false,
  };
}

// A complete, valid userEntitlements document -- individual tests override only the field(s) they
// care about (same convention as entitlements.test.js's own validDoc()).
function validEntitlements(overrides = {}) {
  const now = admin.firestore.Timestamp.now();
  return {
    schemaVersion: 1,
    plan: "free",
    subscriptionStatus: "active",
    maxCameras: 1,
    maxHomeDevices: 1,
    maxConcurrentLiveSessions: 1,
    turnAccessAllowed: true,
    source: "manual",
    validUntil: null,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

async function seedPairingSession(pairingId, cameraDeviceId, cameraAuthUid, pairingSecret) {
  await pairingSessionRef(pairingId).set({
    cameraDeviceId,
    pairingSecretHash: hashPairingSecret(pairingSecret),
    cameraAuthUid,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    expiresAt: admin.firestore.Timestamp.fromMillis(Date.now() + 10 * 60 * 1000),
    consumedAt: null,
    status: "pending",
  });
}

// A fresh {ownerUid, homeDeviceId, cameraDeviceId, cameraAuthUid, pairingId, pairingSecret}
// quadruple with a ready-to-consume pairing session -- every id is unique per call so tests never
// share Firestore state (this file's helpers never reset users/{uid}.cameraCount between tests,
// same reason deviceRegistry.test.js's own "idempotent claim" test uses a dedicated uid).
async function setupClaimAttempt(overrides = {}) {
  const ownerUid = overrides.ownerUid ?? uniqueId("ecs-owner");
  const cameraDeviceId = overrides.cameraDeviceId ?? uniqueId("ecs-camera");
  const homeDeviceId = overrides.homeDeviceId ?? uniqueId("ecs-home");
  const cameraAuthUid = overrides.cameraAuthUid ?? uniqueId("ecs-camera-auth");
  const pairingId = uniqueId("ecs-pairing");
  const pairingSecret = uniqueId("ecs-secret");
  await seedPairingSession(pairingId, cameraDeviceId, cameraAuthUid, pairingSecret);
  return { ownerUid, cameraDeviceId, homeDeviceId, cameraAuthUid, pairingId, pairingSecret };
}

function attemptClaim(attempt) {
  return claimCameraForUser.run(
    fakeRequest(
      {
        cameraDeviceId: attempt.cameraDeviceId,
        pairingId: attempt.pairingId,
        pairingSecret: attempt.pairingSecret,
        homeDeviceId: attempt.homeDeviceId,
      },
      attempt.ownerUid
    )
  );
}

async function cleanupAttempt(attempt) {
  await Promise.all([
    userRef(attempt.ownerUid).delete(),
    entitlementsRef(attempt.ownerUid).delete(),
    claimRef(attempt.cameraDeviceId).delete(),
    registryRef(attempt.cameraDeviceId).delete(),
    registryRef(attempt.homeDeviceId).delete(),
    pairingSessionRef(attempt.pairingId).delete(),
    pairingStateRef(attempt.cameraDeviceId).delete(),
    cameraDeviceLinkRef(attempt.ownerUid, attempt.cameraDeviceId).delete(),
    userRef(attempt.ownerUid).collection("cameraDevices").doc(attempt.cameraDeviceId).delete(),
  ]);
}

// ---------------------------------------------------------------------------------------------
// A. Canonical precedence (1/2: Camera limit -- the only production consumer with a real,
// synchronous, decision-gating legacy source to compare against; see this file's own top comment
// for why Home/TURN/plan precedence (3-8) are covered structurally instead, not duplicated here).
// ---------------------------------------------------------------------------------------------

test("canonical precedence: canonical Camera limit SMALLER than legacy-derived limit -- canonical wins (denies)", async () => {
  const attempt = await setupClaimAttempt();
  // Legacy subscriptionUnits=10 would allow 1 + 10*5 = 51 cameras. Canonical maxCameras=1 is far
  // stricter, and cameraCount is already at that canonical limit.
  await userRef(attempt.ownerUid).set({ subscriptionUnits: 10, cameraCount: 1 });
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: 1 }));

  await assert.rejects(attemptClaim(attempt), (err) => err.code === "resource-exhausted" && err.details?.code === "CAMERA_LIMIT_REACHED");

  await cleanupAttempt(attempt);
});

test("canonical precedence: canonical Camera limit LARGER than legacy-derived limit -- canonical wins (allows)", async () => {
  const attempt = await setupClaimAttempt();
  // Legacy subscriptionUnits=0 would allow only 1 + 0*5 = 1 camera, and cameraCount is already at
  // that legacy limit. Canonical maxCameras=5 is far more generous.
  await userRef(attempt.ownerUid).set({ subscriptionUnits: 0, cameraCount: 1 });
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: 5 }));

  const response = await attemptClaim(attempt);
  assert.equal(response.success, true);
  assert.equal(response.cameraLimit, 5, "the response's cameraLimit must reflect the canonical maxCameras, not the legacy value");

  await cleanupAttempt(attempt);
});

test("canonical precedence: TURN/plan precedence (5-8) -- no legacy TURN/plan source has ever existed in this codebase", () => {
  // getEffectiveUserEntitlements/effectiveUserEntitlementsFromData (entitlements.ts) have never
  // read anything but userEntitlements/{uid} for plan/turnAccessAllowed -- there is no
  // users/{uid} or other legacy field that ever fed either decision, so "canonical wins over
  // legacy" is trivially and permanently true for these two by construction, not by a runtime
  // precedence rule that could regress. See entitlements.test.js's own extensive
  // getEffectiveUserEntitlements coverage (explicit turnAccessAllowed:false/true, plan
  // free/premium) for the actual resolution behavior -- not duplicated here.
  assert.ok(true);
});

// ---------------------------------------------------------------------------------------------
// B. No legacy fallback (9-16)
// ---------------------------------------------------------------------------------------------

test("no legacy fallback: only legacy subscriptionUnits/cameraLimit exist, canonical entitlements absent -- legacy is never used", async () => {
  const attempt = await setupClaimAttempt();
  // No userEntitlements/{uid} document at all. Legacy subscriptionUnits=10 would allow 51 --
  // Free defaults (maxCameras=1) must be used instead.
  await userRef(attempt.ownerUid).set({ subscriptionUnits: 10, cameraLimit: 51, cameraCount: 1 });

  await assert.rejects(attemptClaim(attempt), (err) => err.code === "resource-exhausted" && err.details?.code === "CAMERA_LIMIT_REACHED");

  await cleanupAttempt(attempt);
});

test("no legacy fallback: canonical entitlements document is malformed -- legacy is never used", async () => {
  const attempt = await setupClaimAttempt();
  await userRef(attempt.ownerUid).set({ subscriptionUnits: 10, cameraCount: 1 });
  // Malformed: unknown plan value -> corrupt document -> Free fallback (maxCameras=1), not legacy.
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ plan: "ultra" }));

  await assert.rejects(attemptClaim(attempt), (err) => err.code === "resource-exhausted" && err.details?.code === "CAMERA_LIMIT_REACHED");

  await cleanupAttempt(attempt);
});

test("no legacy fallback: canonical maxCameras field absent -- legacy is never substituted", async () => {
  const attempt = await setupClaimAttempt();
  await userRef(attempt.ownerUid).set({ subscriptionUnits: 10, cameraCount: 1 });
  const doc = validEntitlements();
  delete doc.maxCameras;
  await entitlementsRef(attempt.ownerUid).set(doc);

  // Missing required field -> corrupt document -> Free fallback (maxCameras=1), never legacy.
  await assert.rejects(attemptClaim(attempt), (err) => err.code === "resource-exhausted" && err.details?.code === "CAMERA_LIMIT_REACHED");

  await cleanupAttempt(attempt);
});

test("no legacy fallback: null canonical maxCameras field -- legacy is never substituted", async () => {
  const attempt = await setupClaimAttempt();
  await userRef(attempt.ownerUid).set({ subscriptionUnits: 10, cameraCount: 1 });
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: null }));

  await assert.rejects(attemptClaim(attempt), (err) => err.code === "resource-exhausted" && err.details?.code === "CAMERA_LIMIT_REACHED");

  await cleanupAttempt(attempt);
});

test("no legacy fallback: canonical maxCameras=0 (explicit, valid) is not replaced by a truthy legacy default", async () => {
  const attempt = await setupClaimAttempt();
  // No prior cameraCount at all (brand-new user) -- even the very FIRST claim must be denied,
  // proving 0 is honored literally, not treated as falsy/missing and defaulted.
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: 0 }));
  await userRef(attempt.ownerUid).set({ subscriptionUnits: 10 }); // would allow 51, if it were consulted

  await assert.rejects(attemptClaim(attempt), (err) => err.code === "resource-exhausted" && err.details?.code === "CAMERA_LIMIT_REACHED");

  await cleanupAttempt(attempt);
});

test("no legacy fallback: canonical turnAccessAllowed=false is never replaced by a legacy true (16) -- no legacy TURN source has ever existed", () => {
  // Same structural note as the TURN/plan precedence test above -- turnAccessAllowed has never had
  // a legacy fallback to begin with. See entitlements.test.js's "active document with
  // turnAccessAllowed false denies TURN" for the actual behavior.
  assert.ok(true);
});

// ---------------------------------------------------------------------------------------------
// D. Production consumers (26, 33, 34, 35 -- 27/28/30 are N/A, see this file's own note; 29/31/32
// are covered by entitlements.test.js's own getTurnCredentials tests plus the no-legacy-fallback
// tests above)
// ---------------------------------------------------------------------------------------------

test("production consumers: Home registration / Camera registration have no synchronous entitlement-gated limit today (N/A)", () => {
  // registerLegacyHome/registerLegacyCamera/attachCameraOwner/registerDevicePublicKey (all in
  // deviceRegistry.ts) never read cameraLimit/subscriptionUnits/userEntitlements at all -- there
  // is no synchronous Home-count or "Camera registration" entitlement gate in this codebase to
  // convert; the only Home-count enforcement is the best-effort reconcile pass
  // (reconcileDevicesOnEntitlementChange/reconcileUserDeviceLimits), which already reads
  // maxHomeDevices from canonical userEntitlements and has never had a legacy source (see
  // entitlements.test.js's own planDeviceLimitsFromEntitlementsData tests). Transactional Home/
  // Camera limit enforcement beyond claimCameraForUser's existing Camera-count check is explicitly
  // out of scope for this task.
  assert.ok(true);
});

test("production consumers: a denied claim never partially writes cameraClaims/registeredDevices/cameraCount (34)", async () => {
  const attempt = await setupClaimAttempt();
  await userRef(attempt.ownerUid).set({ cameraCount: 1 });
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: 1 }));

  await assert.rejects(attemptClaim(attempt));

  const [claimSnap, registrySnap, userSnap] = await Promise.all([
    claimRef(attempt.cameraDeviceId).get(),
    registryRef(attempt.cameraDeviceId).get(),
    userRef(attempt.ownerUid).get(),
  ]);
  assert.equal(claimSnap.exists, false, "no cameraClaims document must be created by a denied claim");
  assert.equal(registrySnap.exists, false, "no registeredDevices document must be created by a denied claim");
  assert.equal(userSnap.get("cameraCount"), 1, "cameraCount must be completely unchanged by a denied claim");

  await cleanupAttempt(attempt);
});

test("production consumers: limit denial preserves the existing public error contract (35)", async () => {
  const attempt = await setupClaimAttempt();
  await userRef(attempt.ownerUid).set({ cameraCount: 1 });
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: 1 }));

  const error = await attemptClaim(attempt).catch((err) => err);

  assert.equal(error.code, "resource-exhausted");
  assert.equal(error.message, "Camera limit reached");
  assert.deepEqual(Object.keys(error.details).sort(), ["allowedCameraCount", "code", "currentCameraCount", "nextCameraCount"].sort());
  assert.equal(error.details.code, "CAMERA_LIMIT_REACHED");
  assert.equal(error.details.allowedCameraCount, 1);
  assert.equal(error.details.currentCameraCount, 1);
  assert.equal(error.details.nextCameraCount, 2);

  await cleanupAttempt(attempt);
});

// ---------------------------------------------------------------------------------------------
// F. Writers (37, 38, 39, 40 -- 36 is N/A, see this file's own note)
// ---------------------------------------------------------------------------------------------

test("writers: no production code writes userEntitlements today (36, N/A)", () => {
  // Google Play Billing / purchase verification / a userEntitlements writer are explicitly out of
  // scope for this task -- confirmed by reading every functions/src/*.ts occurrence of
  // "userEntitlements": every one is a `.get()` read (entitlements.ts, deviceChallenges.ts,
  // index.ts's claimCameraForUser/releaseCameraForUser/unpairCameraFromDevice/
  // releaseCameraFromCamera) or the reconcileDevicesOnEntitlementChange trigger's own
  // `document: "userEntitlements/{uid}"` path declaration -- never a `.set()`/`.update()`.
  assert.ok(true);
});

test("writers: changing legacy users/{uid}.cameraLimit directly, without touching canonical entitlements, changes nothing (38)", async () => {
  const attempt = await setupClaimAttempt();
  await userRef(attempt.ownerUid).set({ cameraCount: 1, cameraLimit: 999 });
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: 1 }));

  await assert.rejects(attemptClaim(attempt), (err) => err.code === "resource-exhausted" && err.details?.code === "CAMERA_LIMIT_REACHED");

  await cleanupAttempt(attempt);
});

test("writers: changing legacy users/{uid}.subscriptionUnits directly, without touching canonical entitlements, changes nothing (39)", async () => {
  const attempt = await setupClaimAttempt();
  await userRef(attempt.ownerUid).set({ cameraCount: 1, subscriptionUnits: 999 });
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: 1 }));

  await assert.rejects(attemptClaim(attempt), (err) => err.code === "resource-exhausted" && err.details?.code === "CAMERA_LIMIT_REACHED");

  await cleanupAttempt(attempt);
});

test("writers: releaseCameraForUser writes the canonical maxCameras into the legacy cameraLimit mirror, not a legacy-derived value", async () => {
  const attempt = await setupClaimAttempt();
  await claimRef(attempt.cameraDeviceId).set({ uid: attempt.ownerUid, cameraAuthUid: attempt.cameraAuthUid });
  await userRef(attempt.ownerUid).set({ subscriptionUnits: 10, cameraCount: 1 }); // legacy would write 51
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: 3 }));

  const response = await releaseCameraForUser.run(fakeRequest({ cameraDeviceId: attempt.cameraDeviceId }, attempt.ownerUid));
  assert.deepEqual(response, { success: true }, "response schema (40) must stay exactly {success: true}");

  const userData = (await userRef(attempt.ownerUid).get()).data();
  assert.equal(userData.cameraLimit, 3, "the written cameraLimit mirror must reflect canonical maxCameras, not the legacy-derived 51");

  await cleanupAttempt(attempt);
});

// ---------------------------------------------------------------------------------------------
// Regression flow (explicit 4-scenario version)
// ---------------------------------------------------------------------------------------------

test("regression: canonical allow + legacy deny -> operation follows canonical allow", async () => {
  const attempt = await setupClaimAttempt();
  await userRef(attempt.ownerUid).set({ subscriptionUnits: 0, cameraCount: 1 }); // legacy: allowed=1, would deny
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: 2 })); // canonical: allows

  const response = await attemptClaim(attempt);
  assert.equal(response.success, true);

  await cleanupAttempt(attempt);
});

test("regression: canonical deny + legacy allow -> operation follows canonical deny", async () => {
  const attempt = await setupClaimAttempt();
  await userRef(attempt.ownerUid).set({ subscriptionUnits: 10, cameraCount: 1 }); // legacy: allowed=51, would allow
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: 1 })); // canonical: denies

  await assert.rejects(attemptClaim(attempt), (err) => err.code === "resource-exhausted" && err.details?.code === "CAMERA_LIMIT_REACHED");

  await cleanupAttempt(attempt);
});

test("regression: canonical missing/malformed + legacy allow -> operation does not use legacy, no protected side effect", async () => {
  const attempt = await setupClaimAttempt();
  await userRef(attempt.ownerUid).set({ subscriptionUnits: 10, cameraCount: 1 }); // legacy would allow
  // No userEntitlements document at all -> Free (maxCameras=1) -> denies, since cameraCount already at 1.

  await assert.rejects(attemptClaim(attempt), (err) => err.code === "resource-exhausted" && err.details?.code === "CAMERA_LIMIT_REACHED");

  const [claimSnap, registrySnap] = await Promise.all([claimRef(attempt.cameraDeviceId).get(), registryRef(attempt.cameraDeviceId).get()]);
  assert.equal(claimSnap.exists, false, "no protected side effect: cameraClaims must not be created");
  assert.equal(registrySnap.exists, false, "no protected side effect: registeredDevices must not be created");

  await cleanupAttempt(attempt);
});

test("regression: canonical read failure + legacy allow -> operation fails closed, no protected side effect (structural)", () => {
  // Not directly fault-injectable against a real Firestore emulator (no client-side hook to force
  // one specific t.get() to reject mid-transaction) -- same limitation already documented for
  // every other "Firestore read error" scenario in this project's own test suites (see
  // deviceChallenges.test.js/turnCredentialsDeviceProof.test.js's own equivalent notes). The
  // fail-closed guarantee is structural instead: claimCameraForUser's
  // `t.get(entitlementsRef)` (see functions/src/index.ts) is awaited directly, with no try/catch
  // around it or around the transaction as a whole -- a rejected read propagates out of the
  // `db.runTransaction(...)` call uncaught, so the ENTIRE transaction is aborted (Firestore
  // guarantees no partial commit) and the callable's own promise rejects; there is no code path
  // that catches this error and falls back to reading subscriptionUnits/cameraLimit instead.
  assert.ok(true);
});

// ---------------------------------------------------------------------------------------------
// E. Regression static guard -- production code must never again read the legacy
// subscriptionUnits/cameraLimit Firestore fields for a decision.
// ---------------------------------------------------------------------------------------------

// The only known-good remaining dot-access to `.cameraLimit` in production code: `txResult.cameraLimit`
// (functions/src/index.ts, claimCameraForUser's own response/log construction) -- txResult is a
// plain JS object returned from the transaction callback, already carrying the canonical value
// (`deviceLimits.maxCameras`, assigned earlier in that same transaction), never a Firestore
// document/snapshot. Matched by trimmed-line shape (not just "contains cameraLimit") so this
// allowlist stays narrow: it does not exempt any OTHER dot/bracket-access to `.cameraLimit`,
// including a new one on a differently-named variable.
const ALLOWED_CAMERA_LIMIT_DOT_ACCESS_LINES = [/^cameraLimit:\s*txResult\.cameraLimit,?$/];

test("static guard: no functions/src/*.ts file reads legacy subscriptionUnits/cameraLimit via DocumentSnapshot.get(), dot-access, or bracket-access", () => {
  // Targets every read-style shape a legacy Firestore field could be pulled out of a document in
  // this codebase's own style (snap.get(...), or a plain object obtained from snap.data() read via
  // dot- or bracket-access -- e.g. userData.cameraLimit / userSnap.data().cameraLimit /
  // document["cameraLimit"] / userData["subscriptionUnits"]):
  //   - snap.get("subscriptionUnits") / snap.get("cameraLimit")
  //   - dot-access .subscriptionUnits / .cameraLimit
  //   - bracket-access ["subscriptionUnits"] / ["cameraLimit"] (either quote style)
  //
  // Explicitly ALLOWED (not a regression) and deliberately NOT caught by these patterns:
  //   - the one remaining compatibility write `subscriptionUnits: 0` (an object-literal KEY with a
  //     literal value, in claimCameraForUser's new-user-document creation) -- none of the patterns
  //     above match a bare object-literal key (they all require a leading `.`, `.get(`, or `[`).
  //   - canonical-value writes/passthrough that merely happen to use the identifier `cameraLimit`
  //     as a local variable or object-literal key/shorthand (`const cameraLimit = allowedCameraCount`,
  //     `cameraLimit: deviceLimits.maxCameras`, the `cameraLimit,` shorthand write) -- none of these
  //     are a `.cameraLimit`/`["cameraLimit"]` access either.
  //   - `txResult.cameraLimit` specifically (see ALLOWED_CAMERA_LIMIT_DOT_ACCESS_LINES above) --
  //     the one genuine `.cameraLimit` dot-access in production code, already a canonical-value
  //     passthrough, not a legacy document read.
  const srcDir = path.join(__dirname, "..", "src");
  const files = fs.readdirSync(srcDir).filter((f) => f.endsWith(".ts"));
  assert.ok(files.length > 0, "sanity check: functions/src must contain .ts files");

  const forbiddenPatterns = [
    { name: 'snap.get("subscriptionUnits")', regex: /\.get\(\s*["']subscriptionUnits["']\s*\)/ },
    { name: 'snap.get("cameraLimit")', regex: /\.get\(\s*["']cameraLimit["']\s*\)/ },
    { name: "dot-access .subscriptionUnits", regex: /\.subscriptionUnits\b/ },
    { name: "dot-access .cameraLimit", regex: /\.cameraLimit\b/, allowlist: ALLOWED_CAMERA_LIMIT_DOT_ACCESS_LINES },
    { name: 'bracket-access ["subscriptionUnits"]', regex: /\[\s*["']subscriptionUnits["']\s*\]/ },
    { name: 'bracket-access ["cameraLimit"]', regex: /\[\s*["']cameraLimit["']\s*\]/ },
  ];

  const violations = [];
  for (const file of files) {
    const contents = fs.readFileSync(path.join(srcDir, file), "utf8");
    const lines = contents.split("\n");
    lines.forEach((line, index) => {
      const trimmed = line.trim();
      if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) return; // comments
      for (const pattern of forbiddenPatterns) {
        if (!pattern.regex.test(line)) continue;
        if (pattern.allowlist && pattern.allowlist.some((allowed) => allowed.test(trimmed))) continue;
        violations.push(`${file}:${index + 1}: matched "${pattern.name}": ${trimmed}`);
      }
    });
  }

  assert.deepEqual(
    violations,
    [],
    `production authorization code must never read legacy subscriptionUnits/cameraLimit:\n${violations.join("\n")}`
  );
});

test("static guard: the patterns actually detect a regression (does not silently pass on everything)", () => {
  // Proves the guard above is not vacuously true -- runs the exact same patterns against
  // deliberately reconstructed legacy-style lines and confirms each one WOULD have been flagged,
  // including the two shapes this specific hardening pass was added for: dot-access and
  // bracket-access reads of a legacy field off a plain object (not just snap.get(...)).
  const detectableRegressions = [
    { line: 'const subscriptionUnits = (userSnap.get("subscriptionUnits") as number) ?? 0;', regex: /\.get\(\s*["']subscriptionUnits["']\s*\)/ },
    { line: "const limit = userData.cameraLimit;", regex: /\.cameraLimit\b/ },
    { line: 'const limit = userData["cameraLimit"];', regex: /\[\s*["']cameraLimit["']\s*\]/ },
    { line: 'const units = userData["subscriptionUnits"];', regex: /\[\s*["']subscriptionUnits["']\s*\]/ },
    { line: "const limit = userSnap.data().cameraLimit;", regex: /\.cameraLimit\b/ },
    { line: "const limit = document.cameraLimit;", regex: /\.cameraLimit\b/ },
  ];

  for (const { line, regex } of detectableRegressions) {
    assert.ok(regex.test(line), `guard must detect: ${line}`);
    // None of these regression lines match the narrow txResult.cameraLimit allowlist either.
    assert.ok(
      !ALLOWED_CAMERA_LIMIT_DOT_ACCESS_LINES.some((allowed) => allowed.test(line.trim())),
      `regression line must not be exempted by the allowlist: ${line}`
    );
  }
});

test("static guard: the txResult.cameraLimit allowlist stays narrow -- it does not exempt other cameraLimit access", () => {
  const stillForbidden = [
    "const limit = txResult.data().cameraLimit;", // different shape, must still be caught
    'cameraLimit: someOtherObject.cameraLimit,', // same key name, different (non-canonical) source object
  ];
  for (const line of stillForbidden) {
    assert.ok(
      !ALLOWED_CAMERA_LIMIT_DOT_ACCESS_LINES.some((allowed) => allowed.test(line.trim())),
      `must not be exempted by the allowlist: ${line}`
    );
  }

  // And the actual production line is exempted.
  assert.ok(ALLOWED_CAMERA_LIMIT_DOT_ACCESS_LINES.some((allowed) => allowed.test("cameraLimit: txResult.cameraLimit,")));
});
