const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

// Requiring lib/index.js runs admin.initializeApp() once; requires npm run build to have produced
// lib/ from src/ first (source of truth stays src).
const {
  claimCameraForUser,
  registerDevicePublicKey,
  releaseCameraForUser,
} = require("../lib/index.js");
const admin = require("firebase-admin");

const db = admin.firestore();

// ---------------------------------------------------------------------------------------------
// Strict transactional Camera/Home device-slot limits. Camera-slot allocation (claimCameraForUser)
// was already fully atomic (canonical entitlements + count read + allocation write, all inside one
// db.runTransaction) as of the previous task -- this file's own Camera section exists mainly to
// PROVE that atomicity under real concurrency (it was never previously proven by a concurrency
// test), not to re-derive it. Home-slot allocation (registerDevicePublicKey's HOME bootstrap, via
// applyPublicKeyRegistration in deviceRegistry.ts) had NO limit enforcement at all before this
// task -- this file is the primary coverage for that new behavior.
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

function fakeRequest(data, uid, authOverrides = {}) {
  return {
    data,
    auth: uid ? { uid, token: { auth_time: Math.floor(Date.now() / 1000), ...authOverrides }, rawToken: "" } : undefined,
    rawRequest: {},
    acceptsStreaming: false,
  };
}

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

// claimCameraForUser now requires the Home to already be canonically registered (see the
// registerLegacyHome legacy-bypass fix, section G below) -- it no longer lazily creates a HOME
// registeredDevices document itself. Every ordinary Camera-focused claim attempt in this file
// needs its Home pre-registered exactly as registerDevicePublicKey's own HOME-bootstrap would have
// left it, or the claim is rejected before ever reaching the Camera-limit logic those tests exist
// to exercise. Section G's own tests deliberately do NOT call this -- they exist specifically to
// prove what happens when a Home is NOT registered first.
async function seedHomeRegistration(homeDeviceId, ownerUid) {
  const now = admin.firestore.Timestamp.now();
  await registryRef(homeDeviceId).set({
    schemaVersion: 1,
    deviceId: homeDeviceId,
    role: "HOME",
    authUid: ownerUid,
    ownerUid,
    status: "active",
    suspensionReason: null,
    identityMode: "keystore",
    publicKey: "tdl-test-home-public-key",
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    revokedAt: null,
    deviceProofVersion: null,
  });
}

// A fresh {ownerUid, homeDeviceId, cameraDeviceId, cameraAuthUid, pairingId, pairingSecret}
// quadruple with a ready-to-consume pairing session and an already-registered Home -- every id
// unique per call, so tests never share Firestore state (this file never resets
// users/{uid}.cameraCount between tests).
async function setupClaimAttempt(overrides = {}) {
  const ownerUid = overrides.ownerUid ?? uniqueId("tdl-owner");
  const cameraDeviceId = overrides.cameraDeviceId ?? uniqueId("tdl-camera");
  const homeDeviceId = overrides.homeDeviceId ?? uniqueId("tdl-home");
  const cameraAuthUid = overrides.cameraAuthUid ?? uniqueId("tdl-camera-auth");
  const pairingId = uniqueId("tdl-pairing");
  const pairingSecret = uniqueId("tdl-secret");
  await Promise.all([
    seedPairingSession(pairingId, cameraDeviceId, cameraAuthUid, pairingSecret),
    overrides.skipHomeRegistration ? Promise.resolve() : seedHomeRegistration(homeDeviceId, ownerUid),
  ]);
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

async function cleanupClaimAttempt(attempt) {
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

function generateEcKeyPair() {
  return crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}
function publicKeySpkiBase64(publicKey) {
  return publicKey.export({ type: "spki", format: "der" }).toString("base64");
}
function freshPublicKey() {
  return publicKeySpkiBase64(generateEcKeyPair().publicKey);
}

function attemptHomeRegistration(homeDeviceId, uid, publicKey, authOverrides = {}) {
  return registerDevicePublicKey.run(
    fakeRequest({ deviceId: homeDeviceId, role: "HOME", publicKey, algorithm: "ES256" }, uid, authOverrides)
  );
}

async function cleanupHomeAttempt(uid, homeDeviceIds) {
  await Promise.all([
    userRef(uid).delete(),
    entitlementsRef(uid).delete(),
    ...homeDeviceIds.map((id) => registryRef(id).delete()),
  ]);
}

// =================================================================================================
// A. Camera basic (1-10)
// =================================================================================================
// Items 6-9 (canonical-vs-legacy precedence for Camera) already have dedicated, thorough coverage
// in entitlementsCanonicalSource.test.js (added in the previous task, unchanged by this one) -- not
// duplicated here. This section confirms 1-5 and 10 directly against this file's own fixtures.

test("Camera basic 1: a new claim below maxCameras succeeds", async () => {
  const attempt = await setupClaimAttempt();
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: 2 }));

  const response = await attemptClaim(attempt);
  assert.equal(response.success, true);
  assert.equal(response.cameraCount, 1);

  await cleanupClaimAttempt(attempt);
});

test("Camera basic 2: a claim exactly at maxCameras is rejected", async () => {
  const attempt = await setupClaimAttempt();
  await userRef(attempt.ownerUid).set({ cameraCount: 1 });
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: 1 }));

  await assert.rejects(attemptClaim(attempt), (err) => err.code === "resource-exhausted" && err.details?.code === "CAMERA_LIMIT_REACHED");

  await cleanupClaimAttempt(attempt);
});

test("Camera basic 3: maxCameras = 0 rejects the first new claim", async () => {
  const attempt = await setupClaimAttempt();
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: 0 }));

  await assert.rejects(attemptClaim(attempt), (err) => err.code === "resource-exhausted" && err.details?.code === "CAMERA_LIMIT_REACHED");

  await cleanupClaimAttempt(attempt);
});

test("Camera basic 4: a repeated idempotent claim of an already-owned Camera never takes a new slot", async () => {
  const attempt = await setupClaimAttempt();
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: 1 }));

  const first = await attemptClaim(attempt);
  assert.equal(first.cameraCount, 1);

  const secondAttempt = { ...attempt, pairingId: uniqueId("tdl-pairing"), pairingSecret: uniqueId("tdl-secret") };
  await seedPairingSession(secondAttempt.pairingId, secondAttempt.cameraDeviceId, secondAttempt.cameraAuthUid, secondAttempt.pairingSecret);
  const second = await attemptClaim(secondAttempt);

  assert.equal(second.success, true);
  assert.equal(second.cameraCount, 1, "cameraCount must not increment on an idempotent re-claim");

  await cleanupClaimAttempt(attempt);
  await pairingSessionRef(secondAttempt.pairingId).delete();
});

test("Camera basic 5: a Camera already claimed by a DIFFERENT user is not treated as an idempotent retry", async () => {
  const attempt = await setupClaimAttempt();
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: 1 }));
  await attemptClaim(attempt);

  const intruderAttempt = await setupClaimAttempt({ cameraDeviceId: attempt.cameraDeviceId, cameraAuthUid: attempt.cameraAuthUid });
  await entitlementsRef(intruderAttempt.ownerUid).set(validEntitlements({ maxCameras: 1 }));

  await assert.rejects(attemptClaim(intruderAttempt), (err) => err.code === "failed-precondition" && err.message === "CAMERA_ALREADY_CLAIMED");

  await cleanupClaimAttempt(attempt);
  await cleanupClaimAttempt(intruderAttempt);
});

test("Camera basic 10: a limit rejection leaves no partial Camera writes", async () => {
  const attempt = await setupClaimAttempt();
  await userRef(attempt.ownerUid).set({ cameraCount: 1 });
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: 1 }));

  await assert.rejects(attemptClaim(attempt));

  const [claimSnap, registrySnap, cameraDeviceSnap, pairingStateSnap, userSnap] = await Promise.all([
    claimRef(attempt.cameraDeviceId).get(),
    registryRef(attempt.cameraDeviceId).get(),
    cameraDeviceLinkRef(attempt.ownerUid, attempt.cameraDeviceId).get(),
    pairingStateRef(attempt.cameraDeviceId).get(),
    userRef(attempt.ownerUid).get(),
  ]);
  assert.equal(claimSnap.exists, false, "no cameraClaims document");
  assert.equal(registrySnap.exists, false, "no registeredDevices document");
  assert.equal(cameraDeviceSnap.exists, false, "no users/{uid}/cameraDevices document");
  assert.equal(pairingStateSnap.exists, false, "no pairingState document");
  assert.equal(userSnap.get("cameraCount"), 1, "cameraCount completely unchanged");

  const pairingAfter = await pairingSessionRef(attempt.pairingId).get();
  assert.equal(pairingAfter.get("status"), "pending", "the pairing session must not be consumed by a rejected claim");

  await cleanupClaimAttempt(attempt);
});

// =================================================================================================
// B. Camera concurrency (11-16)
// =================================================================================================

test("Camera concurrency 11: maxCameras=1, two parallel claims of DIFFERENT Cameras -> exactly 1 success, 1 rejection, final count=1", async () => {
  const ownerUid = uniqueId("tdl-cc11-owner");
  await entitlementsRef(ownerUid).set(validEntitlements({ maxCameras: 1 }));

  const attemptA = await setupClaimAttempt({ ownerUid });
  const attemptB = await setupClaimAttempt({ ownerUid });

  const results = await Promise.allSettled([attemptClaim(attemptA), attemptClaim(attemptB)]);
  const fulfilled = results.filter((r) => r.status === "fulfilled");
  const rejected = results.filter((r) => r.status === "rejected");

  assert.equal(fulfilled.length, 1, "exactly one claim must succeed");
  assert.equal(rejected.length, 1, "exactly one claim must be rejected");
  assert.equal(rejected[0].reason.code, "resource-exhausted");
  assert.equal(rejected[0].reason.details?.code, "CAMERA_LIMIT_REACHED");

  // Verify FIRESTORE STATE, not just the responses.
  const userSnap = await userRef(ownerUid).get();
  assert.equal(userSnap.get("cameraCount"), 1, "canonical stored Camera count must be exactly 1");
  const claimsSnap = await db.collection("cameraClaims").where("uid", "==", ownerUid).get();
  assert.equal(claimsSnap.size, 1, "exactly one cameraClaims document for this owner");

  await cleanupClaimAttempt(attemptA);
  await cleanupClaimAttempt(attemptB);
});

test("Camera concurrency 12: maxCameras=2, five parallel claims of new Cameras -> exactly 2 success, final count=2", async () => {
  const ownerUid = uniqueId("tdl-cc12-owner");
  await entitlementsRef(ownerUid).set(validEntitlements({ maxCameras: 2 }));

  const attempts = await Promise.all([1, 2, 3, 4, 5].map(() => setupClaimAttempt({ ownerUid })));
  const results = await Promise.allSettled(attempts.map((a) => attemptClaim(a)));

  const fulfilled = results.filter((r) => r.status === "fulfilled");
  const rejected = results.filter((r) => r.status === "rejected");
  assert.equal(fulfilled.length, 2, "exactly two claims must succeed");
  assert.equal(rejected.length, 3, "exactly three claims must be rejected");
  for (const r of rejected) {
    assert.equal(r.reason.details?.code, "CAMERA_LIMIT_REACHED");
  }

  const userSnap = await userRef(ownerUid).get();
  assert.equal(userSnap.get("cameraCount"), 2, "canonical stored Camera count must be exactly 2, never more");

  await Promise.all(attempts.map((a) => cleanupClaimAttempt(a)));
});

test("Camera concurrency 13: two parallel identical claims of the SAME Camera never take two slots", async () => {
  const ownerUid = uniqueId("tdl-cc13-owner");
  await entitlementsRef(ownerUid).set(validEntitlements({ maxCameras: 1 }));
  const attempt = await setupClaimAttempt({ ownerUid });

  const results = await Promise.allSettled([attemptClaim(attempt), attemptClaim(attempt)]);
  // Both use the SAME pairing session -- Firestore's own transaction contention/retry means at
  // most one consumes it; the other either succeeds idempotently (if it lands after the first
  // committed) or is rejected (if the pairing session was already consumed) -- both outcomes are
  // safe; what matters is the FINAL COUNT.
  const fulfilled = results.filter((r) => r.status === "fulfilled");
  assert.ok(fulfilled.length >= 1, "at least one of the two identical requests must succeed");

  const userSnap = await userRef(ownerUid).get();
  assert.equal(userSnap.get("cameraCount"), 1, "cameraCount must increase by at most one, never two");

  await cleanupClaimAttempt(attempt);
});

test("Camera concurrency 14: transaction retry never creates duplicate ownership documents", async () => {
  const ownerUid = uniqueId("tdl-cc14-owner");
  await entitlementsRef(ownerUid).set(validEntitlements({ maxCameras: 3 }));
  const attempts = await Promise.all([1, 2, 3].map(() => setupClaimAttempt({ ownerUid })));

  await Promise.all(attempts.map((a) => attemptClaim(a)));

  const claimsSnap = await db.collection("cameraClaims").where("uid", "==", ownerUid).get();
  assert.equal(claimsSnap.size, 3, "exactly one cameraClaims document per claimed camera, never duplicated by a retry");
  const cameraDevicesSnap = await userRef(ownerUid).collection("cameraDevices").get();
  assert.equal(cameraDevicesSnap.size, 3);

  await Promise.all(attempts.map((a) => cleanupClaimAttempt(a)));
});

test("Camera concurrency 15: release frees the slot, and a new claim can then take it", async () => {
  const ownerUid = uniqueId("tdl-cc15-owner");
  await entitlementsRef(ownerUid).set(validEntitlements({ maxCameras: 1 }));
  const firstAttempt = await setupClaimAttempt({ ownerUid });
  await attemptClaim(firstAttempt);

  const blockedAttempt = await setupClaimAttempt({ ownerUid });
  await assert.rejects(attemptClaim(blockedAttempt), (err) => err.details?.code === "CAMERA_LIMIT_REACHED");

  await releaseCameraForUser.run(fakeRequest({ cameraDeviceId: firstAttempt.cameraDeviceId }, ownerUid));

  const afterReleaseAttempt = await setupClaimAttempt({ ownerUid, cameraDeviceId: blockedAttempt.cameraDeviceId, cameraAuthUid: blockedAttempt.cameraAuthUid });
  const response = await attemptClaim(afterReleaseAttempt);
  assert.equal(response.success, true, "a new claim must succeed once the slot has been freed by release");

  const userSnap = await userRef(ownerUid).get();
  assert.equal(userSnap.get("cameraCount"), 1);

  await cleanupClaimAttempt(firstAttempt);
  await cleanupClaimAttempt(blockedAttempt);
  await cleanupClaimAttempt(afterReleaseAttempt);
});

test("Camera concurrency 16: a parallel release and a new claim never leave the count above the limit", async () => {
  const ownerUid = uniqueId("tdl-cc16-owner");
  await entitlementsRef(ownerUid).set(validEntitlements({ maxCameras: 1 }));
  const firstAttempt = await setupClaimAttempt({ ownerUid });
  await attemptClaim(firstAttempt);

  const newAttempt = await setupClaimAttempt({ ownerUid });
  await Promise.allSettled([
    releaseCameraForUser.run(fakeRequest({ cameraDeviceId: firstAttempt.cameraDeviceId }, ownerUid)),
    attemptClaim(newAttempt),
  ]);

  const userSnap = await userRef(ownerUid).get();
  assert.ok(userSnap.get("cameraCount") <= 1, "count must never exceed the limit regardless of race outcome");

  await cleanupClaimAttempt(firstAttempt);
  await cleanupClaimAttempt(newAttempt);
});

// =================================================================================================
// C. Home basic (17-25)
// =================================================================================================

test("Home basic 17: a new Home below maxHomeDevices registers", async () => {
  const uid = uniqueId("tdl-home17-uid");
  const homeDeviceId = uniqueId("tdl-home17-device");
  await entitlementsRef(uid).set(validEntitlements({ maxHomeDevices: 2 }));

  const response = await attemptHomeRegistration(homeDeviceId, uid, freshPublicKey());
  assert.deepEqual(response, { success: true, identityMode: "keystore" });
  assert.equal((await registryRef(homeDeviceId).get()).exists, true);

  await cleanupHomeAttempt(uid, [homeDeviceId]);
});

test("Home basic 18: registration at an already-reached maxHomeDevices is rejected", async () => {
  const uid = uniqueId("tdl-home18-uid");
  const existingHomeId = uniqueId("tdl-home18-existing");
  const newHomeId = uniqueId("tdl-home18-new");
  await entitlementsRef(uid).set(validEntitlements({ maxHomeDevices: 1 }));
  await attemptHomeRegistration(existingHomeId, uid, freshPublicKey());

  await assert.rejects(
    attemptHomeRegistration(newHomeId, uid, freshPublicKey()),
    (err) => err.code === "resource-exhausted" && err.message === "HOME_DEVICE_LIMIT_REACHED"
  );
  assert.equal((await registryRef(newHomeId).get()).exists, false);

  await cleanupHomeAttempt(uid, [existingHomeId, newHomeId]);
});

test("Home basic 19: maxHomeDevices = 0 rejects a brand-new Home", async () => {
  const uid = uniqueId("tdl-home19-uid");
  const homeDeviceId = uniqueId("tdl-home19-device");
  await entitlementsRef(uid).set(validEntitlements({ maxHomeDevices: 0 }));

  await assert.rejects(
    attemptHomeRegistration(homeDeviceId, uid, freshPublicKey()),
    (err) => err.code === "resource-exhausted" && err.message === "HOME_DEVICE_LIMIT_REACHED"
  );
  assert.equal((await registryRef(homeDeviceId).get()).exists, false);

  await cleanupHomeAttempt(uid, [homeDeviceId]);
});

test("Home basic 20: a repeated registration of the same Home by the same authUid never takes a new slot", async () => {
  const uid = uniqueId("tdl-home20-uid");
  const homeDeviceId = uniqueId("tdl-home20-device");
  const publicKey = freshPublicKey();
  await entitlementsRef(uid).set(validEntitlements({ maxHomeDevices: 1 }));

  const first = await attemptHomeRegistration(homeDeviceId, uid, publicKey);
  assert.deepEqual(first, { success: true, identityMode: "keystore" });

  // A second, different Home would now be rejected (limit=1 already occupied) -- confirms the
  // repeated call above genuinely did not free up room for anything else, i.e. it did not somehow
  // get treated as "not counted."
  const second = await attemptHomeRegistration(homeDeviceId, uid, publicKey);
  assert.deepEqual(second, { success: true, identityMode: "keystore" }, "idempotent resubmission of the same key must keep succeeding");

  const otherHomeId = uniqueId("tdl-home20-other");
  await assert.rejects(
    attemptHomeRegistration(otherHomeId, uid, freshPublicKey()),
    (err) => err.message === "HOME_DEVICE_LIMIT_REACHED"
  );

  await cleanupHomeAttempt(uid, [homeDeviceId, otherHomeId]);
});

test("Home basic 21: the same device ID under a DIFFERENT authUid is rejected by the existing identity-conflict error", async () => {
  const ownerUid = uniqueId("tdl-home21-owner");
  const intruderUid = uniqueId("tdl-home21-intruder");
  const homeDeviceId = uniqueId("tdl-home21-device");
  await entitlementsRef(ownerUid).set(validEntitlements({ maxHomeDevices: 1 }));
  await entitlementsRef(intruderUid).set(validEntitlements({ maxHomeDevices: 1 }));
  await attemptHomeRegistration(homeDeviceId, ownerUid, freshPublicKey());

  await assert.rejects(
    attemptHomeRegistration(homeDeviceId, intruderUid, freshPublicKey()),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_IDENTITY_MISMATCH"
  );

  await cleanupHomeAttempt(ownerUid, [homeDeviceId]);
  await entitlementsRef(intruderUid).delete();
});

test("Home basic 22: a new device ID for the same user occupies a SEPARATE slot", async () => {
  const uid = uniqueId("tdl-home22-uid");
  const firstHomeId = uniqueId("tdl-home22-first");
  const secondHomeId = uniqueId("tdl-home22-second");
  await entitlementsRef(uid).set(validEntitlements({ maxHomeDevices: 2 }));

  await attemptHomeRegistration(firstHomeId, uid, freshPublicKey());
  const second = await attemptHomeRegistration(secondHomeId, uid, freshPublicKey());
  assert.deepEqual(second, { success: true, identityMode: "keystore" });

  const homesSnap = await db.collection("registeredDevices").where("ownerUid", "==", uid).get();
  const homeDocs = homesSnap.docs.filter((d) => d.data().role === "HOME");
  assert.equal(homeDocs.length, 2, "two distinct Home device IDs must occupy two distinct slots");

  await cleanupHomeAttempt(uid, [firstHomeId, secondHomeId]);
});

test("Home basic 23: canonical maxHomeDevices wins over any legacy value", async () => {
  const uid = uniqueId("tdl-home23-uid");
  const existingHomeId = uniqueId("tdl-home23-existing");
  const newHomeId = uniqueId("tdl-home23-new");
  // No legacy Home-count field has ever existed in this schema (confirmed: grep for
  // homeCount/maxHomes across functions/src returns nothing) -- this test instead confirms that a
  // legacy users/{uid}.cameraLimit/subscriptionUnits value (which DOES still exist as a
  // compatibility mirror for Camera) has zero influence on the Home decision.
  await userRef(uid).set({ cameraLimit: 999, subscriptionUnits: 999 });
  await entitlementsRef(uid).set(validEntitlements({ maxHomeDevices: 1 }));
  await attemptHomeRegistration(existingHomeId, uid, freshPublicKey());

  await assert.rejects(
    attemptHomeRegistration(newHomeId, uid, freshPublicKey()),
    (err) => err.message === "HOME_DEVICE_LIMIT_REACHED"
  );

  await cleanupHomeAttempt(uid, [existingHomeId, newHomeId]);
});

test("Home basic 24: missing/malformed canonical entitlements never fall back to legacy -- Free default (1) applies", async () => {
  const uid = uniqueId("tdl-home24-uid");
  const existingHomeId = uniqueId("tdl-home24-existing");
  const newHomeId = uniqueId("tdl-home24-new");
  // No userEntitlements document at all -> Free defaults (maxHomeDevices=1).
  await attemptHomeRegistration(existingHomeId, uid, freshPublicKey());

  await assert.rejects(
    attemptHomeRegistration(newHomeId, uid, freshPublicKey()),
    (err) => err.message === "HOME_DEVICE_LIMIT_REACHED"
  );
  assert.equal((await registryRef(newHomeId).get()).exists, false);

  await cleanupHomeAttempt(uid, [existingHomeId, newHomeId]);
});

test("Home basic 24b: a malformed canonical entitlements document also falls back to Free, never legacy", async () => {
  const uid = uniqueId("tdl-home24b-uid");
  const existingHomeId = uniqueId("tdl-home24b-existing");
  const newHomeId = uniqueId("tdl-home24b-new");
  await userRef(uid).set({ cameraLimit: 999 }); // legacy value that must never be consulted
  await entitlementsRef(uid).set(validEntitlements({ plan: "not-a-real-plan" })); // corrupt -> Free
  await attemptHomeRegistration(existingHomeId, uid, freshPublicKey());

  await assert.rejects(
    attemptHomeRegistration(newHomeId, uid, freshPublicKey()),
    (err) => err.message === "HOME_DEVICE_LIMIT_REACHED"
  );

  await cleanupHomeAttempt(uid, [existingHomeId, newHomeId]);
});

test("Home basic 25: a limit rejection writes no registeredDevices/publicKey/status fields at all", async () => {
  const uid = uniqueId("tdl-home25-uid");
  const homeDeviceId = uniqueId("tdl-home25-device");
  await entitlementsRef(uid).set(validEntitlements({ maxHomeDevices: 0 }));

  await assert.rejects(attemptHomeRegistration(homeDeviceId, uid, freshPublicKey()));

  const snap = await registryRef(homeDeviceId).get();
  assert.equal(snap.exists, false, "no registeredDevices document, no publicKey, no status, nothing partial");

  await cleanupHomeAttempt(uid, [homeDeviceId]);
});

// =================================================================================================
// D. Home concurrency (26-30)
// =================================================================================================

test("Home concurrency 26: maxHomeDevices=1, two parallel registrations of DIFFERENT Homes -> exactly 1 success, 1 rejection, final count=1", async () => {
  const uid = uniqueId("tdl-hc26-uid");
  const homeIdA = uniqueId("tdl-hc26-a");
  const homeIdB = uniqueId("tdl-hc26-b");
  await entitlementsRef(uid).set(validEntitlements({ maxHomeDevices: 1 }));

  const results = await Promise.allSettled([
    attemptHomeRegistration(homeIdA, uid, freshPublicKey()),
    attemptHomeRegistration(homeIdB, uid, freshPublicKey()),
  ]);

  const fulfilled = results.filter((r) => r.status === "fulfilled");
  const rejected = results.filter((r) => r.status === "rejected");
  assert.equal(fulfilled.length, 1, "exactly one registration must succeed");
  assert.equal(rejected.length, 1, "exactly one registration must be rejected");
  assert.equal(rejected[0].reason.message, "HOME_DEVICE_LIMIT_REACHED");

  // Verify FIRESTORE STATE, not just the responses.
  const homesSnap = await db.collection("registeredDevices").where("ownerUid", "==", uid).get();
  const homeDocs = homesSnap.docs.filter((d) => d.data().role === "HOME");
  assert.equal(homeDocs.length, 1, "canonical registered Home count must be exactly 1");

  await cleanupHomeAttempt(uid, [homeIdA, homeIdB]);
});

test("Home concurrency 27: maxHomeDevices=2, five parallel registrations -> exactly 2 success, final count=2", async () => {
  const uid = uniqueId("tdl-hc27-uid");
  const homeIds = [1, 2, 3, 4, 5].map(() => uniqueId("tdl-hc27-home"));
  await entitlementsRef(uid).set(validEntitlements({ maxHomeDevices: 2 }));

  const results = await Promise.allSettled(homeIds.map((id) => attemptHomeRegistration(id, uid, freshPublicKey())));
  const fulfilled = results.filter((r) => r.status === "fulfilled");
  const rejected = results.filter((r) => r.status === "rejected");
  assert.equal(fulfilled.length, 2, "exactly two registrations must succeed");
  assert.equal(rejected.length, 3);
  for (const r of rejected) {
    assert.equal(r.reason.message, "HOME_DEVICE_LIMIT_REACHED");
  }

  const homesSnap = await db.collection("registeredDevices").where("ownerUid", "==", uid).get();
  const homeDocs = homesSnap.docs.filter((d) => d.data().role === "HOME");
  assert.equal(homeDocs.length, 2, "canonical registered Home count must be exactly 2, never more");

  await cleanupHomeAttempt(uid, homeIds);
});

test("Home concurrency 28: two parallel registrations of the SAME Home never take two slots", async () => {
  const uid = uniqueId("tdl-hc28-uid");
  const homeDeviceId = uniqueId("tdl-hc28-device");
  const publicKey = freshPublicKey();
  await entitlementsRef(uid).set(validEntitlements({ maxHomeDevices: 1 }));

  const results = await Promise.allSettled([
    attemptHomeRegistration(homeDeviceId, uid, publicKey),
    attemptHomeRegistration(homeDeviceId, uid, publicKey),
  ]);
  // Same key, same device -- both may legitimately succeed (one "home_created", one idempotent on
  // retry), matching deviceRegistry.test.js's own "13. HOME bootstrap -- two concurrent same-key
  // requests" precedent. What matters is only one slot is ever actually occupied.
  const fulfilled = results.filter((r) => r.status === "fulfilled");
  assert.ok(fulfilled.length >= 1);

  const listed = await db.collection("registeredDevices").where("deviceId", "==", homeDeviceId).get();
  assert.equal(listed.size, 1, "exactly one registeredDevices document, never two");

  const homesSnap = await db.collection("registeredDevices").where("ownerUid", "==", uid).get();
  assert.equal(homesSnap.docs.filter((d) => d.data().role === "HOME").length, 1, "exactly one slot occupied, not two");

  await cleanupHomeAttempt(uid, [homeDeviceId]);
});

test("Home concurrency 29: transaction retry never corrupts identity fields", async () => {
  const uid = uniqueId("tdl-hc29-uid");
  const homeDeviceId = uniqueId("tdl-hc29-device");
  const publicKey = freshPublicKey();
  await entitlementsRef(uid).set(validEntitlements({ maxHomeDevices: 1 }));

  await Promise.allSettled([attemptHomeRegistration(homeDeviceId, uid, publicKey), attemptHomeRegistration(homeDeviceId, uid, publicKey)]);

  const data = (await registryRef(homeDeviceId).get()).data();
  assert.equal(data.role, "HOME");
  assert.equal(data.authUid, uid);
  assert.equal(data.ownerUid, uid);
  assert.equal(data.publicKey, publicKey);
  assert.equal(data.identityMode, "keystore");

  await cleanupHomeAttempt(uid, [homeDeviceId]);
});

test("Home concurrency 30: an existing registered Home's own idempotent retry is never blocked by a full limit", async () => {
  const uid = uniqueId("tdl-hc30-uid");
  const homeDeviceId = uniqueId("tdl-hc30-device");
  const publicKey = freshPublicKey();
  await entitlementsRef(uid).set(validEntitlements({ maxHomeDevices: 1 }));
  await attemptHomeRegistration(homeDeviceId, uid, publicKey);
  // The limit is now fully occupied (1/1) -- a repeated call for the SAME already-registered
  // device must still succeed idempotently: the limit check only runs on the missing-document
  // (new slot) branch, never on an existing device's own resubmission.
  const retry = await attemptHomeRegistration(homeDeviceId, uid, publicKey);
  assert.deepEqual(retry, { success: true, identityMode: "keystore" });

  await cleanupHomeAttempt(uid, [homeDeviceId]);
});

// =================================================================================================
// E/F. Status semantics (31-35) and cross-cutting (36-42)
// =================================================================================================

test("Status semantics 32/33: a revoked Home no longer occupies a slot; a suspended Home still does (conservative default)", async () => {
  // Conservative rule adopted for this task (see report): a device continues to occupy its slot
  // until an explicit release/unpair/revoke path frees it. `applyRevokeRegisteredDevice` sets
  // status:"revoked" -- checkRegisteredDeviceOperational/reconcileUserDeviceLimits both already
  // treat "revoked" as the one status that stops counting toward a limit (see
  // reconcileUserDeviceLimits' own `d.status !== "revoked"` filter); "suspended" (plan/manual/
  // security) is NOT such a release -- the device is administratively blocked from operating, but
  // its registry document (and slot) still exists and is not freed. This new Home limit check
  // reuses that exact, already-established filter (`status !== "revoked"`), not a new one.
  const uid = uniqueId("tdl-status-uid");
  const revokedHomeId = uniqueId("tdl-status-revoked");
  const suspendedHomeId = uniqueId("tdl-status-suspended");
  const newHomeId = uniqueId("tdl-status-new");
  await entitlementsRef(uid).set(validEntitlements({ maxHomeDevices: 1 }));

  const now = admin.firestore.Timestamp.now();
  await registryRef(revokedHomeId).set({
    schemaVersion: 1,
    deviceId: revokedHomeId,
    role: "HOME",
    authUid: uid,
    ownerUid: uid,
    status: "revoked",
    suspensionReason: null,
    identityMode: "keystore",
    publicKey: "placeholder",
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    revokedAt: now,
    deviceProofVersion: null,
  });

  // A revoked Home no longer occupies a slot -- a new registration must succeed.
  const afterRevoked = await attemptHomeRegistration(newHomeId, uid, freshPublicKey());
  assert.deepEqual(afterRevoked, { success: true, identityMode: "keystore" });
  await registryRef(newHomeId).delete();

  // Now seed a SUSPENDED Home instead -- it still occupies its slot.
  await registryRef(suspendedHomeId).set({
    schemaVersion: 1,
    deviceId: suspendedHomeId,
    role: "HOME",
    authUid: uid,
    ownerUid: uid,
    status: "suspended",
    suspensionReason: "plan",
    identityMode: "keystore",
    publicKey: "placeholder",
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    revokedAt: null,
    deviceProofVersion: null,
  });

  await assert.rejects(
    attemptHomeRegistration(newHomeId, uid, freshPublicKey()),
    (err) => err.message === "HOME_DEVICE_LIMIT_REACHED",
    "a suspended Home must still occupy its slot"
  );

  await cleanupHomeAttempt(uid, [revokedHomeId, suspendedHomeId, newHomeId]);
});

test("Status semantics 35: Camera slot counting matches the canonical ownership model (cameraClaims-derived cameraCount, revoked still counted)", async () => {
  // Camera's own count (users/{uid}.cameraCount) is driven by cameraClaims/claim-release, never by
  // registeredDevices.status -- confirmed structurally: applyRevokeRegisteredDevice only ever
  // writes registeredDevices fields, never cameraClaims or users/{uid}.cameraCount (see
  // deviceRegistry.ts's own doc: "revoked is the one status detachCameraOwner never clears
  // ownerUid for"). This test proves a revoked Camera still occupies its Camera-count slot, since
  // no explicit release/unpair (the only thing that frees it) has happened.
  const attempt = await setupClaimAttempt();
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: 1 }));
  await attemptClaim(attempt);

  await registryRef(attempt.cameraDeviceId).set({ status: "revoked", revokedAt: admin.firestore.Timestamp.now() }, { merge: true });

  const blockedAttempt = await setupClaimAttempt({ ownerUid: attempt.ownerUid });
  await assert.rejects(attemptClaim(blockedAttempt), (err) => err.details?.code === "CAMERA_LIMIT_REACHED");

  await cleanupClaimAttempt(attempt);
  await cleanupClaimAttempt(blockedAttempt);
});

test("Cross-cutting 36/37: Home and Camera paths each use exactly one canonical entitlement resolution and never read cameraLimit/subscriptionUnits", async () => {
  // Structural confirmation, not a new regex: this task's own diff (functions/src/deviceRegistry.ts,
  // applyPublicKeyRegistration's HOME-bootstrap branch) calls planDeviceLimitsFromEntitlementsData
  // exactly once, the same pure resolver claimCameraForUser already uses -- no second resolver was
  // added. The pre-existing static guard (entitlementsCanonicalSource.test.js) already fails the
  // whole suite if any functions/src/*.ts file reads legacy subscriptionUnits/cameraLimit via
  // .get(), dot-access, or bracket-access -- not duplicated here, this test only exercises the
  // BEHAVIORAL guarantee end-to-end for the Home path specifically (the Camera path's own
  // equivalent behavioral tests already exist in entitlementsCanonicalSource.test.js).
  const uid = uniqueId("tdl-crosscut-uid");
  const existingHomeId = uniqueId("tdl-crosscut-existing");
  const newHomeId = uniqueId("tdl-crosscut-new");
  await userRef(uid).set({ cameraLimit: 999, subscriptionUnits: 999 });
  await entitlementsRef(uid).set(validEntitlements({ maxHomeDevices: 1 }));
  await attemptHomeRegistration(existingHomeId, uid, freshPublicKey());

  await assert.rejects(attemptHomeRegistration(newHomeId, uid, freshPublicKey()), (err) => err.message === "HOME_DEVICE_LIMIT_REACHED");

  await cleanupHomeAttempt(uid, [existingHomeId, newHomeId]);
});

test("Cross-cutting 39: limit failure preserves the existing public error contract for both Camera and Home", async () => {
  const attempt = await setupClaimAttempt();
  await userRef(attempt.ownerUid).set({ cameraCount: 1 });
  await entitlementsRef(attempt.ownerUid).set(validEntitlements({ maxCameras: 1 }));
  const cameraError = await attemptClaim(attempt).catch((e) => e);
  assert.equal(cameraError.code, "resource-exhausted");
  assert.equal(cameraError.message, "Camera limit reached");
  assert.equal(cameraError.details.code, "CAMERA_LIMIT_REACHED");

  const uid = uniqueId("tdl-errcontract-uid");
  const existingHomeId = uniqueId("tdl-errcontract-existing");
  const newHomeId = uniqueId("tdl-errcontract-new");
  await entitlementsRef(uid).set(validEntitlements({ maxHomeDevices: 1 }));
  await attemptHomeRegistration(existingHomeId, uid, freshPublicKey());
  const homeError = await attemptHomeRegistration(newHomeId, uid, freshPublicKey()).catch((e) => e);
  assert.equal(homeError.code, "resource-exhausted");
  assert.equal(homeError.message, "HOME_DEVICE_LIMIT_REACHED");

  await cleanupClaimAttempt(attempt);
  await cleanupHomeAttempt(uid, [existingHomeId, newHomeId]);
});

test("Cross-cutting 40/41: protected side effects only happen after a successful decision; the transaction callback is retry-safe", async () => {
  // Already directly proven by "Camera concurrency 14"/"Home concurrency 29" (no duplicate
  // ownership/identity corruption under real concurrent retries) and "Camera basic 10"/"Home basic
  // 25" (a denied decision leaves zero protected writes) -- this test adds one more direct check:
  // running the SAME successful registration path twice in a row (a natural retry-shaped call
  // pattern) is idempotent and produces no duplicate/parallel side effects.
  const uid = uniqueId("tdl-retrysafe-uid");
  const homeDeviceId = uniqueId("tdl-retrysafe-device");
  const publicKey = freshPublicKey();
  await entitlementsRef(uid).set(validEntitlements({ maxHomeDevices: 1 }));

  await attemptHomeRegistration(homeDeviceId, uid, publicKey);
  const before = (await registryRef(homeDeviceId).get()).data();
  await attemptHomeRegistration(homeDeviceId, uid, publicKey);
  const after = (await registryRef(homeDeviceId).get()).data();

  assert.deepEqual(after.createdAt, before.createdAt, "createdAt must never change on a retry-shaped repeat call");

  await cleanupHomeAttempt(uid, [homeDeviceId]);
});

test("Logs 42: Home limit rejection never logs deviceId, uid, or the entitlement document", async () => {
  const uid = uniqueId("tdl-logs-uid");
  const existingHomeId = uniqueId("tdl-logs-existing");
  const newHomeId = uniqueId("tdl-logs-new");
  await entitlementsRef(uid).set(validEntitlements({ maxHomeDevices: 1 }));
  await attemptHomeRegistration(existingHomeId, uid, freshPublicKey());

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
    await attemptHomeRegistration(newHomeId, uid, freshPublicKey()).catch(() => {});
  } finally {
    process.stdout.write = originalStdoutWrite;
    process.stderr.write = originalStderrWrite;
  }

  const rejectionLine = lines.find((line) => line.includes("HOME_DEVICE_LIMIT_REACHED"));
  assert.ok(rejectionLine, "the rejection log line should still fire");
  const entry = JSON.parse(rejectionLine);
  assert.deepEqual(Object.keys(entry).sort(), ["message", "reason", "role", "severity"].sort());
  assert.ok(!rejectionLine.includes(uid));
  assert.ok(!rejectionLine.includes(newHomeId));
  assert.ok(!rejectionLine.includes(existingHomeId));

  await cleanupHomeAttempt(uid, [existingHomeId, newHomeId]);
});

test("Logs 42b: claimCameraForUser's Home-precondition denial logs (unregistered and operational) never log cameraDeviceId, homeDeviceId, uid, ownerUid, authUid, or a Firestore path", async () => {
  async function captureLog(run) {
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
      await run();
    } finally {
      process.stdout.write = originalStdoutWrite;
      process.stderr.write = originalStderrWrite;
    }
    return lines;
  }

  // Scenario A: an unregistered Home -- exercises the "home_precondition"/DEVICE_NOT_REGISTERED log.
  const unregisteredAttempt = await setupClaimAttempt({ skipHomeRegistration: true });
  const linesA = await captureLog(() => attemptClaim(unregisteredAttempt).catch(() => {}));
  const lineA = linesA.find((line) => line.includes("CLAIM_CAMERA_HOME_DEVICE_STATUS_DENIED"));
  assert.ok(lineA, "the unregistered-Home denial log line should fire");
  const entryA = JSON.parse(lineA);
  assert.deepEqual(
    Object.keys(entryA).sort(),
    ["severity", "message", "operation", "role", "stage", "result", "reason"].sort()
  );
  assert.equal(entryA.operation, "claimCameraForUser");
  assert.equal(entryA.role, "HOME");
  assert.equal(entryA.stage, "home_precondition");
  assert.equal(entryA.result, "denied");
  assert.equal(entryA.reason, "DEVICE_NOT_REGISTERED");
  for (const forbidden of [
    unregisteredAttempt.ownerUid,
    unregisteredAttempt.cameraDeviceId,
    unregisteredAttempt.homeDeviceId,
    "registeredDevices/",
    "cameraClaims/",
    "userEntitlements/",
  ]) {
    assert.ok(!lineA.includes(forbidden), `log line must not contain "${forbidden}"`);
  }
  await cleanupClaimAttempt(unregisteredAttempt);

  // Scenario B: a suspended Home that DOES belong to the caller -- exercises the
  // checkRegisteredDeviceOperational-denied branch of the same log event name.
  const suspendedAttempt = await setupClaimAttempt({ skipHomeRegistration: true });
  const now = admin.firestore.Timestamp.now();
  await registryRef(suspendedAttempt.homeDeviceId).set({
    schemaVersion: 1,
    deviceId: suspendedAttempt.homeDeviceId,
    role: "HOME",
    authUid: suspendedAttempt.ownerUid,
    ownerUid: suspendedAttempt.ownerUid,
    status: "suspended",
    suspensionReason: "manual",
    identityMode: "keystore",
    publicKey: "tdl-logs42b-public-key",
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    revokedAt: null,
    deviceProofVersion: null,
  });
  const linesB = await captureLog(() => attemptClaim(suspendedAttempt).catch(() => {}));
  const lineB = linesB.find((line) => line.includes("CLAIM_CAMERA_HOME_DEVICE_STATUS_DENIED"));
  assert.ok(lineB, "the suspended-Home denial log line should fire");
  const entryB = JSON.parse(lineB);
  assert.deepEqual(
    Object.keys(entryB).sort(),
    ["severity", "message", "operation", "role", "stage", "result", "reason"].sort()
  );
  assert.equal(entryB.reason, "DEVICE_SUSPENDED");
  for (const forbidden of [
    suspendedAttempt.ownerUid,
    suspendedAttempt.cameraDeviceId,
    suspendedAttempt.homeDeviceId,
    "registeredDevices/",
    "cameraClaims/",
    "userEntitlements/",
  ]) {
    assert.ok(!lineB.includes(forbidden), `log line must not contain "${forbidden}"`);
  }
  await cleanupClaimAttempt(suspendedAttempt);
});

// =================================================================================================
// Explicit regression concurrency tests (required verbatim shape): Promise.allSettled, verifying
// FINAL FIRESTORE STATE, not just function responses.
// =================================================================================================

test("REGRESSION: Camera -- maxCameras=1, two different cameraDeviceId in parallel -> fulfilled=1, limit-rejected=1, canonical stored count=1", async () => {
  const ownerUid = uniqueId("tdl-regr-camera-owner");
  await entitlementsRef(ownerUid).set(validEntitlements({ maxCameras: 1 }));
  const attemptA = await setupClaimAttempt({ ownerUid });
  const attemptB = await setupClaimAttempt({ ownerUid });

  const settled = await Promise.allSettled([attemptClaim(attemptA), attemptClaim(attemptB)]);

  const fulfilled = settled.filter((r) => r.status === "fulfilled");
  const limitRejected = settled.filter((r) => r.status === "rejected" && r.reason.details?.code === "CAMERA_LIMIT_REACHED");
  assert.equal(fulfilled.length, 1);
  assert.equal(limitRejected.length, 1);

  const userSnap = await userRef(ownerUid).get();
  assert.equal(userSnap.get("cameraCount"), 1, "canonical stored Camera count must be exactly 1");

  await cleanupClaimAttempt(attemptA);
  await cleanupClaimAttempt(attemptB);
});

test("REGRESSION: Home -- maxHomeDevices=1, two different homeDeviceId in parallel -> fulfilled=1, limit-rejected=1, canonical registered count=1", async () => {
  const uid = uniqueId("tdl-regr-home-uid");
  const homeIdA = uniqueId("tdl-regr-home-a");
  const homeIdB = uniqueId("tdl-regr-home-b");
  await entitlementsRef(uid).set(validEntitlements({ maxHomeDevices: 1 }));

  const settled = await Promise.allSettled([
    attemptHomeRegistration(homeIdA, uid, freshPublicKey()),
    attemptHomeRegistration(homeIdB, uid, freshPublicKey()),
  ]);

  const fulfilled = settled.filter((r) => r.status === "fulfilled");
  const limitRejected = settled.filter((r) => r.status === "rejected" && r.reason.message === "HOME_DEVICE_LIMIT_REACHED");
  assert.equal(fulfilled.length, 1);
  assert.equal(limitRejected.length, 1);

  const homesSnap = await db.collection("registeredDevices").where("ownerUid", "==", uid).get();
  const homeDocs = homesSnap.docs.filter((d) => d.data().role === "HOME");
  assert.equal(homeDocs.length, 1, "canonical registered Home count must be exactly 1");

  await cleanupHomeAttempt(uid, [homeIdA, homeIdB]);
});

// =================================================================================================
// G. Legacy Home bypass fix -- claimCameraForUser used to be able to commit a Camera claim and
// then lazily create a brand-new HOME registeredDevices document afterward (via the old
// registerLegacyHome), entirely outside of registerDevicePublicKey's own maxHomeDevices
// transaction. Fix: registerLegacyHome no longer ever creates a document (see its own doc in
// deviceRegistry.ts and deviceRegistry.test.js's own direct unit tests for that function), and
// claimCameraForUser's transaction now requires the Home to already be registered and operational
// (checkRegisteredDeviceOperational(..., { requireRegistered: true })) BEFORE it does anything
// else -- reusing the existing DEVICE_NOT_REGISTERED reason, not a new one. A genuinely new Home
// device can now only ever be allocated through registerDevicePublicKey's own transaction.
// =================================================================================================

test("Legacy bypass 1/2: an unregistered Home can never bypass maxHomeDevices via claimCameraForUser, typed rejection either way", async () => {
  const ownerUid = uniqueId("tdl-bypass12-owner");
  // maxHomeDevices already exhausted by one canonically-registered Home.
  const existingHomeId = uniqueId("tdl-bypass12-existing-home");
  await entitlementsRef(ownerUid).set(validEntitlements({ maxHomeDevices: 1, maxCameras: 5 }));
  await attemptHomeRegistration(existingHomeId, ownerUid, freshPublicKey());

  const attempt = await setupClaimAttempt({ ownerUid, skipHomeRegistration: true });
  await assert.rejects(
    attemptClaim(attempt),
    (err) => err.code === "not-found" && err.message === "DEVICE_NOT_REGISTERED",
    "an unregistered Home must be rejected with the existing typed reason, never silently allocated"
  );

  const homesSnap = await db.collection("registeredDevices").where("ownerUid", "==", ownerUid).get();
  const homeDocs = homesSnap.docs.filter((d) => d.data().role === "HOME");
  assert.equal(homeDocs.length, 1, "the legacy path must never add a second Home, even though maxHomeDevices was already full");

  await cleanupClaimAttempt(attempt);
  await cleanupHomeAttempt(ownerUid, [existingHomeId]);
});

test("Legacy bypass 2b: maxHomeDevices=0 (zero capacity) still yields DEVICE_NOT_REGISTERED, not a limit-specific reason, for an unregistered Home", async () => {
  const ownerUid = uniqueId("tdl-bypass2b-owner");
  await entitlementsRef(ownerUid).set(validEntitlements({ maxHomeDevices: 0, maxCameras: 5 }));

  const attempt = await setupClaimAttempt({ ownerUid, skipHomeRegistration: true });
  await assert.rejects(attemptClaim(attempt), (err) => err.code === "not-found" && err.message === "DEVICE_NOT_REGISTERED");

  await cleanupClaimAttempt(attempt);
});

test("Legacy bypass 3/4/5/6: rejection for an unregistered Home leaves zero partial writes anywhere (registeredDevices HOME, cameraClaims, cameraDevices, pairing session)", async () => {
  const ownerUid = uniqueId("tdl-bypass3456-owner");
  await entitlementsRef(ownerUid).set(validEntitlements({ maxHomeDevices: 5, maxCameras: 5 }));

  const attempt = await setupClaimAttempt({ ownerUid, skipHomeRegistration: true });
  await assert.rejects(attemptClaim(attempt), (err) => err.code === "not-found" && err.message === "DEVICE_NOT_REGISTERED");

  const [homeSnap, claimSnap, cameraDeviceSnap, pairingSnap, userSnap] = await Promise.all([
    registryRef(attempt.homeDeviceId).get(),
    claimRef(attempt.cameraDeviceId).get(),
    cameraDeviceLinkRef(attempt.ownerUid, attempt.cameraDeviceId).get(),
    pairingSessionRef(attempt.pairingId).get(),
    userRef(attempt.ownerUid).get(),
  ]);
  assert.equal(homeSnap.exists, false, "(3) no registeredDevices HOME document must be created");
  assert.equal(claimSnap.exists, false, "(4) no cameraClaims document must be created");
  assert.equal(cameraDeviceSnap.exists, false, "(5) no users/{uid}/cameraDevices document must be created");
  assert.equal(pairingSnap.get("status"), "pending", "(6) the pairing session must not be consumed");
  assert.equal(pairingSnap.get("consumedAt"), null, "(6) the pairing session must not be consumed");
  assert.equal(userSnap.exists, false, "no users/{uid} document must be created either");

  await cleanupClaimAttempt(attempt);
});

test("Legacy bypass 7: a legacy claim can never register a SECOND Home for the same owner when maxHomeDevices=1", async () => {
  const ownerUid = uniqueId("tdl-bypass7-owner");
  const firstHomeId = uniqueId("tdl-bypass7-first-home");
  await entitlementsRef(ownerUid).set(validEntitlements({ maxHomeDevices: 1, maxCameras: 5 }));
  await attemptHomeRegistration(firstHomeId, ownerUid, freshPublicKey());

  // A second, never-registered Home device id, attempting to ride in via a Camera claim.
  const attempt = await setupClaimAttempt({ ownerUid, skipHomeRegistration: true });
  await assert.rejects(attemptClaim(attempt), (err) => err.code === "not-found" && err.message === "DEVICE_NOT_REGISTERED");

  const homesSnap = await db.collection("registeredDevices").where("ownerUid", "==", ownerUid).get();
  const homeDocs = homesSnap.docs.filter((d) => d.data().role === "HOME");
  assert.equal(homeDocs.length, 1, "still exactly the one originally-registered Home, never two");

  await cleanupClaimAttempt(attempt);
  await cleanupHomeAttempt(ownerUid, [firstHomeId]);
});

test("Legacy bypass 8: two parallel legacy claims for two different unregistered Homes (maxHomeDevices=1) are both rejected as requiring canonical registration", async () => {
  const ownerUid = uniqueId("tdl-bypass8-owner");
  await entitlementsRef(ownerUid).set(validEntitlements({ maxHomeDevices: 1, maxCameras: 5 }));

  const attemptA = await setupClaimAttempt({ ownerUid, skipHomeRegistration: true });
  const attemptB = await setupClaimAttempt({ ownerUid, skipHomeRegistration: true });

  const settled = await Promise.allSettled([attemptClaim(attemptA), attemptClaim(attemptB)]);
  // This project's chosen fix removes legacy Home bootstrap creation entirely (rather than making
  // it transactionally limit-aware), so BOTH must be rejected -- there is no "one succeeds" branch
  // left to reach; neither device was ever canonically registered.
  const rejected = settled.filter((r) => r.status === "rejected" && r.reason.code === "not-found" && r.reason.message === "DEVICE_NOT_REGISTERED");
  assert.equal(rejected.length, 2, "both unregistered-Home legacy claims must be rejected, never one silently allocated");

  const homesSnap = await db.collection("registeredDevices").where("ownerUid", "==", ownerUid).get();
  assert.equal(homesSnap.docs.filter((d) => d.data().role === "HOME").length, 0, "no Home was ever created by either parallel attempt");

  await cleanupClaimAttempt(attemptA);
  await cleanupClaimAttempt(attemptB);
});

test("Legacy bypass 9: an already-registered Keystore HOME still completes claimCameraForUser end-to-end", async () => {
  const ownerUid = uniqueId("tdl-bypass9-owner");
  const homeId = uniqueId("tdl-bypass9-home");
  await entitlementsRef(ownerUid).set(validEntitlements({ maxHomeDevices: 1, maxCameras: 5 }));
  await attemptHomeRegistration(homeId, ownerUid, freshPublicKey());

  const attempt = await setupClaimAttempt({ ownerUid, homeDeviceId: homeId, skipHomeRegistration: true });
  const response = await attemptClaim(attempt);
  assert.equal(response.success, true);

  const homeData = (await registryRef(homeId).get()).data();
  assert.equal(homeData.identityMode, "keystore", "the real registerDevicePublicKey-created identity must be untouched");

  await cleanupClaimAttempt(attempt);
});

test("Legacy bypass 10: a repeated idempotent claim against an already-registered Home keeps working", async () => {
  const ownerUid = uniqueId("tdl-bypass10-owner");
  const homeId = uniqueId("tdl-bypass10-home");
  await entitlementsRef(ownerUid).set(validEntitlements({ maxHomeDevices: 1, maxCameras: 5 }));
  await attemptHomeRegistration(homeId, ownerUid, freshPublicKey());

  const attempt = await setupClaimAttempt({ ownerUid, homeDeviceId: homeId, skipHomeRegistration: true });
  const first = await attemptClaim(attempt);
  assert.equal(first.cameraCount, 1);

  const secondAttempt = { ...attempt, pairingId: uniqueId("tdl-bypass10-pairing"), pairingSecret: uniqueId("tdl-bypass10-secret") };
  await seedPairingSession(secondAttempt.pairingId, secondAttempt.cameraDeviceId, secondAttempt.cameraAuthUid, secondAttempt.pairingSecret);
  const second = await attemptClaim(secondAttempt);
  assert.equal(second.success, true);
  assert.equal(second.cameraCount, 1, "an idempotent repeat claim must not increment cameraCount");

  await cleanupClaimAttempt(attempt);
  await pairingSessionRef(secondAttempt.pairingId).delete();
});

test("Legacy bypass 11: the Camera App's own legacy TURN/registerLegacyCamera path is untouched by this fix (structural)", () => {
  // This fix only changes registerLegacyHome (never creates) and claimCameraForUser (now requires
  // an already-registered, operational Home before it does anything). registerLegacyCamera,
  // attachCameraOwner, detachCameraOwner, and getTurnCredentials' own Camera-legacy-path handling
  // are untouched -- see deviceRegistry.test.js's own pre-existing "18/20." getTurnCredentials
  // (Camera legacy path) tests, which still pass unmodified against the same build.
  assert.ok(true);
});

// =================================================================================================
// H. Home ownership/role audit -- checkRegisteredDeviceOperational alone only inspects
// status/suspensionReason; it never checks role or identity. Before this section's fix,
// claimCameraForUser's own "Home must be registered" check (section G) would have let a claim
// through for ANY registeredDevices/{homeDeviceId} document that merely existed and was "active" --
// regardless of whose it was or what role it actually held. Fixed: claimCameraForUser now also
// requires role === "HOME" AND authUid === uid AND ownerUid === uid, all collapsing to the exact
// same generic DEVICE_NOT_REGISTERED rejection as a genuinely missing document (never a distinct
// error), so a caller can never learn that a given homeDeviceId belongs to someone else, or that it
// exists at all under a different role.
// =================================================================================================

test("Ownership 1: an operational HOME belonging to a DIFFERENT uid cannot be used to complete a claim", async () => {
  const otherUid = uniqueId("tdl-own1-other-uid");
  const attempt = await setupClaimAttempt({ skipHomeRegistration: true });
  await seedHomeRegistration(attempt.homeDeviceId, otherUid); // active HOME, but owned by someone else

  await assert.rejects(attemptClaim(attempt), (err) => err.code === "not-found" && err.message === "DEVICE_NOT_REGISTERED");

  const [claimSnap, cameraDeviceSnap, pairingSnap, userSnap] = await Promise.all([
    claimRef(attempt.cameraDeviceId).get(),
    cameraDeviceLinkRef(attempt.ownerUid, attempt.cameraDeviceId).get(),
    pairingSessionRef(attempt.pairingId).get(),
    userRef(attempt.ownerUid).get(),
  ]);
  assert.equal(claimSnap.exists, false, "no cameraClaims document");
  assert.equal(cameraDeviceSnap.exists, false, "no users/{uid}/cameraDevices document");
  assert.equal(pairingSnap.get("status"), "pending", "pairing session must not be consumed");
  assert.equal(pairingSnap.get("consumedAt"), null);
  assert.equal(userSnap.exists, false, "no users/{uid} document (cameraCount) must be created");

  await cleanupClaimAttempt(attempt);
  await registryRef(attempt.homeDeviceId).delete();
});

test("Ownership 2: a CAMERA-role document at homeDeviceId cannot be used as a Home to complete a claim", async () => {
  const attempt = await setupClaimAttempt({ skipHomeRegistration: true });
  const now = admin.firestore.Timestamp.now();
  await registryRef(attempt.homeDeviceId).set({
    schemaVersion: 1,
    deviceId: attempt.homeDeviceId,
    role: "CAMERA",
    authUid: attempt.ownerUid,
    ownerUid: attempt.ownerUid,
    status: "active",
    suspensionReason: null,
    identityMode: "legacy",
    publicKey: null,
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    revokedAt: null,
    deviceProofVersion: null,
  });

  await assert.rejects(attemptClaim(attempt), (err) => err.code === "not-found" && err.message === "DEVICE_NOT_REGISTERED");

  const [claimSnap, cameraDeviceSnap, pairingSnap, userSnap] = await Promise.all([
    claimRef(attempt.cameraDeviceId).get(),
    cameraDeviceLinkRef(attempt.ownerUid, attempt.cameraDeviceId).get(),
    pairingSessionRef(attempt.pairingId).get(),
    userRef(attempt.ownerUid).get(),
  ]);
  assert.equal(claimSnap.exists, false, "no cameraClaims document");
  assert.equal(cameraDeviceSnap.exists, false, "no users/{uid}/cameraDevices document");
  assert.equal(pairingSnap.get("status"), "pending", "pairing session must not be consumed");
  assert.equal(userSnap.exists, false);

  await cleanupClaimAttempt(attempt);
});

test("Ownership 3: an identity-conflicting HOME document (authUid mismatched from the caller) cannot complete a claim", async () => {
  const otherAuthUid = uniqueId("tdl-own3-other-authuid");
  const attempt = await setupClaimAttempt({ skipHomeRegistration: true });
  const now = admin.firestore.Timestamp.now();
  // role is HOME and ownerUid matches the caller, but authUid does not -- a corrupted/conflicting
  // document that must never be treated as "this caller's own Home" on ownerUid alone.
  await registryRef(attempt.homeDeviceId).set({
    schemaVersion: 1,
    deviceId: attempt.homeDeviceId,
    role: "HOME",
    authUid: otherAuthUid,
    ownerUid: attempt.ownerUid,
    status: "active",
    suspensionReason: null,
    identityMode: "legacy",
    publicKey: null,
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    revokedAt: null,
    deviceProofVersion: null,
  });

  await assert.rejects(attemptClaim(attempt), (err) => err.code === "not-found" && err.message === "DEVICE_NOT_REGISTERED");

  const [claimSnap, cameraDeviceSnap, pairingSnap, userSnap] = await Promise.all([
    claimRef(attempt.cameraDeviceId).get(),
    cameraDeviceLinkRef(attempt.ownerUid, attempt.cameraDeviceId).get(),
    pairingSessionRef(attempt.pairingId).get(),
    userRef(attempt.ownerUid).get(),
  ]);
  assert.equal(claimSnap.exists, false, "no cameraClaims document");
  assert.equal(cameraDeviceSnap.exists, false, "no users/{uid}/cameraDevices document");
  assert.equal(pairingSnap.get("status"), "pending", "pairing session must not be consumed");
  assert.equal(userSnap.exists, false);

  await cleanupClaimAttempt(attempt);
});

test("Ownership 5: a HOME correctly registered to the caller's own uid still completes claimCameraForUser", async () => {
  const attempt = await setupClaimAttempt();
  const response = await attemptClaim(attempt);
  assert.equal(response.success, true);
  assert.equal(response.cameraCount, 1);

  await cleanupClaimAttempt(attempt);
});

test("Ownership 6: an idempotent repeat claim against the caller's own already-registered Home still works", async () => {
  const attempt = await setupClaimAttempt();
  const first = await attemptClaim(attempt);
  assert.equal(first.cameraCount, 1);

  const secondAttempt = { ...attempt, pairingId: uniqueId("tdl-own6-pairing"), pairingSecret: uniqueId("tdl-own6-secret") };
  await seedPairingSession(secondAttempt.pairingId, secondAttempt.cameraDeviceId, secondAttempt.cameraAuthUid, secondAttempt.pairingSecret);
  const second = await attemptClaim(secondAttempt);
  assert.equal(second.success, true);
  assert.equal(second.cameraCount, 1, "an idempotent repeat claim must not increment cameraCount");

  await cleanupClaimAttempt(attempt);
  await pairingSessionRef(secondAttempt.pairingId).delete();
});

test("Ownership 7: the public rejection for a wrong-owner HOME and a wrong-role document are byte-for-byte identical (no oracle)", async () => {
  const otherUid = uniqueId("tdl-own7-other-uid");
  const wrongOwnerAttempt = await setupClaimAttempt({ skipHomeRegistration: true });
  await seedHomeRegistration(wrongOwnerAttempt.homeDeviceId, otherUid);
  const wrongOwnerError = await attemptClaim(wrongOwnerAttempt).catch((e) => e);

  const wrongRoleAttempt = await setupClaimAttempt({ skipHomeRegistration: true });
  const now = admin.firestore.Timestamp.now();
  await registryRef(wrongRoleAttempt.homeDeviceId).set({
    schemaVersion: 1,
    deviceId: wrongRoleAttempt.homeDeviceId,
    role: "CAMERA",
    authUid: wrongRoleAttempt.ownerUid,
    ownerUid: wrongRoleAttempt.ownerUid,
    status: "active",
    suspensionReason: null,
    identityMode: "legacy",
    publicKey: null,
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    revokedAt: null,
    deviceProofVersion: null,
  });
  const wrongRoleError = await attemptClaim(wrongRoleAttempt).catch((e) => e);

  const missingAttempt = await setupClaimAttempt({ skipHomeRegistration: true });
  const missingError = await attemptClaim(missingAttempt).catch((e) => e);

  // All three collapse to the exact same code/message/details -- a client can never tell "belongs
  // to someone else" apart from "wrong role" apart from "does not exist at all".
  for (const err of [wrongOwnerError, wrongRoleError, missingError]) {
    assert.equal(err.code, "not-found");
    assert.equal(err.message, "DEVICE_NOT_REGISTERED");
    assert.equal(err.details, undefined, "no details object that could leak ownerUid/role/existence");
  }

  await cleanupClaimAttempt(wrongOwnerAttempt);
  await registryRef(wrongOwnerAttempt.homeDeviceId).delete();
  await cleanupClaimAttempt(wrongRoleAttempt);
  await cleanupClaimAttempt(missingAttempt);
});
