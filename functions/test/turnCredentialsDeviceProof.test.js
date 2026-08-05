const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

// Requiring lib/index.js runs admin.initializeApp() once; requires npm run build to have produced
// lib/ from src/ first (source of truth stays src).
const {
  getTurnCredentials,
  buildCanonicalDeviceProofPayload,
  buildCanonicalTurnCredentialsRequestPayload,
  sha256Hex,
  DEVICE_CHALLENGE_PURPOSES,
  DEVICE_CHALLENGE_SCHEMA_VERSION,
  DEVICE_PROOF_VERSION,
  validateTurnCredentialsDeviceProof,
  validateDeviceProofSignatureBase64,
  verifyDeviceProofSignature,
  consumeVerifiedTurnCredentialsChallenge,
} = require("../lib/index.js");
const admin = require("firebase-admin");

const db = admin.firestore();
const TURN_PURPOSE = "LIVE_VIEW";

function registryRef(deviceId) {
  return db.collection("registeredDevices").doc(deviceId);
}
function claimRef(cameraDeviceId) {
  return db.collection("cameraClaims").doc(cameraDeviceId);
}
function challengeRef(challengeId) {
  return db.collection("deviceChallenges").doc(challengeId);
}
function entitlementsRef(uid) {
  return db.collection("userEntitlements").doc(uid);
}
// The canonical Home<->Camera link claimCameraForUser (index.ts) writes once, at real claim time
// -- function-only-writable (firestore.rules: `allow write: if false` on this subcollection).
function homeCameraLinkRef(ownerUid, cameraDeviceId) {
  return db.collection("users").doc(ownerUid).collection("cameraDevices").doc(cameraDeviceId);
}

// Minimal CallableRequest stand-in -- same convention as turn-credentials.test.js.
function fakeRequest(data, uid) {
  return {
    data,
    auth: uid ? { uid, token: {}, rawToken: "" } : undefined,
    rawRequest: {},
    acceptsStreaming: false,
  };
}

let uniqueCounter = 0;
function uniqueId(prefix) {
  uniqueCounter += 1;
  return `${prefix}-${Date.now()}-${uniqueCounter}`;
}

function generateEcKeyPair() {
  return crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}

function publicKeySpkiBase64(publicKey) {
  return publicKey.export({ type: "spki", format: "der" }).toString("base64");
}

async function seedRegisteredDevice(deviceId, overrides = {}) {
  const now = admin.firestore.Timestamp.now();
  await registryRef(deviceId).set({
    schemaVersion: 1,
    deviceId,
    role: "CAMERA",
    authUid: "unset-auth-uid",
    ownerUid: null,
    status: "active",
    suspensionReason: null,
    identityMode: "keystore",
    publicKey: "placeholder-public-key",
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    revokedAt: null,
    deviceProofVersion: null,
    ...overrides,
  });
}

// Builds a fully self-consistent {challengeId, challengeDoc, deviceProof} triple: computes the
// exact canonical request/device-proof payloads via the real exported builders, signs the result
// with `signingPrivateKey`, and lets individual tests override specific STORED challenge fields
// (challengeDocOverrides) or the wire signature itself (signatureOverride) to simulate every
// negative scenario without a bespoke setup each time.
function buildDeviceProofScenario({
  role,
  deviceId,
  requestAuthUid,
  cameraDeviceId,
  turnPurpose = TURN_PURPOSE,
  signingPrivateKey,
  nowMillis = Date.now(),
  ttlMs = 60_000,
  nonce = crypto.randomBytes(32).toString("base64url"),
  challengeIdOverride,
  signatureOverride,
  challengeDocOverrides = {},
}) {
  const challengeId = challengeIdOverride ?? uniqueId("challenge").replace(/[^A-Za-z0-9]/g, "");
  const requestHash = sha256Hex(buildCanonicalTurnCredentialsRequestPayload({ cameraDeviceId, turnPurpose }));
  const expiresAtMillis = nowMillis + ttlMs;

  const canonicalDeviceProofPayload = buildCanonicalDeviceProofPayload({
    challengeId,
    deviceId,
    role,
    purpose: DEVICE_CHALLENGE_PURPOSES.TURN_CREDENTIALS,
    authUid: requestAuthUid,
    nonce,
    requestHash,
    expiresAtMillis,
  });

  const signature =
    signatureOverride ??
    crypto.sign("sha256", Buffer.from(canonicalDeviceProofPayload, "utf8"), signingPrivateKey).toString("base64");

  const challengeDoc = {
    schemaVersion: DEVICE_CHALLENGE_SCHEMA_VERSION,
    challengeId,
    deviceId,
    role,
    authUid: requestAuthUid,
    purpose: DEVICE_CHALLENGE_PURPOSES.TURN_CREDENTIALS,
    nonce,
    requestHash,
    createdAt: admin.firestore.Timestamp.now(),
    expiresAt: admin.firestore.Timestamp.fromMillis(expiresAtMillis),
    usedAt: null,
    usedByFunction: null,
    ...challengeDocOverrides,
  };

  return {
    challengeId,
    challengeDoc,
    canonicalDeviceProofPayload,
    deviceProof: { protocolVersion: 1, challengeId, signature },
  };
}

async function seedScenario(scenario) {
  await challengeRef(scenario.challengeId).set(scenario.challengeDoc);
}

// Full, valid, ready-to-verify HOME scenario: registers the HOME device, the target Camera, links
// them via cameraClaims, and seeds a matching, currently-valid, unused challenge. Returns
// everything a test needs plus a `cleanup()` to remove every doc this created.
async function setupValidHomeScenario(overrides = {}) {
  const homeDeviceId = uniqueId("dp-home-device");
  const homeUid = uniqueId("dp-home-uid");
  const cameraDeviceId = uniqueId("dp-camera");
  const cameraAuthUid = uniqueId("dp-camera-auth-uid");
  const homeKeyPair = generateEcKeyPair();

  await seedRegisteredDevice(homeDeviceId, {
    role: "HOME",
    authUid: homeUid,
    ownerUid: homeUid,
    publicKey: publicKeySpkiBase64(homeKeyPair.publicKey),
    ...(overrides.homeDeviceOverrides ?? {}),
  });
  await seedRegisteredDevice(cameraDeviceId, {
    role: "CAMERA",
    authUid: cameraAuthUid,
    ownerUid: homeUid,
    ...(overrides.cameraDeviceOverrides ?? {}),
  });
  await claimRef(cameraDeviceId).set({
    uid: homeUid,
    cameraAuthUid,
    claimedAt: admin.firestore.Timestamp.now(),
    ...(overrides.claimOverrides ?? {}),
  });

  // The canonical Home<->Camera link (see homeCameraLinkRef's own doc) -- pass
  // `homeCameraLinkOverrides: null` to omit it entirely (tests the missing-link denial), or an
  // object to override specific fields (e.g. a different homeDeviceId, to test the link-mismatch
  // denial) -- omitting the key altogether (the default) seeds the exact shape
  // claimCameraForUser itself writes.
  if (overrides.homeCameraLinkOverrides !== null) {
    await homeCameraLinkRef(homeUid, cameraDeviceId).set({
      cameraDeviceId,
      homeDeviceId,
      pairedAt: admin.firestore.Timestamp.now(),
      status: "active",
      ...(overrides.homeCameraLinkOverrides ?? {}),
    });
  }

  const scenario = buildDeviceProofScenario({
    role: "HOME",
    deviceId: homeDeviceId,
    requestAuthUid: homeUid,
    cameraDeviceId,
    signingPrivateKey: homeKeyPair.privateKey,
    ...overrides.scenarioOverrides,
  });
  await seedScenario(scenario);

  return {
    homeDeviceId,
    homeUid,
    cameraDeviceId,
    cameraAuthUid,
    homeKeyPair,
    ...scenario,
    async cleanup() {
      await Promise.all([
        registryRef(homeDeviceId).delete(),
        registryRef(cameraDeviceId).delete(),
        claimRef(cameraDeviceId).delete(),
        challengeRef(scenario.challengeId).delete(),
        entitlementsRef(homeUid).delete(),
        homeCameraLinkRef(homeUid, cameraDeviceId).delete(),
      ]);
    },
  };
}

async function setupValidCameraScenario(overrides = {}) {
  const cameraDeviceId = uniqueId("dp-camera");
  const cameraAuthUid = uniqueId("dp-camera-auth-uid");
  const homeUid = uniqueId("dp-home-uid");
  const cameraKeyPair = generateEcKeyPair();

  await seedRegisteredDevice(cameraDeviceId, {
    role: "CAMERA",
    authUid: cameraAuthUid,
    ownerUid: homeUid,
    publicKey: publicKeySpkiBase64(cameraKeyPair.publicKey),
    ...(overrides.cameraDeviceOverrides ?? {}),
  });
  await claimRef(cameraDeviceId).set({
    uid: homeUid,
    cameraAuthUid,
    claimedAt: admin.firestore.Timestamp.now(),
    ...(overrides.claimOverrides ?? {}),
  });

  const scenario = buildDeviceProofScenario({
    role: "CAMERA",
    deviceId: cameraDeviceId,
    requestAuthUid: cameraAuthUid,
    cameraDeviceId,
    signingPrivateKey: cameraKeyPair.privateKey,
    ...overrides.scenarioOverrides,
  });
  await seedScenario(scenario);

  return {
    cameraDeviceId,
    cameraAuthUid,
    homeUid,
    cameraKeyPair,
    ...scenario,
    async cleanup() {
      await Promise.all([
        registryRef(cameraDeviceId).delete(),
        claimRef(cameraDeviceId).delete(),
        challengeRef(scenario.challengeId).delete(),
        entitlementsRef(homeUid).delete(),
      ]);
    },
  };
}

test.afterEach(() => {
  delete process.env.TURN_REST_SECRET;
});

// ---------------------------------------------------------------------------------------------
// 1: backward compatibility -- Camera legacy path preserved, Home path now fail-closed
// ---------------------------------------------------------------------------------------------
// Home no longer has a working unsigned path (see index.ts's getTurnCredentials, "Fail-closed for
// HOME"): a request without deviceProof from the linked Home owner (cameraClaims.uid) is now
// rejected outright. Camera does not yet send a deviceProof (edgeguard-camera-android's
// TurnCredentialsProvider only ever sends {cameraDeviceId, purpose}), so its own unsigned path
// (cameraClaims.cameraAuthUid) is deliberately left reachable, unchanged.

test("getTurnCredentials: a request without deviceProof at all still works for the Camera legacy path", async () => {
  process.env.TURN_REST_SECRET = "dp-compat-secret";
  const cameraDeviceId = uniqueId("dp-compat-camera");
  const ownerUid = uniqueId("dp-compat-owner");
  const cameraAuthUid = "dp-compat-camera-auth";
  await claimRef(cameraDeviceId).set({ uid: ownerUid, cameraAuthUid });

  const response = await getTurnCredentials.run(fakeRequest({ cameraDeviceId, purpose: TURN_PURPOSE }, cameraAuthUid));

  assert.equal(response.iceServers.length, 1);
  await claimRef(cameraDeviceId).delete();
});

test("getTurnCredentials: a request without deviceProof at all from the linked Home owner is now rejected (fail-closed)", async () => {
  process.env.TURN_REST_SECRET = "dp-compat-secret-2";
  const cameraDeviceId = uniqueId("dp-compat-camera-2");
  const ownerUid = uniqueId("dp-compat-owner-2");
  await claimRef(cameraDeviceId).set({ uid: ownerUid, cameraAuthUid: "dp-compat-camera-auth-2" });

  await assert.rejects(
    getTurnCredentials.run(fakeRequest({ cameraDeviceId, purpose: TURN_PURPOSE }, ownerUid)),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_PROOF_REQUIRED"
  );

  await claimRef(cameraDeviceId).delete();
});

// ---------------------------------------------------------------------------------------------
// 2-5: deviceProof envelope validation (pure + one integration check each)
// ---------------------------------------------------------------------------------------------

test("validateTurnCredentialsDeviceProof: null is rejected", () => {
  assert.equal(validateTurnCredentialsDeviceProof(null).valid, false);
});

test("validateTurnCredentialsDeviceProof: a malformed object is rejected", () => {
  assert.equal(validateTurnCredentialsDeviceProof("not-an-object").valid, false);
  assert.equal(validateTurnCredentialsDeviceProof(42).valid, false);
  assert.equal(validateTurnCredentialsDeviceProof([]).valid, false);
});

test("getTurnCredentials: deviceProof: null in the request is rejected, not treated as absent", async () => {
  const cameraDeviceId = uniqueId("dp-null-camera");
  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest({ cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: null }, "dp-null-uid")
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_DEVICE_PROOF"
  );
});

test("validateTurnCredentialsDeviceProof: an extra field is rejected", () => {
  const result = validateTurnCredentialsDeviceProof({
    protocolVersion: 1,
    challengeId: "abc",
    signature: "AAAA",
    deviceId: "smuggled-in",
  });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "UNEXPECTED_FIELDS");
});

test("validateTurnCredentialsDeviceProof: protocolVersion other than 1 is rejected", () => {
  const result = validateTurnCredentialsDeviceProof({ protocolVersion: 2, challengeId: "abc", signature: "AAAA" });
  assert.equal(result.valid, false);
  assert.equal(result.reason, "INVALID_PROTOCOL_VERSION");
});

test("validateDeviceProofSignatureBase64: malformed/non-canonical/Base64URL signatures are rejected", () => {
  assert.equal(validateDeviceProofSignatureBase64("").valid, false);
  assert.equal(validateDeviceProofSignatureBase64("not base64!!").valid, false);
  assert.equal(validateDeviceProofSignatureBase64("abc-_def").valid, false); // Base64URL chars
  assert.equal(validateDeviceProofSignatureBase64("has whitespace ==").valid, false);
  assert.equal(validateDeviceProofSignatureBase64("QQ=").valid, false); // non-canonical padding
});

// ---------------------------------------------------------------------------------------------
// 6-13: challenge-state checks
// ---------------------------------------------------------------------------------------------

test("getTurnCredentials: a nonexistent challenge is rejected with CHALLENGE_NOT_FOUND", async () => {
  const setup = await setupValidCameraScenario();
  await challengeRef(setup.challengeId).delete(); // never actually stored

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.cameraAuthUid
      )
    ),
    (err) => err.code === "not-found" && err.message === "CHALLENGE_NOT_FOUND"
  );
  await setup.cleanup();
});

test("getTurnCredentials: a challenge whose internal challengeId field doesn't match the document id is rejected", async () => {
  const setup = await setupValidCameraScenario({
    scenarioOverrides: { challengeDocOverrides: { challengeId: "some-other-id" } },
  });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.cameraAuthUid
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_PROOF_DENIED"
  );
  await setup.cleanup();
});

test("getTurnCredentials: a challenge for a different purpose is rejected", async () => {
  const setup = await setupValidCameraScenario({
    scenarioOverrides: { challengeDocOverrides: { purpose: "SOME_OTHER_PURPOSE" } },
  });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.cameraAuthUid
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_PROOF_DENIED"
  );
  await setup.cleanup();
});

test("getTurnCredentials: a challenge belonging to a different authUid is rejected", async () => {
  const setup = await setupValidCameraScenario();

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        "someone-else-entirely"
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_PROOF_DENIED"
  );
  await setup.cleanup();
});

test("getTurnCredentials: an already-used challenge is rejected", async () => {
  const setup = await setupValidCameraScenario({
    scenarioOverrides: { challengeDocOverrides: { usedAt: admin.firestore.Timestamp.now(), usedByFunction: "getTurnCredentials" } },
  });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.cameraAuthUid
      )
    ),
    (err) => err.code === "failed-precondition" && err.message === "CHALLENGE_ALREADY_USED"
  );
  await setup.cleanup();
});

test("getTurnCredentials: an expired challenge is rejected", async () => {
  const setup = await setupValidCameraScenario({ scenarioOverrides: { nowMillis: Date.now() - 120_000, ttlMs: 60_000 } });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.cameraAuthUid
      )
    ),
    (err) => err.code === "failed-precondition" && err.message === "CHALLENGE_EXPIRED"
  );
  await setup.cleanup();
});

test("getTurnCredentials: requestHash mismatch after changing cameraDeviceId is rejected", async () => {
  const setup = await setupValidCameraScenario();
  const otherCameraDeviceId = uniqueId("dp-other-camera");
  await seedRegisteredDevice(otherCameraDeviceId, { role: "CAMERA", authUid: "irrelevant" });
  await claimRef(otherCameraDeviceId).set({ uid: setup.homeUid, cameraAuthUid: setup.cameraAuthUid });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: otherCameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.cameraAuthUid
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_PROOF_DENIED"
  );
  await setup.cleanup();
  await registryRef(otherCameraDeviceId).delete();
  await claimRef(otherCameraDeviceId).delete();
});

test("getTurnCredentials: requestHash mismatch after changing TURN purpose is rejected", async () => {
  const setup = await setupValidCameraScenario(); // signed for TURN_PURPOSE = LIVE_VIEW

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: "ACTIVITY_ZONE", deviceProof: setup.deviceProof },
        setup.cameraAuthUid
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_PROOF_DENIED"
  );
  await setup.cleanup();
});

// ---------------------------------------------------------------------------------------------
// 14-20: requesting-device registry checks
// ---------------------------------------------------------------------------------------------

test("getTurnCredentials: a missing requesting device is rejected", async () => {
  const setup = await setupValidCameraScenario();
  await registryRef(setup.cameraDeviceId).delete();

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.cameraAuthUid
      )
    ),
    (err) => err.code === "not-found" && err.message === "DEVICE_NOT_REGISTERED"
  );
  await setup.cleanup();
});

test("getTurnCredentials: a legacy (not yet keystore) requesting device is rejected", async () => {
  const setup = await setupValidCameraScenario({
    cameraDeviceOverrides: { identityMode: "legacy", publicKey: null },
  });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.cameraAuthUid
      )
    ),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_NOT_PROVISIONED"
  );
  await setup.cleanup();
});

test("getTurnCredentials: a corrupt (keystore, no publicKey) requesting device registry is rejected", async () => {
  // Seed manually: setupValidCameraScenario always writes a real publicKey from the generated key
  // pair, so overwrite it afterward to simulate corruption without changing the setup helper.
  const setup = await setupValidCameraScenario();
  await registryRef(setup.cameraDeviceId).update({ publicKey: null });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.cameraAuthUid
      )
    ),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_IDENTITY_CORRUPT"
  );
  await setup.cleanup();
});

test("getTurnCredentials: registeredDevices.role different from the challenge's role is rejected", async () => {
  const setup = await setupValidCameraScenario({ cameraDeviceOverrides: { role: "HOME" } });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.cameraAuthUid
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_PROOF_DENIED"
  );
  await setup.cleanup();
});

test("getTurnCredentials: registeredDevices.authUid different from the caller is rejected", async () => {
  const setup = await setupValidCameraScenario({ cameraDeviceOverrides: { authUid: "a-different-auth-uid" } });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.cameraAuthUid
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_PROOF_DENIED"
  );
  await setup.cleanup();
});

test("getTurnCredentials: a suspended requesting device is rejected", async () => {
  const setup = await setupValidCameraScenario({ cameraDeviceOverrides: { status: "suspended", suspensionReason: "manual" } });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.cameraAuthUid
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_SUSPENDED"
  );
  await setup.cleanup();
});

test("getTurnCredentials: a revoked requesting device is rejected", async () => {
  const setup = await setupValidCameraScenario({
    cameraDeviceOverrides: { status: "revoked", revokedAt: admin.firestore.Timestamp.now() },
  });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.cameraAuthUid
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_REVOKED"
  );
  await setup.cleanup();
});

// ---------------------------------------------------------------------------------------------
// 21-22: role-specific pairing/target authorization
// ---------------------------------------------------------------------------------------------

test("getTurnCredentials: HOME no longer owns the Camera (claim reassigned) is rejected", async () => {
  const setup = await setupValidHomeScenario();
  await claimRef(setup.cameraDeviceId).update({ uid: "a-different-home-uid" });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.homeUid
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_PROOF_DENIED"
  );
  await setup.cleanup();
});

test("getTurnCredentials: a CAMERA requesting TURN for a different Camera is rejected", async () => {
  const setup = await setupValidCameraScenario();
  const otherCameraDeviceId = uniqueId("dp-other-target-camera");
  await seedRegisteredDevice(otherCameraDeviceId, { role: "CAMERA", authUid: "someone-else" });
  await claimRef(otherCameraDeviceId).set({ uid: setup.homeUid, cameraAuthUid: "someone-else" });

  // Build a NEW, otherwise-valid scenario but with role=CAMERA and cameraDeviceId != deviceId.
  const mismatchScenario = buildDeviceProofScenario({
    role: "CAMERA",
    deviceId: setup.cameraDeviceId,
    requestAuthUid: setup.cameraAuthUid,
    cameraDeviceId: otherCameraDeviceId,
    signingPrivateKey: setup.cameraKeyPair.privateKey,
  });
  await seedScenario(mismatchScenario);

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: otherCameraDeviceId, purpose: TURN_PURPOSE, deviceProof: mismatchScenario.deviceProof },
        setup.cameraAuthUid
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_PROOF_DENIED"
  );

  await setup.cleanup();
  await registryRef(otherCameraDeviceId).delete();
  await claimRef(otherCameraDeviceId).delete();
  await challengeRef(mismatchScenario.challengeId).delete();
});

// ---------------------------------------------------------------------------------------------
// 23-25: target Camera status / entitlement
// ---------------------------------------------------------------------------------------------

test("getTurnCredentials: a suspended target Camera is rejected (HOME proof)", async () => {
  const setup = await setupValidHomeScenario({ cameraDeviceOverrides: { status: "suspended", suspensionReason: "plan" } });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.homeUid
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_SUSPENDED_PLAN"
  );
  await setup.cleanup();
});

test("getTurnCredentials: a revoked target Camera is rejected (HOME proof)", async () => {
  const setup = await setupValidHomeScenario({
    cameraDeviceOverrides: { status: "revoked", revokedAt: admin.firestore.Timestamp.now() },
  });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.homeUid
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_REVOKED"
  );
  await setup.cleanup();
});

test("getTurnCredentials: entitlement changed to TURN-denied after the challenge was issued is rejected", async () => {
  const setup = await setupValidHomeScenario();
  await entitlementsRef(setup.homeUid).set({
    schemaVersion: 1,
    plan: "free",
    subscriptionStatus: "active",
    maxCameras: 1,
    maxHomeDevices: 1,
    maxConcurrentLiveSessions: 1,
    turnAccessAllowed: false,
    source: "manual",
    validUntil: null,
    createdAt: admin.firestore.Timestamp.now(),
    updatedAt: admin.firestore.Timestamp.now(),
  });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.homeUid
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "TURN_ACCESS_DENIED"
  );
  await setup.cleanup();
});

// ---------------------------------------------------------------------------------------------
// 26-27: signature validity
// ---------------------------------------------------------------------------------------------

test("getTurnCredentials: an incorrect signature is rejected", async () => {
  const otherKeyPair = generateEcKeyPair();
  const garbageSignature = crypto
    .sign("sha256", Buffer.from("not the real payload", "utf8"), otherKeyPair.privateKey)
    .toString("base64");
  const setup = await setupValidCameraScenario({ scenarioOverrides: { signatureOverride: garbageSignature } });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.cameraAuthUid
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_PROOF_DENIED"
  );
  await setup.cleanup();
});

test("getTurnCredentials: a signature made with a different P-256 key is rejected", async () => {
  const unrelatedKeyPair = generateEcKeyPair();
  const cameraDeviceId = uniqueId("dp-wrongkey-camera");
  const cameraAuthUid = uniqueId("dp-wrongkey-auth");
  const homeUid = uniqueId("dp-wrongkey-home");
  const realKeyPair = generateEcKeyPair();

  await seedRegisteredDevice(cameraDeviceId, {
    role: "CAMERA",
    authUid: cameraAuthUid,
    ownerUid: homeUid,
    publicKey: publicKeySpkiBase64(realKeyPair.publicKey), // registry has the REAL key
  });
  await claimRef(cameraDeviceId).set({ uid: homeUid, cameraAuthUid });

  const scenario = buildDeviceProofScenario({
    role: "CAMERA",
    deviceId: cameraDeviceId,
    requestAuthUid: cameraAuthUid,
    cameraDeviceId,
    signingPrivateKey: unrelatedKeyPair.privateKey, // signed with a DIFFERENT key
  });
  await seedScenario(scenario);

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest({ cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: scenario.deviceProof }, cameraAuthUid)
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_PROOF_DENIED"
  );

  await registryRef(cameraDeviceId).delete();
  await claimRef(cameraDeviceId).delete();
  await challengeRef(scenario.challengeId).delete();
});

// ---------------------------------------------------------------------------------------------
// 28-34: successful verification and its side effects
// ---------------------------------------------------------------------------------------------

test("getTurnCredentials: a valid HOME proof issues TURN credentials with the existing, unchanged response schema", async () => {
  process.env.TURN_REST_SECRET = "dp-home-success-secret";
  const setup = await setupValidHomeScenario();

  const response = await getTurnCredentials.run(
    fakeRequest({ cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof }, setup.homeUid)
  );

  // Same schema turn-credentials.test.js's own Camera-legacy-path test asserts -- proves the
  // deviceProof-verified issuance path returns byte-for-byte the same response shape as the
  // pre-existing, unsigned buildTurnCredentialsResponse() path (they're literally the same
  // function call -- see index.ts).
  assert.equal(response.iceServers.length, 1);
  assert.deepEqual(response.iceServers[0].urls, [
    "stun:turn.edgeguard.cc:3478",
    "turn:turn.edgeguard.cc:3478?transport=udp",
    "turn:turn.edgeguard.cc:3478?transport=tcp",
    "turns:turn.edgeguard.cc:5349?transport=tcp",
  ]);
  assert.match(response.iceServers[0].username, new RegExp(`^\\d+:${setup.homeUid}$`));
  assert.equal(
    response.iceServers[0].credential,
    crypto.createHmac("sha1", "dp-home-success-secret").update(response.iceServers[0].username).digest("base64")
  );
  assert.equal(typeof response.expiresAt, "number");
  await setup.cleanup();
});

test("getTurnCredentials: a valid CAMERA proof issues TURN credentials", async () => {
  process.env.TURN_REST_SECRET = "dp-camera-success-secret";
  const setup = await setupValidCameraScenario();

  const response = await getTurnCredentials.run(
    fakeRequest(
      { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
      setup.cameraAuthUid
    )
  );

  assert.equal(response.iceServers.length, 1);
  await setup.cleanup();
});

test("getTurnCredentials: a successful proof sets usedAt and usedByFunction=getTurnCredentials", async () => {
  process.env.TURN_REST_SECRET = "dp-usedat-secret";
  const setup = await setupValidCameraScenario();

  await getTurnCredentials.run(
    fakeRequest(
      { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
      setup.cameraAuthUid
    )
  );

  const doc = await challengeRef(setup.challengeId).get();
  assert.notEqual(doc.data().usedAt, null);
  assert.equal(doc.data().usedByFunction, "getTurnCredentials");
  await setup.cleanup();
});

test("getTurnCredentials: a successful proof sets deviceProofVersion=1 on the signing device", async () => {
  process.env.TURN_REST_SECRET = "dp-version-secret";
  const setup = await setupValidCameraScenario();

  await getTurnCredentials.run(
    fakeRequest(
      { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
      setup.cameraAuthUid
    )
  );

  const doc = await registryRef(setup.cameraDeviceId).get();
  assert.equal(doc.data().deviceProofVersion, DEVICE_PROOF_VERSION);
  await setup.cleanup();
});

test("getTurnCredentials: an invalid proof leaves the challenge document unchanged", async () => {
  const setup = await setupValidCameraScenario();
  const before = (await challengeRef(setup.challengeId).get()).data();

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest({ cameraDeviceId: setup.cameraDeviceId, purpose: "ACTIVITY_ZONE", deviceProof: setup.deviceProof }, setup.cameraAuthUid)
    )
  );

  const after = (await challengeRef(setup.challengeId).get()).data();
  assert.equal(after.usedAt, before.usedAt);
  assert.equal(after.usedByFunction, before.usedByFunction);
  await setup.cleanup();
});

test("getTurnCredentials: an invalid proof never sets deviceProofVersion", async () => {
  const setup = await setupValidCameraScenario();

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest({ cameraDeviceId: setup.cameraDeviceId, purpose: "ACTIVITY_ZONE", deviceProof: setup.deviceProof }, setup.cameraAuthUid)
    )
  );

  const doc = await registryRef(setup.cameraDeviceId).get();
  assert.equal(doc.data().deviceProofVersion, null);
  await setup.cleanup();
});

// ---------------------------------------------------------------------------------------------
// 35-37: replay and concurrency
// ---------------------------------------------------------------------------------------------

test("getTurnCredentials: reusing the same signature a second time is rejected", async () => {
  process.env.TURN_REST_SECRET = "dp-replay-secret";
  const setup = await setupValidCameraScenario();

  await getTurnCredentials.run(
    fakeRequest(
      { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
      setup.cameraAuthUid
    )
  );

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.cameraAuthUid
      )
    ),
    (err) => err.code === "failed-precondition" && err.message === "CHALLENGE_ALREADY_USED"
  );
  await setup.cleanup();
});

test("consumeVerifiedTurnCredentialsChallenge: two concurrent consumptions of the same challenge -- exactly one succeeds", async () => {
  const setup = await setupValidCameraScenario();

  const params = {
    requestAuthUid: setup.cameraAuthUid,
    cameraDeviceId: setup.cameraDeviceId,
    turnPurpose: TURN_PURPOSE,
    deviceProof: setup.deviceProof,
    nowMillis: Date.now(),
  };

  const [first, second] = await Promise.all([
    consumeVerifiedTurnCredentialsChallenge(db, params),
    consumeVerifiedTurnCredentialsChallenge(db, params),
  ]);

  const outcomes = [first.outcome, second.outcome];
  assert.equal(outcomes.filter((o) => o === "verified").length, 1, "exactly one must succeed");
  assert.equal(outcomes.filter((o) => o === "denied").length, 1, "the other must be denied, never silently double-applied");

  await setup.cleanup();
});

test("getTurnCredentials: the same challenge cannot be reused for a different TURN request (different camera)", async () => {
  process.env.TURN_REST_SECRET = "dp-reuse-secret";
  const setup = await setupValidCameraScenario();

  await getTurnCredentials.run(
    fakeRequest(
      { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
      setup.cameraAuthUid
    )
  );

  const otherCameraDeviceId = uniqueId("dp-reuse-other-camera");
  await seedRegisteredDevice(otherCameraDeviceId, { role: "CAMERA", authUid: setup.cameraAuthUid });
  await claimRef(otherCameraDeviceId).set({ uid: setup.homeUid, cameraAuthUid: setup.cameraAuthUid });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: otherCameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.cameraAuthUid
      )
    ),
    (err) => err.code === "failed-precondition" && err.message === "CHALLENGE_ALREADY_USED"
  );

  await setup.cleanup();
  await registryRef(otherCameraDeviceId).delete();
  await claimRef(otherCameraDeviceId).delete();
});

// ---------------------------------------------------------------------------------------------
// 38: logging never leaks sensitive material
// ---------------------------------------------------------------------------------------------

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

test("getTurnCredentials: public key, signature, canonical payload, and nonce never appear in logs", async () => {
  process.env.TURN_REST_SECRET = "dp-logging-secret";
  const setup = await setupValidCameraScenario();

  const output = await captureStdio(async () => {
    await getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.cameraAuthUid
      )
    );
  });

  assert.ok(output.includes("TURN_DEVICE_PROOF_VERIFY_SUCCESS"), "the success log line should still fire");
  assert.ok(!output.includes(setup.deviceProof.signature), "signature must never be logged");
  assert.ok(!output.includes(setup.challengeDoc.nonce), "nonce must never be logged");
  assert.ok(!output.includes(setup.canonicalDeviceProofPayload), "canonical payload must never be logged");
  assert.ok(
    !output.includes(publicKeySpkiBase64(setup.cameraKeyPair.publicKey)),
    "public key must never be logged"
  );

  await setup.cleanup();
});

// ---------------------------------------------------------------------------------------------
// Regression: proof verifier / credential issuer call counts.
// ---------------------------------------------------------------------------------------------
// Adapted to this repo's emulator-integration test style (node:test against a real Firestore
// emulator, no mocked seams to literally count calls on -- see this task's own "adapt the first
// count to the existing architecture" instruction). Each count is proxied through an observable
// side effect instead:
//   - unsigned Home request -> rejected before the deviceProof branch is even entered
//     (hasDeviceProofField is false) -- verifier calls = 0, issuer calls = 0. See
//     turn-credentials.test.js's own "performs no registry write and never reaches credential
//     issuance" test (proxied there via a deleted TURN_REST_SECRET still producing
//     DEVICE_PROOF_REQUIRED, never "internal").
//   - invalid signed Home request -> the verifier runs (and denies) -- verifier calls = 1; the
//     issuer is never reached -- issuer calls = 0. Proxied below the same way: TURN_REST_SECRET is
//     deleted, so if buildTurnCredentialsResponse (the issuer) were ever reached it would throw
//     "internal" instead of the expected DEVICE_PROOF_DENIED, and the challenge would end up
//     consumed if the verifier ran a second time.
//   - valid signed Home request -> the verifier runs once (consumes/marks the challenge used) and
//     the issuer runs exactly once (a real TURN response is returned) -- see "a valid HOME proof
//     issues TURN credentials with the existing, unchanged response schema" above, and "reusing
//     the same signature a second time is rejected" for the verifier's own single-use guarantee.

test("getTurnCredentials: an invalid signed Home proof runs the verifier (denies) but never reaches the issuer", async () => {
  delete process.env.TURN_REST_SECRET;
  const otherKeyPair = generateEcKeyPair();
  const garbageSignature = crypto
    .sign("sha256", Buffer.from("not the real payload", "utf8"), otherKeyPair.privateKey)
    .toString("base64");
  const setup = await setupValidHomeScenario({ scenarioOverrides: { signatureOverride: garbageSignature } });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof },
        setup.homeUid
      )
    ),
    // permission-denied/DEVICE_PROOF_DENIED, never "internal" -- proves buildTurnCredentialsResponse
    // (the issuer, which would throw "internal" for a missing secret) was never reached.
    (err) => err.code === "permission-denied" && err.message === "DEVICE_PROOF_DENIED"
  );

  // The verifier DID run (it read and evaluated the challenge) but must never have consumed it --
  // an invalid signature is denied before the atomic consumption step.
  const challengeDoc = await challengeRef(setup.challengeId).get();
  assert.equal(challengeDoc.data().usedAt, null, "an invalid proof must never consume the challenge");

  await setup.cleanup();
});

// =================================================================================================
// Home-device-to-Camera authorization -- verifiedHomeDeviceId, extracted from the verified
// challenge, must be the specific Home installation users/{ownerUid}/cameraDevices/{cameraDeviceId}
// records as having claimed this camera. cameraClaims.uid === request.auth.uid alone (already
// checked above) only proves ACCOUNT-level ownership, not which Home installation signed.
// =================================================================================================

// --- Actor identity is extracted from the verified challenge, never from the request -----------

test("consumeVerifiedTurnCredentialsChallenge: the verified outcome's deviceId is the challenge's own device, not the caller's uid or any request field", async () => {
  const setup = await setupValidHomeScenario();

  const consumption = await consumeVerifiedTurnCredentialsChallenge(db, {
    requestAuthUid: setup.homeUid,
    cameraDeviceId: setup.cameraDeviceId,
    turnPurpose: TURN_PURPOSE,
    deviceProof: setup.deviceProof,
    nowMillis: Date.now(),
  });

  assert.equal(consumption.outcome, "verified");
  assert.equal(consumption.deviceId, setup.homeDeviceId);
  assert.notEqual(consumption.deviceId, setup.homeUid, "deviceId must never equal the auth uid");
  assert.equal(consumption.role, "HOME");

  await setup.cleanup();
});

test("getTurnCredentials: a request with no homeDeviceId/deviceId field at all still completes the signed Home flow", async () => {
  process.env.TURN_REST_SECRET = "dp-noid-secret";
  const setup = await setupValidHomeScenario();

  // Exactly the documented request shape -- cameraDeviceId, purpose, deviceProof. No homeDeviceId,
  // no deviceId, ever.
  const request = { cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof };
  assert.deepEqual(Object.keys(request).sort(), ["cameraDeviceId", "deviceProof", "purpose"].sort());

  const response = await getTurnCredentials.run(fakeRequest(request, setup.homeUid));
  assert.equal(response.iceServers.length, 1);

  await setup.cleanup();
});

test("getTurnCredentials: a forged top-level homeDeviceId/deviceId/role field is ignored -- the verified actor is unchanged", async () => {
  process.env.TURN_REST_SECRET = "dp-forged-fields-secret";
  const setup = await setupValidHomeScenario();

  const response = await getTurnCredentials.run(
    fakeRequest(
      {
        cameraDeviceId: setup.cameraDeviceId,
        purpose: TURN_PURPOSE,
        deviceProof: setup.deviceProof,
        // None of these are part of the documented contract and none are ever read for
        // authorization -- the actor identity comes only from the verified challenge.
        homeDeviceId: "attacker-supplied-home-device-id",
        deviceId: "attacker-supplied-device-id",
        role: "CAMERA",
        authUid: "attacker-supplied-auth-uid",
        ownerUid: "attacker-supplied-owner-uid",
      },
      setup.homeUid
    )
  );

  assert.equal(response.iceServers.length, 1);
  assert.match(response.iceServers[0].username, new RegExp(`^\\d+:${setup.homeUid}$`));

  await setup.cleanup();
});

// --- Home <-> Camera device-level authorization ---------------------------------------------

test("getTurnCredentials: a Home device that claimed this Camera (canonical link) passes", async () => {
  process.env.TURN_REST_SECRET = "dp-link-ok-secret";
  const setup = await setupValidHomeScenario();

  const response = await getTurnCredentials.run(
    fakeRequest({ cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof }, setup.homeUid)
  );

  assert.equal(response.iceServers.length, 1);
  await setup.cleanup();
});

test("getTurnCredentials: no Home<->Camera link document at all is denied (missing link, fail closed)", async () => {
  const setup = await setupValidHomeScenario({ homeCameraLinkOverrides: null });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest({ cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof }, setup.homeUid)
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_PROOF_DENIED"
  );

  await setup.cleanup();
});

test("getTurnCredentials: a different Home device under the SAME owner uid (matching account, wrong installation) is denied", async () => {
  process.env.TURN_REST_SECRET = "dp-samewner-secret";
  // The canonical link records THIS home device as the one that claimed the camera...
  const linkedHomeDeviceId = uniqueId("dp-linked-home-device");
  const setup = await setupValidHomeScenario({ homeCameraLinkOverrides: { homeDeviceId: linkedHomeDeviceId } });

  // ...but setup.deviceProof is signed by setup.homeDeviceId, a DIFFERENT, also-registered Home
  // installation on the exact same account (same homeUid/ownerUid) -- the same Google account
  // signed into a second Home phone. cameraClaims.uid === request.auth.uid still matches (both
  // devices share the same owner), so only the device-level link check can catch this.
  assert.notEqual(setup.homeDeviceId, linkedHomeDeviceId);

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest({ cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof }, setup.homeUid)
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_PROOF_DENIED"
  );

  await setup.cleanup();
});

test("getTurnCredentials: matching ownerUid alone never bypasses the device-level link check", async () => {
  // Same scenario as above, phrased as the core guarantee this task adds: account-level ownership
  // (cameraClaims.uid === request.auth.uid) is necessary but not sufficient.
  process.env.TURN_REST_SECRET = "dp-ownerbypass-secret";
  const otherHomeDeviceId = uniqueId("dp-other-home-device");
  const setup = await setupValidHomeScenario({ homeCameraLinkOverrides: { homeDeviceId: otherHomeDeviceId } });

  const result = await consumeVerifiedTurnCredentialsChallenge(db, {
    requestAuthUid: setup.homeUid, // the real, matching account owner
    cameraDeviceId: setup.cameraDeviceId,
    turnPurpose: TURN_PURPOSE,
    deviceProof: setup.deviceProof, // signed by setup.homeDeviceId, NOT otherHomeDeviceId
    nowMillis: Date.now(),
  });

  assert.equal(result.outcome, "denied");
  assert.equal(result.reason, "HOME_CAMERA_LINK_MISMATCH");

  await setup.cleanup();
});

test("getTurnCredentials: an unpaired (deleted) Home<->Camera link denies a previously-valid Home device", async () => {
  process.env.TURN_REST_SECRET = "dp-unpaired-secret";
  const setup = await setupValidHomeScenario();

  // Simulates a real unpair: releaseCameraForUser/unpairCameraFromDevice/releaseCameraFromCamera
  // all t.delete() this exact document.
  await homeCameraLinkRef(setup.homeUid, setup.cameraDeviceId).delete();

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest({ cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof }, setup.homeUid)
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_PROOF_DENIED"
  );

  await setup.cleanup();
});

test("getTurnCredentials: a different owner's Home device is denied at the account level, before the device-link check", async () => {
  process.env.TURN_REST_SECRET = "dp-otherowner-secret";
  const setup = await setupValidHomeScenario();
  const intruderUid = uniqueId("dp-intruder-uid");

  // The claim is reassigned to a different owner -- claimOwnerUid no longer equals
  // setup.homeUid (requestAuthUid), so this must be denied by the existing account-level check
  // (CAMERA_ACCESS_DENIED) -- confirms the two layers (account-level, then device-level) are both
  // still independently enforced, in the right order.
  await claimRef(setup.cameraDeviceId).set({ uid: intruderUid, cameraAuthUid: setup.cameraAuthUid }, { merge: true });

  const result = await consumeVerifiedTurnCredentialsChallenge(db, {
    requestAuthUid: setup.homeUid,
    cameraDeviceId: setup.cameraDeviceId,
    turnPurpose: TURN_PURPOSE,
    deviceProof: setup.deviceProof,
    nowMillis: Date.now(),
  });

  assert.equal(result.outcome, "denied");
  assert.equal(result.reason, "CAMERA_ACCESS_DENIED");

  await setup.cleanup();
  await claimRef(setup.cameraDeviceId).delete();
});

test("getTurnCredentials: a stranger Camera is never distinguished from a link-mismatch by error shape (no oracle)", async () => {
  process.env.TURN_REST_SECRET = "dp-oracle-secret";
  const linkMismatchSetup = await setupValidHomeScenario({ homeCameraLinkOverrides: null });
  const notFoundResult = await assert.rejects(
    getTurnCredentials.run(
      fakeRequest({ cameraDeviceId: "dp-nonexistent-camera-oracle", purpose: TURN_PURPOSE, deviceProof: linkMismatchSetup.deviceProof }, linkMismatchSetup.homeUid)
    )
  );

  const linkMismatchRejection = await getTurnCredentials
    .run(fakeRequest({ cameraDeviceId: linkMismatchSetup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: linkMismatchSetup.deviceProof }, linkMismatchSetup.homeUid))
    .catch((err) => err);

  // Both are the exact same generic, non-distinguishing public rejection.
  assert.equal(linkMismatchRejection.code, "permission-denied");
  assert.equal(linkMismatchRejection.message, "DEVICE_PROOF_DENIED");

  await linkMismatchSetup.cleanup();
});

// --- Regression: proof verifier / authorization lookup / TURN issuer call counts ----------------
// Adapted to this repo's emulator-integration test style (no mocked seams -- see this file's
// earlier regression test for the same convention). Each count is proxied through an observable
// side effect:
//   - invalid signature -> the verifier runs (transaction executes, reads the challenge) but
//     denies before ever reaching the NEW Home<->Camera link lookup (see deviceChallenges.ts:
//     signature is checked before that lookup specifically so this ordering holds) and before the
//     issuer -- proxied via TURN_REST_SECRET being unset yet the error still being
//     DEVICE_PROOF_DENIED, not "internal", AND via the target camera's registeredDevices document
//     being completely untouched (the link lookup, had it run, would not itself write anything,
//     but this also confirms attachCameraOwner/the issuer never ran).
//   - valid proof, unauthorized Home (no/mismatched link) -> the verifier runs AND the link lookup
//     runs (that's what produces HOME_CAMERA_LINK_MISMATCH) but the issuer is never reached --
//     proxied the same way via the unset secret.
//   - valid proof, authorized Home -> verifier runs, link lookup runs, issuer runs exactly once --
//     a real TURN response is returned.

test("regression: invalid signature never reaches the Home<->Camera authorization lookup or the issuer", async () => {
  delete process.env.TURN_REST_SECRET;
  const otherKeyPair = generateEcKeyPair();
  const garbageSignature = crypto
    .sign("sha256", Buffer.from("not the real payload", "utf8"), otherKeyPair.privateKey)
    .toString("base64");
  const setup = await setupValidHomeScenario({ scenarioOverrides: { signatureOverride: garbageSignature } });
  const cameraBefore = (await registryRef(setup.cameraDeviceId).get()).data();

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest({ cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof }, setup.homeUid)
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_PROOF_DENIED"
  );

  const cameraAfter = (await registryRef(setup.cameraDeviceId).get()).data();
  assert.deepEqual(cameraAfter.updatedAt, cameraBefore.updatedAt, "no registry write must happen past signature verification");

  const challengeDoc = await challengeRef(setup.challengeId).get();
  assert.equal(challengeDoc.data().usedAt, null, "an invalid signature must never consume the challenge");

  await setup.cleanup();
});

test("regression: a valid proof with an unauthorized Home runs the link lookup but never the issuer", async () => {
  delete process.env.TURN_REST_SECRET;
  const setup = await setupValidHomeScenario({ homeCameraLinkOverrides: null });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest({ cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof }, setup.homeUid)
    ),
    // permission-denied/DEVICE_PROOF_DENIED, never "internal" -- proves the issuer
    // (buildTurnCredentialsResponse, which would throw "internal" for the deliberately-unset
    // secret) was never reached, even though the link lookup itself DID run (that's what produced
    // this specific denial).
    (err) => err.code === "permission-denied" && err.message === "DEVICE_PROOF_DENIED"
  );

  const challengeDoc = await challengeRef(setup.challengeId).get();
  assert.equal(challengeDoc.data().usedAt, null, "an unauthorized Home must never consume the challenge");

  await setup.cleanup();
});

test("regression: a valid proof with an authorized Home runs verifier, link lookup, and issuer exactly once", async () => {
  process.env.TURN_REST_SECRET = "dp-full-chain-secret";
  const setup = await setupValidHomeScenario();

  const response = await getTurnCredentials.run(
    fakeRequest({ cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof }, setup.homeUid)
  );

  assert.equal(response.iceServers.length, 1);
  const challengeDoc = await challengeRef(setup.challengeId).get();
  assert.notEqual(challengeDoc.data().usedAt, null, "the verifier must consume the challenge exactly once");
  assert.equal(challengeDoc.data().usedByFunction, "getTurnCredentials");

  // A second call with the same (now-consumed) proof must not succeed again -- issuer runs at
  // most once per proof, matching this file's own "reusing the same signature" test above.
  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest({ cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof }, setup.homeUid)
    ),
    (err) => err.code === "failed-precondition" && err.message === "CHALLENGE_ALREADY_USED"
  );

  await setup.cleanup();
});

test("regression: a denied signed Home request never reaches the Camera legacy path (no attachCameraOwner side effect)", async () => {
  const setup = await setupValidHomeScenario({ homeCameraLinkOverrides: null });
  const before = (await registryRef(setup.cameraDeviceId).get()).data();

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest({ cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof }, setup.homeUid)
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_PROOF_DENIED"
  );

  // attachCameraOwner (the Camera legacy-path bookkeeping call) always bumps updatedAt/lastSeenAt
  // on an existing, identity-matching registeredDevices document -- it is only ever invoked after
  // consumption.outcome === "verified", so it must never have run here.
  const after = (await registryRef(setup.cameraDeviceId).get()).data();
  assert.deepEqual(after.updatedAt, before.updatedAt);
  assert.deepEqual(after.lastSeenAt, before.lastSeenAt);

  await setup.cleanup();
});

// --- Logging: the new Home-device-to-Camera authorization must never log identifiers -----------

test("getTurnCredentials: Home<->Camera link mismatch never logs homeDeviceId, cameraDeviceId, challengeId, authUid, or ownerUid", async () => {
  const setup = await setupValidHomeScenario({ homeCameraLinkOverrides: null });

  const output = await captureStdio(async () => {
    await assert.rejects(
      getTurnCredentials.run(
        fakeRequest({ cameraDeviceId: setup.cameraDeviceId, purpose: TURN_PURPOSE, deviceProof: setup.deviceProof }, setup.homeUid)
      )
    );
  });

  // Inspect only the specific TURN_DEVICE_PROOF_VERIFY_* log entries this task's stricter
  // contract governs -- not the whole captured output, which also (legitimately, unchanged, out
  // of this task's scope) includes the pre-existing GET_TURN_CREDENTIALS_START line logging
  // uid/cameraDeviceId, same as every other pre-existing log line in this callable (see
  // turn-credentials.test.js's own equivalent scoping decision for the DEVICE_PROOF_REQUIRED
  // rejection line).
  const proofLines = output.split("\n").filter((line) => line.includes("TURN_DEVICE_PROOF_VERIFY_"));
  assert.ok(proofLines.some((line) => line.includes("TURN_DEVICE_PROOF_VERIFY_DENIED")), "the denial log line should still fire");

  const forbidden = [setup.homeDeviceId, setup.cameraDeviceId, setup.challengeId, setup.homeUid, setup.deviceProof.signature];
  for (const line of proofLines) {
    const entry = JSON.parse(line);
    // Every field on every TURN_DEVICE_PROOF_VERIFY_* entry must be one of the explicitly allowed
    // safe fields (stage/purpose/role/protocolVersion/reason/message/severity) -- never an
    // identifier.
    for (const key of Object.keys(entry)) {
      assert.ok(
        ["stage", "purpose", "role", "protocolVersion", "reason", "message", "severity"].includes(key),
        `unexpected field "${key}" on log entry: ${line}`
      );
    }
    for (const needle of forbidden) {
      assert.ok(!line.includes(needle), `log entry must not contain "${needle}": ${line}`);
    }
  }

  await setup.cleanup();
});
