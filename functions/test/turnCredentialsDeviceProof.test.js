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
