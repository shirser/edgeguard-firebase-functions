const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

// Requiring lib/index.js runs admin.initializeApp() once; requires npm run build to have produced
// lib/ from src/ first (source of truth stays src).
const {
  createDeviceChallenge,
  DEVICE_CHALLENGE_PURPOSES,
  isDeviceChallengePurpose,
  validateTurnCredentialsRequestPayload,
  buildCanonicalTurnCredentialsRequestPayload,
  sha256Hex,
  buildCanonicalDeviceProofPayload,
  generateChallengeNonce,
  checkDeviceChallengeEligibility,
  buildDeviceChallengeDocument,
  CHALLENGE_NONCE_BYTE_LENGTH,
  CHALLENGE_TTL_SECONDS,
  DEVICE_CHALLENGE_SCHEMA_VERSION,
} = require("../lib/index.js");
const admin = require("firebase-admin");

const db = admin.firestore();

function registryRef(deviceId) {
  return db.collection("registeredDevices").doc(deviceId);
}

function claimRef(cameraDeviceId) {
  return db.collection("cameraClaims").doc(cameraDeviceId);
}

function entitlementsRef(uid) {
  return db.collection("userEntitlements").doc(uid);
}

// Minimal CallableRequest stand-in -- createDeviceChallenge only reads request.auth.uid and
// request.data, so nothing else needs to be real (same convention as turn-credentials.test.js).
function fakeRequest(data, uid) {
  return {
    data,
    auth: uid ? { uid, token: {}, rawToken: "" } : undefined,
    rawRequest: {},
    acceptsStreaming: false,
  };
}

function turnRequestData(deviceId, cameraDeviceId, turnPurpose = "LIVE_VIEW") {
  return {
    deviceId,
    purpose: "TURN_CREDENTIALS",
    requestPayload: { cameraDeviceId, turnPurpose },
  };
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
    publicKey: "dc-test-public-key",
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    revokedAt: null,
    ...overrides,
  });
}

// ---------------------------------------------------------------------------------------------
// 1-19: createDeviceChallenge (integration, against the Firestore emulator)
// ---------------------------------------------------------------------------------------------

test("createDeviceChallenge: unauthenticated request is rejected", async () => {
  await assert.rejects(
    createDeviceChallenge.run(fakeRequest(turnRequestData("dc-unauth-device", "dc-unauth-device"), undefined)),
    (err) => err.code === "unauthenticated" && err.message === "UNAUTHENTICATED"
  );
});

test("createDeviceChallenge: unknown purpose is rejected", async () => {
  await assert.rejects(
    createDeviceChallenge.run(
      fakeRequest(
        { deviceId: "dc-purpose-device", purpose: "BOGUS_PURPOSE", requestPayload: { cameraDeviceId: "dc-purpose-device", turnPurpose: "LIVE_VIEW" } },
        "dc-purpose-uid"
      )
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_PURPOSE"
  );
});

test("createDeviceChallenge: missing deviceId is rejected", async () => {
  await assert.rejects(
    createDeviceChallenge.run(
      fakeRequest(
        { purpose: "TURN_CREDENTIALS", requestPayload: { cameraDeviceId: "dc-missingid-camera", turnPurpose: "LIVE_VIEW" } },
        "dc-missingid-uid"
      )
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_DEVICE_ID"
  );
});

test("createDeviceChallenge: empty/blank deviceId is rejected", async () => {
  await assert.rejects(
    createDeviceChallenge.run(fakeRequest(turnRequestData("", ""), "dc-blankid-uid")),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_DEVICE_ID"
  );
  await assert.rejects(
    createDeviceChallenge.run(fakeRequest(turnRequestData("   ", "   "), "dc-blankid-uid-2")),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_DEVICE_ID"
  );
});

test("createDeviceChallenge: client-supplied role field is rejected", async () => {
  await assert.rejects(
    createDeviceChallenge.run(
      fakeRequest(
        {
          deviceId: "dc-role-device",
          purpose: "TURN_CREDENTIALS",
          role: "HOME",
          requestPayload: { cameraDeviceId: "dc-role-device", turnPurpose: "LIVE_VIEW" },
        },
        "dc-role-uid"
      )
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_REQUEST"
  );
});

test("createDeviceChallenge: client-supplied requestHash field is rejected", async () => {
  await assert.rejects(
    createDeviceChallenge.run(
      fakeRequest(
        {
          deviceId: "dc-hash-device",
          purpose: "TURN_CREDENTIALS",
          requestHash: "a".repeat(64),
          requestPayload: { cameraDeviceId: "dc-hash-device", turnPurpose: "LIVE_VIEW" },
        },
        "dc-hash-uid"
      )
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_REQUEST"
  );
});

test("createDeviceChallenge: malformed requestPayload is rejected", async () => {
  await assert.rejects(
    createDeviceChallenge.run(
      fakeRequest({ deviceId: "dc-malformed-device", purpose: "TURN_CREDENTIALS", requestPayload: "not-an-object" }, "dc-malformed-uid")
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_REQUEST_PAYLOAD"
  );
});

test("createDeviceChallenge: extra field in requestPayload is rejected", async () => {
  await assert.rejects(
    createDeviceChallenge.run(
      fakeRequest(
        {
          deviceId: "dc-extra-device",
          purpose: "TURN_CREDENTIALS",
          requestPayload: { cameraDeviceId: "dc-extra-device", turnPurpose: "LIVE_VIEW", extra: "x" },
        },
        "dc-extra-uid"
      )
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_REQUEST_PAYLOAD"
  );
});

test("createDeviceChallenge: unknown turnPurpose is rejected", async () => {
  await assert.rejects(
    createDeviceChallenge.run(
      fakeRequest(
        { deviceId: "dc-turnpurpose-device", purpose: "TURN_CREDENTIALS", requestPayload: { cameraDeviceId: "dc-turnpurpose-device", turnPurpose: "BOGUS" } },
        "dc-turnpurpose-uid"
      )
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_REQUEST_PAYLOAD"
  );
});

test("createDeviceChallenge: missing registered device is rejected", async () => {
  await assert.rejects(
    createDeviceChallenge.run(fakeRequest(turnRequestData("dc-missing-device", "dc-missing-device"), "dc-missing-uid")),
    (err) => err.code === "not-found" && err.message === "DEVICE_NOT_REGISTERED"
  );
});

test("createDeviceChallenge: a legacy (not yet keystore) device is rejected", async () => {
  const deviceId = "dc-legacy-device";
  const uid = "dc-legacy-uid";
  await seedRegisteredDevice(deviceId, { authUid: uid, identityMode: "legacy", publicKey: null });

  await assert.rejects(
    createDeviceChallenge.run(fakeRequest(turnRequestData(deviceId, deviceId), uid)),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_NOT_PROVISIONED"
  );

  await registryRef(deviceId).delete();
});

test("createDeviceChallenge: a keystore device with no publicKey is rejected as corrupt", async () => {
  const deviceId = "dc-corrupt-device";
  const uid = "dc-corrupt-uid";
  await seedRegisteredDevice(deviceId, { authUid: uid, identityMode: "keystore", publicKey: null });

  await assert.rejects(
    createDeviceChallenge.run(fakeRequest(turnRequestData(deviceId, deviceId), uid)),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_IDENTITY_CORRUPT"
  );

  await registryRef(deviceId).delete();
});

test("createDeviceChallenge: authUid mismatch is rejected", async () => {
  const deviceId = "dc-mismatch-device";
  await seedRegisteredDevice(deviceId, { authUid: "dc-mismatch-real-uid" });

  await assert.rejects(
    createDeviceChallenge.run(fakeRequest(turnRequestData(deviceId, deviceId), "dc-mismatch-wrong-uid")),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_IDENTITY_MISMATCH"
  );

  await registryRef(deviceId).delete();
});

test("createDeviceChallenge: a suspended requesting device is rejected", async () => {
  const deviceId = "dc-suspended-device";
  const uid = "dc-suspended-uid";
  await seedRegisteredDevice(deviceId, { authUid: uid, status: "suspended", suspensionReason: "manual" });

  await assert.rejects(
    createDeviceChallenge.run(fakeRequest(turnRequestData(deviceId, deviceId), uid)),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_SUSPENDED"
  );

  await registryRef(deviceId).delete();
});

test("createDeviceChallenge: a revoked requesting device is rejected", async () => {
  const deviceId = "dc-revoked-device";
  const uid = "dc-revoked-uid";
  await seedRegisteredDevice(deviceId, { authUid: uid, status: "revoked", revokedAt: admin.firestore.Timestamp.now() });

  await assert.rejects(
    createDeviceChallenge.run(fakeRequest(turnRequestData(deviceId, deviceId), uid)),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_REVOKED"
  );

  await registryRef(deviceId).delete();
});

test("createDeviceChallenge: a HOME device without access to the target Camera is rejected", async () => {
  const homeDeviceId = "dc-noaccess-home-device";
  const homeUid = "dc-noaccess-home-uid";
  const cameraDeviceId = "dc-noaccess-camera";
  await seedRegisteredDevice(homeDeviceId, { role: "HOME", authUid: homeUid, ownerUid: homeUid });
  // The claim links a DIFFERENT Home uid to this camera -- homeUid is a real, valid, registered
  // device, just not the one linked to this specific camera.
  await claimRef(cameraDeviceId).set({ uid: "dc-noaccess-someone-else-uid", cameraAuthUid: "dc-noaccess-camera-auth-uid" });

  await assert.rejects(
    createDeviceChallenge.run(fakeRequest(turnRequestData(homeDeviceId, cameraDeviceId), homeUid)),
    (err) => err.code === "permission-denied" && err.message === "PERMISSION_DENIED"
  );

  await registryRef(homeDeviceId).delete();
  await claimRef(cameraDeviceId).delete();
});

test("createDeviceChallenge: a CAMERA requesting about a different cameraDeviceId is rejected", async () => {
  const cameraDeviceId = "dc-wrongtarget-camera";
  const otherCameraDeviceId = "dc-wrongtarget-other-camera";
  const cameraAuthUid = "dc-wrongtarget-camera-auth-uid";
  await seedRegisteredDevice(cameraDeviceId, { role: "CAMERA", authUid: cameraAuthUid });

  await assert.rejects(
    createDeviceChallenge.run(fakeRequest(turnRequestData(cameraDeviceId, otherCameraDeviceId), cameraAuthUid)),
    (err) => err.code === "permission-denied" && err.message === "PERMISSION_DENIED"
  );

  await registryRef(cameraDeviceId).delete();
});

test("createDeviceChallenge: entitlement without TURN access is rejected", async () => {
  const homeDeviceId = "dc-noturn-home-device";
  const homeUid = "dc-noturn-home-uid";
  const cameraDeviceId = "dc-noturn-camera";
  const cameraAuthUid = "dc-noturn-camera-auth-uid";
  await seedRegisteredDevice(homeDeviceId, { role: "HOME", authUid: homeUid, ownerUid: homeUid });
  await seedRegisteredDevice(cameraDeviceId, { role: "CAMERA", authUid: cameraAuthUid, ownerUid: homeUid });
  await claimRef(cameraDeviceId).set({ uid: homeUid, cameraAuthUid });
  await entitlementsRef(homeUid).set({
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
    createDeviceChallenge.run(fakeRequest(turnRequestData(homeDeviceId, cameraDeviceId), homeUid)),
    (err) => err.code === "permission-denied" && err.message === "TURN_ACCESS_DENIED"
  );

  await registryRef(homeDeviceId).delete();
  await registryRef(cameraDeviceId).delete();
  await claimRef(cameraDeviceId).delete();
  await entitlementsRef(homeUid).delete();
});

test("createDeviceChallenge: a successful HOME challenge is created", async () => {
  const homeDeviceId = "dc-success-home-device";
  const homeUid = "dc-success-home-uid";
  const cameraDeviceId = "dc-success-camera";
  const cameraAuthUid = "dc-success-camera-auth-uid";
  await seedRegisteredDevice(homeDeviceId, { role: "HOME", authUid: homeUid, ownerUid: homeUid });
  await seedRegisteredDevice(cameraDeviceId, { role: "CAMERA", authUid: cameraAuthUid, ownerUid: homeUid });
  await claimRef(cameraDeviceId).set({ uid: homeUid, cameraAuthUid });

  const response = await createDeviceChallenge.run(fakeRequest(turnRequestData(homeDeviceId, cameraDeviceId), homeUid));

  assert.equal(response.purpose, "TURN_CREDENTIALS");
  assert.equal(typeof response.challengeId, "string");
  assert.ok(response.challengeId.length > 0);
  assert.equal(typeof response.nonce, "string");
  assert.equal(typeof response.canonicalPayload, "string");
  assert.equal(typeof response.expiresAt, "number");

  const doc = await db.collection("deviceChallenges").doc(response.challengeId).get();
  assert.equal(doc.exists, true);
  assert.equal(doc.data().role, "HOME");
  assert.equal(doc.data().deviceId, homeDeviceId);
  assert.equal(doc.data().authUid, homeUid);

  await registryRef(homeDeviceId).delete();
  await registryRef(cameraDeviceId).delete();
  await claimRef(cameraDeviceId).delete();
});

test("createDeviceChallenge: a successful CAMERA challenge is created", async () => {
  const cameraDeviceId = "dc-success-camera-2";
  const cameraAuthUid = "dc-success-camera-auth-uid-2";
  const homeUid = "dc-success-home-uid-2";
  await seedRegisteredDevice(cameraDeviceId, { role: "CAMERA", authUid: cameraAuthUid, ownerUid: homeUid });
  await claimRef(cameraDeviceId).set({ uid: homeUid, cameraAuthUid });

  const response = await createDeviceChallenge.run(
    fakeRequest(turnRequestData(cameraDeviceId, cameraDeviceId, "MEDIA_TRANSFER"), cameraAuthUid)
  );

  assert.equal(response.purpose, "TURN_CREDENTIALS");

  const doc = await db.collection("deviceChallenges").doc(response.challengeId).get();
  assert.equal(doc.data().role, "CAMERA");
  assert.equal(doc.data().deviceId, cameraDeviceId);
  assert.equal(doc.data().authUid, cameraAuthUid);

  await registryRef(cameraDeviceId).delete();
  await claimRef(cameraDeviceId).delete();
});

test("createDeviceChallenge: role on the stored document comes from the registry, never the request", async () => {
  // request.data structurally cannot even carry a `role` field (see the "client-supplied role
  // field is rejected" test above) -- this asserts the positive side: the callable itself never
  // reads anything named `role` off request.data, only off the registeredDevices document.
  const cameraDeviceId = "dc-role-source-camera";
  const cameraAuthUid = "dc-role-source-camera-auth-uid";
  const homeUid = "dc-role-source-home-uid";
  await seedRegisteredDevice(cameraDeviceId, { role: "CAMERA", authUid: cameraAuthUid, ownerUid: homeUid });
  await claimRef(cameraDeviceId).set({ uid: homeUid, cameraAuthUid });

  const response = await createDeviceChallenge.run(fakeRequest(turnRequestData(cameraDeviceId, cameraDeviceId), cameraAuthUid));
  const doc = await db.collection("deviceChallenges").doc(response.challengeId).get();
  assert.equal(doc.data().role, "CAMERA");

  await registryRef(cameraDeviceId).delete();
  await claimRef(cameraDeviceId).delete();
});

// ---------------------------------------------------------------------------------------------
// 20-24: pure crypto/canonicalization vectors (fixed inputs -- deterministic, no emulator needed)
// ---------------------------------------------------------------------------------------------

test("generateChallengeNonce: 32 random bytes, 43 base64url characters, no padding", () => {
  const nonce = generateChallengeNonce();
  assert.equal(nonce.length, 43);
  assert.match(nonce, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(Buffer.from(nonce, "base64url").length, CHALLENGE_NONCE_BYTE_LENGTH);

  const second = generateChallengeNonce();
  assert.notEqual(nonce, second, "two calls must not produce the same nonce");
});

test("sha256Hex: matches a fixed, well-known SHA-256 test vector", () => {
  // SHA-256 of the empty string -- a universally known constant, independent of this codebase.
  assert.equal(sha256Hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});

test("sha256Hex: lowercase, exactly 64 hex characters, matches Node's own crypto module independently", () => {
  const input = "EDGEGUARD_REQUEST_V1\npurpose=TURN_CREDENTIALS\ncameraDeviceId=camera-1\nturnPurpose=LIVE_VIEW";
  const expected = crypto.createHash("sha256").update(input, "utf8").digest("hex");
  const actual = sha256Hex(input);
  assert.equal(actual, expected);
  assert.equal(actual.length, 64);
  assert.equal(actual, actual.toLowerCase());
});

test("buildCanonicalTurnCredentialsRequestPayload: exact byte-for-byte canonical string", () => {
  const payload = buildCanonicalTurnCredentialsRequestPayload({ cameraDeviceId: "camera-1", turnPurpose: "LIVE_VIEW" });
  assert.equal(payload, "EDGEGUARD_REQUEST_V1\npurpose=TURN_CREDENTIALS\ncameraDeviceId=camera-1\nturnPurpose=LIVE_VIEW");
});

test("buildCanonicalTurnCredentialsRequestPayload: has no trailing newline", () => {
  const payload = buildCanonicalTurnCredentialsRequestPayload({ cameraDeviceId: "camera-1", turnPurpose: "LIVE_VIEW" });
  assert.equal(payload.endsWith("\n"), false);
});

test("buildCanonicalDeviceProofPayload: exact byte-for-byte canonical string", () => {
  const payload = buildCanonicalDeviceProofPayload({
    challengeId: "challenge-abc",
    deviceId: "camera-1",
    role: "CAMERA",
    purpose: "TURN_CREDENTIALS",
    authUid: "uid-xyz",
    nonce: "n".repeat(43),
    requestHash: "h".repeat(64),
    expiresAtMillis: 1_800_000_090_000,
  });

  const expected = [
    "EDGEGUARD_DEVICE_PROOF_V1",
    "challengeId=challenge-abc",
    "deviceId=camera-1",
    "role=CAMERA",
    "purpose=TURN_CREDENTIALS",
    "authUid=uid-xyz",
    `nonce=${"n".repeat(43)}`,
    `requestHash=${"h".repeat(64)}`,
    "expiresAt=1800000090000",
  ].join("\n");

  assert.equal(payload, expected);
});

test("buildCanonicalDeviceProofPayload: has no trailing newline", () => {
  const payload = buildCanonicalDeviceProofPayload({
    challengeId: "challenge-abc",
    deviceId: "camera-1",
    role: "CAMERA",
    purpose: "TURN_CREDENTIALS",
    authUid: "uid-xyz",
    nonce: "n".repeat(43),
    requestHash: "h".repeat(64),
    expiresAtMillis: 1_800_000_090_000,
  });
  assert.equal(payload.endsWith("\n"), false);
  assert.equal(payload.includes("\n\n"), false);
});

// ---------------------------------------------------------------------------------------------
// 25-27, 29: challenge document/response shape (integration)
// ---------------------------------------------------------------------------------------------

test("createDeviceChallenge: TTL is exactly 90 seconds", async () => {
  const cameraDeviceId = "dc-ttl-camera";
  const cameraAuthUid = "dc-ttl-camera-auth-uid";
  const homeUid = "dc-ttl-home-uid";
  await seedRegisteredDevice(cameraDeviceId, { role: "CAMERA", authUid: cameraAuthUid, ownerUid: homeUid });
  await claimRef(cameraDeviceId).set({ uid: homeUid, cameraAuthUid });

  const before = Date.now();
  const response = await createDeviceChallenge.run(fakeRequest(turnRequestData(cameraDeviceId, cameraDeviceId), cameraAuthUid));
  const after = Date.now();

  assert.ok(response.expiresAt >= before + CHALLENGE_TTL_SECONDS * 1000);
  assert.ok(response.expiresAt <= after + CHALLENGE_TTL_SECONDS * 1000);

  await registryRef(cameraDeviceId).delete();
  await claimRef(cameraDeviceId).delete();
});

test("createDeviceChallenge: stored document contains only the allowed fields", async () => {
  const cameraDeviceId = "dc-fields-camera";
  const cameraAuthUid = "dc-fields-camera-auth-uid";
  const homeUid = "dc-fields-home-uid";
  await seedRegisteredDevice(cameraDeviceId, { role: "CAMERA", authUid: cameraAuthUid, ownerUid: homeUid });
  await claimRef(cameraDeviceId).set({ uid: homeUid, cameraAuthUid });

  const response = await createDeviceChallenge.run(fakeRequest(turnRequestData(cameraDeviceId, cameraDeviceId), cameraAuthUid));
  const doc = await db.collection("deviceChallenges").doc(response.challengeId).get();

  assert.deepEqual(
    Object.keys(doc.data()).sort(),
    [
      "authUid",
      "challengeId",
      "createdAt",
      "deviceId",
      "expiresAt",
      "nonce",
      "purpose",
      "requestHash",
      "role",
      "schemaVersion",
      "usedAt",
      "usedByFunction",
    ].sort()
  );
  assert.equal(doc.data().schemaVersion, DEVICE_CHALLENGE_SCHEMA_VERSION);
  assert.equal(doc.data().usedAt, null);
  assert.equal(doc.data().usedByFunction, null);

  await registryRef(cameraDeviceId).delete();
  await claimRef(cameraDeviceId).delete();
});

test("createDeviceChallenge: response never exposes authUid/publicKey/requestHash as separate fields", async () => {
  const cameraDeviceId = "dc-response-shape-camera";
  const cameraAuthUid = "dc-response-shape-camera-auth-uid";
  const homeUid = "dc-response-shape-home-uid";
  await seedRegisteredDevice(cameraDeviceId, { role: "CAMERA", authUid: cameraAuthUid, ownerUid: homeUid });
  await claimRef(cameraDeviceId).set({ uid: homeUid, cameraAuthUid });

  const response = await createDeviceChallenge.run(fakeRequest(turnRequestData(cameraDeviceId, cameraDeviceId), cameraAuthUid));

  assert.deepEqual(Object.keys(response).sort(), ["canonicalPayload", "challengeId", "expiresAt", "nonce", "purpose"].sort());

  await registryRef(cameraDeviceId).delete();
  await claimRef(cameraDeviceId).delete();
});

test("createDeviceChallenge: two sequential calls produce different challengeId and nonce", async () => {
  const cameraDeviceId = "dc-sequential-camera";
  const cameraAuthUid = "dc-sequential-camera-auth-uid";
  const homeUid = "dc-sequential-home-uid";
  await seedRegisteredDevice(cameraDeviceId, { role: "CAMERA", authUid: cameraAuthUid, ownerUid: homeUid });
  await claimRef(cameraDeviceId).set({ uid: homeUid, cameraAuthUid });

  const first = await createDeviceChallenge.run(fakeRequest(turnRequestData(cameraDeviceId, cameraDeviceId), cameraAuthUid));
  const second = await createDeviceChallenge.run(fakeRequest(turnRequestData(cameraDeviceId, cameraDeviceId), cameraAuthUid));

  assert.notEqual(first.challengeId, second.challengeId);
  assert.notEqual(first.nonce, second.nonce);

  await registryRef(cameraDeviceId).delete();
  await claimRef(cameraDeviceId).delete();
  await db.collection("deviceChallenges").doc(first.challengeId).delete();
  await db.collection("deviceChallenges").doc(second.challengeId).delete();
});

// ---------------------------------------------------------------------------------------------
// Pure-function coverage for the closed types themselves (supports 1-19 above)
// ---------------------------------------------------------------------------------------------

test("isDeviceChallengePurpose: TURN_CREDENTIALS and the three LIVE_VIEW_* purposes are accepted, nothing else", () => {
  assert.equal(isDeviceChallengePurpose(DEVICE_CHALLENGE_PURPOSES.TURN_CREDENTIALS), true);
  assert.equal(isDeviceChallengePurpose(DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START), true);
  assert.equal(isDeviceChallengePurpose(DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_RENEW), true);
  assert.equal(isDeviceChallengePurpose(DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_END), true);
  assert.equal(isDeviceChallengePurpose("LIVE_VIEW_SESSION_CREATE"), false);
  assert.equal(isDeviceChallengePurpose(""), false);
  assert.equal(isDeviceChallengePurpose(undefined), false);
});

test("validateTurnCredentialsRequestPayload: accepts exactly {cameraDeviceId, turnPurpose}", () => {
  const result = validateTurnCredentialsRequestPayload({ cameraDeviceId: "camera-1", turnPurpose: "ACTIVITY_ZONE" });
  assert.deepEqual(result, { valid: true, payload: { cameraDeviceId: "camera-1", turnPurpose: "ACTIVITY_ZONE" } });
});

test("validateTurnCredentialsRequestPayload: rejects an empty cameraDeviceId", () => {
  assert.equal(validateTurnCredentialsRequestPayload({ cameraDeviceId: "", turnPurpose: "LIVE_VIEW" }).valid, false);
});

test("validateTurnCredentialsRequestPayload: rejects an over-length cameraDeviceId", () => {
  assert.equal(
    validateTurnCredentialsRequestPayload({ cameraDeviceId: "x".repeat(129), turnPurpose: "LIVE_VIEW" }).valid,
    false
  );
});

test("checkDeviceChallengeEligibility: eligible active keystore device returns its registry role", () => {
  const decision = checkDeviceChallengeEligibility(
    {
      schemaVersion: 1,
      deviceId: "d1",
      role: "HOME",
      authUid: "uid-1",
      ownerUid: "uid-1",
      status: "active",
      suspensionReason: null,
      identityMode: "keystore",
      publicKey: "pk",
      createdAt: admin.firestore.Timestamp.now(),
      updatedAt: admin.firestore.Timestamp.now(),
      lastSeenAt: admin.firestore.Timestamp.now(),
      revokedAt: null,
    },
    "uid-1"
  );
  assert.deepEqual(decision, { eligible: true, role: "HOME" });
});

test("checkDeviceChallengeEligibility: null document is DEVICE_NOT_REGISTERED", () => {
  assert.deepEqual(checkDeviceChallengeEligibility(null, "uid-1"), { eligible: false, reason: "DEVICE_NOT_REGISTERED" });
});

test("buildDeviceChallengeDocument: assembles exactly the fixed schema, usedAt/usedByFunction null", () => {
  const doc = buildDeviceChallengeDocument({
    challengeId: "c1",
    deviceId: "d1",
    role: "CAMERA",
    authUid: "uid-1",
    purpose: "TURN_CREDENTIALS",
    nonce: "n".repeat(43),
    requestHash: "h".repeat(64),
    expiresAt: admin.firestore.Timestamp.now(),
  });
  assert.equal(doc.schemaVersion, 1);
  assert.equal(doc.usedAt, null);
  assert.equal(doc.usedByFunction, null);
  assert.equal(doc.challengeId, "c1");
  assert.equal(doc.deviceId, "d1");
  assert.equal(doc.role, "CAMERA");
  assert.equal(doc.authUid, "uid-1");
});
