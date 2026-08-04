const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

// Requiring lib/index.js runs admin.initializeApp() once; requires npm run build to have produced
// lib/ from src/ first (source of truth stays src).
const {
  identityConflictReason,
  registerLegacyCamera,
  registerLegacyHome,
  attachCameraOwner,
  detachCameraOwner,
  touchRegisteredDevice,
  createCameraPairingSession,
  claimCameraForUser,
  getTurnCredentials,
  submitCameraEvent,
  releaseCameraForUser,
  releaseCameraFromCamera,
  unpairCameraFromDevice,
  registerDevicePublicKey,
  validateEcP256PublicKey,
  applyPublicKeyRegistration,
  applyCameraPublicKeyRegistration,
  revokeRegisteredDevice,
  decideRevokeRegisteredDevice,
  applyRevokeRegisteredDevice,
  checkRegisteredDeviceOperational,
  planDeviceLimitDecision,
  reconcileUserDeviceLimits,
} = require("../lib/index.js");
const admin = require("firebase-admin");

const db = admin.firestore();

function registryRef(deviceId) {
  return db.collection("registeredDevices").doc(deviceId);
}

function fakeRequest(data, uid) {
  return {
    data,
    auth: uid ? { uid, token: {}, rawToken: "" } : undefined,
    rawRequest: {},
    acceptsStreaming: false,
  };
}

const CAMERA_ID = "camera-registry-test";
const HOME_DEVICE_ID = "home-registry-test";
const OWNER_UID = "owner-registry-uid";
const OTHER_OWNER_UID = "other-owner-registry-uid";
const CAMERA_AUTH_UID = "camera-auth-registry-uid";
const OTHER_CAMERA_AUTH_UID = "other-camera-auth-registry-uid";

test.afterEach(async () => {
  await registryRef(CAMERA_ID).delete();
  await registryRef(HOME_DEVICE_ID).delete();
});

// --- identityConflictReason: pure function --------------------------------------------------

test("identityConflictReason: no existing document is never a conflict", () => {
  assert.equal(
    identityConflictReason(null, { deviceId: CAMERA_ID, role: "CAMERA", authUid: CAMERA_AUTH_UID }),
    null
  );
});

test("identityConflictReason: matching deviceId/role/authUid is not a conflict", () => {
  const existing = { deviceId: CAMERA_ID, role: "CAMERA", authUid: CAMERA_AUTH_UID };
  assert.equal(identityConflictReason(existing, existing), null);
});

test("identityConflictReason: deviceId mismatch is DEVICE_ID_MISMATCH", () => {
  const existing = { deviceId: "other-id", role: "CAMERA", authUid: CAMERA_AUTH_UID };
  assert.equal(
    identityConflictReason(existing, { deviceId: CAMERA_ID, role: "CAMERA", authUid: CAMERA_AUTH_UID }),
    "DEVICE_ID_MISMATCH"
  );
});

test("identityConflictReason: role mismatch is ROLE_MISMATCH", () => {
  const existing = { deviceId: CAMERA_ID, role: "HOME", authUid: CAMERA_AUTH_UID };
  assert.equal(
    identityConflictReason(existing, { deviceId: CAMERA_ID, role: "CAMERA", authUid: CAMERA_AUTH_UID }),
    "ROLE_MISMATCH"
  );
});

test("identityConflictReason: authUid mismatch is AUTH_UID_MISMATCH", () => {
  const existing = { deviceId: CAMERA_ID, role: "CAMERA", authUid: CAMERA_AUTH_UID };
  assert.equal(
    identityConflictReason(existing, { deviceId: CAMERA_ID, role: "CAMERA", authUid: OTHER_CAMERA_AUTH_UID }),
    "AUTH_UID_MISMATCH"
  );
});

// --- 1/2/3. new legacy CAMERA is created with ownerUid null, status active, suspensionReason null

test("registerLegacyCamera creates a new legacy CAMERA with ownerUid null, status active, suspensionReason null", async () => {
  await registerLegacyCamera(db, CAMERA_ID, CAMERA_AUTH_UID);

  const snap = await registryRef(CAMERA_ID).get();
  assert.equal(snap.exists, true);
  const data = snap.data();
  assert.equal(data.schemaVersion, 1);
  assert.equal(data.deviceId, CAMERA_ID);
  assert.equal(data.role, "CAMERA");
  assert.equal(data.authUid, CAMERA_AUTH_UID);
  assert.equal(data.ownerUid, null);
  assert.equal(data.status, "active");
  assert.equal(data.suspensionReason, null);
  assert.equal(data.identityMode, "legacy");
  assert.equal(data.publicKey, null);
  assert.equal(data.revokedAt, null);
  assert.ok(data.createdAt);
  assert.ok(data.updatedAt);
  assert.ok(data.lastSeenAt);
});

// --- 3. HOME is created with authUid/ownerUid from the authenticated request -------------------

test("registerLegacyHome creates a HOME device with authUid == ownerUid == the given uid", async () => {
  await registerLegacyHome(db, HOME_DEVICE_ID, OWNER_UID);

  const data = (await registryRef(HOME_DEVICE_ID).get()).data();
  assert.equal(data.role, "HOME");
  assert.equal(data.authUid, OWNER_UID);
  assert.equal(data.ownerUid, OWNER_UID);
});

// --- attachCameraOwner on a fresh device creates it with the given ownerUid --------------------

test("attachCameraOwner on a device with no prior document creates it with the given ownerUid", async () => {
  await attachCameraOwner(db, CAMERA_ID, CAMERA_AUTH_UID, OWNER_UID);

  const data = (await registryRef(CAMERA_ID).get()).data();
  assert.equal(data.role, "CAMERA");
  assert.equal(data.authUid, CAMERA_AUTH_UID);
  assert.equal(data.ownerUid, OWNER_UID);
});

// --- 4/18. repeated registration is idempotent, never creates a duplicate document -------------

test("registerLegacyCamera called twice with the same identity is idempotent (no duplicate, same fields)", async () => {
  await registerLegacyCamera(db, CAMERA_ID, CAMERA_AUTH_UID);
  await registerLegacyCamera(db, CAMERA_ID, CAMERA_AUTH_UID);

  const snap = await registryRef(CAMERA_ID).get();
  assert.equal(snap.exists, true);
  assert.equal(snap.data().ownerUid, null);

  const listed = await db.collection("registeredDevices").where("deviceId", "==", CAMERA_ID).get();
  assert.equal(listed.size, 1, "exactly one document for this deviceId, never a duplicate");
});

// --- 5. a repeated touch does not change createdAt ---------------------------------------------

test("touchRegisteredDevice never changes createdAt on a repeated call", async () => {
  await registerLegacyCamera(db, CAMERA_ID, CAMERA_AUTH_UID);
  const createdAtBefore = (await registryRef(CAMERA_ID).get()).data().createdAt;

  await touchRegisteredDevice(db, CAMERA_ID);
  const afterTouch = (await registryRef(CAMERA_ID).get()).data();

  assert.equal(afterTouch.createdAt.isEqual(createdAtBefore), true);
});

test("touchRegisteredDevice is a safe no-op for a device that was never registered", async () => {
  await touchRegisteredDevice(db, "device-never-registered");
  assert.equal((await registryRef("device-never-registered").get()).exists, false);
});

// --- 6. a different authUid cannot overwrite an existing authUid -------------------------------

test("a different authUid cannot overwrite an existing device's authUid", async () => {
  await registerLegacyCamera(db, CAMERA_ID, CAMERA_AUTH_UID);
  await registerLegacyCamera(db, CAMERA_ID, OTHER_CAMERA_AUTH_UID);

  assert.equal((await registryRef(CAMERA_ID).get()).data().authUid, CAMERA_AUTH_UID);
});

// --- 7. a device's role cannot be changed -------------------------------------------------------

test("a device's role cannot be changed from CAMERA to HOME", async () => {
  await registerLegacyCamera(db, CAMERA_ID, CAMERA_AUTH_UID);
  await registerLegacyHome(db, CAMERA_ID, CAMERA_AUTH_UID);

  assert.equal((await registryRef(CAMERA_ID).get()).data().role, "CAMERA");
});

// --- 8/9. suspended/revoked never automatically return to active -------------------------------

async function seedRegisteredDevice(deviceId, overrides = {}) {
  const now = admin.firestore.Timestamp.now();
  await registryRef(deviceId).set({
    schemaVersion: 1,
    deviceId,
    role: "CAMERA",
    authUid: CAMERA_AUTH_UID,
    ownerUid: OWNER_UID,
    status: "active",
    suspensionReason: null,
    identityMode: "legacy",
    publicKey: null,
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    revokedAt: null,
    ...overrides,
  });
}

test("a suspended device is never returned to active by lazy registration", async () => {
  await seedRegisteredDevice(CAMERA_ID, { status: "suspended", suspensionReason: "manual" });
  await registerLegacyCamera(db, CAMERA_ID, CAMERA_AUTH_UID);

  assert.equal((await registryRef(CAMERA_ID).get()).data().status, "suspended");
});

test("11. a suspended device's suspensionReason is preserved by lazy registration", async () => {
  await seedRegisteredDevice(CAMERA_ID, { status: "suspended", suspensionReason: "plan" });
  await registerLegacyCamera(db, CAMERA_ID, CAMERA_AUTH_UID);

  assert.equal((await registryRef(CAMERA_ID).get()).data().suspensionReason, "plan");
});

test("a revoked device is never returned to active by lazy registration", async () => {
  await seedRegisteredDevice(CAMERA_ID, { status: "revoked", revokedAt: admin.firestore.Timestamp.now() });
  await registerLegacyCamera(db, CAMERA_ID, CAMERA_AUTH_UID);

  const data = (await registryRef(CAMERA_ID).get()).data();
  assert.equal(data.status, "revoked");
  assert.ok(data.revokedAt);
});

// --- 10/11. keystore identity is never downgraded, publicKey is never removed -------------------

test("a keystore identity is never downgraded to legacy by lazy registration", async () => {
  await seedRegisteredDevice(CAMERA_ID, { identityMode: "keystore", publicKey: "keystore-public-key" });
  await registerLegacyCamera(db, CAMERA_ID, CAMERA_AUTH_UID);

  assert.equal((await registryRef(CAMERA_ID).get()).data().identityMode, "keystore");
});

test("an existing keystore identity's publicKey is never removed by lazy registration", async () => {
  await seedRegisteredDevice(CAMERA_ID, { identityMode: "keystore", publicKey: "keystore-public-key" });
  await registerLegacyCamera(db, CAMERA_ID, CAMERA_AUTH_UID);

  assert.equal((await registryRef(CAMERA_ID).get()).data().publicKey, "keystore-public-key");
});

// --- claim adds the correct ownerUid, without touching other identity fields -------------------

test("attachCameraOwner on an existing device sets ownerUid without touching authUid/status/identityMode", async () => {
  await seedRegisteredDevice(CAMERA_ID, { ownerUid: null });
  await attachCameraOwner(db, CAMERA_ID, CAMERA_AUTH_UID, OTHER_OWNER_UID);

  const data = (await registryRef(CAMERA_ID).get()).data();
  assert.equal(data.ownerUid, OTHER_OWNER_UID);
  assert.equal(data.authUid, CAMERA_AUTH_UID);
  assert.equal(data.status, "active");
  assert.equal(data.identityMode, "legacy");
});

test("attachCameraOwner is a no-op when the given cameraAuthUid is missing", async () => {
  await attachCameraOwner(db, CAMERA_ID, null, OWNER_UID);
  assert.equal((await registryRef(CAMERA_ID).get()).exists, false);
});

// --- 12/13. a normal unpair clears ownerUid, never sets revoked ---------------------------------

test("detachCameraOwner clears only ownerUid, touching nothing else identity/administrative", async () => {
  await seedRegisteredDevice(CAMERA_ID, {
    ownerUid: OWNER_UID,
    status: "suspended",
    suspensionReason: "security",
    identityMode: "keystore",
    publicKey: "keystore-public-key",
  });
  await detachCameraOwner(db, CAMERA_ID);

  const data = (await registryRef(CAMERA_ID).get()).data();
  assert.equal(data.ownerUid, null);
  assert.equal(data.authUid, CAMERA_AUTH_UID);
  assert.equal(data.status, "suspended");
  assert.equal(data.suspensionReason, "security");
  assert.equal(data.identityMode, "keystore");
  assert.equal(data.publicKey, "keystore-public-key");
});

test("detachCameraOwner never sets status to revoked", async () => {
  await seedRegisteredDevice(CAMERA_ID, { ownerUid: OWNER_UID, status: "active" });
  await detachCameraOwner(db, CAMERA_ID);

  const data = (await registryRef(CAMERA_ID).get()).data();
  assert.equal(data.status, "active");
  assert.equal(data.revokedAt, null);
});

test("detachCameraOwner: a revoked device keeps ownerUid -- cleanup is not registry detach", async () => {
  const revokedAt = admin.firestore.Timestamp.now();
  await seedRegisteredDevice(CAMERA_ID, {
    ownerUid: OWNER_UID,
    status: "revoked",
    revokedAt,
    identityMode: "keystore",
    publicKey: "keystore-public-key",
  });

  await detachCameraOwner(db, CAMERA_ID);

  const data = (await registryRef(CAMERA_ID).get()).data();
  assert.equal(data.ownerUid, OWNER_UID, "revoked devices keep their ownerUid through unpair/cleanup");
  assert.equal(data.status, "revoked");
  assert.equal(data.revokedAt.isEqual(revokedAt), true, "revokedAt must not change");
  assert.equal(data.identityMode, "keystore");
  assert.equal(data.publicKey, "keystore-public-key");
});

test("detachCameraOwner: a repeated cleanup call against an already-revoked device is idempotent", async () => {
  const revokedAt = admin.firestore.Timestamp.now();
  await seedRegisteredDevice(CAMERA_ID, { ownerUid: OWNER_UID, status: "revoked", revokedAt });

  await detachCameraOwner(db, CAMERA_ID);
  const afterFirst = (await registryRef(CAMERA_ID).get()).data();

  await detachCameraOwner(db, CAMERA_ID);
  const afterSecond = (await registryRef(CAMERA_ID).get()).data();

  assert.equal(afterSecond.ownerUid, OWNER_UID);
  assert.equal(afterSecond.updatedAt.isEqual(afterFirst.updatedAt), true, "a no-op repeat must not bump updatedAt");
  assert.equal(afterSecond.revokedAt.isEqual(revokedAt), true);
});

test("detachCameraOwner is a safe no-op for a device that was never registered", async () => {
  await detachCameraOwner(db, "device-never-registered-2");
  assert.equal((await registryRef("device-never-registered-2").get()).exists, false);
});

// --- integration: createCameraPairingSession/claimCameraForUser/getTurnCredentials/ -------------
// --- submitCameraEvent registry side effects, and registry conflicts never breaking them -------

function hashPairingSecret(secret) {
  return crypto.createHash("sha256").update(secret).digest("hex");
}

const claimRef = () => db.collection("cameraClaims").doc(CAMERA_ID);
const pairingSessionRef = (pairingId) => db.collection("cameraPairingSessions").doc(pairingId);

test.afterEach(async () => {
  await claimRef().delete();
  delete process.env.TURN_REST_SECRET;
});

test("createCameraPairingSession registers a legacy CAMERA with ownerUid null", async () => {
  await createCameraPairingSession.run(
    fakeRequest({ cameraDeviceId: CAMERA_ID, pairingSecretHash: "hash" }, CAMERA_AUTH_UID)
  );

  const data = (await registryRef(CAMERA_ID).get()).data();
  assert.equal(data.role, "CAMERA");
  assert.equal(data.authUid, CAMERA_AUTH_UID);
  assert.equal(data.ownerUid, null);
});

test("17. a conflicting registeredDevices document does not break createCameraPairingSession", async () => {
  // A pre-existing, conflicting identity (different authUid) -- registerLegacyCamera will skip
  // the write, but the callable itself must still succeed exactly as if the registry didn't exist.
  await seedRegisteredDevice(CAMERA_ID, { authUid: OTHER_CAMERA_AUTH_UID });

  const response = await createCameraPairingSession.run(
    fakeRequest({ cameraDeviceId: CAMERA_ID, pairingSecretHash: "hash" }, CAMERA_AUTH_UID)
  );

  assert.ok(response.pairingId);
  assert.ok(response.expiresAt);
  // The conflicting identity is left untouched, not overwritten.
  assert.equal((await registryRef(CAMERA_ID).get()).data().authUid, OTHER_CAMERA_AUTH_UID);
});

async function seedValidPairingSession(pairingId, pairingSecret) {
  await pairingSessionRef(pairingId).set({
    cameraDeviceId: CAMERA_ID,
    pairingSecretHash: hashPairingSecret(pairingSecret),
    cameraAuthUid: CAMERA_AUTH_UID,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    expiresAt: admin.firestore.Timestamp.fromMillis(Date.now() + 10 * 60 * 1000),
    consumedAt: null,
    status: "pending",
  });
}

test.afterEach(async () => {
  const sessions = await db.collection("cameraPairingSessions").where("cameraDeviceId", "==", CAMERA_ID).get();
  await Promise.all(sessions.docs.map((d) => d.ref.delete()));
});

test("2. claimCameraForUser attaches the correct ownerUid to the CAMERA device", async () => {
  const pairingId = "pairing-claim-test-1";
  await seedValidPairingSession(pairingId, "s3cr3t-1");

  await claimCameraForUser.run(
    fakeRequest(
      { cameraDeviceId: CAMERA_ID, pairingId, pairingSecret: "s3cr3t-1", homeDeviceId: HOME_DEVICE_ID },
      OWNER_UID
    )
  );

  const cameraData = (await registryRef(CAMERA_ID).get()).data();
  assert.equal(cameraData.role, "CAMERA");
  assert.equal(cameraData.authUid, CAMERA_AUTH_UID);
  assert.equal(cameraData.ownerUid, OWNER_UID);

  const homeData = (await registryRef(HOME_DEVICE_ID).get()).data();
  assert.equal(homeData.role, "HOME");
  assert.equal(homeData.authUid, OWNER_UID);
  assert.equal(homeData.ownerUid, OWNER_UID);
});

// Dedicated to this one test, deliberately distinct from OWNER_UID (reused by several other tests
// in this file, e.g. "2. claimCameraForUser attaches..." above). claimCameraForUser's camera-limit
// check reads users/{uid}.cameraCount, and nothing in this file ever resets that document between
// tests (see point 6 of this fix: this test must not reset it either) -- reusing OWNER_UID here
// would make this test's outcome depend on execution order, since an earlier test's own real claim
// already left users/{OWNER_UID}.cameraCount at 1. That is the actual root cause of this test
// previously hitting CAMERA_LIMIT_REACHED: cameraClaims/{CAMERA_ID} itself was correctly absent
// going into this test (the "delete claimRef() after every test" afterEach below did its job), but
// users/{OWNER_UID}.cameraCount was NOT reset alongside it, so the very next real claim attempt for
// OWNER_UID -- whether counted as "this test's first call" or "the file's second-ever claim call"
// -- took the non-idempotent "new claim" branch (cameraClaims didn't exist) against an
// already-incremented cameraCount, and 1 (existing) + 1 (this attempt) exceeded the
// subscriptionUnits=0 allowance of exactly 1 camera. A private owner uid, used by no other test,
// makes this test fully self-contained: its own first claim always starts from cameraCount 0.
const IDEMPOTENT_CLAIM_OWNER_UID = "idempotent-claim-owner-uid";

test.afterEach(async () => {
  await db.collection("users").doc(IDEMPOTENT_CLAIM_OWNER_UID).delete();
});

test("21. a repeated (idempotent) claim by the same owner does not create a duplicate registry document", async () => {
  // claimCameraForUser's own "Idempotent: already claimed by this user" branch requires a fresh,
  // still-pending pairing session each time (a session's own status flips to "consumed" the
  // moment it's used) -- two distinct sessions for the same cameraDeviceId/owner is exactly what
  // "the same Camera being claimed again by its already-existing owner" looks like in practice
  // (e.g. the Home App retrying after an ambiguous network response to the first attempt).
  const pairingId1 = "pairing-claim-test-2a";
  await seedValidPairingSession(pairingId1, "s3cr3t-2a");

  // 1. First successful claim.
  const firstResponse = await claimCameraForUser.run(
    fakeRequest(
      { cameraDeviceId: CAMERA_ID, pairingId: pairingId1, pairingSecret: "s3cr3t-2a", homeDeviceId: HOME_DEVICE_ID },
      IDEMPOTENT_CLAIM_OWNER_UID
    )
  );
  assert.equal(firstResponse.success, true);
  assert.equal(firstResponse.cameraCount, 1);

  // 2. Immediately confirm cameraClaims -- exactly the precondition claimCameraForUser's own
  // idempotent-owner branch requires -- was actually created durably by the first claim, with the
  // right owner uid and cameraAuthUid, before doing anything else.
  const claimAfterFirst = await claimRef().get();
  assert.equal(claimAfterFirst.exists, true, "cameraClaims must exist right after a successful claim");
  assert.equal(claimAfterFirst.get("uid"), IDEMPOTENT_CLAIM_OWNER_UID);
  assert.ok(claimAfterFirst.get("cameraAuthUid"), "cameraAuthUid must be recorded on the claim");

  const registryBeforeSecondClaim = (await registryRef(CAMERA_ID).get()).data();

  // 3. For the second claim, prepare only a brand-new, valid, still-pending pairing session.
  // seedValidPairingSession() (defined above) only ever writes cameraPairingSessions/{pairingId}
  // -- it never touches cameraClaims or users, so it cannot be what clears the claim from step 1;
  // no narrower helper is needed, and no Firestore state is cleared, deleted, or overwritten here.
  const pairingId2 = "pairing-claim-test-2b";
  await seedValidPairingSession(pairingId2, "s3cr3t-2b");

  // 7. Claim again for the same cameraDeviceId/owner/homeDeviceId, using only the new session.
  const secondResponse = await claimCameraForUser.run(
    fakeRequest(
      { cameraDeviceId: CAMERA_ID, pairingId: pairingId2, pairingSecret: "s3cr3t-2b", homeDeviceId: HOME_DEVICE_ID },
      IDEMPOTENT_CLAIM_OWNER_UID
    )
  );

  // 8. The repeated claim succeeds, cameraCount is unchanged, and the registry has exactly one
  // document whose identity/administrative fields are untouched.
  assert.equal(secondResponse.success, true);
  assert.equal(secondResponse.cameraCount, 1, "cameraCount must stay 1, not increment on a repeat claim");

  const listed = await db.collection("registeredDevices").where("deviceId", "==", CAMERA_ID).get();
  assert.equal(listed.size, 1, "exactly one registeredDevices document for this deviceId");

  const registryAfterSecondClaim = listed.docs[0].data();
  assert.equal(registryAfterSecondClaim.createdAt.isEqual(registryBeforeSecondClaim.createdAt), true);
  assert.equal(registryAfterSecondClaim.role, registryBeforeSecondClaim.role);
  assert.equal(registryAfterSecondClaim.authUid, registryBeforeSecondClaim.authUid);
  assert.equal(registryAfterSecondClaim.ownerUid, IDEMPOTENT_CLAIM_OWNER_UID);
  assert.equal(registryAfterSecondClaim.ownerUid, registryBeforeSecondClaim.ownerUid);
  assert.equal(registryAfterSecondClaim.status, registryBeforeSecondClaim.status);
  assert.equal(registryAfterSecondClaim.identityMode, registryBeforeSecondClaim.identityMode);
});

test("12/13. releaseCameraForUser (Home-initiated unpair) clears ownerUid and never sets revoked", async () => {
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });
  await seedRegisteredDevice(CAMERA_ID, { ownerUid: OWNER_UID, status: "active" });

  const response = await releaseCameraForUser.run(fakeRequest({ cameraDeviceId: CAMERA_ID }, OWNER_UID));

  assert.deepEqual(response, { success: true });
  const data = (await registryRef(CAMERA_ID).get()).data();
  assert.equal(data.ownerUid, null);
  assert.equal(data.status, "active");
  assert.equal(data.revokedAt, null);
});

test("12/13. releaseCameraFromCamera (Camera-initiated unpair) clears ownerUid and never sets revoked", async () => {
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });
  await seedRegisteredDevice(CAMERA_ID, { ownerUid: OWNER_UID, status: "active" });

  const response = await releaseCameraFromCamera.run(fakeRequest({ cameraDeviceId: CAMERA_ID }, CAMERA_AUTH_UID));

  assert.deepEqual(response, { success: true });
  const data = (await registryRef(CAMERA_ID).get()).data();
  assert.equal(data.ownerUid, null);
  assert.equal(data.status, "active");
  assert.equal(data.revokedAt, null);
});

test("18/20. getTurnCredentials called by the Home owner records the Camera's authUid from cameraClaims, not the Home uid, and a registry conflict does not break it", async () => {
  process.env.TURN_REST_SECRET = "device-registry-test-secret";
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });
  // A pre-existing, conflicting identity -- attachCameraOwner will skip the write, but
  // getTurnCredentials itself must still succeed.
  await seedRegisteredDevice(CAMERA_ID, { authUid: OTHER_CAMERA_AUTH_UID, ownerUid: null });

  const response = await getTurnCredentials.run(
    fakeRequest({ cameraDeviceId: CAMERA_ID, purpose: "LIVE_VIEW" }, OWNER_UID)
  );

  assert.equal(response.iceServers.length, 1);
  // The conflicting identity is left untouched -- proves the registry write was skipped, not
  // silently corrupted, and that getTurnCredentials' own response is unaffected either way.
  assert.equal((await registryRef(CAMERA_ID).get()).data().authUid, OTHER_CAMERA_AUTH_UID);
});

test("20. getTurnCredentials called by the Home owner (no conflict) records the Camera's authUid, not the Home's own uid", async () => {
  process.env.TURN_REST_SECRET = "device-registry-test-secret";
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });

  await getTurnCredentials.run(fakeRequest({ cameraDeviceId: CAMERA_ID, purpose: "LIVE_VIEW" }, OWNER_UID));

  const data = (await registryRef(CAMERA_ID).get()).data();
  assert.equal(data.role, "CAMERA");
  assert.equal(data.authUid, CAMERA_AUTH_UID, "must be the Camera's own auth uid, not the Home caller's uid");
  assert.notEqual(data.authUid, OWNER_UID);
  assert.equal(data.ownerUid, OWNER_UID);
});

test("19. a conflicting registeredDevices document does not break submitCameraEvent", async () => {
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });
  await seedRegisteredDevice(CAMERA_ID, { authUid: OTHER_CAMERA_AUTH_UID, ownerUid: null });

  const response = await submitCameraEvent.run(
    fakeRequest(
      { cameraDeviceId: CAMERA_ID, type: "camera_offline", title: "t", body: "b", severity: "warning" },
      CAMERA_AUTH_UID
    )
  );

  assert.deepEqual(response, { success: true });
  assert.equal((await registryRef(CAMERA_ID).get()).data().authUid, OTHER_CAMERA_AUTH_UID);
});

test("submitCameraEvent (no conflict) attaches the correct ownerUid from cameraClaims", async () => {
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });

  await submitCameraEvent.run(
    fakeRequest(
      { cameraDeviceId: CAMERA_ID, type: "camera_offline", title: "t", body: "b", severity: "warning" },
      CAMERA_AUTH_UID
    )
  );

  const data = (await registryRef(CAMERA_ID).get()).data();
  assert.equal(data.authUid, CAMERA_AUTH_UID);
  assert.equal(data.ownerUid, OWNER_UID);
});

// =================================================================================================
// registerDevicePublicKey -- Android Keystore identity (legacy -> keystore)
// =================================================================================================
// Uses its own dedicated ids/uids throughout (never CAMERA_ID/HOME_DEVICE_ID/OWNER_UID/
// CAMERA_AUTH_UID from earlier in this file) so this section's outcome never depends on what ran
// before it -- exactly the lesson the "idempotent claim" test fix elsewhere in this file already
// established about shared constants leaking cameraCount state across tests.

const KEY_TEST_CAMERA_ID = "camera-keystore-test";
const KEY_TEST_HOME_ID = "home-keystore-test";
const KEY_TEST_OWNER_UID = "keystore-owner-uid";
const KEY_TEST_OTHER_UID = "keystore-other-uid";
const KEY_TEST_CAMERA_AUTH_UID = "keystore-camera-auth-uid";
const KEY_TEST_OTHER_CAMERA_AUTH_UID = "keystore-other-camera-auth-uid";

function keyTestClaimRef() {
  return db.collection("cameraClaims").doc(KEY_TEST_CAMERA_ID);
}

test.afterEach(async () => {
  await registryRef(KEY_TEST_CAMERA_ID).delete();
  await registryRef(KEY_TEST_HOME_ID).delete();
  await keyTestClaimRef().delete();
});

async function seedKeyTestDevice(deviceId, overrides = {}) {
  const now = admin.firestore.Timestamp.now();
  await registryRef(deviceId).set({
    schemaVersion: 1,
    deviceId,
    role: "CAMERA",
    authUid: KEY_TEST_CAMERA_AUTH_UID,
    ownerUid: KEY_TEST_OWNER_UID,
    status: "active",
    suspensionReason: null,
    identityMode: "legacy",
    publicKey: null,
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    revokedAt: null,
    ...overrides,
  });
}

// --- test key material, generated fresh per test run -- never a static/committed private key ----

function derToBase64(keyObject) {
  return keyObject.export({ format: "der", type: "spki" }).toString("base64");
}

function generateP256PublicKeyBase64() {
  return derToBase64(crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey);
}

function generateRsaPublicKeyBase64() {
  return crypto
    .generateKeyPairSync("rsa", { modulusLength: 2048 })
    .publicKey.export({ format: "der", type: "spki" })
    .toString("base64");
}

function generateWrongCurvePublicKeyBase64() {
  return derToBase64(crypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" }).publicKey);
}

function generateP256PrivateKeyDerBase64() {
  return crypto
    .generateKeyPairSync("ec", { namedCurve: "prime256v1" })
    .privateKey.export({ format: "der", type: "pkcs8" })
    .toString("base64");
}

// --- request validation (1-11) -------------------------------------------------------------------

test("registerDevicePublicKey: 1. unauthenticated request rejected", async () => {
  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
        undefined
      )
    ),
    (err) => err.code === "unauthenticated"
  );
});

test("registerDevicePublicKey: 2. malformed deviceId (blank after trim) rejected", async () => {
  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: "   ", role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_DEVICE_ID"
  );
});

test("registerDevicePublicKey: malformed deviceId (over 128 chars) rejected", async () => {
  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: "x".repeat(129), role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_DEVICE_ID"
  );
});

test("registerDevicePublicKey: 3. invalid role rejected", async () => {
  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "ADMIN", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_ROLE"
  );
});

test("registerDevicePublicKey: 4. unsupported algorithm rejected", async () => {
  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "RS256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_ALGORITHM"
  );
});

test("registerDevicePublicKey: 5. empty publicKey rejected", async () => {
  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest({ deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: "", algorithm: "ES256" }, KEY_TEST_CAMERA_AUTH_UID)
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_PUBLIC_KEY"
  );
});

test("registerDevicePublicKey: 6. oversized publicKey rejected", async () => {
  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: "A".repeat(513), algorithm: "ES256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_PUBLIC_KEY"
  );
});

test("registerDevicePublicKey: 7. whitespace-containing Base64 rejected", async () => {
  const withWhitespace = `${generateP256PublicKeyBase64()}\n`;
  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: withWhitespace, algorithm: "ES256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_PUBLIC_KEY"
  );
});

test("registerDevicePublicKey: 8. Base64URL variant rejected", async () => {
  const std = generateP256PublicKeyBase64();
  const base64url = `-${std.slice(1)}`; // forces a base64url-only character regardless of the random key's own bytes
  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: base64url, algorithm: "ES256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_PUBLIC_KEY"
  );
});

test("registerDevicePublicKey: 9. malformed DER rejected", async () => {
  const notDer = Buffer.from("this is definitely not a valid SPKI DER structure").toString("base64");
  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: notDer, algorithm: "ES256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_PUBLIC_KEY"
  );
});

test("registerDevicePublicKey: 10. RSA public key rejected", async () => {
  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: generateRsaPublicKeyBase64(), algorithm: "ES256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_PUBLIC_KEY"
  );
});

test("registerDevicePublicKey: 11. EC key on the wrong curve rejected", async () => {
  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        {
          deviceId: KEY_TEST_CAMERA_ID,
          role: "CAMERA",
          publicKey: generateWrongCurvePublicKeyBase64(),
          algorithm: "ES256",
        },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_PUBLIC_KEY"
  );
});

test("registerDevicePublicKey: a private key (PKCS8 DER) instead of a public SPKI key is rejected", async () => {
  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        {
          deviceId: KEY_TEST_CAMERA_ID,
          role: "CAMERA",
          publicKey: generateP256PrivateKeyDerBase64(),
          algorithm: "ES256",
        },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_PUBLIC_KEY"
  );
});

// --- 12-21: authorization and registry-document preconditions -----------------------------------

test("registerDevicePublicKey: 12. valid P-256 SPKI is accepted", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID);
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });

  const response = await registerDevicePublicKey.run(
    fakeRequest(
      { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
      KEY_TEST_CAMERA_AUTH_UID
    )
  );

  assert.deepEqual(response, { success: true, identityMode: "keystore" });
});

test("registerDevicePublicKey: 13. missing registry document rejected (HOME)", async () => {
  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_HOME_ID, role: "HOME", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
        KEY_TEST_OWNER_UID
      )
    ),
    (err) => err.code === "not-found" && err.message === "DEVICE_NOT_REGISTERED"
  );
});

test("registerDevicePublicKey: missing registry document rejected (CAMERA, cameraClaims present)", async () => {
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });
  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "not-found" && err.message === "DEVICE_NOT_REGISTERED"
  );
});

test("registerDevicePublicKey: 14. HOME with matching authUid/ownerUid succeeds", async () => {
  await seedKeyTestDevice(KEY_TEST_HOME_ID, {
    role: "HOME",
    authUid: KEY_TEST_OWNER_UID,
    ownerUid: KEY_TEST_OWNER_UID,
  });

  const response = await registerDevicePublicKey.run(
    fakeRequest(
      { deviceId: KEY_TEST_HOME_ID, role: "HOME", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
      KEY_TEST_OWNER_UID
    )
  );

  assert.deepEqual(response, { success: true, identityMode: "keystore" });
});

test("registerDevicePublicKey: 15. HOME authUid mismatch rejected", async () => {
  await seedKeyTestDevice(KEY_TEST_HOME_ID, {
    role: "HOME",
    authUid: KEY_TEST_OWNER_UID,
    ownerUid: KEY_TEST_OWNER_UID,
  });

  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_HOME_ID, role: "HOME", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
        KEY_TEST_OTHER_UID
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_IDENTITY_MISMATCH"
  );
});

test("registerDevicePublicKey: 16. HOME ownerUid mismatch rejected", async () => {
  // authUid matches the caller, but ownerUid on the stored document does not -- an inconsistent
  // state that must still be rejected (ownerUid is part of HOME's authorization too).
  await seedKeyTestDevice(KEY_TEST_HOME_ID, {
    role: "HOME",
    authUid: KEY_TEST_OWNER_UID,
    ownerUid: KEY_TEST_OTHER_UID,
  });

  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_HOME_ID, role: "HOME", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
        KEY_TEST_OWNER_UID
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_IDENTITY_MISMATCH"
  );
});

test("registerDevicePublicKey: 17. CAMERA without cameraClaims rejected", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID);

  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "not-found" && err.message === "CAMERA_NOT_CLAIMED"
  );
});

test("registerDevicePublicKey: 18. CAMERA with matching cameraAuthUid succeeds", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID);
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });

  const response = await registerDevicePublicKey.run(
    fakeRequest(
      { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
      KEY_TEST_CAMERA_AUTH_UID
    )
  );

  assert.deepEqual(response, { success: true, identityMode: "keystore" });
});

test("registerDevicePublicKey: 19. CAMERA registration called by the Home owner is rejected", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID);
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });

  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
        KEY_TEST_OWNER_UID // the linked Home owner, not the Camera's own auth identity
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_IDENTITY_MISMATCH"
  );
});

test("registerDevicePublicKey: 20. registry role conflict rejected", async () => {
  // Registered as HOME, but the request claims CAMERA for the same deviceId.
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID, {
    role: "HOME",
    authUid: KEY_TEST_CAMERA_AUTH_UID,
    ownerUid: KEY_TEST_CAMERA_AUTH_UID,
  });
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });

  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_IDENTITY_MISMATCH"
  );
});

test("registerDevicePublicKey: 21. registry authUid conflict (drifted from cameraClaims) rejected", async () => {
  // The registry's own authUid disagrees with cameraClaims.cameraAuthUid -- defense in depth, see
  // applyPublicKeyRegistration's own authUid check.
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID, { authUid: KEY_TEST_OTHER_CAMERA_AUTH_UID });
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });

  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_IDENTITY_MISMATCH"
  );
});

// Field-by-field comparison rather than assert.deepEqual(before, after): Firestore Timestamp
// objects are compared via their own .isEqual() elsewhere in this file (deepEqual's structural
// comparison is not a documented-safe way to compare two separately-read Timestamp instances).
function assertRegistryDocUnchanged(before, after) {
  assert.equal(after.deviceId, before.deviceId);
  assert.equal(after.role, before.role);
  assert.equal(after.authUid, before.authUid);
  assert.equal(after.ownerUid, before.ownerUid);
  assert.equal(after.status, before.status);
  assert.equal(after.suspensionReason, before.suspensionReason);
  assert.equal(after.identityMode, before.identityMode);
  assert.equal(after.publicKey, before.publicKey);
  assert.equal(after.revokedAt, before.revokedAt);
  assert.equal(after.createdAt.isEqual(before.createdAt), true);
  assert.equal(after.updatedAt.isEqual(before.updatedAt), true);
  assert.equal(after.lastSeenAt.isEqual(before.lastSeenAt), true);
}

// --- CAMERA authorization atomicity fix ----------------------------------------------------------
// applyCameraPublicKeyRegistration() reads cameraClaims AND registeredDevices inside the SAME
// Firestore transaction as the eventual write -- fixing a real race where an out-of-transaction
// pre-check of cameraClaims could be invalidated by a concurrent unpair before the (separate)
// registry transaction committed. True concurrent-timing tests of "did the two reads happen inside
// exactly the same transaction" would need to inject a delay/hook into the transaction callback
// itself (heavier test infrastructure than this project uses elsewhere) -- what's tested below
// instead is the deterministic, directly observable consequence: the claim check is always read
// live at call time (never a cached/pre-fetched value passed in from outside), and no path ever
// mutates the registry document without the claim check having *just* passed inside that same
// call.

test("registerDevicePublicKey: CAMERA claim and registry are read together -- a claim deleted right before the call is seen immediately, not from a stale earlier check", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID);
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });

  // Simulates unpair happening before this specific registration attempt (as opposed to the
  // previously-possible window between an earlier out-of-transaction pre-check and a later,
  // separate registry transaction) -- there is no separate pre-check left to go stale.
  await keyTestClaimRef().delete();

  const before = (await registryRef(KEY_TEST_CAMERA_ID).get()).data();

  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "not-found" && err.message === "CAMERA_NOT_CLAIMED"
  );

  const after = (await registryRef(KEY_TEST_CAMERA_ID).get()).data();
  assert.equal(after.identityMode, "legacy", "the registry must be completely unaffected");
  assert.equal(after.publicKey, before.publicKey);
  assert.equal(after.updatedAt.isEqual(before.updatedAt), true);
});

test("registerDevicePublicKey: applyCameraPublicKeyRegistration() itself reports camera_not_claimed and never touches the registry when cameraClaims is absent", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID);
  const before = (await registryRef(KEY_TEST_CAMERA_ID).get()).data();
  // Deliberately no cameraClaims document at all.

  const result = await applyCameraPublicKeyRegistration(db, {
    cameraDeviceId: KEY_TEST_CAMERA_ID,
    authenticatedUid: KEY_TEST_CAMERA_AUTH_UID,
    canonicalPublicKey: generateP256PublicKeyBase64(),
  });

  assert.deepEqual(result, { outcome: "camera_not_claimed" });
  const after = (await registryRef(KEY_TEST_CAMERA_ID).get()).data();
  assertRegistryDocUnchanged(before, after);
});

test("registerDevicePublicKey: a mismatched cameraAuthUid inside the same transaction leaves the registry completely unchanged", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID);
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });
  const before = (await registryRef(KEY_TEST_CAMERA_ID).get()).data();

  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
        KEY_TEST_OTHER_CAMERA_AUTH_UID // authenticated, but not the uid recorded on the claim
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_IDENTITY_MISMATCH"
  );

  const after = (await registryRef(KEY_TEST_CAMERA_ID).get()).data();
  assertRegistryDocUnchanged(before, after);
});

test("registerDevicePublicKey: CAMERA without cameraClaims leaves an existing registry document completely unchanged", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID);
  const before = (await registryRef(KEY_TEST_CAMERA_ID).get()).data();
  // Deliberately no cameraClaims document at all.

  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "not-found" && err.message === "CAMERA_NOT_CLAIMED"
  );

  const after = (await registryRef(KEY_TEST_CAMERA_ID).get()).data();
  assertRegistryDocUnchanged(before, after);
});

// --- 22-31: transaction / status / idempotency / conflict / corruption behavior ------------------

test("registerDevicePublicKey: 22. first registration updates only identityMode/publicKey/updatedAt/lastSeenAt", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID);
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });
  const before = (await registryRef(KEY_TEST_CAMERA_ID).get()).data();

  const publicKey = generateP256PublicKeyBase64();
  await registerDevicePublicKey.run(
    fakeRequest({ deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey, algorithm: "ES256" }, KEY_TEST_CAMERA_AUTH_UID)
  );

  const after = (await registryRef(KEY_TEST_CAMERA_ID).get()).data();
  assert.equal(after.identityMode, "keystore");
  assert.equal(after.publicKey, publicKey);
  assert.equal(after.updatedAt.isEqual(before.updatedAt), false);
  assert.equal(after.lastSeenAt.isEqual(before.lastSeenAt), false);

  // Everything else is byte-for-byte unchanged.
  assert.equal(after.deviceId, before.deviceId);
  assert.equal(after.role, before.role);
  assert.equal(after.authUid, before.authUid);
  assert.equal(after.ownerUid, before.ownerUid);
  assert.equal(after.status, before.status);
  assert.equal(after.suspensionReason, before.suspensionReason);
  assert.equal(after.createdAt.isEqual(before.createdAt), true);
  assert.equal(after.revokedAt, before.revokedAt);
});

test("registerDevicePublicKey: 23. active status is preserved through registration", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID, { status: "active" });
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });

  await registerDevicePublicKey.run(
    fakeRequest(
      { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
      KEY_TEST_CAMERA_AUTH_UID
    )
  );

  assert.equal((await registryRef(KEY_TEST_CAMERA_ID).get()).data().status, "active");
});

test("registerDevicePublicKey: 24. suspended status and suspensionReason are preserved, registration still succeeds", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID, { status: "suspended", suspensionReason: "manual" });
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });

  const response = await registerDevicePublicKey.run(
    fakeRequest(
      { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
      KEY_TEST_CAMERA_AUTH_UID
    )
  );

  assert.deepEqual(response, { success: true, identityMode: "keystore" });
  const data = (await registryRef(KEY_TEST_CAMERA_ID).get()).data();
  assert.equal(data.status, "suspended");
  assert.equal(data.suspensionReason, "manual");
  assert.equal(data.identityMode, "keystore");
});

test("registerDevicePublicKey: 25. revoked device is rejected and left unchanged", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID, { status: "revoked", revokedAt: admin.firestore.Timestamp.now() });
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });
  const before = (await registryRef(KEY_TEST_CAMERA_ID).get()).data();

  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_REVOKED"
  );

  const after = (await registryRef(KEY_TEST_CAMERA_ID).get()).data();
  assert.equal(after.identityMode, "legacy");
  assert.equal(after.publicKey, null);
  assert.equal(after.updatedAt.isEqual(before.updatedAt), true);
});

test("registerDevicePublicKey: 26/27/28. repeated same-key registration is idempotent, createdAt/updatedAt unchanged", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID);
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });

  const publicKey = generateP256PublicKeyBase64();
  const request = () =>
    registerDevicePublicKey.run(
      fakeRequest({ deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey, algorithm: "ES256" }, KEY_TEST_CAMERA_AUTH_UID)
    );

  const firstResponse = await request();
  const afterFirst = (await registryRef(KEY_TEST_CAMERA_ID).get()).data();

  const secondResponse = await request();
  const afterSecond = (await registryRef(KEY_TEST_CAMERA_ID).get()).data();

  assert.deepEqual(firstResponse, { success: true, identityMode: "keystore" });
  assert.deepEqual(secondResponse, { success: true, identityMode: "keystore" });
  assert.equal(afterSecond.publicKey, publicKey);
  assert.equal(afterSecond.createdAt.isEqual(afterFirst.createdAt), true);
  assert.equal(afterSecond.updatedAt.isEqual(afterFirst.updatedAt), true, "updatedAt must not change on an idempotent repeat");
  assert.equal(afterSecond.lastSeenAt.isEqual(afterFirst.lastSeenAt), false, "lastSeenAt should still be refreshed");
});

test("registerDevicePublicKey: 29. a different-key replacement attempt is rejected and the stored key is unchanged", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID);
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });

  const firstKey = generateP256PublicKeyBase64();
  await registerDevicePublicKey.run(
    fakeRequest(
      { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: firstKey, algorithm: "ES256" },
      KEY_TEST_CAMERA_AUTH_UID
    )
  );

  const secondKey = generateP256PublicKeyBase64();
  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: secondKey, algorithm: "ES256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "failed-precondition" && err.message === "PUBLIC_KEY_ALREADY_REGISTERED"
  );

  assert.equal((await registryRef(KEY_TEST_CAMERA_ID).get()).data().publicKey, firstKey);
});

test("registerDevicePublicKey: 30. legacy + non-null publicKey is treated as corrupt, not auto-fixed", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID, { identityMode: "legacy", publicKey: "unexpected-non-null-value" });
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });

  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_IDENTITY_CORRUPT"
  );

  const after = (await registryRef(KEY_TEST_CAMERA_ID).get()).data();
  assert.equal(after.identityMode, "legacy");
  assert.equal(after.publicKey, "unexpected-non-null-value");
});

test("registerDevicePublicKey: 31. keystore + null publicKey is treated as corrupt, not auto-fixed", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID, { identityMode: "keystore", publicKey: null });
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });

  await assert.rejects(
    registerDevicePublicKey.run(
      fakeRequest(
        { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: generateP256PublicKeyBase64(), algorithm: "ES256" },
        KEY_TEST_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_IDENTITY_CORRUPT"
  );

  const after = (await registryRef(KEY_TEST_CAMERA_ID).get()).data();
  assert.equal(after.identityMode, "keystore");
  assert.equal(after.publicKey, null);
});

// --- 32/33: concurrent registration ---------------------------------------------------------------

test("registerDevicePublicKey: 32. two concurrent same-key requests both succeed, exactly one stored key", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID);
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });

  const publicKey = generateP256PublicKeyBase64();
  const makeRequest = () =>
    registerDevicePublicKey.run(
      fakeRequest({ deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey, algorithm: "ES256" }, KEY_TEST_CAMERA_AUTH_UID)
    );

  const [first, second] = await Promise.all([makeRequest(), makeRequest()]);

  assert.deepEqual(first, { success: true, identityMode: "keystore" });
  assert.deepEqual(second, { success: true, identityMode: "keystore" });
  assert.equal((await registryRef(KEY_TEST_CAMERA_ID).get()).data().publicKey, publicKey);
});

test("registerDevicePublicKey: 33. two concurrent different-key requests leave only one stored key", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID);
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });

  const keyA = generateP256PublicKeyBase64();
  const keyB = generateP256PublicKeyBase64();

  const results = await Promise.allSettled([
    registerDevicePublicKey.run(
      fakeRequest({ deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: keyA, algorithm: "ES256" }, KEY_TEST_CAMERA_AUTH_UID)
    ),
    registerDevicePublicKey.run(
      fakeRequest({ deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: keyB, algorithm: "ES256" }, KEY_TEST_CAMERA_AUTH_UID)
    ),
  ]);

  const fulfilled = results.filter((r) => r.status === "fulfilled");
  const rejected = results.filter((r) => r.status === "rejected");

  // Firestore's own optimistic-concurrency transaction retry guarantees exactly one write wins --
  // never a last-write-wins replacement of the other's key.
  assert.equal(fulfilled.length, 1, "exactly one request must succeed");
  assert.equal(rejected.length, 1, "the other must be rejected, never silently overwritten");
  assert.equal(rejected[0].reason.message, "PUBLIC_KEY_ALREADY_REGISTERED");

  const finalKey = (await registryRef(KEY_TEST_CAMERA_ID).get()).data().publicKey;
  assert.ok(finalKey === keyA || finalKey === keyB, "the stored key must be exactly one of the two submitted keys");
});

// --- 34/35: logging never leaks the key or the caller's uid --------------------------------------

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

test("registerDevicePublicKey: 34/35. logs never contain the raw publicKey or request.auth.uid", async () => {
  await seedKeyTestDevice(KEY_TEST_CAMERA_ID);
  await keyTestClaimRef().set({ uid: KEY_TEST_OWNER_UID, cameraAuthUid: KEY_TEST_CAMERA_AUTH_UID });

  const publicKey = generateP256PublicKeyBase64();
  const output = await captureStdio(async () => {
    await registerDevicePublicKey.run(
      fakeRequest({ deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey, algorithm: "ES256" }, KEY_TEST_CAMERA_AUTH_UID)
    );
  });

  assert.ok(output.includes("REGISTER_DEVICE_PUBLIC_KEY_SUCCESS"), "the success log line should still fire");
  assert.ok(!output.includes(publicKey), "raw publicKey must never be logged");
  assert.ok(!output.includes(KEY_TEST_CAMERA_AUTH_UID), "the caller's request.auth.uid must never be logged");
  assert.ok(!output.includes(KEY_TEST_OWNER_UID), "ownerUid must never be logged");
});

test("registerDevicePublicKey: an invalid-key rejection log never contains the raw (invalid) key either", async () => {
  const notDer = Buffer.from("still not a valid SPKI DER structure").toString("base64");

  const output = await captureStdio(async () => {
    await assert.rejects(
      registerDevicePublicKey.run(
        fakeRequest(
          { deviceId: KEY_TEST_CAMERA_ID, role: "CAMERA", publicKey: notDer, algorithm: "ES256" },
          KEY_TEST_CAMERA_AUTH_UID
        )
      )
    );
  });

  assert.ok(output.includes("REGISTER_DEVICE_PUBLIC_KEY_INVALID"));
  assert.ok(!output.includes(notDer), "the raw (invalid) key must not be logged even on rejection");
  assert.ok(!output.includes(KEY_TEST_CAMERA_AUTH_UID));
});

// --- 36: a genuine Firestore failure is never swallowed as success -------------------------------
// Exercised directly against applyPublicKeyRegistration() (the layer that actually owns this
// guarantee -- see its own doc) with a minimal fake `db` whose runTransaction() rejects, rather
// than against the full callable: there is no dependency-injection point for admin.firestore()
// inside the real registerDevicePublicKey callable, and reaching for a mocking library just to
// fake a network-level Firestore outage would be exactly the "heavy new test infrastructure" this
// project avoids. This still directly proves the property in question: a rejected transaction
// propagates as a rejected promise, never as a fabricated success.

test("registerDevicePublicKey: 36. a Firestore transaction failure propagates, it is never swallowed as success", async () => {
  const fakeDb = {
    collection: () => ({ doc: () => ({}) }),
    runTransaction: async () => {
      throw new Error("simulated Firestore outage");
    },
  };

  await assert.rejects(
    applyPublicKeyRegistration(fakeDb, {
      deviceId: KEY_TEST_CAMERA_ID,
      role: "CAMERA",
      expectedAuthUid: KEY_TEST_CAMERA_AUTH_UID,
      expectedOwnerUid: null,
      canonicalPublicKey: generateP256PublicKeyBase64(),
    }),
    (err) => err.message === "simulated Firestore outage"
  );
});

// --- validateEcP256PublicKey: a few direct, fast unit checks on the pure validator itself --------

test("validateEcP256PublicKey: accepts a real P-256 SPKI key and computes a lowercase-hex fingerprint", () => {
  const publicKey = generateP256PublicKeyBase64();
  const result = validateEcP256PublicKey(publicKey);

  assert.equal(result.valid, true);
  assert.equal(result.canonicalBase64, publicKey);
  assert.match(result.fingerprint, /^[0-9a-f]{64}$/);
});

test("validateEcP256PublicKey: rejects non-canonical Base64 (same decoded bytes, different re-encoding)", () => {
  // Buffer.from([0xff]).toString("base64") canonically encodes to "/w==" -- the last quartet's
  // unused low bits are zero in a canonical encoding. "/x==" decodes to that exact same single
  // byte (0xff) under a lenient decoder (only the meaningful top bits are read), but is not what
  // re-encoding that byte actually produces -- exactly the non-canonical case this check exists to
  // catch. A general Base64-canonicality property, not specific to EC keys, so a trivial 1-byte
  // example is used here instead of hand-corrupting a real ~91-byte SPKI key (whose own trailing
  // quartet position would need the same reasoning applied, but is harder to verify by hand).
  const result = validateEcP256PublicKey("/x==");

  assert.equal(result.valid, false);
  assert.equal(result.reason, "NON_CANONICAL_BASE64");
});

// =================================================================================================
// revokeRegisteredDevice -- explicit revocation of a lost/stolen device
// =================================================================================================

const REVOKE_CAMERA_ID = "camera-revoke-test";
const REVOKE_OWNER_UID = "revoke-owner-uid";
const REVOKE_STRANGER_UID = "revoke-stranger-uid";
const REVOKE_CAMERA_AUTH_UID = "revoke-camera-auth-uid";

test.afterEach(async () => {
  await registryRef(REVOKE_CAMERA_ID).delete();
});

async function seedRevokeTestDevice(deviceId, overrides = {}) {
  const now = admin.firestore.Timestamp.now();
  await registryRef(deviceId).set({
    schemaVersion: 1,
    deviceId,
    role: "CAMERA",
    authUid: REVOKE_CAMERA_AUTH_UID,
    ownerUid: REVOKE_OWNER_UID,
    status: "active",
    suspensionReason: null,
    identityMode: "legacy",
    publicKey: null,
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    revokedAt: null,
    ...overrides,
  });
}

test("revokeRegisteredDevice: 1. owner can revoke their own active device", async () => {
  await seedRevokeTestDevice(REVOKE_CAMERA_ID, { status: "active" });

  const response = await revokeRegisteredDevice.run(fakeRequest({ deviceId: REVOKE_CAMERA_ID }, REVOKE_OWNER_UID));

  assert.deepEqual(response, { success: true, status: "revoked", alreadyRevoked: false });
  const data = (await registryRef(REVOKE_CAMERA_ID).get()).data();
  assert.equal(data.status, "revoked");
  assert.ok(data.revokedAt);
  assert.equal(data.suspensionReason, null);
});

test("revokeRegisteredDevice: 2. owner can revoke their own suspended device", async () => {
  await seedRevokeTestDevice(REVOKE_CAMERA_ID, { status: "suspended", suspensionReason: "plan" });

  const response = await revokeRegisteredDevice.run(fakeRequest({ deviceId: REVOKE_CAMERA_ID }, REVOKE_OWNER_UID));

  assert.deepEqual(response, { success: true, status: "revoked", alreadyRevoked: false });
  const data = (await registryRef(REVOKE_CAMERA_ID).get()).data();
  assert.equal(data.status, "revoked");
  assert.equal(data.suspensionReason, null);
});

test("revokeRegisteredDevice: 3. a different (non-owner) authenticated user gets permission-denied", async () => {
  await seedRevokeTestDevice(REVOKE_CAMERA_ID, { status: "active" });

  await assert.rejects(
    revokeRegisteredDevice.run(fakeRequest({ deviceId: REVOKE_CAMERA_ID }, REVOKE_STRANGER_UID)),
    (err) => err.code === "permission-denied" && err.message === "PERMISSION_DENIED"
  );

  assert.equal((await registryRef(REVOKE_CAMERA_ID).get()).data().status, "active");
});

test("revokeRegisteredDevice: 4. unauthenticated request rejected", async () => {
  await seedRevokeTestDevice(REVOKE_CAMERA_ID, { status: "active" });

  await assert.rejects(
    revokeRegisteredDevice.run(fakeRequest({ deviceId: REVOKE_CAMERA_ID }, undefined)),
    (err) => err.code === "unauthenticated"
  );
});

test("revokeRegisteredDevice: 5. a device with ownerUid null cannot be revoked by a client", async () => {
  await seedRevokeTestDevice(REVOKE_CAMERA_ID, { status: "active", ownerUid: null });

  await assert.rejects(
    revokeRegisteredDevice.run(fakeRequest({ deviceId: REVOKE_CAMERA_ID }, REVOKE_OWNER_UID)),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_NOT_OWNED"
  );

  assert.equal((await registryRef(REVOKE_CAMERA_ID).get()).data().status, "active");
});

test("revokeRegisteredDevice: a deviceId with no registeredDevices document gets not-found", async () => {
  await assert.rejects(
    revokeRegisteredDevice.run(fakeRequest({ deviceId: "device-never-registered-revoke" }, REVOKE_OWNER_UID)),
    (err) => err.code === "not-found" && err.message === "DEVICE_NOT_REGISTERED"
  );
});

test("revokeRegisteredDevice: 6/7. a repeated revoke by the same owner is idempotent and never changes the original revokedAt", async () => {
  await seedRevokeTestDevice(REVOKE_CAMERA_ID, { status: "active" });

  const first = await revokeRegisteredDevice.run(fakeRequest({ deviceId: REVOKE_CAMERA_ID }, REVOKE_OWNER_UID));
  assert.deepEqual(first, { success: true, status: "revoked", alreadyRevoked: false });

  const afterFirst = (await registryRef(REVOKE_CAMERA_ID).get()).data();
  const originalRevokedAt = afterFirst.revokedAt;
  const originalUpdatedAt = afterFirst.updatedAt;
  assert.ok(originalRevokedAt);

  // A short real delay so a bug that DID bump updatedAt/revokedAt on the idempotent repeat would
  // produce a detectably different Timestamp, not one indistinguishable by coincidence.
  await new Promise((resolve) => setTimeout(resolve, 50));

  const second = await revokeRegisteredDevice.run(fakeRequest({ deviceId: REVOKE_CAMERA_ID }, REVOKE_OWNER_UID));
  assert.deepEqual(second, { success: true, status: "revoked", alreadyRevoked: true });

  const afterSecond = (await registryRef(REVOKE_CAMERA_ID).get()).data();
  assert.equal(afterSecond.revokedAt.isEqual(originalRevokedAt), true, "revokedAt must never change on a repeat revoke");
  assert.equal(afterSecond.updatedAt.isEqual(originalUpdatedAt), true, "updatedAt must not be bumped on a no-op repeat");
});

test("revokeRegisteredDevice: 8. publicKey and identityMode are preserved through revoke", async () => {
  const publicKey = generateP256PublicKeyBase64();
  await seedRevokeTestDevice(REVOKE_CAMERA_ID, { status: "active", identityMode: "keystore", publicKey });

  await revokeRegisteredDevice.run(fakeRequest({ deviceId: REVOKE_CAMERA_ID }, REVOKE_OWNER_UID));

  const data = (await registryRef(REVOKE_CAMERA_ID).get()).data();
  assert.equal(data.identityMode, "keystore");
  assert.equal(data.publicKey, publicKey);
});

test("revokeRegisteredDevice: deviceId/role/authUid/ownerUid/createdAt/lastSeenAt are all preserved through revoke", async () => {
  await seedRevokeTestDevice(REVOKE_CAMERA_ID, { status: "active" });
  const before = (await registryRef(REVOKE_CAMERA_ID).get()).data();

  await revokeRegisteredDevice.run(fakeRequest({ deviceId: REVOKE_CAMERA_ID }, REVOKE_OWNER_UID));

  const after = (await registryRef(REVOKE_CAMERA_ID).get()).data();
  assert.equal(after.deviceId, before.deviceId);
  assert.equal(after.role, before.role);
  assert.equal(after.authUid, before.authUid);
  assert.equal(after.ownerUid, before.ownerUid);
  assert.equal(after.createdAt.isEqual(before.createdAt), true);
  assert.equal(after.lastSeenAt.isEqual(before.lastSeenAt), true);
});

test("revokeRegisteredDevice: 9. a revoked device cannot be restored through any client-reachable path", async () => {
  await seedRevokeTestDevice(REVOKE_CAMERA_ID, { status: "active" });
  await revokeRegisteredDevice.run(fakeRequest({ deviceId: REVOKE_CAMERA_ID }, REVOKE_OWNER_UID));
  assert.equal((await registryRef(REVOKE_CAMERA_ID).get()).data().status, "revoked");

  // There is no unrevoke/reactivate callable at all -- the closest thing a client can still reach
  // is the same lazy-migration bookkeeping every pairing/TURN/event call already performs, which
  // must never resurrect a revoked device (already covered generally by "a revoked device is
  // never returned to active by lazy registration" above; repeated here against a device that
  // went through the real revokeRegisteredDevice callable specifically).
  await registerLegacyCamera(db, REVOKE_CAMERA_ID, REVOKE_CAMERA_AUTH_UID);
  await touchRegisteredDevice(db, REVOKE_CAMERA_ID);

  assert.equal((await registryRef(REVOKE_CAMERA_ID).get()).data().status, "revoked");
});

// --- decideRevokeRegisteredDevice: pure function -------------------------------------------------

test("decideRevokeRegisteredDevice: no existing document is not_found", () => {
  assert.deepEqual(decideRevokeRegisteredDevice(null, REVOKE_OWNER_UID), { outcome: "not_found" });
});

test("decideRevokeRegisteredDevice: ownerUid null is no_owner regardless of requesting uid", () => {
  const existing = { ownerUid: null, status: "active" };
  assert.deepEqual(decideRevokeRegisteredDevice(existing, REVOKE_OWNER_UID), { outcome: "no_owner" });
});

test("decideRevokeRegisteredDevice: a non-owner requester is owner_mismatch", () => {
  const existing = { ownerUid: REVOKE_OWNER_UID, status: "active" };
  assert.deepEqual(decideRevokeRegisteredDevice(existing, REVOKE_STRANGER_UID), { outcome: "owner_mismatch" });
});

// =================================================================================================
// checkRegisteredDeviceOperational -- centralized status enforcement (pure function)
// =================================================================================================

test("checkRegisteredDeviceOperational: active is operational", () => {
  assert.deepEqual(checkRegisteredDeviceOperational({ status: "active", suspensionReason: null }), {
    operational: true,
  });
});

test("checkRegisteredDeviceOperational: suspended/plan is DEVICE_SUSPENDED_PLAN", () => {
  assert.deepEqual(checkRegisteredDeviceOperational({ status: "suspended", suspensionReason: "plan" }), {
    operational: false,
    reason: "DEVICE_SUSPENDED_PLAN",
  });
});

test("checkRegisteredDeviceOperational: suspended/manual is the generic DEVICE_SUSPENDED", () => {
  assert.deepEqual(checkRegisteredDeviceOperational({ status: "suspended", suspensionReason: "manual" }), {
    operational: false,
    reason: "DEVICE_SUSPENDED",
  });
});

test("checkRegisteredDeviceOperational: suspended/security is the generic DEVICE_SUSPENDED", () => {
  assert.deepEqual(checkRegisteredDeviceOperational({ status: "suspended", suspensionReason: "security" }), {
    operational: false,
    reason: "DEVICE_SUSPENDED",
  });
});

test("checkRegisteredDeviceOperational: revoked is DEVICE_REVOKED", () => {
  assert.deepEqual(checkRegisteredDeviceOperational({ status: "revoked", suspensionReason: null }), {
    operational: false,
    reason: "DEVICE_REVOKED",
  });
});

test("checkRegisteredDeviceOperational: a missing document is operational by default (permissive)", () => {
  assert.deepEqual(checkRegisteredDeviceOperational(null), { operational: true });
});

test("checkRegisteredDeviceOperational: a missing document is DEVICE_NOT_REGISTERED when requireRegistered is set", () => {
  assert.deepEqual(checkRegisteredDeviceOperational(null, { requireRegistered: true }), {
    operational: false,
    reason: "DEVICE_NOT_REGISTERED",
  });
});

// =================================================================================================
// Device-status enforcement -- getTurnCredentials / submitCameraEvent / claimCameraForUser /
// createCameraPairingSession / cleanup exceptions
// =================================================================================================

const ENFORCE_CAMERA_ID = "camera-enforce-test";
const ENFORCE_OWNER_UID = "enforce-owner-uid";
const ENFORCE_CAMERA_AUTH_UID = "enforce-camera-auth-uid";

function enforceClaimRef() {
  return db.collection("cameraClaims").doc(ENFORCE_CAMERA_ID);
}

test.afterEach(async () => {
  await registryRef(ENFORCE_CAMERA_ID).delete();
  await enforceClaimRef().delete();
  delete process.env.TURN_REST_SECRET;
});

async function seedEnforceDevice(overrides = {}) {
  const now = admin.firestore.Timestamp.now();
  await registryRef(ENFORCE_CAMERA_ID).set({
    schemaVersion: 1,
    deviceId: ENFORCE_CAMERA_ID,
    role: "CAMERA",
    authUid: ENFORCE_CAMERA_AUTH_UID,
    ownerUid: ENFORCE_OWNER_UID,
    status: "active",
    suspensionReason: null,
    identityMode: "legacy",
    publicKey: null,
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    revokedAt: null,
    ...overrides,
  });
}

test("enforcement: 26. an active Camera's linked Home still receives TURN credentials", async () => {
  process.env.TURN_REST_SECRET = "enforce-test-secret";
  await enforceClaimRef().set({ uid: ENFORCE_OWNER_UID, cameraAuthUid: ENFORCE_CAMERA_AUTH_UID });
  await seedEnforceDevice({ status: "active" });

  const response = await getTurnCredentials.run(
    fakeRequest({ cameraDeviceId: ENFORCE_CAMERA_ID, purpose: "LIVE_VIEW" }, ENFORCE_OWNER_UID)
  );

  assert.equal(response.iceServers.length, 1);
});

test("enforcement: 27. a suspended Camera's linked Home is denied TURN credentials", async () => {
  process.env.TURN_REST_SECRET = "enforce-test-secret";
  await enforceClaimRef().set({ uid: ENFORCE_OWNER_UID, cameraAuthUid: ENFORCE_CAMERA_AUTH_UID });
  await seedEnforceDevice({ status: "suspended", suspensionReason: "plan" });

  await assert.rejects(
    getTurnCredentials.run(fakeRequest({ cameraDeviceId: ENFORCE_CAMERA_ID, purpose: "LIVE_VIEW" }, ENFORCE_OWNER_UID)),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_SUSPENDED_PLAN"
  );
});

test("enforcement: 28. a revoked Camera's linked Home is denied TURN credentials", async () => {
  process.env.TURN_REST_SECRET = "enforce-test-secret";
  await enforceClaimRef().set({ uid: ENFORCE_OWNER_UID, cameraAuthUid: ENFORCE_CAMERA_AUTH_UID });
  await seedEnforceDevice({ status: "revoked", revokedAt: admin.firestore.Timestamp.now() });

  await assert.rejects(
    getTurnCredentials.run(fakeRequest({ cameraDeviceId: ENFORCE_CAMERA_ID, purpose: "LIVE_VIEW" }, ENFORCE_OWNER_UID)),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_REVOKED"
  );
});

test("enforcement: 29. a suspended Camera cannot submit an event", async () => {
  await enforceClaimRef().set({ uid: ENFORCE_OWNER_UID, cameraAuthUid: ENFORCE_CAMERA_AUTH_UID });
  await seedEnforceDevice({ status: "suspended", suspensionReason: "manual" });

  await assert.rejects(
    submitCameraEvent.run(
      fakeRequest(
        { cameraDeviceId: ENFORCE_CAMERA_ID, type: "camera_offline", title: "t", body: "b", severity: "warning" },
        ENFORCE_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_SUSPENDED"
  );
});

test("enforcement: 30. a revoked Camera cannot submit an event", async () => {
  await enforceClaimRef().set({ uid: ENFORCE_OWNER_UID, cameraAuthUid: ENFORCE_CAMERA_AUTH_UID });
  await seedEnforceDevice({ status: "revoked", revokedAt: admin.firestore.Timestamp.now() });

  await assert.rejects(
    submitCameraEvent.run(
      fakeRequest(
        { cameraDeviceId: ENFORCE_CAMERA_ID, type: "camera_offline", title: "t", body: "b", severity: "warning" },
        ENFORCE_CAMERA_AUTH_UID
      )
    ),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_REVOKED"
  );
});

test("enforcement: 31. releaseCameraForUser (cleanup/unpair) remains accessible for a revoked Camera, but does not detach registry ownership", async () => {
  const revokedAt = admin.firestore.Timestamp.now();
  await enforceClaimRef().set({ uid: ENFORCE_OWNER_UID, cameraAuthUid: ENFORCE_CAMERA_AUTH_UID });
  await seedEnforceDevice({ status: "revoked", revokedAt, identityMode: "keystore", publicKey: "enforce-revoked-key" });

  const response = await releaseCameraForUser.run(fakeRequest({ cameraDeviceId: ENFORCE_CAMERA_ID }, ENFORCE_OWNER_UID));

  // Cleanup of the pairing artifacts themselves (cameraClaims, cameraDevices, pairingState) still
  // succeeds -- only the registry's own ownerUid/status/revokedAt/publicKey/identityMode survive
  // unchanged. Revoked cleanup != registry detach.
  assert.deepEqual(response, { success: true });
  assert.equal((await enforceClaimRef().get()).exists, false, "cameraClaims must still be deleted");
  const data = (await registryRef(ENFORCE_CAMERA_ID).get()).data();
  assert.equal(data.ownerUid, ENFORCE_OWNER_UID, "registry ownerUid must survive unpair after revoke");
  assert.equal(data.status, "revoked", "unpair after revoke must not resurrect the device");
  assert.equal(data.revokedAt.isEqual(revokedAt), true, "revokedAt must not change");
  assert.equal(data.identityMode, "keystore");
  assert.equal(data.publicKey, "enforce-revoked-key");
});

test("enforcement: a repeated unpair/cleanup against an already-revoked Camera is idempotent", async () => {
  const revokedAt = admin.firestore.Timestamp.now();
  await enforceClaimRef().set({ uid: ENFORCE_OWNER_UID, cameraAuthUid: ENFORCE_CAMERA_AUTH_UID });
  await seedEnforceDevice({ status: "revoked", revokedAt });

  await releaseCameraForUser.run(fakeRequest({ cameraDeviceId: ENFORCE_CAMERA_ID }, ENFORCE_OWNER_UID));
  const afterFirst = (await registryRef(ENFORCE_CAMERA_ID).get()).data();

  // A second cleanup call for the same camera would normally hit "not claimed"
  // (releaseCameraForUser requires an existing claim) -- unpairCameraFromDevice is the
  // no-op-when-already-unclaimed path, exactly the scenario a repeated cleanup attempt hits in
  // practice.
  const secondResponse = await unpairCameraFromDevice.run(
    fakeRequest({ cameraDeviceId: ENFORCE_CAMERA_ID }, ENFORCE_CAMERA_AUTH_UID)
  );
  const afterSecond = (await registryRef(ENFORCE_CAMERA_ID).get()).data();

  assert.deepEqual(secondResponse, { success: true });
  assert.equal(afterSecond.ownerUid, ENFORCE_OWNER_UID);
  assert.equal(afterSecond.status, "revoked");
  assert.equal(afterSecond.revokedAt.isEqual(revokedAt), true);
  assert.equal(afterSecond.updatedAt.isEqual(afterFirst.updatedAt), true, "no further registry write on the repeat");
});

test("enforcement: 31b. unpairCameraFromDevice (cleanup/unpair) remains accessible for a suspended Camera", async () => {
  await enforceClaimRef().set({ uid: ENFORCE_OWNER_UID, cameraAuthUid: ENFORCE_CAMERA_AUTH_UID });
  await seedEnforceDevice({ status: "suspended", suspensionReason: "plan" });

  const response = await unpairCameraFromDevice.run(fakeRequest({ cameraDeviceId: ENFORCE_CAMERA_ID }, ENFORCE_CAMERA_AUTH_UID));

  assert.deepEqual(response, { success: true });
  const data = (await registryRef(ENFORCE_CAMERA_ID).get()).data();
  assert.equal(data.ownerUid, null);
  assert.equal(data.status, "suspended", "unpair must not change status");
});

test("enforcement: 31c. revokeRegisteredDevice itself remains accessible for an already-suspended device", async () => {
  await seedEnforceDevice({ status: "suspended", suspensionReason: "plan" });

  const response = await revokeRegisteredDevice.run(fakeRequest({ deviceId: ENFORCE_CAMERA_ID }, ENFORCE_OWNER_UID));

  assert.deepEqual(response, { success: true, status: "revoked", alreadyRevoked: false });
});

test("enforcement: a revoked Camera cannot start a new pairing session (createCameraPairingSession)", async () => {
  await seedEnforceDevice({ status: "revoked", revokedAt: admin.firestore.Timestamp.now() });

  await assert.rejects(
    createCameraPairingSession.run(
      fakeRequest({ cameraDeviceId: ENFORCE_CAMERA_ID, pairingSecretHash: "hash" }, ENFORCE_CAMERA_AUTH_UID)
    ),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_REVOKED"
  );
});

test("enforcement: a suspended Camera cannot complete a claim (claimCameraForUser)", async () => {
  await seedEnforceDevice({ status: "suspended", suspensionReason: "security" });
  const pairingId = "pairing-enforce-suspended-1";
  await db
    .collection("cameraPairingSessions")
    .doc(pairingId)
    .set({
      cameraDeviceId: ENFORCE_CAMERA_ID,
      pairingSecretHash: crypto.createHash("sha256").update("s3cr3t-enforce-1").digest("hex"),
      cameraAuthUid: ENFORCE_CAMERA_AUTH_UID,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: admin.firestore.Timestamp.fromMillis(Date.now() + 10 * 60 * 1000),
      consumedAt: null,
      status: "pending",
    });

  await assert.rejects(
    claimCameraForUser.run(
      fakeRequest(
        { cameraDeviceId: ENFORCE_CAMERA_ID, pairingId, pairingSecret: "s3cr3t-enforce-1", homeDeviceId: "home-enforce-1" },
        ENFORCE_OWNER_UID
      )
    ),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_SUSPENDED"
  );

  await db.collection("cameraPairingSessions").doc(pairingId).delete();
});

// =================================================================================================
// Unpair regression: publicKey/identityMode preserved (12/13) -- keystore-seeded device, unlike the
// existing "12/13." tests above which only cover a legacy device's status/ownerUid/revokedAt.
// =================================================================================================

const UNPAIR_REGRESSION_CAMERA_ID = "camera-unpair-keystore-regression";
const UNPAIR_REGRESSION_OWNER_UID = "unpair-keystore-owner-uid";
const UNPAIR_REGRESSION_CAMERA_AUTH_UID = "unpair-keystore-camera-auth-uid";

test.afterEach(async () => {
  await registryRef(UNPAIR_REGRESSION_CAMERA_ID).delete();
  await db.collection("cameraClaims").doc(UNPAIR_REGRESSION_CAMERA_ID).delete();
});

test("unpair regression: 10/12/13. releaseCameraForUser clears ownerUid but preserves publicKey and identityMode", async () => {
  const publicKey = generateP256PublicKeyBase64();
  await db
    .collection("cameraClaims")
    .doc(UNPAIR_REGRESSION_CAMERA_ID)
    .set({ uid: UNPAIR_REGRESSION_OWNER_UID, cameraAuthUid: UNPAIR_REGRESSION_CAMERA_AUTH_UID });
  const now = admin.firestore.Timestamp.now();
  await registryRef(UNPAIR_REGRESSION_CAMERA_ID).set({
    schemaVersion: 1,
    deviceId: UNPAIR_REGRESSION_CAMERA_ID,
    role: "CAMERA",
    authUid: UNPAIR_REGRESSION_CAMERA_AUTH_UID,
    ownerUid: UNPAIR_REGRESSION_OWNER_UID,
    status: "active",
    suspensionReason: null,
    identityMode: "keystore",
    publicKey,
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    revokedAt: null,
  });

  const response = await releaseCameraForUser.run(
    fakeRequest({ cameraDeviceId: UNPAIR_REGRESSION_CAMERA_ID }, UNPAIR_REGRESSION_OWNER_UID)
  );

  assert.deepEqual(response, { success: true });
  const data = (await registryRef(UNPAIR_REGRESSION_CAMERA_ID).get()).data();
  assert.equal(data.ownerUid, null, "10. ownerUid must be cleared");
  assert.equal(data.status, "active", "11. status must be untouched");
  assert.equal(data.identityMode, "keystore", "13. identityMode must be untouched");
  assert.equal(data.publicKey, publicKey, "12. publicKey must be untouched");
});

test("unpair regression: a suspended device stays suspended through a normal unpair", async () => {
  await db
    .collection("cameraClaims")
    .doc(UNPAIR_REGRESSION_CAMERA_ID)
    .set({ uid: UNPAIR_REGRESSION_OWNER_UID, cameraAuthUid: UNPAIR_REGRESSION_CAMERA_AUTH_UID });
  const now = admin.firestore.Timestamp.now();
  await registryRef(UNPAIR_REGRESSION_CAMERA_ID).set({
    schemaVersion: 1,
    deviceId: UNPAIR_REGRESSION_CAMERA_ID,
    role: "CAMERA",
    authUid: UNPAIR_REGRESSION_CAMERA_AUTH_UID,
    ownerUid: UNPAIR_REGRESSION_OWNER_UID,
    status: "suspended",
    suspensionReason: "plan",
    identityMode: "legacy",
    publicKey: null,
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    revokedAt: null,
  });

  await releaseCameraForUser.run(fakeRequest({ cameraDeviceId: UNPAIR_REGRESSION_CAMERA_ID }, UNPAIR_REGRESSION_OWNER_UID));

  const data = (await registryRef(UNPAIR_REGRESSION_CAMERA_ID).get()).data();
  assert.equal(data.status, "suspended");
  assert.equal(data.suspensionReason, "plan");
});

// =================================================================================================
// reconcileUserDeviceLimits / planDeviceLimitDecision -- plan-based suspension
// =================================================================================================

const RECONCILE_OWNER_UID = "reconcile-owner-uid";
const RECONCILE_OTHER_OWNER_UID = "reconcile-other-owner-uid";

function reconcileDeviceIds(prefix, count) {
  return Array.from({ length: count }, (_, i) => `${prefix}-${i}`);
}

async function seedReconcileDevice(deviceId, role, ownerUid, createdAtMillis, overrides = {}) {
  await registryRef(deviceId).set({
    schemaVersion: 1,
    deviceId,
    role,
    authUid: `${deviceId}-auth`,
    ownerUid,
    status: "active",
    suspensionReason: null,
    identityMode: "legacy",
    publicKey: null,
    createdAt: admin.firestore.Timestamp.fromMillis(createdAtMillis),
    updatedAt: admin.firestore.Timestamp.fromMillis(createdAtMillis),
    lastSeenAt: admin.firestore.Timestamp.fromMillis(createdAtMillis),
    revokedAt: null,
    ...overrides,
  });
}

async function deleteReconcileDevices(deviceIds) {
  await Promise.all(deviceIds.map((id) => registryRef(id).delete()));
}

test("reconcileUserDeviceLimits: 14/15. maxCameras=1 leaves the oldest Camera active, suspends the rest as suspended/plan", async () => {
  const ids = reconcileDeviceIds("reconcile-cam-a", 3);
  await Promise.all(ids.map((id, i) => seedReconcileDevice(id, "CAMERA", RECONCILE_OWNER_UID, 1000 + i * 10)));

  const result = await reconcileUserDeviceLimits(db, RECONCILE_OWNER_UID, { maxCameras: 1, maxHomeDevices: 1 });

  assert.equal(result.camerasSuspended, 2);
  assert.equal(result.camerasReactivated, 0);

  const docs = await Promise.all(ids.map((id) => registryRef(id).get()));
  assert.equal(docs[0].data().status, "active", "oldest device (earliest createdAt) stays active");
  assert.equal(docs[1].data().status, "suspended");
  assert.equal(docs[1].data().suspensionReason, "plan");
  assert.equal(docs[2].data().status, "suspended");
  assert.equal(docs[2].data().suspensionReason, "plan");

  await deleteReconcileDevices(ids);
});

test("reconcileUserDeviceLimits: 16. Home and Camera devices are counted against their own limit independently", async () => {
  const cameraIds = reconcileDeviceIds("reconcile-role-cam", 2);
  const homeIds = reconcileDeviceIds("reconcile-role-home", 2);
  await Promise.all([
    ...cameraIds.map((id, i) => seedReconcileDevice(id, "CAMERA", RECONCILE_OWNER_UID, 2000 + i * 10)),
    ...homeIds.map((id, i) => seedReconcileDevice(id, "HOME", RECONCILE_OWNER_UID, 2000 + i * 10)),
  ]);

  const result = await reconcileUserDeviceLimits(db, RECONCILE_OWNER_UID, { maxCameras: 1, maxHomeDevices: 2 });

  assert.equal(result.camerasSuspended, 1, "1 of 2 Cameras suspended (limit 1)");
  assert.equal(result.homeDevicesSuspended, 0, "0 of 2 Homes suspended (limit 2, exactly enough)");

  await deleteReconcileDevices([...cameraIds, ...homeIds]);
});

test("reconcileUserDeviceLimits: 17/23. deterministic ordering -- a repeated reconcile with the same limit selects the same devices and makes no further writes", async () => {
  const ids = reconcileDeviceIds("reconcile-det", 3);
  await Promise.all(ids.map((id, i) => seedReconcileDevice(id, "CAMERA", RECONCILE_OWNER_UID, 3000 + i * 10)));

  await reconcileUserDeviceLimits(db, RECONCILE_OWNER_UID, { maxCameras: 2, maxHomeDevices: 1 });
  const afterFirst = await Promise.all(ids.map((id) => registryRef(id).get()));
  const statusesFirst = afterFirst.map((d) => d.data().status);

  const secondResult = await reconcileUserDeviceLimits(db, RECONCILE_OWNER_UID, { maxCameras: 2, maxHomeDevices: 1 });
  const afterSecond = await Promise.all(ids.map((id) => registryRef(id).get()));
  const statusesSecond = afterSecond.map((d) => d.data().status);

  assert.deepEqual(statusesSecond, statusesFirst);
  assert.equal(secondResult.camerasSuspended, 0, "a repeated reconcile with unchanged limits makes no further writes");
  assert.equal(secondResult.camerasReactivated, 0);

  await deleteReconcileDevices(ids);
});

test("reconcileUserDeviceLimits: 17b. tie-break on identical createdAt falls back to deviceId ascending", async () => {
  const sameMillis = 4000;
  const ids = ["reconcile-tie-b", "reconcile-tie-a", "reconcile-tie-c"];
  await Promise.all(ids.map((id) => seedReconcileDevice(id, "CAMERA", RECONCILE_OWNER_UID, sameMillis)));

  await reconcileUserDeviceLimits(db, RECONCILE_OWNER_UID, { maxCameras: 1, maxHomeDevices: 1 });

  const data = await Promise.all(ids.map((id) => registryRef(id).get()));
  const byId = Object.fromEntries(data.map((d) => [d.id, d.data().status]));
  assert.equal(byId["reconcile-tie-a"], "active", "lexicographically smallest deviceId wins the tie");
  assert.equal(byId["reconcile-tie-b"], "suspended");
  assert.equal(byId["reconcile-tie-c"], "suspended");

  await deleteReconcileDevices(ids);
});

test("reconcileUserDeviceLimits: 18. raising the limit reactivates only devices suspended/plan", async () => {
  const ids = reconcileDeviceIds("reconcile-raise", 2);
  await seedReconcileDevice(ids[0], "CAMERA", RECONCILE_OWNER_UID, 5000, { status: "suspended", suspensionReason: "plan" });
  await seedReconcileDevice(ids[1], "CAMERA", RECONCILE_OWNER_UID, 5010, { status: "suspended", suspensionReason: "plan" });

  const result = await reconcileUserDeviceLimits(db, RECONCILE_OWNER_UID, { maxCameras: 2, maxHomeDevices: 1 });

  assert.equal(result.camerasReactivated, 2);
  const docs = await Promise.all(ids.map((id) => registryRef(id).get()));
  assert.ok(docs.every((d) => d.data().status === "active" && d.data().suspensionReason === null));

  await deleteReconcileDevices(ids);
});

test("reconcileUserDeviceLimits: 19. a manual-suspended device is never reactivated by a limit increase", async () => {
  const id = "reconcile-manual-1";
  await seedReconcileDevice(id, "CAMERA", RECONCILE_OWNER_UID, 6000, { status: "suspended", suspensionReason: "manual" });

  const result = await reconcileUserDeviceLimits(db, RECONCILE_OWNER_UID, { maxCameras: 10, maxHomeDevices: 10 });

  assert.equal(result.camerasReactivated, 0);
  const data = (await registryRef(id).get()).data();
  assert.equal(data.status, "suspended");
  assert.equal(data.suspensionReason, "manual");

  await deleteReconcileDevices([id]);
});

test("reconcileUserDeviceLimits: 20. a security-suspended device is never reactivated by a limit increase", async () => {
  const id = "reconcile-security-1";
  await seedReconcileDevice(id, "CAMERA", RECONCILE_OWNER_UID, 6100, { status: "suspended", suspensionReason: "security" });

  const result = await reconcileUserDeviceLimits(db, RECONCILE_OWNER_UID, { maxCameras: 10, maxHomeDevices: 10 });

  assert.equal(result.camerasReactivated, 0);
  const data = (await registryRef(id).get()).data();
  assert.equal(data.status, "suspended");
  assert.equal(data.suspensionReason, "security");

  await deleteReconcileDevices([id]);
});

test("reconcileUserDeviceLimits: 21. a revoked device is never reactivated, and never counted toward the limit", async () => {
  const revokedId = "reconcile-revoked-1";
  const activeId = "reconcile-revoked-active-1";
  await seedReconcileDevice(revokedId, "CAMERA", RECONCILE_OWNER_UID, 6200, {
    status: "revoked",
    revokedAt: admin.firestore.Timestamp.now(),
  });
  await seedReconcileDevice(activeId, "CAMERA", RECONCILE_OWNER_UID, 6210);

  const result = await reconcileUserDeviceLimits(db, RECONCILE_OWNER_UID, { maxCameras: 1, maxHomeDevices: 1 });

  assert.equal(result.camerasSuspended, 0, "the one active device fits the limit of 1 -- the revoked one is not counted");
  assert.equal((await registryRef(revokedId).get()).data().status, "revoked");
  assert.equal((await registryRef(activeId).get()).data().status, "active");

  await deleteReconcileDevices([revokedId, activeId]);
});

// --- manual/security suspended devices count toward the limit (they are NOT excluded from the
// count -- only from automatic reactivation/re-suspension). See docs/DEVICE_REGISTRY.md's
// corrected "Plan-based suspension" section. -------------------------------------------------

test("reconcileUserDeviceLimits: 1. a manual-suspended device occupies a plan slot", async () => {
  // Section 4's own example: A (manual, created first) occupies the only slot at limit=1, so B
  // (active, created second) becomes excess and is suspended/plan -- even though A itself stays
  // operationally suspended the whole time.
  const idA = "reconcile-manual-slot-a";
  const idB = "reconcile-manual-slot-b";
  await seedReconcileDevice(idA, "CAMERA", RECONCILE_OWNER_UID, 7000, { status: "suspended", suspensionReason: "manual" });
  await seedReconcileDevice(idB, "CAMERA", RECONCILE_OWNER_UID, 7010, { status: "active" });

  const result = await reconcileUserDeviceLimits(db, RECONCILE_OWNER_UID, { maxCameras: 1, maxHomeDevices: 1 });

  assert.equal(result.camerasSuspended, 1, "B is pushed into excess by A occupying the slot");
  const dataA = (await registryRef(idA).get()).data();
  const dataB = (await registryRef(idB).get()).data();
  assert.equal(dataA.status, "suspended");
  assert.equal(dataA.suspensionReason, "manual", "5/7. A's reason must stay manual, never rewritten to plan");
  assert.equal(dataB.status, "suspended");
  assert.equal(dataB.suspensionReason, "plan", "5. B becomes suspended/plan because its slot was taken by A");

  await deleteReconcileDevices([idA, idB]);
});

test("reconcileUserDeviceLimits: 2. a security-suspended device occupies a plan slot", async () => {
  const idA = "reconcile-security-slot-a";
  const idB = "reconcile-security-slot-b";
  await seedReconcileDevice(idA, "CAMERA", RECONCILE_OWNER_UID, 7100, { status: "suspended", suspensionReason: "security" });
  await seedReconcileDevice(idB, "CAMERA", RECONCILE_OWNER_UID, 7110, { status: "active" });

  const result = await reconcileUserDeviceLimits(db, RECONCILE_OWNER_UID, { maxCameras: 1, maxHomeDevices: 1 });

  assert.equal(result.camerasSuspended, 1);
  const dataA = (await registryRef(idA).get()).data();
  const dataB = (await registryRef(idB).get()).data();
  assert.equal(dataA.suspensionReason, "security", "7. A's reason must stay security, never rewritten to plan");
  assert.equal(dataB.status, "suspended");
  assert.equal(dataB.suspensionReason, "plan");

  await deleteReconcileDevices([idA, idB]);
});

test("reconcileUserDeviceLimits: 6. raising the limit activates only the suspended/plan device, never the manual-suspended slot-holder", async () => {
  // Section 4's second example: same A/B as above, limit raised 1 -> 2. A stays manual
  // (never auto-reactivated); B (now within plan) is reactivated because its reason is "plan".
  const idA = "reconcile-manual-raise-a";
  const idB = "reconcile-manual-raise-b";
  await seedReconcileDevice(idA, "CAMERA", RECONCILE_OWNER_UID, 7200, { status: "suspended", suspensionReason: "manual" });
  await seedReconcileDevice(idB, "CAMERA", RECONCILE_OWNER_UID, 7210, { status: "suspended", suspensionReason: "plan" });

  const result = await reconcileUserDeviceLimits(db, RECONCILE_OWNER_UID, { maxCameras: 2, maxHomeDevices: 1 });

  assert.equal(result.camerasReactivated, 1, "only B is reactivated");
  const dataA = (await registryRef(idA).get()).data();
  const dataB = (await registryRef(idB).get()).data();
  assert.equal(dataA.status, "suspended");
  assert.equal(dataA.suspensionReason, "manual", "A is never auto-reactivated regardless of available slots");
  assert.equal(dataB.status, "active");
  assert.equal(dataB.suspensionReason, null);

  await deleteReconcileDevices([idA, idB]);
});

test("reconcileUserDeviceLimits: 22. a device with ownerUid null is never touched or counted", async () => {
  const id = "reconcile-no-owner-1";
  await seedReconcileDevice(id, "CAMERA", RECONCILE_OWNER_UID, 6300);
  await registryRef(id).update({ ownerUid: null });

  const result = await reconcileUserDeviceLimits(db, RECONCILE_OWNER_UID, { maxCameras: 0, maxHomeDevices: 0 });

  assert.equal(result.camerasSuspended, 0);
  const data = (await registryRef(id).get()).data();
  assert.equal(data.status, "active", "ownerUid==null devices are outside any user's limit entirely");

  await deleteReconcileDevices([id]);
});

test("reconcileUserDeviceLimits: does not affect a different owner's devices", async () => {
  const mineId = "reconcile-isolation-mine";
  const theirsId = "reconcile-isolation-theirs";
  await seedReconcileDevice(mineId, "CAMERA", RECONCILE_OWNER_UID, 6400);
  await seedReconcileDevice(theirsId, "CAMERA", RECONCILE_OTHER_OWNER_UID, 6400);

  await reconcileUserDeviceLimits(db, RECONCILE_OWNER_UID, { maxCameras: 0, maxHomeDevices: 0 });

  assert.equal((await registryRef(mineId).get()).data().status, "suspended");
  assert.equal((await registryRef(theirsId).get()).data().status, "active");

  await deleteReconcileDevices([mineId, theirsId]);
});

// --- planDeviceLimitDecision: pure function --------------------------------------------------

function fakeReconcileDevice(deviceId, createdAtMillis, overrides = {}) {
  return {
    deviceId,
    status: "active",
    suspensionReason: null,
    createdAt: admin.firestore.Timestamp.fromMillis(createdAtMillis),
    ...overrides,
  };
}

test("planDeviceLimitDecision: keeps the oldest `limit` devices active, suspends the rest as plan", () => {
  const devices = [fakeReconcileDevice("c", 300), fakeReconcileDevice("a", 100), fakeReconcileDevice("b", 200)];
  const result = planDeviceLimitDecision(devices, 2);

  assert.deepEqual(result.toSuspendPlan, ["c"]);
  assert.deepEqual(result.toReactivate, []);
});

test("planDeviceLimitDecision: a limit of 0 suspends every eligible device", () => {
  const devices = [fakeReconcileDevice("a", 100), fakeReconcileDevice("b", 200)];
  const result = planDeviceLimitDecision(devices, 0);

  assert.deepEqual([...result.toSuspendPlan].sort(), ["a", "b"]);
});

test("planDeviceLimitDecision: manual/security suspended devices never appear in either output list themselves", () => {
  const devices = [
    fakeReconcileDevice("manual-1", 100, { status: "suspended", suspensionReason: "manual" }),
    fakeReconcileDevice("security-1", 200, { status: "suspended", suspensionReason: "security" }),
  ];
  const result = planDeviceLimitDecision(devices, 5);

  assert.deepEqual(result.toSuspendPlan, []);
  assert.deepEqual(result.toReactivate, []);
});

test("planDeviceLimitDecision: 1/5. a manual-suspended device still occupies a plan slot, pushing a later active device to excess", () => {
  const devices = [
    fakeReconcileDevice("manual-first", 100, { status: "suspended", suspensionReason: "manual" }),
    fakeReconcileDevice("active-second", 200, { status: "active" }),
  ];
  const result = planDeviceLimitDecision(devices, 1);

  assert.deepEqual(result.toSuspendPlan, ["active-second"], "the manual device took the only slot");
  assert.deepEqual(result.toReactivate, []);
});

test("planDeviceLimitDecision: 6/7. raising the limit reactivates only the suspended/plan device, never rewrites a manual reason", () => {
  const devices = [
    fakeReconcileDevice("manual-first", 100, { status: "suspended", suspensionReason: "manual" }),
    fakeReconcileDevice("plan-second", 200, { status: "suspended", suspensionReason: "plan" }),
  ];
  const result = planDeviceLimitDecision(devices, 2);

  assert.deepEqual(result.toReactivate, ["plan-second"]);
  assert.deepEqual(result.toSuspendPlan, [], "the manual device is not in either list -- its reason is never touched");
});

test("planDeviceLimitDecision: a device already in its correct state produces no output entry", () => {
  const devices = [fakeReconcileDevice("already-active", 100, { status: "active" })];
  const result = planDeviceLimitDecision(devices, 1);

  assert.deepEqual(result.toSuspendPlan, []);
  assert.deepEqual(result.toReactivate, []);
});
