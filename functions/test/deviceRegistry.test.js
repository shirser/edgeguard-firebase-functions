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
