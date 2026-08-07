const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

// Requiring lib/index.js runs admin.initializeApp() once; requires npm run build to have produced
// lib/ from src/ first (source of truth stays src).
const {
  createDeviceChallenge,
  registerDevicePublicKey,
  startLiveViewSession,
  renewLiveViewSession,
  endLiveViewSession,
  DEVICE_CHALLENGE_PURPOSES,
  LIVE_VIEW_LEASE_TTL_MS,
  LIVE_VIEW_ALLOCATOR_MAX_ENTRIES,
  runLiveViewTransaction,
  MAX_EMULATOR_TRANSACTION_RETRY_ATTEMPTS,
  isValidLiveViewSessionIdFormat,
  LIVE_VIEW_SESSION_ID_LENGTH,
} = require("../lib/index.js");
const admin = require("firebase-admin");

const db = admin.firestore();

// ---------------------------------------------------------------------------------------------
// Live View sessions -- stage 1 of coturn abuse protection. Server-issued, short (90s), renewable
// lease binding {ownerUid, homeDeviceId, cameraDeviceId}, enforced via startLiveViewSession/
// renewLiveViewSession/endLiveViewSession -- all three authorized by the existing HOME
// challenge/signature/device-proof mechanism (createDeviceChallenge + Keystore P-256 signature),
// never a client-asserted homeDeviceId. See docs/LIVE_VIEW_SESSIONS.md.
// ---------------------------------------------------------------------------------------------

function registryRef(deviceId) {
  return db.collection("registeredDevices").doc(deviceId);
}
function claimRef(cameraDeviceId) {
  return db.collection("cameraClaims").doc(cameraDeviceId);
}
function entitlementsRef(uid) {
  return db.collection("userEntitlements").doc(uid);
}
function homeCameraLinkRef(ownerUid, cameraDeviceId) {
  return db.collection("users").doc(ownerUid).collection("cameraDevices").doc(cameraDeviceId);
}
function sessionRef(sessionId) {
  return db.collection("liveViewSessions").doc(sessionId);
}
function allocatorRef(uid) {
  return db.collection("liveViewUserStates").doc(uid);
}
function challengeRef(challengeId) {
  return db.collection("deviceChallenges").doc(challengeId);
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
    maxCameras: 5,
    maxHomeDevices: 5,
    maxConcurrentLiveSessions: 1,
    turnAccessAllowed: true,
    source: "manual",
    validUntil: null,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

function generateEcKeyPair() {
  return crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}
function publicKeySpkiBase64(publicKey) {
  return publicKey.export({ type: "spki", format: "der" }).toString("base64");
}

// Seeds a fully keystore-provisioned HOME registeredDevices document directly (bypasses
// registerDevicePublicKey/its own maxHomeDevices enforcement -- irrelevant to this file, which is
// entirely about the session layer built on top of an already-registered Home) with the given
// keypair's public key, so a signature produced by that keypair verifies against it.
async function seedHomeDevice(homeDeviceId, ownerUid, keyPair, overrides = {}) {
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
    publicKey: publicKeySpkiBase64(keyPair.publicKey),
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    revokedAt: null,
    deviceProofVersion: null,
    ...overrides,
  });
}

async function seedCameraDevice(cameraDeviceId, cameraAuthUid, overrides = {}) {
  const now = admin.firestore.Timestamp.now();
  await registryRef(cameraDeviceId).set({
    schemaVersion: 1,
    deviceId: cameraDeviceId,
    role: "CAMERA",
    authUid: cameraAuthUid,
    ownerUid: null,
    status: "active",
    suspensionReason: null,
    identityMode: "legacy",
    publicKey: null,
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    revokedAt: null,
    deviceProofVersion: null,
    ...overrides,
  });
}

// A fresh {ownerUid, homeDeviceId, cameraDeviceId, cameraAuthUid, keyPair} scenario: a
// keystore-registered HOME, a claimed+linked CAMERA, ready to start a Live View session.
async function setupScenario(overrides = {}) {
  const ownerUid = overrides.ownerUid ?? uniqueId("lvs-owner");
  const homeDeviceId = overrides.homeDeviceId ?? uniqueId("lvs-home");
  const cameraDeviceId = overrides.cameraDeviceId ?? uniqueId("lvs-camera");
  const cameraAuthUid = overrides.cameraAuthUid ?? uniqueId("lvs-camera-auth");
  const keyPair = overrides.keyPair ?? generateEcKeyPair();

  await seedHomeDevice(homeDeviceId, ownerUid, keyPair, overrides.homeOverrides ?? {});

  if (!overrides.skipCamera) {
    const now = admin.firestore.Timestamp.now();
    await seedCameraDevice(cameraDeviceId, cameraAuthUid, overrides.cameraOverrides ?? {});
    await claimRef(cameraDeviceId).set({
      uid: overrides.claimOwnerUid ?? ownerUid,
      cameraAuthUid,
      claimedAt: now,
    });
    await homeCameraLinkRef(overrides.claimOwnerUid ?? ownerUid, cameraDeviceId).set({
      cameraDeviceId,
      homeDeviceId: overrides.linkedHomeDeviceId ?? homeDeviceId,
      pairedAt: now,
      status: "active",
    });
  }

  return { ownerUid, homeDeviceId, cameraDeviceId, cameraAuthUid, keyPair };
}

async function cleanupScenario(scenario, extraSessionIds = [], extraHomeDeviceIds = []) {
  await Promise.all([
    registryRef(scenario.homeDeviceId).delete(),
    registryRef(scenario.cameraDeviceId).delete(),
    claimRef(scenario.cameraDeviceId).delete(),
    homeCameraLinkRef(scenario.ownerUid, scenario.cameraDeviceId).delete(),
    entitlementsRef(scenario.ownerUid).delete(),
    allocatorRef(scenario.ownerUid).delete(),
    ...extraSessionIds.map((id) => sessionRef(id).delete()),
    ...extraHomeDeviceIds.map((id) => registryRef(id).delete()),
  ]);
}

// Requests a fresh, signed device-proof envelope for one specific purpose/requestPayload, ready to
// pass as `deviceProof` to startLiveViewSession/renewLiveViewSession/endLiveViewSession. Each call
// consumes a brand-new challenge (single-use), matching real client behavior of requesting one
// challenge per operation attempt.
async function signChallenge(scenario, purpose, requestPayload) {
  const challengeResp = await createDeviceChallenge.run(
    fakeRequest({ deviceId: scenario.homeDeviceId, purpose, requestPayload }, scenario.ownerUid)
  );
  const signature = crypto
    .sign("sha256", Buffer.from(challengeResp.canonicalPayload, "utf8"), scenario.keyPair.privateKey)
    .toString("base64");
  return {
    deviceProof: { protocolVersion: 1, challengeId: challengeResp.challengeId, signature },
    challengeId: challengeResp.challengeId,
  };
}

async function attemptStart(scenario, cameraDeviceId = scenario.cameraDeviceId) {
  const { deviceProof } = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, { cameraDeviceId });
  return startLiveViewSession.run(fakeRequest({ cameraDeviceId, deviceProof }, scenario.ownerUid));
}

async function attemptRenew(scenario, sessionId) {
  const { deviceProof } = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_RENEW, { sessionId });
  return renewLiveViewSession.run(fakeRequest({ sessionId, deviceProof }, scenario.ownerUid));
}

async function attemptEnd(scenario, sessionId) {
  const { deviceProof } = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_END, { sessionId });
  return endLiveViewSession.run(fakeRequest({ sessionId, deviceProof }, scenario.ownerUid));
}

// The ONLY rejection ever tolerated as "a legitimate retry-me signal, not a correctness bug"
// anywhere in this file's concurrency tests: gRPC code 10 (ABORTED) -- Firestore's own documented,
// canonical status for a transaction that lost repeated write contention and exhausted the Admin
// SDK's own bounded retry budget. Never accepted as "any rejection is fine", never confused with
// internal/permission-denied/not-found/unknown.
//
// A gRPC code 3 (INVALID_ARGUMENT) rejection with message "Transaction is invalid or closed" was
// observed intermittently (roughly 1 in 5-6 runs) when running the FULL multi-file test suite
// (`npm run test:functions`, ~9 files, ~470 tests, sustained emulator load over ~150s) -- but NEVER
// once in two separate, standalone, project-code-free reproduction attempts against a freshly
// started emulator: (1) 16 parallel transactions racing on one shared document, each doing 3
// parallel reads + real P-256 sign/verify work, across 40+ attempts; (2) a repro exactly
// shape-matched to executeStartLiveViewSession vs. executeEndLiveViewSession's own read/write
// pattern (a 6-read START-like transaction racing a 2-read END-like transaction on a shared
// document), across 60 trials. A full audit of every `db.runTransaction` callback in
// deviceChallenges.ts/liveViewSessions.ts also found no un-awaited async work and no case of a
// transaction reference (`t`) ever being stored or used outside its own callback. Since the cause of
// the code-3 rejection could not be confirmed as legitimate contention (as opposed to some other,
// unexplained condition), it is deliberately NOT tolerated here: if it recurs, this function returns
// false for it and the calling assertion FAILS, surfacing it rather than silently accepting it.
function isRetryExhaustionError(err) {
  return err && err.code === 10;
}

// Full Firestore-state invariant check for one owner -- used after every concurrency scenario to
// verify the FINAL state, regardless of which racing operation actually won. See requirement 8:
// every allocator entry must have exactly one matching canonical ACTIVE session; every allocator
// ACTIVE session must be unexpired; every ENDED session must be absent from the allocator; there
// must be no orphan allocator entries and no orphan ACTIVE session docs (an ACTIVE, unexpired
// session for this owner that the allocator does not know about).
async function assertConsistentState(ownerUid, nowMillis = Date.now()) {
  const allocatorSnap = await allocatorRef(ownerUid).get();
  const active = allocatorSnap.exists ? allocatorSnap.data().activeSessions || {} : {};
  const sessionsSnap = await db.collection("liveViewSessions").where("ownerUid", "==", ownerUid).get();
  const sessionsById = new Map(sessionsSnap.docs.map((d) => [d.id, d.data()]));

  for (const [sessionId, entry] of Object.entries(active)) {
    const session = sessionsById.get(sessionId);
    assert.ok(session, `allocator entry ${sessionId} must reference an existing session document`);
    assert.equal(session.status, "ACTIVE", `allocator entry ${sessionId} must reference an ACTIVE session`);
    assert.equal(session.endedAt, null);
    assert.equal(entry.homeDeviceId, session.homeDeviceId);
    assert.equal(entry.cameraDeviceId, session.cameraDeviceId);
    assert.ok(
      session.leaseExpiresAt.toMillis() > nowMillis,
      `allocator entry ${sessionId} must reference an unexpired session`
    );
  }

  for (const [sessionId, session] of sessionsById) {
    if (session.status === "ENDED") {
      assert.ok(!(sessionId in active), `an ENDED session (${sessionId}) must never remain in the allocator`);
    } else if (session.leaseExpiresAt.toMillis() > nowMillis) {
      assert.ok(
        sessionId in active,
        `an ACTIVE, unexpired session (${sessionId}) must never be orphaned (absent from the allocator)`
      );
    }
  }
}

// =================================================================================================
// A. START -- basic
// =================================================================================================

test("START 1: a new session starts successfully and is reflected in both liveViewSessions and the allocator", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1 }));

  const response = await attemptStart(scenario);
  assert.ok(response.sessionId);
  assert.equal(response.leaseDurationMs, LIVE_VIEW_LEASE_TTL_MS);
  assert.ok(response.leaseExpiresAt > Date.now());
  assert.ok(response.leaseExpiresAt <= Date.now() + LIVE_VIEW_LEASE_TTL_MS + 5000);

  const sessionSnap = await sessionRef(response.sessionId).get();
  const session = sessionSnap.data();
  assert.equal(session.sessionId, response.sessionId);
  assert.equal(session.ownerUid, scenario.ownerUid);
  assert.equal(session.homeDeviceId, scenario.homeDeviceId);
  assert.equal(session.cameraDeviceId, scenario.cameraDeviceId);
  assert.equal(session.status, "ACTIVE");
  assert.equal(session.endedAt, null);
  assert.ok(session.createdAt);
  assert.ok(session.leaseExpiresAt);

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  const allocator = allocatorSnap.data();
  assert.equal(Object.keys(allocator.activeSessions).length, 1);
  assert.equal(allocator.activeSessions[response.sessionId].homeDeviceId, scenario.homeDeviceId);
  assert.equal(allocator.activeSessions[response.sessionId].cameraDeviceId, scenario.cameraDeviceId);

  await cleanupScenario(scenario, [response.sessionId]);
});

test("START 2: at the entitlement limit, a new (different camera) START is rejected with a distinguishable reason", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1 }));
  const first = await attemptStart(scenario);

  const secondCameraId = uniqueId("lvs-second-camera");
  const secondCameraAuthUid = uniqueId("lvs-second-camera-auth");
  const now = admin.firestore.Timestamp.now();
  await seedCameraDevice(secondCameraId, secondCameraAuthUid);
  await claimRef(secondCameraId).set({ uid: scenario.ownerUid, cameraAuthUid: secondCameraAuthUid, claimedAt: now });
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).set({
    cameraDeviceId: secondCameraId,
    homeDeviceId: scenario.homeDeviceId,
    pairedAt: now,
    status: "active",
  });

  await assert.rejects(
    attemptStart(scenario, secondCameraId),
    (err) => err.code === "resource-exhausted" && err.message === "LIVE_VIEW_SESSION_LIMIT_REACHED"
  );

  await registryRef(secondCameraId).delete();
  await claimRef(secondCameraId).delete();
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).delete();
  await cleanupScenario(scenario, [first.sessionId]);
});

test("START 25: entitlement limit 1 -- second distinct pair rejected, first still succeeded", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1 }));
  const response = await attemptStart(scenario);
  assert.ok(response.sessionId);

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  assert.equal(Object.keys(allocatorSnap.data().activeSessions).length, 1);

  await cleanupScenario(scenario, [response.sessionId]);
});

test("START 26: entitlement limit greater than 1 allows that many distinct concurrent sessions", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 2 }));
  const first = await attemptStart(scenario);

  const secondCameraId = uniqueId("lvs-limit2-camera");
  const secondCameraAuthUid = uniqueId("lvs-limit2-camera-auth");
  const now = admin.firestore.Timestamp.now();
  await seedCameraDevice(secondCameraId, secondCameraAuthUid);
  await claimRef(secondCameraId).set({ uid: scenario.ownerUid, cameraAuthUid: secondCameraAuthUid, claimedAt: now });
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).set({
    cameraDeviceId: secondCameraId,
    homeDeviceId: scenario.homeDeviceId,
    pairedAt: now,
    status: "active",
  });

  const second = await attemptStart(scenario, secondCameraId);
  assert.notEqual(second.sessionId, first.sessionId);

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  assert.equal(Object.keys(allocatorSnap.data().activeSessions).length, 2);

  await registryRef(secondCameraId).delete();
  await claimRef(secondCameraId).delete();
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).delete();
  await cleanupScenario(scenario, [first.sessionId, second.sessionId]);
});

test("START 27: a missing/malformed entitlement document uses the existing Free fallback (maxConcurrentLiveSessions=1)", async () => {
  const scenario = await setupScenario();
  // No userEntitlements document at all.
  const first = await attemptStart(scenario);
  assert.ok(first.sessionId);

  const secondCameraId = uniqueId("lvs-free-camera");
  const secondCameraAuthUid = uniqueId("lvs-free-camera-auth");
  const now = admin.firestore.Timestamp.now();
  await seedCameraDevice(secondCameraId, secondCameraAuthUid);
  await claimRef(secondCameraId).set({ uid: scenario.ownerUid, cameraAuthUid: secondCameraAuthUid, claimedAt: now });
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).set({
    cameraDeviceId: secondCameraId,
    homeDeviceId: scenario.homeDeviceId,
    pairedAt: now,
    status: "active",
  });

  await assert.rejects(
    attemptStart(scenario, secondCameraId),
    (err) => err.code === "resource-exhausted" && err.message === "LIVE_VIEW_SESSION_LIMIT_REACHED"
  );

  // Malformed entitlement document (bad schemaVersion) -- also falls back to Free, never a crash,
  // never a legacy-field fallback.
  await entitlementsRef(scenario.ownerUid).set({ schemaVersion: 999, garbage: true });
  await assert.rejects(
    attemptStart(scenario, secondCameraId),
    (err) => err.code === "resource-exhausted" && err.message === "LIVE_VIEW_SESSION_LIMIT_REACHED"
  );

  await registryRef(secondCameraId).delete();
  await claimRef(secondCameraId).delete();
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).delete();
  await cleanupScenario(scenario, [first.sessionId]);
});

// =================================================================================================
// B. START -- identity/ownership/binding denials (generic, non-oracle)
// =================================================================================================

test("START 16: a wrong (different keypair) signature is rejected generically", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());

  const challengeResp = await createDeviceChallenge.run(
    fakeRequest(
      { deviceId: scenario.homeDeviceId, purpose: DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, requestPayload: { cameraDeviceId: scenario.cameraDeviceId } },
      scenario.ownerUid
    )
  );
  const wrongKeyPair = generateEcKeyPair();
  const badSignature = crypto.sign("sha256", Buffer.from(challengeResp.canonicalPayload, "utf8"), wrongKeyPair.privateKey).toString("base64");

  await assert.rejects(
    startLiveViewSession.run(
      fakeRequest(
        {
          cameraDeviceId: scenario.cameraDeviceId,
          deviceProof: { protocolVersion: 1, challengeId: challengeResp.challengeId, signature: badSignature },
        },
        scenario.ownerUid
      )
    ),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  const challengeSnap = await challengeRef(challengeResp.challengeId).get();
  assert.equal(challengeSnap.get("usedAt"), null, "a rejected operation must not consume the challenge");

  await cleanupScenario(scenario);
});

test("START 17: a HOME belonging to a different account cannot start a session for someone else's camera", async () => {
  const scenarioA = await setupScenario();
  await entitlementsRef(scenarioA.ownerUid).set(validEntitlements());

  const scenarioB = await setupScenario({ skipCamera: true });
  await entitlementsRef(scenarioB.ownerUid).set(validEntitlements());

  // scenarioB's own Home attempts to start a session for scenarioA's camera.
  const { deviceProof } = await signChallenge(scenarioB, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, {
    cameraDeviceId: scenarioA.cameraDeviceId,
  });
  await assert.rejects(
    startLiveViewSession.run(fakeRequest({ cameraDeviceId: scenarioA.cameraDeviceId, deviceProof }, scenarioB.ownerUid)),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  await cleanupScenario(scenarioA);
  await cleanupScenario(scenarioB);
});

test("START 18: a Camera claimed by a different owner cannot be started", async () => {
  const scenario = await setupScenario({ skipCamera: true });
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());

  const otherOwnerUid = uniqueId("lvs-other-owner");
  const cameraDeviceId = uniqueId("lvs-otherowner-camera");
  const cameraAuthUid = uniqueId("lvs-otherowner-camera-auth");
  const now = admin.firestore.Timestamp.now();
  await seedCameraDevice(cameraDeviceId, cameraAuthUid);
  await claimRef(cameraDeviceId).set({ uid: otherOwnerUid, cameraAuthUid, claimedAt: now });
  await homeCameraLinkRef(otherOwnerUid, cameraDeviceId).set({ cameraDeviceId, homeDeviceId: "irrelevant-home", pairedAt: now, status: "active" });

  await assert.rejects(
    attemptStart(scenario, cameraDeviceId),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  await registryRef(cameraDeviceId).delete();
  await claimRef(cameraDeviceId).delete();
  await homeCameraLinkRef(otherOwnerUid, cameraDeviceId).delete();
  await cleanupScenario(scenario);
});

test("START 19: a Camera linked to a DIFFERENT Home (same owner) cannot be started by this Home", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());

  // A second Home device, registered to the SAME owner, but never linked to this camera.
  const secondHomeId = uniqueId("lvs-second-home");
  const secondKeyPair = generateEcKeyPair();
  await seedHomeDevice(secondHomeId, scenario.ownerUid, secondKeyPair);
  const secondHomeScenario = { ...scenario, homeDeviceId: secondHomeId, keyPair: secondKeyPair };

  await assert.rejects(
    attemptStart(secondHomeScenario, scenario.cameraDeviceId),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  await registryRef(secondHomeId).delete();
  await cleanupScenario(scenario);
});

test("START 20a: createDeviceChallenge itself already refuses to issue a LIVE_VIEW_START challenge to a suspended/revoked Home", async () => {
  const suspended = await setupScenario({ homeOverrides: { status: "suspended", suspensionReason: "manual" } });
  await entitlementsRef(suspended.ownerUid).set(validEntitlements());
  await assert.rejects(
    createDeviceChallenge.run(
      fakeRequest(
        { deviceId: suspended.homeDeviceId, purpose: DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, requestPayload: { cameraDeviceId: suspended.cameraDeviceId } },
        suspended.ownerUid
      )
    ),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_SUSPENDED"
  );
  await cleanupScenario(suspended);
});

test("START 20b: TOCTOU -- a Home suspended/revoked AFTER its challenge was already issued still cannot start (session-layer check catches it too)", async () => {
  const suspended = await setupScenario();
  await entitlementsRef(suspended.ownerUid).set(validEntitlements());
  const signed = await signChallenge(suspended, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, { cameraDeviceId: suspended.cameraDeviceId });
  await registryRef(suspended.homeDeviceId).update({ status: "suspended", suspensionReason: "manual" });

  await assert.rejects(
    startLiveViewSession.run(fakeRequest({ cameraDeviceId: suspended.cameraDeviceId, deviceProof: signed.deviceProof }, suspended.ownerUid)),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_SUSPENDED"
  );

  await cleanupScenario(suspended);
});

test("START 21: a suspended/revoked Camera (already confirmed owned+linked) cannot be started -- distinguishable reason is safe here too", async () => {
  const suspended = await setupScenario({ cameraOverrides: { status: "suspended", suspensionReason: "security" } });
  await entitlementsRef(suspended.ownerUid).set(validEntitlements());
  await assert.rejects(
    attemptStart(suspended),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_SUSPENDED"
  );
  await cleanupScenario(suspended);

  const revoked = await setupScenario({ cameraOverrides: { status: "revoked", revokedAt: admin.firestore.Timestamp.now() } });
  await entitlementsRef(revoked.ownerUid).set(validEntitlements());
  await assert.rejects(
    attemptStart(revoked),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_REVOKED"
  );
  await cleanupScenario(revoked);
});

test("START 14/15: client-supplied timestamps and homeDeviceId are rejected outright (unexpected request fields)", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());

  const { deviceProof } = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, {
    cameraDeviceId: scenario.cameraDeviceId,
  });

  await assert.rejects(
    startLiveViewSession.run(
      fakeRequest({ cameraDeviceId: scenario.cameraDeviceId, deviceProof, leaseExpiresAt: Date.now() + 999999999 }, scenario.ownerUid)
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_REQUEST"
  );

  await assert.rejects(
    startLiveViewSession.run(
      fakeRequest({ cameraDeviceId: scenario.cameraDeviceId, deviceProof, homeDeviceId: "attacker-supplied-home" }, scenario.ownerUid)
    ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_REQUEST"
  );

  await cleanupScenario(scenario);
});

// =================================================================================================
// C. Idempotent START
// =================================================================================================

test("START 8: a repeated START of the same (Home, Camera) pair is idempotent -- same sessionId, no second slot", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1 }));

  const first = await attemptStart(scenario);
  const second = await attemptStart(scenario);

  assert.equal(second.sessionId, first.sessionId);

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  assert.equal(Object.keys(allocatorSnap.data().activeSessions).length, 1);

  await cleanupScenario(scenario, [first.sessionId]);
});

// =================================================================================================
// K. Strict allocator-entry <-> canonical-session consistency (validateAllocatorEntryAgainstSession)
// =================================================================================================
// Every one of these corrupts exactly ONE field so that the allocator's cached entry and the
// canonical liveViewSessions document disagree, while everything else stays legitimate -- proving
// validateAllocatorEntryAgainstSession (and the strict session parser it depends on) is actually
// consulted field-by-field, not just "does a document exist with status ACTIVE and a future lease".
// Any mismatch must fail closed with a generic denial (never a duplicate slot, never a silent
// renewal) -- see docs/LIVE_VIEW_SESSIONS.md.

test("MISMATCH: an allocator entry whose pair resolves to a session with a DIFFERENT ownerUid is denied (idempotent START)", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1 }));
  const started = await attemptStart(scenario);

  // Corrupt the canonical session's ownerUid directly -- the allocator's own entry (looked up under
  // this exact owner's allocator document) is untouched, so idempotent START finds it purely via
  // (homeDeviceId, cameraDeviceId) and only then discovers the session itself disagrees on owner.
  await sessionRef(started.sessionId).update({ ownerUid: uniqueId("lvs-hijack-owner") });

  await assert.rejects(
    attemptStart(scenario),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  assert.equal(Object.keys(allocatorSnap.data().activeSessions).length, 1, "no second slot must ever be granted");

  await cleanupScenario(scenario, [started.sessionId]);
});

test("MISMATCH: an allocator entry with a DIFFERENT homeDeviceId than its session is denied (RENEW)", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  await allocatorRef(scenario.ownerUid).update({
    [`activeSessions.${started.sessionId}.homeDeviceId`]: uniqueId("lvs-hijack-home"),
  });

  await assert.rejects(
    attemptRenew(scenario, started.sessionId),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  const sessionSnap = await sessionRef(started.sessionId).get();
  assert.equal(sessionSnap.get("leaseExpiresAt").toMillis(), started.leaseExpiresAt, "must not be renewed");

  await cleanupScenario(scenario, [started.sessionId]);
});

test("MISMATCH: an allocator entry with a DIFFERENT cameraDeviceId than its session is denied (RENEW)", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  await allocatorRef(scenario.ownerUid).update({
    [`activeSessions.${started.sessionId}.cameraDeviceId`]: uniqueId("lvs-hijack-camera"),
  });

  await assert.rejects(
    attemptRenew(scenario, started.sessionId),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  const sessionSnap = await sessionRef(started.sessionId).get();
  assert.equal(sessionSnap.get("leaseExpiresAt").toMillis(), started.leaseExpiresAt, "must not be renewed");

  await cleanupScenario(scenario, [started.sessionId]);
});

test("MISMATCH: an allocator entry with a DIFFERENT createdAt than its session is denied (RENEW)", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  await allocatorRef(scenario.ownerUid).update({
    [`activeSessions.${started.sessionId}.createdAt`]: admin.firestore.Timestamp.fromMillis(Date.now() - 999999),
  });

  await assert.rejects(
    attemptRenew(scenario, started.sessionId),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  const sessionSnap = await sessionRef(started.sessionId).get();
  assert.equal(sessionSnap.get("leaseExpiresAt").toMillis(), started.leaseExpiresAt, "must not be renewed");

  await cleanupScenario(scenario, [started.sessionId]);
});

test("MISMATCH: an allocator entry with a DIFFERENT (but still unexpired) leaseExpiresAt than its session is denied (RENEW)", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  await allocatorRef(scenario.ownerUid).update({
    [`activeSessions.${started.sessionId}.leaseExpiresAt`]: admin.firestore.Timestamp.fromMillis(Date.now() + LIVE_VIEW_LEASE_TTL_MS + 30000),
  });

  await assert.rejects(
    attemptRenew(scenario, started.sessionId),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  const sessionSnap = await sessionRef(started.sessionId).get();
  assert.equal(sessionSnap.get("leaseExpiresAt").toMillis(), started.leaseExpiresAt, "must not be renewed");

  await cleanupScenario(scenario, [started.sessionId]);
});

test("MISMATCH: a session with the wrong schemaVersion is treated as malformed and denies RENEW (fail closed, no state change)", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  await sessionRef(started.sessionId).update({ schemaVersion: 999 });

  await assert.rejects(
    attemptRenew(scenario, started.sessionId),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  assert.equal(
    allocatorSnap.data().activeSessions[started.sessionId].leaseExpiresAt.toMillis(),
    started.leaseExpiresAt,
    "the allocator's own copy must not be renewed off the back of a malformed session"
  );

  await sessionRef(started.sessionId).update({ schemaVersion: 1 });
  await cleanupScenario(scenario, [started.sessionId]);
});

test("MISMATCH: a session whose status is ENDED but still referenced ACTIVE by the allocator is denied (RENEW)", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  // Directly end the session doc WITHOUT going through executeEndLiveViewSession, so the
  // allocator's own entry is deliberately left stale (still claims ACTIVE) -- exactly the kind of
  // drift validateAllocatorEntryAgainstSession/the direct session-status check must catch.
  await sessionRef(started.sessionId).update({ status: "ENDED", endedAt: admin.firestore.Timestamp.now() });

  await assert.rejects(
    attemptRenew(scenario, started.sessionId),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  const sessionSnap = await sessionRef(started.sessionId).get();
  assert.equal(sessionSnap.get("status"), "ENDED", "must remain ENDED, never silently reactivated");

  await cleanupScenario(scenario, [started.sessionId]);
});

test("MISMATCH: an ACTIVE session with a corrupt non-null endedAt is treated as malformed and denies RENEW", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  // status stays "ACTIVE" but endedAt is (illegally) a Timestamp -- parseLiveViewSession must
  // reject this combination outright rather than accept a partially-valid session.
  await sessionRef(started.sessionId).update({ endedAt: admin.firestore.Timestamp.now() });

  await assert.rejects(
    attemptRenew(scenario, started.sessionId),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  assert.equal(
    allocatorSnap.data().activeSessions[started.sessionId].leaseExpiresAt.toMillis(),
    started.leaseExpiresAt,
    "must not be renewed off the back of a malformed session"
  );

  await sessionRef(started.sessionId).update({ endedAt: null });
  await cleanupScenario(scenario, [started.sessionId]);
});

// =================================================================================================
// D. RENEW
// =================================================================================================

test("RENEW basic: a valid renew extends leaseExpiresAt and is reflected in the allocator", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  await new Promise((resolve) => setTimeout(resolve, 5));
  const renewed = await attemptRenew(scenario, started.sessionId);

  assert.equal(renewed.sessionId, started.sessionId);
  assert.ok(renewed.leaseExpiresAt >= started.leaseExpiresAt);

  const sessionSnap = await sessionRef(started.sessionId).get();
  assert.equal(sessionSnap.get("leaseExpiresAt").toMillis(), renewed.leaseExpiresAt);

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  assert.equal(allocatorSnap.data().activeSessions[started.sessionId].leaseExpiresAt.toMillis(), renewed.leaseExpiresAt);

  await cleanupScenario(scenario, [started.sessionId]);
});

test("RENEW: does not accumulate -- always resets from now(), never extends the old leaseExpiresAt", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  // Artificially push the stored lease far into the future to prove renew does NOT add to it.
  const farFuture = admin.firestore.Timestamp.fromMillis(Date.now() + 10 * LIVE_VIEW_LEASE_TTL_MS);
  await sessionRef(started.sessionId).update({ leaseExpiresAt: farFuture });
  await allocatorRef(scenario.ownerUid).update({
    [`activeSessions.${started.sessionId}.leaseExpiresAt`]: farFuture,
  });

  const renewed = await attemptRenew(scenario, started.sessionId);
  assert.ok(renewed.leaseExpiresAt < farFuture.toMillis(), "renew must reset from now(), never extend the prior value");
  assert.ok(renewed.leaseExpiresAt <= Date.now() + LIVE_VIEW_LEASE_TTL_MS + 5000);

  await cleanupScenario(scenario, [started.sessionId]);
});

test("RENEW 22: an expired session cannot be renewed", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  const past = admin.firestore.Timestamp.fromMillis(Date.now() - 1000);
  await sessionRef(started.sessionId).update({ leaseExpiresAt: past });

  await assert.rejects(
    attemptRenew(scenario, started.sessionId),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  await cleanupScenario(scenario, [started.sessionId]);
});

test("RENEW 23: an ended session cannot be renewed", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);
  await attemptEnd(scenario, started.sessionId);

  await assert.rejects(
    attemptRenew(scenario, started.sessionId),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  await cleanupScenario(scenario, [started.sessionId]);
});

test("RENEW: a missing session cannot be renewed", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());

  // A syntactically-valid (Firestore-auto-id-shaped) but never-created sessionId.
  const neverStartedSessionId = db.collection("liveViewSessions").doc().id;
  await assert.rejects(
    attemptRenew(scenario, neverStartedSessionId),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  await cleanupScenario(scenario);
});

test("RENEW 12: a session absent from the allocator (but present as ACTIVE in liveViewSessions) cannot be renewed", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  // Simulate an allocator entry that was lost/never written -- fail closed. A genuinely HEALTHY,
  // just-empty allocator (not a corrupt one) so this isolates SESSION_NOT_IN_ALLOCATOR specifically.
  await allocatorRef(scenario.ownerUid).set({
    schemaVersion: 1,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    integrityStatus: "HEALTHY",
    corruptAt: null,
    corruptionReason: null,
    activeSessions: {},
  });

  await assert.rejects(
    attemptRenew(scenario, started.sessionId),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  await cleanupScenario(scenario, [started.sessionId]);
});

test("RENEW: still requires the Camera to be operational, owned by caller, and linked to this Home", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  await registryRef(scenario.cameraDeviceId).update({ status: "suspended", suspensionReason: "manual" });

  await assert.rejects(
    attemptRenew(scenario, started.sessionId),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_SUSPENDED"
  );

  await cleanupScenario(scenario, [started.sessionId]);
});

test("RENEW: createDeviceChallenge already refuses a LIVE_VIEW_RENEW challenge for a suspended/revoked Home", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);
  await registryRef(scenario.homeDeviceId).update({ status: "suspended", suspensionReason: "manual" });

  await assert.rejects(
    createDeviceChallenge.run(
      fakeRequest(
        { deviceId: scenario.homeDeviceId, purpose: DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_RENEW, requestPayload: { sessionId: started.sessionId } },
        scenario.ownerUid
      )
    ),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_SUSPENDED"
  );

  await cleanupScenario(scenario, [started.sessionId]);
});

test("RENEW: TOCTOU -- a Home suspended AFTER its renew challenge was issued still cannot renew (unlike END)", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);
  const signed = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_RENEW, { sessionId: started.sessionId });
  await registryRef(scenario.homeDeviceId).update({ status: "suspended", suspensionReason: "manual" });

  await assert.rejects(
    renewLiveViewSession.run(fakeRequest({ sessionId: started.sessionId, deviceProof: signed.deviceProof }, scenario.ownerUid)),
    (err) => err.code === "permission-denied" && err.message === "DEVICE_SUSPENDED"
  );

  await cleanupScenario(scenario, [started.sessionId]);
});

// =================================================================================================
// M. RENEW -- canonical entitlement re-check, inside the same transaction as the renewal itself.
// =================================================================================================
// Resolved via effectiveUserEntitlementsFromData -- the same canonical resolver every other
// consumer uses, never the legacy users/{uid}.subscriptionUnits field -- and denies renewal
// whenever the account's CURRENT limit can no longer accommodate the number of sessions presently
// occupying a slot (this one included), not merely "this one session's own rank". See
// docs/LIVE_VIEW_SESSIONS.md's "RENEW entitlement behavior" section.

test("RENEW ENTITLEMENT: maxConcurrentLiveSessions === 0 denies renewal of an otherwise-valid, lone active session", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1 }));
  const started = await attemptStart(scenario);

  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 0 }));

  await assert.rejects(
    attemptRenew(scenario, started.sessionId),
    (err) => err.code === "resource-exhausted" && err.message === "LIVE_VIEW_ENTITLEMENT_DENIED"
  );

  const sessionSnap = await sessionRef(started.sessionId).get();
  assert.equal(sessionSnap.get("leaseExpiresAt").toMillis(), started.leaseExpiresAt, "must not be renewed");

  await cleanupScenario(scenario, [started.sessionId]);
});

test("RENEW ENTITLEMENT: a blocked subscription (zeroed rights) denies renewal", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 3 }));
  const started = await attemptStart(scenario);

  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ subscriptionStatus: "blocked", maxConcurrentLiveSessions: 3 }));

  await assert.rejects(
    attemptRenew(scenario, started.sessionId),
    (err) => err.code === "resource-exhausted" && err.message === "LIVE_VIEW_ENTITLEMENT_DENIED"
  );

  await cleanupScenario(scenario, [started.sessionId]);
});

test("RENEW ENTITLEMENT: an expired entitlement falls back to Free and denies renewal once the account is over Free's limit", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 3 }));
  const first = await attemptStart(scenario);

  const secondCameraId = uniqueId("lvs-renew-ent-camera");
  const secondCameraAuthUid = uniqueId("lvs-renew-ent-camera-auth");
  const now = admin.firestore.Timestamp.now();
  await seedCameraDevice(secondCameraId, secondCameraAuthUid);
  await claimRef(secondCameraId).set({ uid: scenario.ownerUid, cameraAuthUid: secondCameraAuthUid, claimedAt: now });
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).set({
    cameraDeviceId: secondCameraId,
    homeDeviceId: scenario.homeDeviceId,
    pairedAt: now,
    status: "active",
  });
  const second = await attemptStart(scenario, secondCameraId);

  // Free's own default is maxConcurrentLiveSessions=1 -- two already-active sessions now exceed it.
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ subscriptionStatus: "expired", maxConcurrentLiveSessions: 3 }));

  await assert.rejects(
    attemptRenew(scenario, first.sessionId),
    (err) => err.code === "resource-exhausted" && err.message === "LIVE_VIEW_ENTITLEMENT_DENIED"
  );
  await assert.rejects(
    attemptRenew(scenario, second.sessionId),
    (err) => err.code === "resource-exhausted" && err.message === "LIVE_VIEW_ENTITLEMENT_DENIED",
    "the downgrade denies renewal of ALL over-limit sessions equally, not just one 'loser'"
  );

  await registryRef(secondCameraId).delete();
  await claimRef(secondCameraId).delete();
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).delete();
  await cleanupScenario(scenario, [first.sessionId, second.sessionId]);
});

test("RENEW ENTITLEMENT: a malformed entitlement document falls back to Free and denies renewal once over Free's limit", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 3 }));
  const first = await attemptStart(scenario);

  const secondCameraId = uniqueId("lvs-renew-malformed-camera");
  const secondCameraAuthUid = uniqueId("lvs-renew-malformed-camera-auth");
  const now = admin.firestore.Timestamp.now();
  await seedCameraDevice(secondCameraId, secondCameraAuthUid);
  await claimRef(secondCameraId).set({ uid: scenario.ownerUid, cameraAuthUid: secondCameraAuthUid, claimedAt: now });
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).set({
    cameraDeviceId: secondCameraId,
    homeDeviceId: scenario.homeDeviceId,
    pairedAt: now,
    status: "active",
  });
  const second = await attemptStart(scenario, secondCameraId);

  await entitlementsRef(scenario.ownerUid).set({ schemaVersion: 999, garbage: true });

  await assert.rejects(
    attemptRenew(scenario, first.sessionId),
    (err) => err.code === "resource-exhausted" && err.message === "LIVE_VIEW_ENTITLEMENT_DENIED"
  );

  await registryRef(secondCameraId).delete();
  await claimRef(secondCameraId).delete();
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).delete();
  await cleanupScenario(scenario, [first.sessionId, second.sessionId]);
});

test("RENEW ENTITLEMENT: a missing entitlement document uses the safe Free fallback (maxConcurrentLiveSessions=1) and allows renewal within it", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1 }));
  const started = await attemptStart(scenario);
  await entitlementsRef(scenario.ownerUid).delete();

  const renewed = await attemptRenew(scenario, started.sessionId);
  assert.equal(renewed.sessionId, started.sessionId);

  await cleanupScenario(scenario, [started.sessionId]);
});

test("RENEW ENTITLEMENT: a downgrade below the current active-session count denies renewal of the over-limit sessions", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 2 }));
  const first = await attemptStart(scenario);

  const secondCameraId = uniqueId("lvs-renew-downgrade-camera");
  const secondCameraAuthUid = uniqueId("lvs-renew-downgrade-camera-auth");
  const now = admin.firestore.Timestamp.now();
  await seedCameraDevice(secondCameraId, secondCameraAuthUid);
  await claimRef(secondCameraId).set({ uid: scenario.ownerUid, cameraAuthUid: secondCameraAuthUid, claimedAt: now });
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).set({
    cameraDeviceId: secondCameraId,
    homeDeviceId: scenario.homeDeviceId,
    pairedAt: now,
    status: "active",
  });
  const second = await attemptStart(scenario, secondCameraId);

  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1 }));

  await assert.rejects(
    attemptRenew(scenario, first.sessionId),
    (err) => err.code === "resource-exhausted" && err.message === "LIVE_VIEW_ENTITLEMENT_DENIED"
  );

  // Both sessions must remain ACTIVE and end-able -- a downgrade denies RENEWAL, never forcibly
  // ends an existing session outright.
  const firstSessionSnap = await sessionRef(first.sessionId).get();
  assert.equal(firstSessionSnap.get("status"), "ACTIVE");
  const endResponse = await attemptEnd(scenario, first.sessionId);
  assert.deepEqual(endResponse, { sessionId: first.sessionId, success: true });

  await registryRef(secondCameraId).delete();
  await claimRef(secondCameraId).delete();
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).delete();
  await cleanupScenario(scenario, [first.sessionId, second.sessionId]);
});

// =================================================================================================
// E. END
// =================================================================================================

test("END basic: a valid end sets status ENDED, removes the allocator entry, and consumes the challenge", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  const { deviceProof, challengeId } = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_END, {
    sessionId: started.sessionId,
  });
  const response = await endLiveViewSession.run(fakeRequest({ sessionId: started.sessionId, deviceProof }, scenario.ownerUid));
  assert.deepEqual(response, { sessionId: started.sessionId, success: true });

  const sessionSnap = await sessionRef(started.sessionId).get();
  assert.equal(sessionSnap.get("status"), "ENDED");
  assert.ok(sessionSnap.get("endedAt"));

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  assert.equal(Object.keys(allocatorSnap.data().activeSessions).length, 0);

  const challengeSnap = await challengeRef(challengeId).get();
  assert.ok(challengeSnap.get("usedAt"), "END must consume its own challenge");

  await cleanupScenario(scenario, [started.sessionId]);
});

test("END 24: repeated END of the same session is idempotent and safe", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  const first = await attemptEnd(scenario, started.sessionId);
  assert.deepEqual(first, { sessionId: started.sessionId, success: true });

  const second = await attemptEnd(scenario, started.sessionId);
  assert.deepEqual(second, { sessionId: started.sessionId, success: true });

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  assert.equal(Object.keys(allocatorSnap.data().activeSessions).length, 0, "allocator must not be corrupted by a repeat end");

  await cleanupScenario(scenario, [started.sessionId]);
});

test("END: possible even for a since-suspended/revoked Home or Camera, once identity/ownership are confirmed", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  await registryRef(scenario.homeDeviceId).update({ status: "suspended", suspensionReason: "manual" });
  await registryRef(scenario.cameraDeviceId).update({ status: "revoked", revokedAt: admin.firestore.Timestamp.now() });

  const response = await attemptEnd(scenario, started.sessionId);
  assert.deepEqual(response, { sessionId: started.sessionId, success: true });

  await cleanupScenario(scenario, [started.sessionId]);
});

test("END: a downgraded plan (entitlement change) does not block ending an existing session", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1 }));
  const started = await attemptStart(scenario);

  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 0 }));

  const response = await attemptEnd(scenario, started.sessionId);
  assert.deepEqual(response, { sessionId: started.sessionId, success: true });

  await cleanupScenario(scenario, [started.sessionId]);
});

test("END: cannot be performed by a different Home or a different owner", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  const otherScenario = await setupScenario({ skipCamera: true });
  await assert.rejects(
    attemptEnd(otherScenario, started.sessionId),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  await cleanupScenario(scenario, [started.sessionId]);
  await cleanupScenario(otherScenario);
});

test("END PRUNE 1: END removes every unrelated EXPIRED allocator entry, not just the target sessionId", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 10 }));
  const started = await attemptStart(scenario);

  // An unrelated, already-EXPIRED entry that has nothing to do with the target session -- a real
  // pruning test must show END removes it too, not merely the entry it was asked about.
  const expiredGhostId = db.collection("liveViewSessions").doc().id;
  await allocatorRef(scenario.ownerUid).update({
    [`activeSessions.${expiredGhostId}`]: {
      sessionId: expiredGhostId,
      homeDeviceId: uniqueId("lvs-ghost-home"),
      cameraDeviceId: uniqueId("lvs-ghost-camera"),
      createdAt: admin.firestore.Timestamp.fromMillis(Date.now() - 999999),
      leaseExpiresAt: admin.firestore.Timestamp.fromMillis(Date.now() - 1000),
    },
  });

  const response = await attemptEnd(scenario, started.sessionId);
  assert.deepEqual(response, { sessionId: started.sessionId, success: true });

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  const active = allocatorSnap.data().activeSessions;
  assert.ok(!(started.sessionId in active), "the target session must be removed");
  assert.ok(!(expiredGhostId in active), "the unrelated EXPIRED entry must also be pruned");
  assert.equal(Object.keys(active).length, 0);

  await cleanupScenario(scenario, [started.sessionId]);
});

test("END PRUNE 2: repeated (idempotent) END still performs a full cleanup pass", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 10 }));
  const started = await attemptStart(scenario);

  const first = await attemptEnd(scenario, started.sessionId);
  assert.deepEqual(first, { sessionId: started.sessionId, success: true });

  // Inject a fresh EXPIRED entry AFTER the first end -- proves the SECOND (idempotent) end also
  // runs the full prune, not just a no-op early return.
  const expiredGhostId = db.collection("liveViewSessions").doc().id;
  await allocatorRef(scenario.ownerUid).update({
    [`activeSessions.${expiredGhostId}`]: {
      sessionId: expiredGhostId,
      homeDeviceId: uniqueId("lvs-ghost-home"),
      cameraDeviceId: uniqueId("lvs-ghost-camera"),
      createdAt: admin.firestore.Timestamp.fromMillis(Date.now() - 999999),
      leaseExpiresAt: admin.firestore.Timestamp.fromMillis(Date.now() - 1000),
    },
  });

  const second = await attemptEnd(scenario, started.sessionId);
  assert.deepEqual(second, { sessionId: started.sessionId, success: true });

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  assert.equal(Object.keys(allocatorSnap.data().activeSessions).length, 0, "the repeat end must still prune the expired entry");

  await cleanupScenario(scenario, [started.sessionId]);
});

test("END PRUNE 3: an unrelated, still-UNEXPIRED allocator entry is preserved by END", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 10 }));
  const started = await attemptStart(scenario);

  // A second, genuinely real, still-active session for the SAME owner (different camera).
  const secondCameraId = uniqueId("lvs-prune3-camera");
  const secondCameraAuthUid = uniqueId("lvs-prune3-camera-auth");
  const now = admin.firestore.Timestamp.now();
  await seedCameraDevice(secondCameraId, secondCameraAuthUid);
  await claimRef(secondCameraId).set({ uid: scenario.ownerUid, cameraAuthUid: secondCameraAuthUid, claimedAt: now });
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).set({
    cameraDeviceId: secondCameraId,
    homeDeviceId: scenario.homeDeviceId,
    pairedAt: now,
    status: "active",
  });
  const second = await attemptStart(scenario, secondCameraId);

  const response = await attemptEnd(scenario, started.sessionId);
  assert.deepEqual(response, { sessionId: started.sessionId, success: true });

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  const active = allocatorSnap.data().activeSessions;
  assert.ok(!(started.sessionId in active), "the ended session must be removed");
  assert.ok(second.sessionId in active, "the unrelated, unexpired session must be preserved");

  const secondSessionSnap = await sessionRef(second.sessionId).get();
  assert.equal(secondSessionSnap.get("status"), "ACTIVE", "the unrelated session must remain untouched");

  await registryRef(secondCameraId).delete();
  await claimRef(secondCameraId).delete();
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).delete();
  await cleanupScenario(scenario, [started.sessionId, second.sessionId]);
});

// =================================================================================================
// N. Corrupt allocator handling -- explicit integrityStatus state machine (see
// docs/LIVE_VIEW_SESSIONS.md's "Corrupt allocator handling" section). Proves the exact bypass a
// blind "reset to empty" would have permitted -- two canonically-ACTIVE sessions, one corrupt
// allocator entry among them, END of one must NEVER make the other silently vanish from
// allocator-based counting while remaining ACTIVE.
// =================================================================================================

// Starts a SECOND, genuinely real, distinct (Home, Camera) session for the same scenario/owner
// (reusing the same Home, a fresh Camera) -- used throughout this section to set up "two
// canonically-ACTIVE sessions" without duplicating the seed/claim/link boilerplate at each call
// site.
async function startSecondSession(scenario, label) {
  const cameraDeviceId = uniqueId(`lvs-${label}-camera`);
  const cameraAuthUid = uniqueId(`lvs-${label}-camera-auth`);
  const now = admin.firestore.Timestamp.now();
  await seedCameraDevice(cameraDeviceId, cameraAuthUid);
  await claimRef(cameraDeviceId).set({ uid: scenario.ownerUid, cameraAuthUid, claimedAt: now });
  await homeCameraLinkRef(scenario.ownerUid, cameraDeviceId).set({
    cameraDeviceId,
    homeDeviceId: scenario.homeDeviceId,
    pairedAt: now,
    status: "active",
  });
  const response = await attemptStart(scenario, cameraDeviceId);
  return { cameraDeviceId, cameraAuthUid, sessionId: response.sessionId };
}
async function cleanupSecondSession(second) {
  await registryRef(second.cameraDeviceId).delete();
  await claimRef(second.cameraDeviceId).delete();
  await homeCameraLinkRef(second.ownerUid ?? undefined, second.cameraDeviceId).delete().catch(() => {});
}

test("CORRUPT ALLOCATOR 1: END on a corrupt allocator marks it CORRUPT without touching activeSessions, and still ends the target session", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 5 }));
  const started = await attemptStart(scenario);

  // Inject exactly ONE malformed entry alongside the real, valid one -- parseAllocatorState fails
  // the WHOLE map on this single bad entry (never a partial parse), so the allocator is now corrupt
  // as a whole even though the real entry is individually fine.
  await allocatorRef(scenario.ownerUid).update({ "activeSessions.malformed-ghost": "not-an-object-entry" });

  const beforeSnap = await allocatorRef(scenario.ownerUid).get();
  const rawActiveSessionsBefore = beforeSnap.data().activeSessions;

  const response = await attemptEnd(scenario, started.sessionId);
  assert.deepEqual(response, { sessionId: started.sessionId, success: true }, "END of a verified, owned session must succeed even though the allocator is corrupt");

  const sessionSnap = await sessionRef(started.sessionId).get();
  assert.equal(sessionSnap.get("status"), "ENDED", "the target session must be marked ENDED");

  const afterSnap = await allocatorRef(scenario.ownerUid).get();
  const allocator = afterSnap.data();
  assert.equal(allocator.integrityStatus, "CORRUPT", "the allocator must be explicitly marked CORRUPT, never silently repaired");
  assert.ok(allocator.corruptAt, "corruptAt must be set");
  assert.equal(allocator.corruptionReason, "PARSE_FAILED");
  assert.deepEqual(
    allocator.activeSessions,
    rawActiveSessionsBefore,
    "activeSessions must be byte-for-byte UNTOUCHED by END -- never reset to {}, never repaired as a side effect"
  );

  await cleanupScenario(scenario, [started.sessionId]);
});

test("CORRUPT ALLOCATOR 2: an unrelated canonically-ACTIVE session is never silently forgotten -- no session-limit bypass after END encounters corruption", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 2 }));
  const sessionA = await attemptStart(scenario);
  const sessionB = await startSecondSession(scenario, "corrupt2");

  // Corrupt the allocator -- sessionA's and sessionB's own entries are both still individually
  // valid and present, but the map as a whole no longer parses.
  await allocatorRef(scenario.ownerUid).update({ "activeSessions.malformed-ghost": "not-an-object-entry" });

  // End session A. Under the OLD (unsafe) design this would have reset activeSessions to {},
  // making session B invisible to allocator-based counting while it remains canonically ACTIVE --
  // exactly the bypass this test exists to rule out.
  const endResponse = await attemptEnd(scenario, sessionA.sessionId);
  assert.deepEqual(endResponse, { sessionId: sessionA.sessionId, success: true });

  // Session B must still be canonically ACTIVE -- END of A must never touch B's own document.
  const sessionBSnap = await sessionRef(sessionB.sessionId).get();
  assert.equal(sessionBSnap.get("status"), "ACTIVE", "session B must remain canonically ACTIVE, never silently forgotten");

  // The allocator must be explicitly CORRUPT, and STILL contain B's (and the malformed ghost's)
  // raw entry -- never an apparently-healthy empty map.
  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  const allocator = allocatorSnap.data();
  assert.equal(allocator.integrityStatus, "CORRUPT");
  assert.ok(sessionB.sessionId in allocator.activeSessions, "session B's own entry must still be present in the (corrupt, untouched) map");

  // The actual bypass check: a further START (for a THIRD camera) must be DENIED, not silently
  // granted a slot because the allocator "looks empty". If the old reset-to-{} behavior were still
  // in place, this would incorrectly succeed even though B alone already occupies the account's
  // entire 2-session limit.
  const thirdCameraId = uniqueId("lvs-corrupt2-third-camera");
  const thirdCameraAuthUid = uniqueId("lvs-corrupt2-third-camera-auth");
  const now = admin.firestore.Timestamp.now();
  await seedCameraDevice(thirdCameraId, thirdCameraAuthUid);
  await claimRef(thirdCameraId).set({ uid: scenario.ownerUid, cameraAuthUid: thirdCameraAuthUid, claimedAt: now });
  await homeCameraLinkRef(scenario.ownerUid, thirdCameraId).set({
    cameraDeviceId: thirdCameraId,
    homeDeviceId: scenario.homeDeviceId,
    pairedAt: now,
    status: "active",
  });
  await assert.rejects(
    attemptStart(scenario, thirdCameraId),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED",
    "START must be denied while the allocator remains CORRUPT -- no session-limit bypass"
  );
  const sessionsAfterStartAttempt = await db.collection("liveViewSessions").where("ownerUid", "==", scenario.ownerUid).where("status", "==", "ACTIVE").get();
  assert.equal(sessionsAfterStartAttempt.size, 1, "only session B may remain ACTIVE -- no third session may ever have been created");

  // RENEW of the still-legitimately-ACTIVE session B must ALSO be denied while CORRUPT.
  await assert.rejects(
    attemptRenew(scenario, sessionB.sessionId),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED",
    "RENEW must be denied while the allocator remains CORRUPT"
  );

  await registryRef(thirdCameraId).delete();
  await claimRef(thirdCameraId).delete();
  await homeCameraLinkRef(scenario.ownerUid, thirdCameraId).delete();
  await registryRef(sessionB.cameraDeviceId).delete();
  await claimRef(sessionB.cameraDeviceId).delete();
  await homeCameraLinkRef(scenario.ownerUid, sessionB.cameraDeviceId).delete();
  await cleanupScenario(scenario, [sessionA.sessionId, sessionB.sessionId]);
});

test("CORRUPT ALLOCATOR 3: repeated END while the allocator remains CORRUPT is safe and never rewrites corruptAt or activeSessions a second time", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 2 }));
  const sessionA = await attemptStart(scenario);
  const sessionB = await startSecondSession(scenario, "corrupt3");

  await allocatorRef(scenario.ownerUid).update({ "activeSessions.malformed-ghost": "not-an-object-entry" });

  const firstEnd = await attemptEnd(scenario, sessionA.sessionId);
  assert.deepEqual(firstEnd, { sessionId: sessionA.sessionId, success: true });

  const afterFirstEnd = await allocatorRef(scenario.ownerUid).get();
  const corruptAtAfterFirst = afterFirstEnd.data().corruptAt;
  const activeSessionsAfterFirst = afterFirstEnd.data().activeSessions;
  assert.ok(corruptAtAfterFirst);

  // A second END (of a DIFFERENT, still-ACTIVE session, on the same already-corrupt allocator)
  // must succeed and must NOT touch the allocator document a second time -- corruptAt/activeSessions
  // must reflect the ORIGINAL discovery, byte-for-byte, never a later repeat's timestamp/content.
  const secondEnd = await attemptEnd(scenario, sessionB.sessionId);
  assert.deepEqual(secondEnd, { sessionId: sessionB.sessionId, success: true }, "END must remain safe/possible even while already CORRUPT");

  const afterSecondEnd = await allocatorRef(scenario.ownerUid).get();
  const allocator = afterSecondEnd.data();
  assert.equal(allocator.integrityStatus, "CORRUPT");
  assert.equal(
    allocator.corruptAt.toMillis(),
    corruptAtAfterFirst.toMillis(),
    "corruptAt must be UNCHANGED by the repeat END -- reflects only the original discovery"
  );
  assert.deepEqual(allocator.activeSessions, activeSessionsAfterFirst, "activeSessions must be UNCHANGED by the repeat END");

  // Both sessions must have actually ended, despite the allocator never healing.
  const sessionASnap = await sessionRef(sessionA.sessionId).get();
  const sessionBSnap = await sessionRef(sessionB.sessionId).get();
  assert.equal(sessionASnap.get("status"), "ENDED");
  assert.equal(sessionBSnap.get("status"), "ENDED");

  await registryRef(sessionB.cameraDeviceId).delete();
  await claimRef(sessionB.cameraDeviceId).delete();
  await homeCameraLinkRef(scenario.ownerUid, sessionB.cameraDeviceId).delete();
  await cleanupScenario(scenario, [sessionA.sessionId, sessionB.sessionId]);
});

test("CORRUPT ALLOCATOR 4: integrityStatus === CORRUPT short-circuits before schemaVersion/unexpected-key checks -- stacked additional corruption is never re-diagnosed or repaired", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 2 }));
  const sessionA = await attemptStart(scenario);
  const sessionB = await startSecondSession(scenario, "corrupt4");

  // First, genuinely mark the allocator CORRUPT (mirrors CORRUPT ALLOCATOR 1's own setup) so
  // corruptAt reflects a real "first discovery" instant. Session B stays canonically ACTIVE
  // throughout this entire test -- used below to exercise the CORRUPT-denial path for RENEW
  // without it being confused with "session already ended".
  await allocatorRef(scenario.ownerUid).update({ "activeSessions.malformed-ghost": "not-an-object-entry" });
  const firstEnd = await attemptEnd(scenario, sessionA.sessionId);
  assert.deepEqual(firstEnd, { sessionId: sessionA.sessionId, success: true });

  const afterFirstEnd = await allocatorRef(scenario.ownerUid).get();
  assert.equal(afterFirstEnd.data().integrityStatus, "CORRUPT");
  const corruptAtBefore = afterFirstEnd.data().corruptAt;
  const activeSessionsBefore = afterFirstEnd.data().activeSessions;
  assert.ok(corruptAtBefore);

  // Stack ADDITIONAL corruption directly on top of the already-CORRUPT document -- an invalid
  // schemaVersion AND an unexpected top-level field. If integrityStatus === "CORRUPT" is checked
  // FIRST (the fix under test), none of this can ever be reached or matter: the document must
  // still be recognized as the SAME already-known corruption, not "rediscovered" via these fields.
  await allocatorRef(scenario.ownerUid).update({
    schemaVersion: 999,
    unexpectedField: "attacker-or-bug-injected",
  });

  // Repeat END of the SAME (already-ENDED) target session A -- per this module's own design, every
  // successful END, including a repeat/idempotent one, still attempts the allocator branch.
  const secondEnd = await attemptEnd(scenario, sessionA.sessionId);
  assert.deepEqual(secondEnd, { sessionId: sessionA.sessionId, success: true }, "END must remain safe/possible even against this doubly-corrupt allocator");

  const afterSecondEnd = await allocatorRef(scenario.ownerUid).get();
  const allocator = afterSecondEnd.data();
  assert.equal(allocator.integrityStatus, "CORRUPT");
  assert.equal(
    allocator.corruptAt.toMillis(),
    corruptAtBefore.toMillis(),
    "corruptAt must be UNCHANGED -- the doubly-corrupt read must never be treated as a fresh discovery"
  );
  assert.deepEqual(allocator.activeSessions, activeSessionsBefore, "activeSessions must be UNCHANGED");
  // The stacked corruption itself must not be silently "repaired" as a side effect -- proving
  // maybeMarkAllocatorCorrupt performed NO write at all on this second call.
  assert.equal(allocator.schemaVersion, 999, "the corrupt schemaVersion must not be silently repaired back to 1");
  assert.equal(allocator.unexpectedField, "attacker-or-bug-injected", "the unexpected field must not be silently stripped");

  await assert.rejects(
    attemptStart(scenario),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED",
    "START must remain denied while the allocator remains CORRUPT"
  );
  // Session B is still genuinely ACTIVE -- this specifically exercises the allocator-CORRUPT
  // denial path for RENEW, not "session already ended".
  await assert.rejects(
    attemptRenew(scenario, sessionB.sessionId),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED",
    "RENEW must remain denied while the allocator remains CORRUPT"
  );

  await registryRef(sessionB.cameraDeviceId).delete();
  await claimRef(sessionB.cameraDeviceId).delete();
  await homeCameraLinkRef(scenario.ownerUid, sessionB.cameraDeviceId).delete();
  await cleanupScenario(scenario, [sessionA.sessionId, sessionB.sessionId]);
});

test("END PRUNE 5: the just-ENDED sessionId is absent from the allocator immediately after commit", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  const preSnap = await allocatorRef(scenario.ownerUid).get();
  assert.ok(started.sessionId in preSnap.data().activeSessions);

  await attemptEnd(scenario, started.sessionId);

  const postSnap = await allocatorRef(scenario.ownerUid).get();
  assert.ok(!(started.sessionId in postSnap.data().activeSessions), "must be absent immediately after the END transaction commits");

  await cleanupScenario(scenario, [started.sessionId]);
});

// =================================================================================================
// F. Expiry / lazy pruning
// =================================================================================================

test("START 6/7: after the old session's lease expires, lazy pruning frees the slot for a new START", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1 }));
  const first = await attemptStart(scenario);

  // Simulate lease expiry directly on both the canonical session doc and the allocator's own copy
  // -- no scheduled cleanup exists; the NEXT start/renew/end must prune this itself.
  const past = admin.firestore.Timestamp.fromMillis(Date.now() - 1000);
  await sessionRef(first.sessionId).update({ leaseExpiresAt: past });
  await allocatorRef(scenario.ownerUid).update({ [`activeSessions.${first.sessionId}.leaseExpiresAt`]: past });

  const secondCameraId = uniqueId("lvs-expiry-camera");
  const secondCameraAuthUid = uniqueId("lvs-expiry-camera-auth");
  const now = admin.firestore.Timestamp.now();
  await seedCameraDevice(secondCameraId, secondCameraAuthUid);
  await claimRef(secondCameraId).set({ uid: scenario.ownerUid, cameraAuthUid: secondCameraAuthUid, claimedAt: now });
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).set({
    cameraDeviceId: secondCameraId,
    homeDeviceId: scenario.homeDeviceId,
    pairedAt: now,
    status: "active",
  });

  const second = await attemptStart(scenario, secondCameraId);
  assert.notEqual(second.sessionId, first.sessionId);

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  const active = allocatorSnap.data().activeSessions;
  assert.equal(Object.keys(active).length, 1, "the expired entry must have been pruned, not just added to");
  assert.ok(second.sessionId in active);
  assert.ok(!(first.sessionId in active));

  await registryRef(secondCameraId).delete();
  await claimRef(secondCameraId).delete();
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).delete();
  await cleanupScenario(scenario, [first.sessionId, second.sessionId]);
});

test("START: a repeated START for the SAME pair after its own lease expired allocates a genuinely new session (old one is not idempotently reused)", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1 }));
  const first = await attemptStart(scenario);

  const past = admin.firestore.Timestamp.fromMillis(Date.now() - 1000);
  await sessionRef(first.sessionId).update({ leaseExpiresAt: past });
  await allocatorRef(scenario.ownerUid).update({ [`activeSessions.${first.sessionId}.leaseExpiresAt`]: past });

  const second = await attemptStart(scenario);
  assert.notEqual(second.sessionId, first.sessionId, "an expired session must never be idempotently returned as still-active");

  await cleanupScenario(scenario, [first.sessionId, second.sessionId]);
});

// =================================================================================================
// G. Fail-closed integrity
// =================================================================================================

test("START 11: a corrupt allocator document denies START (fail-closed, not silently reset)", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  await allocatorRef(scenario.ownerUid).set({ schemaVersion: 1, activeSessions: "not-an-object" });

  await assert.rejects(
    attemptStart(scenario),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  const sessionsSnap = await db.collection("liveViewSessions").where("ownerUid", "==", scenario.ownerUid).get();
  assert.equal(sessionsSnap.size, 0, "no session must be created when the allocator is fail-closed");

  await cleanupScenario(scenario);
});

test("START 13: an allocator entry present for a pair whose canonical session document does not confirm it is denied (fail-closed, no duplicate)", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1 }));

  // Allocator claims an active session for this exact pair, but no such liveViewSessions document
  // actually exists.
  await allocatorRef(scenario.ownerUid).set({
    schemaVersion: 1,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    activeSessions: {
      "ghost-session-id": {
        sessionId: "ghost-session-id",
        homeDeviceId: scenario.homeDeviceId,
        cameraDeviceId: scenario.cameraDeviceId,
        createdAt: admin.firestore.Timestamp.now(),
        leaseExpiresAt: admin.firestore.Timestamp.fromMillis(Date.now() + LIVE_VIEW_LEASE_TTL_MS),
      },
    },
  });

  await assert.rejects(
    attemptStart(scenario),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );

  const sessionsSnap = await db.collection("liveViewSessions").where("ownerUid", "==", scenario.ownerUid).get();
  assert.equal(sessionsSnap.size, 0, "no new session must be created when the allocator disagrees with the canonical record");

  await cleanupScenario(scenario);
});

// =================================================================================================
// L. Strict, bounded allocator parsing -- every malformed shape must fail closed (deny, no session
// ever created), never a partial acceptance of "the entries that did parse".
// =================================================================================================

async function assertStartDeniedByCorruptAllocator(scenario) {
  await assert.rejects(
    attemptStart(scenario),
    (err) => err.code === "permission-denied" && err.message === "LIVE_VIEW_SESSION_DENIED"
  );
  const sessionsSnap = await db.collection("liveViewSessions").where("ownerUid", "==", scenario.ownerUid).get();
  assert.equal(sessionsSnap.size, 0, "no session may ever be created against a malformed allocator");
}

test("ALLOCATOR STRICT: wrong schemaVersion denies START", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  await allocatorRef(scenario.ownerUid).set({
    schemaVersion: 999,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    activeSessions: {},
  });
  await assertStartDeniedByCorruptAllocator(scenario);
  await cleanupScenario(scenario);
});

// Every ALLOCATOR STRICT test below constructs an otherwise-HEALTHY-shaped envelope
// (integrityStatus/corruptAt/corruptionReason included) so it isolates exactly the ONE structural
// defect under test, rather than accidentally also tripping the (separately, exhaustively tested)
// integrityStatus check.
function healthyAllocatorEnvelope(activeSessions) {
  return {
    schemaVersion: 1,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    integrityStatus: "HEALTHY",
    corruptAt: null,
    corruptionReason: null,
    activeSessions,
  };
}

test("ALLOCATOR STRICT: a non-Timestamp updatedAt denies START", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  await allocatorRef(scenario.ownerUid).set({
    schemaVersion: 1,
    updatedAt: "not-a-timestamp",
    integrityStatus: "HEALTHY",
    corruptAt: null,
    corruptionReason: null,
    activeSessions: {},
  });
  await assertStartDeniedByCorruptAllocator(scenario);
  await cleanupScenario(scenario);
});

test("ALLOCATOR STRICT: activeSessions as an array (not a plain map) denies START", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  await allocatorRef(scenario.ownerUid).set(healthyAllocatorEnvelope([]));
  await assertStartDeniedByCorruptAllocator(scenario);
  await cleanupScenario(scenario);
});

test("ALLOCATOR STRICT: a malformed (non-Firestore-auto-id-shaped) sessionId key denies START", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  await allocatorRef(scenario.ownerUid).set(
    healthyAllocatorEnvelope({
      "not/a-valid-id": {
        sessionId: "not/a-valid-id",
        homeDeviceId: scenario.homeDeviceId,
        cameraDeviceId: scenario.cameraDeviceId,
        createdAt: admin.firestore.Timestamp.now(),
        leaseExpiresAt: admin.firestore.Timestamp.fromMillis(Date.now() + LIVE_VIEW_LEASE_TTL_MS),
      },
    })
  );
  await assertStartDeniedByCorruptAllocator(scenario);
  await cleanupScenario(scenario);
});

test("ALLOCATOR STRICT: an entry with an empty homeDeviceId denies START", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const ghostId = db.collection("liveViewSessions").doc().id;
  await allocatorRef(scenario.ownerUid).set(
    healthyAllocatorEnvelope({
      [ghostId]: {
        sessionId: ghostId,
        homeDeviceId: "",
        cameraDeviceId: scenario.cameraDeviceId,
        createdAt: admin.firestore.Timestamp.now(),
        leaseExpiresAt: admin.firestore.Timestamp.fromMillis(Date.now() + LIVE_VIEW_LEASE_TTL_MS),
      },
    })
  );
  await assertStartDeniedByCorruptAllocator(scenario);
  await cleanupScenario(scenario);
});

test("ALLOCATOR STRICT: an entry with an over-length cameraDeviceId (>128 chars) denies START", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const ghostId = db.collection("liveViewSessions").doc().id;
  await allocatorRef(scenario.ownerUid).set(
    healthyAllocatorEnvelope({
      [ghostId]: {
        sessionId: ghostId,
        homeDeviceId: scenario.homeDeviceId,
        cameraDeviceId: "x".repeat(129),
        createdAt: admin.firestore.Timestamp.now(),
        leaseExpiresAt: admin.firestore.Timestamp.fromMillis(Date.now() + LIVE_VIEW_LEASE_TTL_MS),
      },
    })
  );
  await assertStartDeniedByCorruptAllocator(scenario);
  await cleanupScenario(scenario);
});

test("ALLOCATOR STRICT: two entries sharing the same (homeDeviceId, cameraDeviceId) pair under different session ids denies START", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const idA = db.collection("liveViewSessions").doc().id;
  const idB = db.collection("liveViewSessions").doc().id;
  const now = admin.firestore.Timestamp.now();
  const leaseExpiresAt = admin.firestore.Timestamp.fromMillis(Date.now() + LIVE_VIEW_LEASE_TTL_MS);
  await allocatorRef(scenario.ownerUid).set(
    healthyAllocatorEnvelope({
      [idA]: { sessionId: idA, homeDeviceId: scenario.homeDeviceId, cameraDeviceId: scenario.cameraDeviceId, createdAt: now, leaseExpiresAt },
      [idB]: { sessionId: idB, homeDeviceId: scenario.homeDeviceId, cameraDeviceId: scenario.cameraDeviceId, createdAt: now, leaseExpiresAt },
    })
  );
  await assertStartDeniedByCorruptAllocator(scenario);
  await cleanupScenario(scenario);
});

test(`ALLOCATOR STRICT: exceeding LIVE_VIEW_ALLOCATOR_MAX_ENTRIES (${LIVE_VIEW_ALLOCATOR_MAX_ENTRIES}) denies START, independent of entitlement value`, async () => {
  const scenario = await setupScenario();
  // A generous entitlement -- proves the ceiling is enforced regardless of the account's own limit.
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1000 }));
  const now = admin.firestore.Timestamp.now();
  const leaseExpiresAt = admin.firestore.Timestamp.fromMillis(Date.now() + LIVE_VIEW_LEASE_TTL_MS);
  const activeSessions = {};
  for (let i = 0; i < LIVE_VIEW_ALLOCATOR_MAX_ENTRIES + 1; i += 1) {
    const id = db.collection("liveViewSessions").doc().id;
    activeSessions[id] = {
      sessionId: id,
      homeDeviceId: uniqueId(`lvs-bound-home-${i}`),
      cameraDeviceId: uniqueId(`lvs-bound-camera-${i}`),
      createdAt: now,
      leaseExpiresAt,
    };
  }
  await allocatorRef(scenario.ownerUid).set(healthyAllocatorEnvelope(activeSessions));
  await assertStartDeniedByCorruptAllocator(scenario);
  await cleanupScenario(scenario);
});

// =================================================================================================
// M2. Write-side enforcement of LIVE_VIEW_ALLOCATOR_MAX_ENTRIES (Fix 1). The read-side test above
// proves a stored 33-entry map is rejected as corrupt; these prove START itself never WRITES a
// 33rd entry in the first place, even when maxConcurrentLiveSessions is far larger than the
// allocator's own hard ceiling -- the effective cap for a NEW slot is
// min(maxConcurrentLiveSessions, LIVE_VIEW_ALLOCATOR_MAX_ENTRIES).
// =================================================================================================

// Builds `count` distinct, individually-valid, mutually-non-colliding allocator entries -- no
// backing liveViewSessions documents are created, since a NEW-pair START (the thing under test
// here) only ever COUNTS other entries, never re-validates them against their own session
// documents (that re-validation is exclusively the idempotent-match path's job -- see
// validateAllocatorEntryAgainstSession -- and is exercised separately by test C below).
function buildDistinctAllocatorEntries(count) {
  const now = admin.firestore.Timestamp.now();
  const leaseExpiresAt = admin.firestore.Timestamp.fromMillis(Date.now() + LIVE_VIEW_LEASE_TTL_MS);
  const activeSessions = {};
  for (let i = 0; i < count; i += 1) {
    const id = db.collection("liveViewSessions").doc().id;
    activeSessions[id] = {
      sessionId: id,
      homeDeviceId: uniqueId(`lvs-cap-home-${i}`),
      cameraDeviceId: uniqueId(`lvs-cap-camera-${i}`),
      createdAt: now,
      leaseExpiresAt,
    };
  }
  return activeSessions;
}

test("ALLOCATOR CAP A: 31 valid entries + entitlement 1000 -- a new distinct START succeeds and the allocator ends with exactly 32 entries", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1000 }));
  await allocatorRef(scenario.ownerUid).set(healthyAllocatorEnvelope(buildDistinctAllocatorEntries(31)));

  const response = await attemptStart(scenario);
  assert.ok(response.sessionId);

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  assert.equal(Object.keys(allocatorSnap.data().activeSessions).length, LIVE_VIEW_ALLOCATOR_MAX_ENTRIES);
  assert.equal(allocatorSnap.data().integrityStatus, "HEALTHY");

  await cleanupScenario(scenario, [response.sessionId]);
});

test("ALLOCATOR CAP B: 32 valid entries + entitlement 1000 -- a new distinct START is denied, allocator stays at 32, no session created, challenge unconsumed", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1000 }));
  await allocatorRef(scenario.ownerUid).set(healthyAllocatorEnvelope(buildDistinctAllocatorEntries(32)));

  const { deviceProof, challengeId } = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, {
    cameraDeviceId: scenario.cameraDeviceId,
  });
  await assert.rejects(
    startLiveViewSession.run(fakeRequest({ cameraDeviceId: scenario.cameraDeviceId, deviceProof }, scenario.ownerUid)),
    (err) => err.code === "resource-exhausted" && err.message === "LIVE_VIEW_SESSION_LIMIT_REACHED"
  );

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  assert.equal(Object.keys(allocatorSnap.data().activeSessions).length, 32, "must never grow past the 32-entry ceiling");

  const sessionsSnap = await db.collection("liveViewSessions").where("ownerUid", "==", scenario.ownerUid).get();
  assert.equal(sessionsSnap.size, 0, "no candidate session document may be created when the write-side cap denies the START");

  const challengeSnap = await challengeRef(challengeId).get();
  assert.equal(challengeSnap.get("usedAt"), null, "a write-side-capped denial must never consume the challenge");

  await cleanupScenario(scenario);
});

test("ALLOCATOR CAP C: at exactly 32 entries, START for an already-active exact Home+Camera pair still returns the existing session idempotently (no 33rd entry)", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1000 }));

  // A REAL session for this scenario's own (Home, Camera) pair -- the idempotent path re-reads and
  // re-validates this specific entry's own canonical session document, so (unlike the distinct-pair
  // entries above) it must be genuine.
  const started = await attemptStart(scenario);

  // Pad the allocator up to exactly 32 total entries -- 31 more distinct, synthetic entries plus
  // the one real one already there.
  const padding = buildDistinctAllocatorEntries(31);
  await allocatorRef(scenario.ownerUid).update(
    Object.fromEntries(Object.entries(padding).map(([id, entry]) => [`activeSessions.${id}`, entry]))
  );
  const preSnap = await allocatorRef(scenario.ownerUid).get();
  assert.equal(Object.keys(preSnap.data().activeSessions).length, 32);

  const response = await attemptStart(scenario);
  assert.equal(response.sessionId, started.sessionId, "must idempotently return the SAME existing session, not deny or allocate a new one");

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  assert.equal(Object.keys(allocatorSnap.data().activeSessions).length, 32, "must remain exactly 32 -- no 33rd entry");

  await cleanupScenario(scenario, [started.sessionId]);
});

// =================================================================================================
// H. Challenge replay / consumption
// =================================================================================================

test("START 9: a challenge cannot be replayed for a second START attempt", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 2 }));

  const { deviceProof } = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, {
    cameraDeviceId: scenario.cameraDeviceId,
  });
  const first = await startLiveViewSession.run(fakeRequest({ cameraDeviceId: scenario.cameraDeviceId, deviceProof }, scenario.ownerUid));
  assert.ok(first.sessionId);

  await assert.rejects(
    startLiveViewSession.run(fakeRequest({ cameraDeviceId: scenario.cameraDeviceId, deviceProof }, scenario.ownerUid)),
    (err) => err.code === "failed-precondition" && err.message === "CHALLENGE_ALREADY_USED"
  );

  await cleanupScenario(scenario, [first.sessionId]);
});

test("START 10: a rejected operation never consumes its challenge", async () => {
  const scenario = await setupScenario();
  // No entitlements doc set with maxConcurrentLiveSessions=0 to force a denial unrelated to the
  // challenge itself -- proves denial-for-any-reason never marks the challenge used.
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 0 }));

  const { deviceProof, challengeId } = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, {
    cameraDeviceId: scenario.cameraDeviceId,
  });
  await assert.rejects(
    startLiveViewSession.run(fakeRequest({ cameraDeviceId: scenario.cameraDeviceId, deviceProof }, scenario.ownerUid)),
    (err) => err.code === "resource-exhausted" && err.message === "LIVE_VIEW_SESSION_LIMIT_REACHED"
  );

  const challengeSnap = await challengeRef(challengeId).get();
  assert.equal(challengeSnap.get("usedAt"), null);

  await cleanupScenario(scenario);
});

// =================================================================================================
// I. Concurrency / race conditions -- Promise.allSettled, verifying FINAL FIRESTORE STATE.
// =================================================================================================

test("CONCURRENCY 1: two parallel START of the SAME (Home, Camera) pair produce exactly one sessionId and one occupied slot", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1 }));

  const proofA = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, { cameraDeviceId: scenario.cameraDeviceId });
  const proofB = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, { cameraDeviceId: scenario.cameraDeviceId });

  const results = await Promise.allSettled([
    startLiveViewSession.run(fakeRequest({ cameraDeviceId: scenario.cameraDeviceId, deviceProof: proofA.deviceProof }, scenario.ownerUid)),
    startLiveViewSession.run(fakeRequest({ cameraDeviceId: scenario.cameraDeviceId, deviceProof: proofB.deviceProof }, scenario.ownerUid)),
  ]);

  // The common, expected outcome is both fulfilling with the SAME sessionId (the second is the
  // idempotent repeat of the first). Under genuine write contention on the shared allocator
  // document, one side can rarely exhaust the SDK's own bounded transaction retry budget -- see
  // isRetryExhaustionError's own doc -- which is tolerated ONLY as exactly that one signal, never
  // any other rejection reason.
  const fulfilled = results.filter((r) => r.status === "fulfilled");
  const rejected = results.filter((r) => r.status === "rejected");
  assert.ok(fulfilled.length >= 1, "at least one START must succeed");
  for (const r of rejected) {
    assert.ok(isRetryExhaustionError(r.reason), `unexpected rejection: code=${r.reason.code} message=${r.reason.message}`);
  }
  if (fulfilled.length === 2) {
    assert.equal(fulfilled[0].value.sessionId, fulfilled[1].value.sessionId, "both must resolve to the SAME sessionId");
  }

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  assert.equal(Object.keys(allocatorSnap.data().activeSessions).length, 1, "exactly one slot must be occupied");
  const sessionsSnap = await db.collection("liveViewSessions").where("ownerUid", "==", scenario.ownerUid).get();
  assert.equal(sessionsSnap.size, 1, "exactly one liveViewSessions document must exist for this owner");

  await assertConsistentState(scenario.ownerUid);
  await cleanupScenario(scenario, [fulfilled[0].value.sessionId]);
});

test("CONCURRENCY 2: two parallel START of DIFFERENT cameras at limit=1 -> exactly one success, one limit rejection", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1 }));

  const secondCameraId = uniqueId("lvs-cc2-camera");
  const secondCameraAuthUid = uniqueId("lvs-cc2-camera-auth");
  const now = admin.firestore.Timestamp.now();
  await seedCameraDevice(secondCameraId, secondCameraAuthUid);
  await claimRef(secondCameraId).set({ uid: scenario.ownerUid, cameraAuthUid: secondCameraAuthUid, claimedAt: now });
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).set({
    cameraDeviceId: secondCameraId,
    homeDeviceId: scenario.homeDeviceId,
    pairedAt: now,
    status: "active",
  });

  const proofA = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, { cameraDeviceId: scenario.cameraDeviceId });
  const proofB = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, { cameraDeviceId: secondCameraId });

  const results = await Promise.allSettled([
    startLiveViewSession.run(fakeRequest({ cameraDeviceId: scenario.cameraDeviceId, deviceProof: proofA.deviceProof }, scenario.ownerUid)),
    startLiveViewSession.run(fakeRequest({ cameraDeviceId: secondCameraId, deviceProof: proofB.deviceProof }, scenario.ownerUid)),
  ]);

  const fulfilled = results.filter((r) => r.status === "fulfilled");
  const rejected = results.filter((r) => r.status === "rejected");
  assert.equal(fulfilled.length, 1, "exactly one START must succeed");
  assert.equal(rejected.length, 1, "exactly one START must be rejected");
  // The loser is denied either with the clean semantic reason (it lost the race for the one slot
  // and ran to completion to discover that), or -- rarely, under genuine write contention -- with
  // exactly the retry-exhaustion signal (see isRetryExhaustionError's own doc). Never anything else.
  assert.ok(
    rejected[0].reason.message === "LIVE_VIEW_SESSION_LIMIT_REACHED" || isRetryExhaustionError(rejected[0].reason),
    `unexpected rejection: code=${rejected[0].reason.code} message=${rejected[0].reason.message}`
  );

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  assert.equal(Object.keys(allocatorSnap.data().activeSessions).length, 1, "canonical occupied-slot count must be exactly 1");

  await assertConsistentState(scenario.ownerUid);
  await registryRef(secondCameraId).delete();
  await claimRef(secondCameraId).delete();
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).delete();
  await cleanupScenario(scenario, [fulfilled[0].value.sessionId]);
});

test("CONCURRENCY 3: a parallel START and END never leave the system in an inconsistent state", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1 }));
  const started = await attemptStart(scenario);

  const proofStart = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, { cameraDeviceId: scenario.cameraDeviceId });
  const proofEnd = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_END, { sessionId: started.sessionId });

  const results = await Promise.allSettled([
    startLiveViewSession.run(fakeRequest({ cameraDeviceId: scenario.cameraDeviceId, deviceProof: proofStart.deviceProof }, scenario.ownerUid)),
    endLiveViewSession.run(fakeRequest({ sessionId: started.sessionId, deviceProof: proofEnd.deviceProof }, scenario.ownerUid)),
  ]);

  // Both fulfilling is the common, expected outcome (START either finds the existing active
  // session idempotently, or -- if END committed first -- allocates a fresh one). Under genuine
  // Firestore write contention on the shared allocator document, the SDK's own bounded transaction
  // retry budget can occasionally exhaust for whichever side loses repeated conflicts -- that is a
  // legitimate "retry me" signal a real client already handles, not a correctness bug in this
  // module, so it is tolerated here for START specifically. END -- deliberately the simpler,
  // faster transaction of the two -- must still always fulfill. If START is rejected, it must be
  // rejected for EXACTLY the retry-exhaustion signal (see isRetryExhaustionError's own doc) -- never
  // silently tolerated as "any rejection is fine", never internal/permission-denied/not-found/
  // unknown/generic-without-checking-code.
  const [startResult, endResult] = results;
  assert.equal(endResult.status, "fulfilled", "END of one's own session must never itself fail");
  if (startResult.status === "rejected") {
    assert.ok(
      isRetryExhaustionError(startResult.reason),
      `unexpected rejection: code=${startResult.reason.code} message=${startResult.reason.message}`
    );
  }

  const endedSessionSnap = await sessionRef(started.sessionId).get();
  assert.equal(endedSessionSnap.get("status"), "ENDED");

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  assert.ok(Object.keys(allocatorSnap.data().activeSessions).length <= 1, "never more than one occupied slot");

  await assertConsistentState(scenario.ownerUid);
  const extraSessionIds = startResult.status === "fulfilled" ? [started.sessionId, startResult.value.sessionId] : [started.sessionId];
  await cleanupScenario(scenario, extraSessionIds);
});

test("CONCURRENCY 4: two parallel RENEW of the same session both succeed and leave a single, consistent lease", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  const proofA = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_RENEW, { sessionId: started.sessionId });
  const proofB = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_RENEW, { sessionId: started.sessionId });

  const results = await Promise.allSettled([
    renewLiveViewSession.run(fakeRequest({ sessionId: started.sessionId, deviceProof: proofA.deviceProof }, scenario.ownerUid)),
    renewLiveViewSession.run(fakeRequest({ sessionId: started.sessionId, deviceProof: proofB.deviceProof }, scenario.ownerUid)),
  ]);

  for (const r of results) {
    assert.equal(r.status, "fulfilled");
  }

  const sessionSnap = await sessionRef(started.sessionId).get();
  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  assert.equal(
    sessionSnap.get("leaseExpiresAt").toMillis(),
    allocatorSnap.data().activeSessions[started.sessionId].leaseExpiresAt.toMillis(),
    "the session document and the allocator's own copy must always agree"
  );

  await assertConsistentState(scenario.ownerUid);
  await cleanupScenario(scenario, [started.sessionId]);
});

test("CONCURRENCY 5: RENEW racing with END never revives an ended session", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());
  const started = await attemptStart(scenario);

  const proofRenew = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_RENEW, { sessionId: started.sessionId });
  const proofEnd = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_END, { sessionId: started.sessionId });

  const results = await Promise.allSettled([
    renewLiveViewSession.run(fakeRequest({ sessionId: started.sessionId, deviceProof: proofRenew.deviceProof }, scenario.ownerUid)),
    endLiveViewSession.run(fakeRequest({ sessionId: started.sessionId, deviceProof: proofEnd.deviceProof }, scenario.ownerUid)),
  ]);

  // Either interleaving is legitimate (renew-then-end ends a renewed session; end-then-renew
  // rejects the renew against an already-ended session) -- what must ALWAYS hold is the final
  // state: the session is ended, never left ACTIVE.
  const sessionSnap = await sessionRef(started.sessionId).get();
  assert.equal(sessionSnap.get("status"), "ENDED");

  const endResult = results[1];
  assert.equal(endResult.status, "fulfilled", "END of one's own session must never itself fail");

  await assertConsistentState(scenario.ownerUid);
  await cleanupScenario(scenario, [started.sessionId]);
});

test("CONCURRENCY 6: a losing challenge in a race remains unconsumed unless its own operation actually committed", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 1 }));

  const secondCameraId = uniqueId("lvs-cc6-camera");
  const secondCameraAuthUid = uniqueId("lvs-cc6-camera-auth");
  const now = admin.firestore.Timestamp.now();
  await seedCameraDevice(secondCameraId, secondCameraAuthUid);
  await claimRef(secondCameraId).set({ uid: scenario.ownerUid, cameraAuthUid: secondCameraAuthUid, claimedAt: now });
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).set({
    cameraDeviceId: secondCameraId,
    homeDeviceId: scenario.homeDeviceId,
    pairedAt: now,
    status: "active",
  });

  const proofA = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, { cameraDeviceId: scenario.cameraDeviceId });
  const proofB = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, { cameraDeviceId: secondCameraId });

  const results = await Promise.allSettled([
    startLiveViewSession.run(fakeRequest({ cameraDeviceId: scenario.cameraDeviceId, deviceProof: proofA.deviceProof }, scenario.ownerUid)),
    startLiveViewSession.run(fakeRequest({ cameraDeviceId: secondCameraId, deviceProof: proofB.deviceProof }, scenario.ownerUid)),
  ]);

  const fulfilled = results.filter((r) => r.status === "fulfilled");
  const rejected = results.filter((r) => r.status === "rejected");
  assert.equal(fulfilled.length, 1, "at limit=1, exactly one distinct-pair START must succeed");
  assert.equal(rejected.length, 1);

  // Whichever challenge belongs to the LOSING (rejected, limit-reached) operation must remain
  // unconsumed -- a denial for any reason must never mark a challenge as used.
  const losingChallengeId = results[0].status === "rejected" ? proofA.challengeId : proofB.challengeId;
  const winningChallengeId = results[0].status === "fulfilled" ? proofA.challengeId : proofB.challengeId;
  const losingChallengeSnap = await challengeRef(losingChallengeId).get();
  const winningChallengeSnap = await challengeRef(winningChallengeId).get();
  assert.equal(losingChallengeSnap.get("usedAt"), null, "the losing operation's challenge must remain unconsumed");
  assert.ok(winningChallengeSnap.get("usedAt"), "the winning (committed) operation's challenge must be consumed");

  await assertConsistentState(scenario.ownerUid);
  await registryRef(secondCameraId).delete();
  await claimRef(secondCameraId).delete();
  await homeCameraLinkRef(scenario.ownerUid, secondCameraId).delete();
  await cleanupScenario(scenario, [fulfilled[0].value.sessionId]);
});

// =================================================================================================
// J. Logging safety -- new logs must never contain identifiers.
// =================================================================================================
// Deliberately does NOT filter captured lines down to ones containing a "LIVE_VIEW_SESSION"
// substring first -- that would silently skip createDeviceChallenge's own DEVICE_CHALLENGE_CREATE_*
// log lines (which never contain that substring for the LIVE_VIEW_* purposes), exactly the gap this
// requirement exists to close. EVERY captured stdout/stderr line, across the FULL
// createDeviceChallenge -> start/renew/end flow, is inspected: any JSON line whose own "message"
// belongs to this feature (DEVICE_CHALLENGE_* or LIVE_VIEW_SESSION_*) must have only allow-listed
// keys, and literally every line (JSON or not, in-family or not) is scanned for every forbidden
// identifier value.

const LOG_SAFE_ALLOWED_KEYS = ["severity", "message", "operation", "role", "stage", "result", "reason", "purpose"];

async function captureLogLines(fn) {
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
  return lines;
}

function assertNoLeaksInLogLines(lines, forbiddenValues) {
  let inFamilyLineCount = 0;
  for (const line of lines) {
    for (const forbiddenValue of forbiddenValues) {
      if (forbiddenValue) {
        assert.ok(!line.includes(forbiddenValue), `log line must not contain "${forbiddenValue}": ${line}`);
      }
    }
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }
    if (typeof entry.message !== "string") continue;
    if (!entry.message.startsWith("DEVICE_CHALLENGE_") && !entry.message.startsWith("LIVE_VIEW_SESSION_")) continue;
    inFamilyLineCount += 1;
    for (const key of Object.keys(entry)) {
      assert.ok(LOG_SAFE_ALLOWED_KEYS.includes(key), `log field "${key}" is not in the allowed safe-field list (line: ${line})`);
    }
  }
  return inFamilyLineCount;
}

test("LOGS: the full createDeviceChallenge -> start/renew/end flow never logs identifiers, in ANY captured line (not just ones matching a substring filter)", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements());

  let started;
  let renewed;
  let challengeIds = [];

  const lines = await captureLogLines(async () => {
    const startSigned = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, { cameraDeviceId: scenario.cameraDeviceId });
    challengeIds.push(startSigned.challengeId);
    started = await startLiveViewSession.run(
      fakeRequest({ cameraDeviceId: scenario.cameraDeviceId, deviceProof: startSigned.deviceProof }, scenario.ownerUid)
    );

    const renewSigned = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_RENEW, { sessionId: started.sessionId });
    challengeIds.push(renewSigned.challengeId);
    renewed = await renewLiveViewSession.run(fakeRequest({ sessionId: started.sessionId, deviceProof: renewSigned.deviceProof }, scenario.ownerUid));

    const endSigned = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_END, { sessionId: started.sessionId });
    challengeIds.push(endSigned.challengeId);
    await endLiveViewSession.run(fakeRequest({ sessionId: started.sessionId, deviceProof: endSigned.deviceProof }, scenario.ownerUid));
  });

  const forbidden = [
    scenario.ownerUid,
    scenario.homeDeviceId,
    scenario.cameraDeviceId,
    started.sessionId,
    ...challengeIds,
    publicKeySpkiBase64(scenario.keyPair.publicKey),
    "registeredDevices/",
    "liveViewSessions/",
    "liveViewUserStates/",
    "deviceChallenges/",
    "cameraClaims/",
    "users/",
  ];

  const inFamilyCount = assertNoLeaksInLogLines(lines, forbidden);
  assert.ok(inFamilyCount >= 6, "expected at least one DEVICE_CHALLENGE_ and one LIVE_VIEW_SESSION_ line per operation across create+start+renew+end");

  await cleanupScenario(scenario, [started.sessionId]);
});

test("LOGS: a denied createDeviceChallenge (bad payload) and a denied startLiveViewSession (limit reached) never log identifiers either", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 0 }));

  let challengeIdUsed;
  const lines = await captureLogLines(async () => {
    // A denial inside createDeviceChallenge itself (malformed requestPayload for LIVE_VIEW_START).
    await createDeviceChallenge
      .run(
        fakeRequest(
          { deviceId: scenario.homeDeviceId, purpose: DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, requestPayload: { cameraDeviceId: "" } },
          scenario.ownerUid
        )
      )
      .catch(() => {});

    // A denial inside startLiveViewSession itself (entitlement limit reached).
    const signed = await signChallenge(scenario, DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START, { cameraDeviceId: scenario.cameraDeviceId });
    challengeIdUsed = signed.challengeId;
    await startLiveViewSession
      .run(fakeRequest({ cameraDeviceId: scenario.cameraDeviceId, deviceProof: signed.deviceProof }, scenario.ownerUid))
      .catch(() => {});
  });

  const forbidden = [
    scenario.ownerUid,
    scenario.homeDeviceId,
    scenario.cameraDeviceId,
    challengeIdUsed,
    "registeredDevices/",
    "liveViewSessions/",
    "liveViewUserStates/",
    "deviceChallenges/",
  ];
  const inFamilyCount = assertNoLeaksInLogLines(lines, forbidden);
  assert.ok(inFamilyCount > 0, "at least one DEVICE_CHALLENGE_/LIVE_VIEW_SESSION_ log line must fire");

  await cleanupScenario(scenario);
});

// =================================================================================================
// O. runLiveViewTransaction -- emulator-only compatibility retry (see docs/LIVE_VIEW_SESSIONS.md's
// "Concurrency: emulator transaction-retry gap" section). Exercises the wrapper's retry decision
// directly against a fake `db` (no real Firestore connection) so the emulator-detection branch
// itself -- including the "no FIRESTORE_EMULATOR_HOST" (production) branch -- can be tested. The
// rest of this file can never naturally exercise the production branch, since the whole suite runs
// against a real emulator with FIRESTORE_EMULATOR_HOST always set.
// =================================================================================================

function makeCode3Error(message) {
  const err = new Error(message);
  err.code = 3;
  return err;
}

// Temporarily overrides process.env.FIRESTORE_EMULATOR_HOST for the duration of `fn`, always
// restoring the ORIGINAL value afterward (even on failure) -- critical here since the rest of this
// suite's own real Firestore connectivity depends on this exact variable staying set once this
// test finishes, and no test may leak a mutated value into any other test.
async function withEmulatorEnv(value, fn) {
  const original = process.env.FIRESTORE_EMULATOR_HOST;
  try {
    if (value === undefined) {
      delete process.env.FIRESTORE_EMULATOR_HOST;
    } else {
      process.env.FIRESTORE_EMULATOR_HOST = value;
    }
    return await fn();
  } finally {
    if (original === undefined) {
      delete process.env.FIRESTORE_EMULATOR_HOST;
    } else {
      process.env.FIRESTORE_EMULATOR_HOST = original;
    }
  }
}

test("runLiveViewTransaction: emulator env + exact code3/message retries and succeeds on the second attempt", async () => {
  await withEmulatorEnv("127.0.0.1:8080", async () => {
    let calls = 0;
    const fakeDb = {
      runTransaction: async (fn) => {
        calls += 1;
        if (calls === 1) {
          throw makeCode3Error("3 INVALID_ARGUMENT: Transaction is invalid or closed.");
        }
        return fn({});
      },
    };
    const result = await runLiveViewTransaction(fakeDb, async () => "ok");
    assert.equal(result, "ok", "must return the callback's own result normally once the retry succeeds");
    assert.equal(calls, 2, "must retry exactly once after the first code-3/matching-message failure");
  });
});

test("runLiveViewTransaction: emulator env + code3 with a DIFFERENT message does not retry", async () => {
  await withEmulatorEnv("127.0.0.1:8080", async () => {
    let calls = 0;
    const fakeDb = {
      runTransaction: async () => {
        calls += 1;
        throw makeCode3Error("3 INVALID_ARGUMENT: some other condition entirely");
      },
    };
    await assert.rejects(runLiveViewTransaction(fakeDb, async () => "ok"), (err) => err.code === 3);
    assert.equal(calls, 1, "must not retry a code-3 error whose message does not match exactly");
  });
});

test("runLiveViewTransaction: emulator env + UNKNOWN (code 2) does not retry", async () => {
  await withEmulatorEnv("127.0.0.1:8080", async () => {
    let calls = 0;
    const fakeDb = {
      runTransaction: async () => {
        calls += 1;
        const err = new Error("2 UNKNOWN: ");
        err.code = 2;
        throw err;
      },
    };
    await assert.rejects(runLiveViewTransaction(fakeDb, async () => "ok"), (err) => err.code === 2);
    assert.equal(calls, 1, "must never retry UNKNOWN, even in emulator mode");
  });
});

test("runLiveViewTransaction: no FIRESTORE_EMULATOR_HOST (production) + exact code3/message performs no outer retry", async () => {
  await withEmulatorEnv(undefined, async () => {
    let calls = 0;
    const fakeDb = {
      runTransaction: async () => {
        calls += 1;
        throw makeCode3Error("3 INVALID_ARGUMENT: Transaction is invalid or closed.");
      },
    };
    await assert.rejects(
      runLiveViewTransaction(fakeDb, async () => "ok"),
      (err) => err.code === 3 && err.message.includes("Transaction is invalid or closed")
    );
    assert.equal(
      calls,
      1,
      "production must never perform the emulator-only outer retry, even for the exact condition that IS retried under the emulator"
    );
  });
});

test("runLiveViewTransaction: the maximum retry bound is enforced", async () => {
  await withEmulatorEnv("127.0.0.1:8080", async () => {
    let calls = 0;
    const fakeDb = {
      runTransaction: async () => {
        calls += 1;
        throw makeCode3Error("3 INVALID_ARGUMENT: Transaction is invalid or closed.");
      },
    };
    await assert.rejects(runLiveViewTransaction(fakeDb, async () => "ok"), (err) => err.code === 3);
    assert.equal(
      calls,
      MAX_EMULATOR_TRANSACTION_RETRY_ATTEMPTS,
      `must attempt exactly ${MAX_EMULATOR_TRANSACTION_RETRY_ATTEMPTS} times total, never more`
    );
  });
});

// =================================================================================================
// Q. isValidLiveViewSessionIdFormat -- the ONE canonical Live View session-id validator (Fix 3).
// A Live View sessionId is generated exclusively via db.collection("liveViewSessions").doc().id,
// which always produces exactly 20 characters from [A-Za-z0-9] -- pinned to that exact shape, not
// a generous upper bound.
// =================================================================================================

test("SESSION ID FORMAT: a real db.collection(...).doc().id passes", () => {
  const realId = db.collection("liveViewSessions").doc().id;
  assert.equal(realId.length, LIVE_VIEW_SESSION_ID_LENGTH);
  assert.equal(isValidLiveViewSessionIdFormat(realId), true);
});

test("SESSION ID FORMAT: a 1-character ID fails", () => {
  assert.equal(isValidLiveViewSessionIdFormat("a"), false);
});

test("SESSION ID FORMAT: a 19-character ID fails", () => {
  assert.equal(isValidLiveViewSessionIdFormat("a".repeat(19)), false);
});

test("SESSION ID FORMAT: a 21-character ID fails", () => {
  assert.equal(isValidLiveViewSessionIdFormat("a".repeat(21)), false);
});

test("SESSION ID FORMAT: a 128-character ID fails", () => {
  assert.equal(isValidLiveViewSessionIdFormat("a".repeat(128)), false);
});

test("SESSION ID FORMAT: a slash-containing (otherwise 20-character) ID fails", () => {
  assert.equal(isValidLiveViewSessionIdFormat(`${"a".repeat(19)}/`), false);
});

// =================================================================================================
// R. Collision-free Home+Camera pair-duplicate detection (Fix 4). The allocator's own duplicate-
// pair check must never conflate two DIFFERENT (homeDeviceId, cameraDeviceId) pairs just because a
// naive delimiter-joined string representation happens to collide -- device IDs are otherwise-
// unrestricted strings and may themselves contain any character, including whatever separator a
// joined string would use.
// =================================================================================================

test("PAIR COLLISION: homeDeviceId=\"a b\"/cameraDeviceId=\"c\" and homeDeviceId=\"a\"/cameraDeviceId=\"b c\" are treated as DIFFERENT pairs, not a false duplicate", async () => {
  const scenario = await setupScenario();
  await entitlementsRef(scenario.ownerUid).set(validEntitlements({ maxConcurrentLiveSessions: 5 }));

  const idA = db.collection("liveViewSessions").doc().id;
  const idB = db.collection("liveViewSessions").doc().id;
  const now = admin.firestore.Timestamp.now();
  const leaseExpiresAt = admin.firestore.Timestamp.fromMillis(Date.now() + LIVE_VIEW_LEASE_TTL_MS);

  await allocatorRef(scenario.ownerUid).set(
    healthyAllocatorEnvelope({
      [idA]: { sessionId: idA, homeDeviceId: "a b", cameraDeviceId: "c", createdAt: now, leaseExpiresAt },
      [idB]: { sessionId: idB, homeDeviceId: "a", cameraDeviceId: "b c", createdAt: now, leaseExpiresAt },
    })
  );

  // If the delimiter collision were still present, this pair of entries would be misdiagnosed as
  // a duplicate and the WHOLE allocator would be rejected as corrupt -- denying even an unrelated,
  // genuine, distinct-pair START. With the fix, the allocator must parse as perfectly HEALTHY.
  const response = await attemptStart(scenario);
  assert.ok(response.sessionId, "a genuine, unrelated START must succeed -- the allocator must not be misdiagnosed as corrupt");

  const allocatorSnap = await allocatorRef(scenario.ownerUid).get();
  assert.equal(allocatorSnap.data().integrityStatus, "HEALTHY", "the allocator must never have been marked CORRUPT by this delimiter collision");
  assert.equal(Object.keys(allocatorSnap.data().activeSessions).length, 3, "both synthetic entries plus the new genuine one");

  await cleanupScenario(scenario, [response.sessionId]);
});
