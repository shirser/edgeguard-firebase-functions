const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

// Requiring lib/index.js runs admin.initializeApp() once; requires npm run build to have produced
// lib/ from src/ first (source of truth stays src).
const {
  getTurnAuthorizationGrant,
  signTurnAuthorizationGrant,
  verifyTurnAuthorizationGrant,
  createDeviceChallenge,
  DEVICE_CHALLENGE_PURPOSES,
  TURN_GRANT_TTL_SECONDS,
  LIVE_VIEW_LEASE_TTL_MS,
} = require("../lib/index.js");
const admin = require("firebase-admin");

const db = admin.firestore();

// ---------------------------------------------------------------------------------------------
// getTurnAuthorizationGrant -- Firebase-side half of the VPS TURN Auth API design (see
// docs/COTURN_AUDIT.md). HOME requires a signed LIVE_VIEW_TURN_GRANT device proof (exactly like
// startLiveViewSession/renewLiveViewSession/endLiveViewSession's own HOME proofs, see
// liveViewSessions.test.js) -- account-level uid alone is deliberately NOT sufficient, since the
// same Google account can be signed into more than one Home installation. CAMERA needs no
// equivalent proof (uid === cameraAuthUid is already per-installation for Camera, see
// turnAuthorizationGrant.ts's own doc). Session/allocator docs are still constructed directly
// (same style as liveViewSessions.test.js's "ALLOCATOR STRICT" section) rather than running the
// full startLiveViewSession flow -- this module's own authorization logic is what's under test.
// ---------------------------------------------------------------------------------------------

function sessionRef(sessionId) {
  return db.collection("liveViewSessions").doc(sessionId);
}
function allocatorRef(uid) {
  return db.collection("liveViewUserStates").doc(uid);
}
function claimRef(cameraDeviceId) {
  return db.collection("cameraClaims").doc(cameraDeviceId);
}
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

function generateEcKeyPair() {
  return crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}
function publicKeySpkiBase64(publicKey) {
  return publicKey.export({ type: "spki", format: "der" }).toString("base64");
}

// Seeds a fully keystore-provisioned HOME registeredDevices document -- mirrors
// liveViewSessions.test.js's own seedHomeDevice exactly, needed here because getTurnAuthorizationGrant
// now verifies a real Keystore signature for HOME, not just request.auth.uid.
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

// Requests a fresh, signed LIVE_VIEW_TURN_GRANT device-proof envelope for one specific Home
// installation -- ready to pass as `deviceProof` to getTurnAuthorizationGrant. Single-use, matching
// real client behavior (one challenge per grant-request attempt).
async function signGrantChallenge(ownerUid, homeDeviceId, keyPair, sessionId) {
  const challengeResp = await createDeviceChallenge.run(
    fakeRequest(
      { deviceId: homeDeviceId, purpose: DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_TURN_GRANT, requestPayload: { sessionId } },
      ownerUid
    )
  );
  const signature = crypto
    .sign("sha256", Buffer.from(challengeResp.canonicalPayload, "utf8"), keyPair.privateKey)
    .toString("base64");
  return { protocolVersion: 1, challengeId: challengeResp.challengeId, signature };
}

// Builds a mutually-consistent {sessionDoc, allocatorEntry} pair -- entry.createdAt/leaseExpiresAt
// must be the exact same Timestamp instance/value as the session's own, per
// validateAllocatorEntryAgainstSession's strict equality checks. Also seeds a real, keystore-backed
// HOME registeredDevices document for `homeDeviceId` (and, when `homeKeyPair` is supplied, an
// *additional* HOME device belonging to the SAME ownerUid but a DIFFERENT device id/keypair --
// the "second Home installation" scenario the device-binding fix exists to deny).
async function setupActiveScenario(overrides = {}) {
  const ownerUid = overrides.ownerUid || `owner-${db.collection("_").doc().id}`;
  const cameraAuthUid = overrides.cameraAuthUid || `camera-auth-${db.collection("_").doc().id}`;
  const homeDeviceId = overrides.homeDeviceId || `home-device-${db.collection("_").doc().id}`;
  const cameraDeviceId = overrides.cameraDeviceId || `camera-device-${db.collection("_").doc().id}`;
  const sessionId = db.collection("liveViewSessions").doc().id;
  const now = admin.firestore.Timestamp.now();
  const leaseExpiresAt = admin.firestore.Timestamp.fromMillis(Date.now() + LIVE_VIEW_LEASE_TTL_MS);
  const homeKeyPair = overrides.homeKeyPair || generateEcKeyPair();

  await sessionRef(sessionId).set({
    schemaVersion: 1,
    sessionId,
    ownerUid,
    homeDeviceId,
    cameraDeviceId,
    status: "ACTIVE",
    createdAt: now,
    updatedAt: now,
    leaseExpiresAt,
    endedAt: null,
  });

  await allocatorRef(ownerUid).set({
    schemaVersion: 1,
    updatedAt: now,
    integrityStatus: "HEALTHY",
    corruptAt: null,
    corruptionReason: null,
    activeSessions: {
      [sessionId]: {
        sessionId,
        homeDeviceId,
        cameraDeviceId,
        createdAt: now,
        leaseExpiresAt,
      },
    },
  });

  await claimRef(cameraDeviceId).set({ uid: ownerUid, cameraAuthUid });
  await seedHomeDevice(homeDeviceId, ownerUid, homeKeyPair, overrides.homeOverrides ?? {});

  return { sessionId, ownerUid, cameraAuthUid, homeDeviceId, cameraDeviceId, homeKeyPair };
}

async function cleanupScenario(scenario, extraHomeDeviceIds = []) {
  await Promise.all([
    sessionRef(scenario.sessionId).delete(),
    allocatorRef(scenario.ownerUid).delete(),
    claimRef(scenario.cameraDeviceId).delete(),
    registryRef(scenario.homeDeviceId).delete(),
    ...extraHomeDeviceIds.map((id) => registryRef(id).delete()),
  ]);
}

// Issues a grant for the session's OWN homeDeviceId/keypair -- the common-case success path used
// by most tests below.
async function requestHomeGrant(scenario, sessionId = scenario.sessionId, uid = scenario.ownerUid) {
  const deviceProof = await signGrantChallenge(scenario.ownerUid, scenario.homeDeviceId, scenario.homeKeyPair, sessionId);
  return getTurnAuthorizationGrant.run(fakeRequest({ sessionId, role: "HOME", deviceProof }, uid));
}

test.beforeEach(() => {
  process.env.TURN_GRANT_SIGNING_SECRET = "grant-test-secret";
});
test.afterEach(() => {
  delete process.env.TURN_GRANT_SIGNING_SECRET;
});

// --- pure sign/verify round trip ---

test("signTurnAuthorizationGrant/verifyTurnAuthorizationGrant round-trips a valid grant", () => {
  const payload = { sessionId: "a".repeat(20), role: "HOME", uid: "uid-1", exp: 9999999999 };
  const grant = signTurnAuthorizationGrant(payload, "secret-a");
  const result = verifyTurnAuthorizationGrant(grant, "secret-a", 1000);
  assert.equal(result.valid, true);
  assert.deepEqual(result.payload, payload);
});

test("verifyTurnAuthorizationGrant rejects a grant signed with a different secret", () => {
  const payload = { sessionId: "a".repeat(20), role: "HOME", uid: "uid-1", exp: 9999999999 };
  const grant = signTurnAuthorizationGrant(payload, "secret-a");
  assert.equal(verifyTurnAuthorizationGrant(grant, "secret-b", 1000).valid, false);
});

test("verifyTurnAuthorizationGrant rejects a tampered payload (signature no longer matches)", () => {
  const payload = { sessionId: "a".repeat(20), role: "HOME", uid: "uid-1", exp: 9999999999 };
  const grant = signTurnAuthorizationGrant(payload, "secret-a");
  const [payloadB64, sig] = grant.split(".");
  const tamperedPayload = Buffer.from(JSON.stringify({ ...payload, role: "CAMERA" })).toString("base64url");
  assert.equal(verifyTurnAuthorizationGrant(`${tamperedPayload}.${sig}`, "secret-a", 1000).valid, false);
  void payloadB64;
});

test("verifyTurnAuthorizationGrant rejects an expired grant", () => {
  const payload = { sessionId: "a".repeat(20), role: "HOME", uid: "uid-1", exp: 1000 };
  const grant = signTurnAuthorizationGrant(payload, "secret-a");
  assert.equal(verifyTurnAuthorizationGrant(grant, "secret-a", 1000).valid, false);
  assert.equal(verifyTurnAuthorizationGrant(grant, "secret-a", 999).valid, true);
});

test("verifyTurnAuthorizationGrant rejects malformed input (no dot, garbage base64url, wrong part count)", () => {
  assert.equal(verifyTurnAuthorizationGrant("not-a-grant", "secret-a", 1000).valid, false);
  assert.equal(verifyTurnAuthorizationGrant("a.b.c", "secret-a", 1000).valid, false);
  assert.equal(verifyTurnAuthorizationGrant("!!!.!!!", "secret-a", 1000).valid, false);
});

// --- getTurnAuthorizationGrant callable ---

test("getTurnAuthorizationGrant rejects an unauthenticated caller", async () => {
  await assert.rejects(
    () => getTurnAuthorizationGrant.run(fakeRequest({ sessionId: "a".repeat(20), role: "HOME" }, undefined)),
    (err) => err.code === "unauthenticated"
  );
});

test("getTurnAuthorizationGrant rejects an unexpected extra field", async () => {
  await assert.rejects(
    () =>
      getTurnAuthorizationGrant.run(
        fakeRequest({ sessionId: "a".repeat(20), role: "HOME", extra: 1 }, "some-uid")
      ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_REQUEST"
  );
});

test("getTurnAuthorizationGrant rejects a malformed sessionId", async () => {
  await assert.rejects(
    () => getTurnAuthorizationGrant.run(fakeRequest({ sessionId: "too-short", role: "HOME" }, "some-uid")),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_SESSION_ID"
  );
});

test("getTurnAuthorizationGrant rejects an invalid role", async () => {
  await assert.rejects(
    () => getTurnAuthorizationGrant.run(fakeRequest({ sessionId: "a".repeat(20), role: "OWNER" }, "some-uid")),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_ROLE"
  );
});

test("getTurnAuthorizationGrant rejects a HOME request with no deviceProof at all", async () => {
  await assert.rejects(
    () => getTurnAuthorizationGrant.run(fakeRequest({ sessionId: "a".repeat(20), role: "HOME" }, "some-uid")),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_DEVICE_PROOF"
  );
});

test("getTurnAuthorizationGrant rejects a HOME request with a malformed deviceProof envelope", async () => {
  await assert.rejects(
    () =>
      getTurnAuthorizationGrant.run(
        fakeRequest({ sessionId: "a".repeat(20), role: "HOME", deviceProof: { protocolVersion: 1 } }, "some-uid")
      ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_DEVICE_PROOF"
  );
});

test("getTurnAuthorizationGrant rejects a CAMERA request that includes a deviceProof field", async () => {
  const scenario = await setupActiveScenario();
  await assert.rejects(
    () =>
      getTurnAuthorizationGrant.run(
        fakeRequest(
          { sessionId: scenario.sessionId, role: "CAMERA", deviceProof: { protocolVersion: 1, challengeId: "x", signature: "AA==" } },
          scenario.cameraAuthUid
        )
      ),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_REQUEST"
  );
  await cleanupScenario(scenario);
});

test("getTurnAuthorizationGrant issues a valid grant for the HOME owner of an ACTIVE session, signed by the session's own homeDeviceId", async () => {
  const scenario = await setupActiveScenario();
  const before = Math.floor(Date.now() / 1000);
  const result = await requestHomeGrant(scenario);
  assert.equal(typeof result.grant, "string");
  const verified = verifyTurnAuthorizationGrant(result.grant, "grant-test-secret", before);
  assert.equal(verified.valid, true);
  assert.equal(verified.payload.sessionId, scenario.sessionId);
  assert.equal(verified.payload.role, "HOME");
  assert.equal(verified.payload.uid, scenario.ownerUid);
  assert.equal(result.expiresAt, verified.payload.exp);
  assert.ok(result.expiresAt <= before + TURN_GRANT_TTL_SECONDS + 1);
  await cleanupScenario(scenario);
});

test("getTurnAuthorizationGrant issues a valid grant for the linked CAMERA identity", async () => {
  const scenario = await setupActiveScenario();
  const result = await getTurnAuthorizationGrant.run(
    fakeRequest({ sessionId: scenario.sessionId, role: "CAMERA" }, scenario.cameraAuthUid)
  );
  const verified = verifyTurnAuthorizationGrant(result.grant, "grant-test-secret", 0);
  assert.equal(verified.valid, true);
  assert.equal(verified.payload.role, "CAMERA");
  assert.equal(verified.payload.uid, scenario.cameraAuthUid);
  await cleanupScenario(scenario);
});

// --- SECURITY REGRESSION: Home device binding (the gap this fix closes) -----------------------
// Before this fix, getTurnAuthorizationGrant authorized HOME purely via `uid === session.ownerUid`
// -- any Home installation signed into the SAME Google account as the session's owner could obtain
// a grant for a session it never started, because the same account can own more than one Home
// installation (each its own registeredDevices document/Keystore key). These tests prove a SECOND
// Home device belonging to the exact same ownerUid, but not the one the session is bound to, is
// denied -- and that the legitimate device (the one that actually holds the session) still works.

test("SECURITY: a second Home installation under the SAME ownerUid, but not the session's own homeDeviceId, is denied a grant", async () => {
  const scenario = await setupActiveScenario();
  const otherHomeDeviceId = `home-device-other-${db.collection("_").doc().id}`;
  const otherKeyPair = generateEcKeyPair();
  // Same ownerUid, same Firebase account, genuinely its own separate registeredDevices/Keystore
  // identity -- exactly the "second Home installation" scenario from turnAuthorizationGrant.ts's
  // own doc, not a forged/unregistered device.
  await seedHomeDevice(otherHomeDeviceId, scenario.ownerUid, otherKeyPair);

  const deviceProof = await signGrantChallenge(scenario.ownerUid, otherHomeDeviceId, otherKeyPair, scenario.sessionId);
  await assert.rejects(
    () =>
      getTurnAuthorizationGrant.run(
        fakeRequest({ sessionId: scenario.sessionId, role: "HOME", deviceProof }, scenario.ownerUid)
      ),
    (err) => err.code === "permission-denied" && err.message === "TURN_GRANT_DENIED"
  );

  // The legitimate device (the one the session is actually bound to) still succeeds -- proves the
  // denial above is specifically about device identity, not e.g. a broken scenario fixture.
  const result = await requestHomeGrant(scenario);
  assert.equal(typeof result.grant, "string");

  await cleanupScenario(scenario, [otherHomeDeviceId]);
});

test("getTurnAuthorizationGrant denies a HOME request from a caller whose Keystore signature is genuine but for a different, unrelated Home account entirely", async () => {
  const scenario = await setupActiveScenario();
  const strangerUid = `stranger-${db.collection("_").doc().id}`;
  const strangerHomeDeviceId = `home-device-stranger-${db.collection("_").doc().id}`;
  const strangerKeyPair = generateEcKeyPair();
  await seedHomeDevice(strangerHomeDeviceId, strangerUid, strangerKeyPair);

  // createDeviceChallenge itself is authUid-scoped (the stranger can only ever get a challenge
  // bound to their OWN authUid/device) -- so this can only ever fail identity, never succeed as
  // scenario.ownerUid.
  const deviceProof = await signGrantChallenge(strangerUid, strangerHomeDeviceId, strangerKeyPair, scenario.sessionId);
  await assert.rejects(
    () =>
      getTurnAuthorizationGrant.run(
        fakeRequest({ sessionId: scenario.sessionId, role: "HOME", deviceProof }, strangerUid)
      ),
    (err) => err.code === "permission-denied" && err.message === "TURN_GRANT_DENIED"
  );

  await cleanupScenario(scenario, [strangerHomeDeviceId]);
});

test("getTurnAuthorizationGrant denies a HOME request with a wrong (different keypair) signature", async () => {
  const scenario = await setupActiveScenario();
  const wrongKeyPair = generateEcKeyPair();
  const challengeResp = await createDeviceChallenge.run(
    fakeRequest(
      {
        deviceId: scenario.homeDeviceId,
        purpose: DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_TURN_GRANT,
        requestPayload: { sessionId: scenario.sessionId },
      },
      scenario.ownerUid
    )
  );
  const badSignature = crypto
    .sign("sha256", Buffer.from(challengeResp.canonicalPayload, "utf8"), wrongKeyPair.privateKey)
    .toString("base64");
  await assert.rejects(
    () =>
      getTurnAuthorizationGrant.run(
        fakeRequest(
          {
            sessionId: scenario.sessionId,
            role: "HOME",
            deviceProof: { protocolVersion: 1, challengeId: challengeResp.challengeId, signature: badSignature },
          },
          scenario.ownerUid
        )
      ),
    (err) => err.code === "permission-denied" && err.message === "TURN_GRANT_DENIED"
  );
  await cleanupScenario(scenario);
});

test("getTurnAuthorizationGrant denies replaying an already-consumed deviceProof", async () => {
  const scenario = await setupActiveScenario();
  const deviceProof = await signGrantChallenge(scenario.ownerUid, scenario.homeDeviceId, scenario.homeKeyPair, scenario.sessionId);
  const first = await getTurnAuthorizationGrant.run(
    fakeRequest({ sessionId: scenario.sessionId, role: "HOME", deviceProof }, scenario.ownerUid)
  );
  assert.equal(typeof first.grant, "string");
  await assert.rejects(
    () =>
      getTurnAuthorizationGrant.run(
        fakeRequest({ sessionId: scenario.sessionId, role: "HOME", deviceProof }, scenario.ownerUid)
      ),
    (err) => err.code === "permission-denied" && err.message === "TURN_GRANT_DENIED"
  );
  await cleanupScenario(scenario);
});

test("getTurnAuthorizationGrant denies a HOME grant for a Home device suspended AFTER the deviceProof was signed (race-window enforcement)", async () => {
  // createDeviceChallenge itself already refuses to issue a challenge to a suspended device (see
  // checkDeviceChallengeEligibility) -- that alone would make a straightforward "suspend, then try"
  // test pass for the wrong reason. This test instead signs the proof while the device is still
  // active, THEN suspends it, THEN redeems the grant -- isolating getTurnAuthorizationGrant's own
  // operational enforcement (verification.operational.operational), which exists specifically to
  // close the race window between challenge issuance and grant redemption, exactly like RENEW's own
  // enforcement of the same check.
  const scenario = await setupActiveScenario();
  const deviceProof = await signGrantChallenge(scenario.ownerUid, scenario.homeDeviceId, scenario.homeKeyPair, scenario.sessionId);
  await registryRef(scenario.homeDeviceId).update({ status: "suspended", suspensionReason: "policy" });
  await assert.rejects(
    () =>
      getTurnAuthorizationGrant.run(
        fakeRequest({ sessionId: scenario.sessionId, role: "HOME", deviceProof }, scenario.ownerUid)
      ),
    (err) => err.code === "permission-denied" && err.message === "TURN_GRANT_DENIED"
  );
  await cleanupScenario(scenario);
});

test("getTurnAuthorizationGrant denies a CAMERA request from a caller who is not the linked camera identity", async () => {
  const scenario = await setupActiveScenario();
  await assert.rejects(
    () =>
      getTurnAuthorizationGrant.run(fakeRequest({ sessionId: scenario.sessionId, role: "CAMERA" }, "someone-else")),
    (err) => err.code === "permission-denied" && err.message === "TURN_GRANT_DENIED"
  );
  await cleanupScenario(scenario);
});

test("getTurnAuthorizationGrant denies a HOME request with no deviceProof for a nonexistent session (shape check runs first)", async () => {
  await assert.rejects(
    () => getTurnAuthorizationGrant.run(fakeRequest({ sessionId: "b".repeat(20), role: "HOME" }, "some-uid")),
    (err) => err.code === "invalid-argument" && err.message === "INVALID_DEVICE_PROOF"
  );
});

test("getTurnAuthorizationGrant denies a HOME request with a genuine deviceProof for a nonexistent session", async () => {
  const ownerUid = `owner-${db.collection("_").doc().id}`;
  const homeDeviceId = `home-device-${db.collection("_").doc().id}`;
  const keyPair = generateEcKeyPair();
  await seedHomeDevice(homeDeviceId, ownerUid, keyPair);
  const nonexistentSessionId = "b".repeat(20);
  const deviceProof = await signGrantChallenge(ownerUid, homeDeviceId, keyPair, nonexistentSessionId);
  await assert.rejects(
    () =>
      getTurnAuthorizationGrant.run(
        fakeRequest({ sessionId: nonexistentSessionId, role: "HOME", deviceProof }, ownerUid)
      ),
    (err) => err.code === "permission-denied" && err.message === "TURN_GRANT_DENIED"
  );
  await registryRef(homeDeviceId).delete();
});

test("getTurnAuthorizationGrant denies a request for an ENDED session", async () => {
  const scenario = await setupActiveScenario();
  await sessionRef(scenario.sessionId).update({ status: "ENDED", endedAt: admin.firestore.Timestamp.now() });
  await allocatorRef(scenario.ownerUid).update({ activeSessions: {} });
  await assert.rejects(
    () => requestHomeGrant(scenario),
    (err) => err.code === "permission-denied" && err.message === "TURN_GRANT_DENIED"
  );
  await cleanupScenario(scenario);
});

test("getTurnAuthorizationGrant denies a request whose allocator entry no longer matches the session (stale/mismatched)", async () => {
  const scenario = await setupActiveScenario();
  // Corrupt the allocator entry's homeDeviceId so validateAllocatorEntryAgainstSession fails even
  // though the session itself still parses as a valid, ACTIVE session.
  await allocatorRef(scenario.ownerUid).update({
    [`activeSessions.${scenario.sessionId}.homeDeviceId`]: "a-different-home-device",
  });
  await assert.rejects(
    () => requestHomeGrant(scenario),
    (err) => err.code === "permission-denied" && err.message === "TURN_GRANT_DENIED"
  );
  await cleanupScenario(scenario);
});

test("getTurnAuthorizationGrant denies a request whose allocator has no entry for this sessionId", async () => {
  const scenario = await setupActiveScenario();
  await allocatorRef(scenario.ownerUid).update({ activeSessions: {} });
  await assert.rejects(
    () => requestHomeGrant(scenario),
    (err) => err.code === "permission-denied" && err.message === "TURN_GRANT_DENIED"
  );
  await cleanupScenario(scenario);
});

test("getTurnAuthorizationGrant denies a request when the allocator is CORRUPT", async () => {
  const scenario = await setupActiveScenario();
  await allocatorRef(scenario.ownerUid).set({
    schemaVersion: 1,
    updatedAt: admin.firestore.Timestamp.now(),
    integrityStatus: "CORRUPT",
    corruptAt: admin.firestore.Timestamp.now(),
    corruptionReason: "PARSE_FAILED",
  });
  await assert.rejects(
    () => requestHomeGrant(scenario),
    (err) => err.code === "permission-denied" && err.message === "TURN_GRANT_DENIED"
  );
  await cleanupScenario(scenario);
});

test("getTurnAuthorizationGrant fails internal (missing secret) rather than signing with an empty key", async () => {
  const scenario = await setupActiveScenario();
  delete process.env.TURN_GRANT_SIGNING_SECRET;
  await assert.rejects(
    () => requestHomeGrant(scenario),
    (err) => err.code === "internal"
  );
  process.env.TURN_GRANT_SIGNING_SECRET = "grant-test-secret";
  await cleanupScenario(scenario);
});
