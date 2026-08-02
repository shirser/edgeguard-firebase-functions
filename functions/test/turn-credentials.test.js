const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");

// Requiring lib/index.js runs admin.initializeApp() once; requires npm run
// build to have produced lib/ from src/ first (source of truth stays src).
const {
  getTurnCredentials,
  isValidTurnPurpose,
  buildTurnUsername,
  computeTurnCredential,
  buildTurnCredentialsResponse,
  verifyCameraAccess,
} = require("../lib/index.js");
const admin = require("firebase-admin");

const db = admin.firestore();
const CAMERA_ID = "camera-turn-test";
const OWNER_UID = "home-owner-uid";
const CAMERA_AUTH_UID = "camera-auth-uid";
const OTHER_UID = "someone-else-uid";

function claimRef() {
  return db.collection("cameraClaims").doc(CAMERA_ID);
}

// Minimal CallableRequest stand-in -- getTurnCredentials only reads
// request.auth.uid and request.data, so nothing else needs to be real.
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

// --- pure helpers ---

test("isValidTurnPurpose accepts only the 5 known purposes", () => {
  for (const purpose of [
    "LIVE_VIEW",
    "PLACEMENT_PREVIEW",
    "ACTIVITY_ZONE",
    "ENTRY_EXIT_LINE",
    "MEDIA_TRANSFER",
  ]) {
    assert.equal(isValidTurnPurpose(purpose), true);
  }
  assert.equal(isValidTurnPurpose("BOGUS"), false);
  assert.equal(isValidTurnPurpose(""), false);
  assert.equal(isValidTurnPurpose(undefined), false);
  assert.equal(isValidTurnPurpose(123), false);
});

test("buildTurnUsername formats as <expiresAtSeconds>:<uid>", () => {
  assert.equal(buildTurnUsername(1234567890, "uid-abc"), "1234567890:uid-abc");
});

test("computeTurnCredential is base64(HMAC-SHA1(secret, username))", () => {
  const secret = "shared-secret";
  const username = "1234567890:uid-abc";
  const expected = crypto.createHmac("sha1", secret).update(username).digest("base64");
  assert.equal(computeTurnCredential(secret, username), expected);
});

test("buildTurnCredentialsResponse: missing/empty secret throws internal", () => {
  assert.throws(() => buildTurnCredentialsResponse(undefined, "uid-abc"), (err) => err.code === "internal");
  assert.throws(() => buildTurnCredentialsResponse("", "uid-abc"), (err) => err.code === "internal");
});

test("buildTurnCredentialsResponse: expiresAt is exactly 600s after the given now", () => {
  const now = 1_800_000_000;
  const response = buildTurnCredentialsResponse("secret", "uid-abc", now);
  assert.equal(response.expiresAt, now + 600);
});

test("buildTurnCredentialsResponse: expiresAt defaults to ~600s from the real clock", () => {
  const before = Math.floor(Date.now() / 1000);
  const response = buildTurnCredentialsResponse("secret", "uid-abc");
  const after = Math.floor(Date.now() / 1000);
  assert.ok(response.expiresAt >= before + 600);
  assert.ok(response.expiresAt <= after + 600);
});

test("buildTurnCredentialsResponse: exact 4 STUN/TURN URLs, correct username and credential", () => {
  const now = 1_800_000_000;
  const uid = "uid-abc";
  const secret = "shared-secret";
  const response = buildTurnCredentialsResponse(secret, uid, now);

  assert.equal(response.iceServers.length, 1);
  assert.deepEqual(response.iceServers[0].urls, [
    "stun:turn.edgeguard.cc:3478",
    "turn:turn.edgeguard.cc:3478?transport=udp",
    "turn:turn.edgeguard.cc:3478?transport=tcp",
    "turns:turn.edgeguard.cc:5349?transport=tcp",
  ]);
  assert.equal(response.iceServers[0].username, `${now + 600}:${uid}`);
  assert.equal(
    response.iceServers[0].credential,
    crypto.createHmac("sha1", secret).update(`${now + 600}:${uid}`).digest("base64")
  );
});

// --- verifyCameraAccess (Firestore emulator) ---

test("verifyCameraAccess: not-found when cameraClaims doc doesn't exist", async () => {
  assert.equal(await verifyCameraAccess(db, CAMERA_ID, OWNER_UID), "not-found");
});

test("verifyCameraAccess: denied for a uid that is neither owner nor linked camera", async () => {
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });
  assert.equal(await verifyCameraAccess(db, CAMERA_ID, OTHER_UID), "denied");
});

test("verifyCameraAccess: ok for the linked Home owner uid", async () => {
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });
  assert.equal(await verifyCameraAccess(db, CAMERA_ID, OWNER_UID), "ok");
});

test("verifyCameraAccess: ok for the linked Camera identity uid", async () => {
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });
  assert.equal(await verifyCameraAccess(db, CAMERA_ID, CAMERA_AUTH_UID), "ok");
});

// --- getTurnCredentials.run() end-to-end ---

test("getTurnCredentials: no auth -> unauthenticated", async () => {
  await assert.rejects(
    getTurnCredentials.run(fakeRequest({ cameraDeviceId: CAMERA_ID, purpose: "LIVE_VIEW" }, undefined)),
    (err) => err.code === "unauthenticated"
  );
});

test("getTurnCredentials: empty cameraDeviceId -> invalid-argument", async () => {
  await assert.rejects(
    getTurnCredentials.run(fakeRequest({ cameraDeviceId: "", purpose: "LIVE_VIEW" }, OWNER_UID)),
    (err) => err.code === "invalid-argument"
  );
});

test("getTurnCredentials: missing cameraDeviceId -> invalid-argument", async () => {
  await assert.rejects(
    getTurnCredentials.run(fakeRequest({ purpose: "LIVE_VIEW" }, OWNER_UID)),
    (err) => err.code === "invalid-argument"
  );
});

test("getTurnCredentials: unknown purpose -> invalid-argument", async () => {
  await assert.rejects(
    getTurnCredentials.run(fakeRequest({ cameraDeviceId: CAMERA_ID, purpose: "BOGUS" }, OWNER_UID)),
    (err) => err.code === "invalid-argument"
  );
});

test("getTurnCredentials: camera not found -> not-found", async () => {
  await assert.rejects(
    getTurnCredentials.run(fakeRequest({ cameraDeviceId: CAMERA_ID, purpose: "LIVE_VIEW" }, OWNER_UID)),
    (err) => err.code === "not-found"
  );
});

test("getTurnCredentials: user without access -> permission-denied", async () => {
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });
  await assert.rejects(
    getTurnCredentials.run(fakeRequest({ cameraDeviceId: CAMERA_ID, purpose: "LIVE_VIEW" }, OTHER_UID)),
    (err) => err.code === "permission-denied"
  );
});

test("getTurnCredentials: missing secret -> internal", async () => {
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });
  delete process.env.TURN_REST_SECRET;
  await assert.rejects(
    getTurnCredentials.run(fakeRequest({ cameraDeviceId: CAMERA_ID, purpose: "LIVE_VIEW" }, OWNER_UID)),
    (err) => err.code === "internal"
  );
});

test("getTurnCredentials: successful response for the linked Home owner", async () => {
  process.env.TURN_REST_SECRET = "integration-test-secret";
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });

  const response = await getTurnCredentials.run(
    fakeRequest({ cameraDeviceId: CAMERA_ID, purpose: "LIVE_VIEW" }, OWNER_UID)
  );

  assert.equal(response.iceServers.length, 1);
  assert.deepEqual(response.iceServers[0].urls, [
    "stun:turn.edgeguard.cc:3478",
    "turn:turn.edgeguard.cc:3478?transport=udp",
    "turn:turn.edgeguard.cc:3478?transport=tcp",
    "turns:turn.edgeguard.cc:5349?transport=tcp",
  ]);
  assert.match(response.iceServers[0].username, /^\d+:home-owner-uid$/);
  assert.equal(
    response.iceServers[0].credential,
    crypto
      .createHmac("sha1", "integration-test-secret")
      .update(response.iceServers[0].username)
      .digest("base64")
  );

  const nowSeconds = Math.floor(Date.now() / 1000);
  assert.ok(response.expiresAt >= nowSeconds + 590 && response.expiresAt <= nowSeconds + 610);
});

test("getTurnCredentials: successful response for the linked Camera identity", async () => {
  process.env.TURN_REST_SECRET = "integration-test-secret";
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });

  const response = await getTurnCredentials.run(
    fakeRequest({ cameraDeviceId: CAMERA_ID, purpose: "LIVE_VIEW" }, CAMERA_AUTH_UID)
  );

  assert.match(response.iceServers[0].username, /^\d+:camera-auth-uid$/);
});
