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

test("getTurnCredentials: missing secret -> internal (Camera legacy path)", async () => {
  // OWNER_UID (Home) is used for this file's other pre-existing scenario checks, but the
  // missing-secret error only surfaces from buildTurnCredentialsResponse, which the Home path no
  // longer reaches without a deviceProof (see the fail-closed tests below) -- CAMERA_AUTH_UID
  // still reaches it via the preserved Camera legacy path.
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });
  delete process.env.TURN_REST_SECRET;
  await assert.rejects(
    getTurnCredentials.run(fakeRequest({ cameraDeviceId: CAMERA_ID, purpose: "LIVE_VIEW" }, CAMERA_AUTH_UID)),
    (err) => err.code === "internal"
  );
});

// --- Home fail-closed: deviceProof is now mandatory for the linked Home owner ------------------
// (see index.ts's getTurnCredentials, "Fail-closed for HOME"). Camera does not yet send a
// deviceProof (edgeguard-camera-android's TurnCredentialsProvider only ever sends
// {cameraDeviceId, purpose}), so its own legacy, unsigned path is deliberately preserved -- see
// "successful response for the linked Camera identity (preserved legacy path)" below.

test("getTurnCredentials: an old unsigned request from the linked Home owner is rejected with DEVICE_PROOF_REQUIRED", async () => {
  process.env.TURN_REST_SECRET = "integration-test-secret";
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });

  await assert.rejects(
    getTurnCredentials.run(fakeRequest({ cameraDeviceId: CAMERA_ID, purpose: "LIVE_VIEW" }, OWNER_UID)),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_PROOF_REQUIRED"
  );
});

test("getTurnCredentials: legacy top-level proof fields (no nested deviceProof) from the Home owner are ignored, still rejected", async () => {
  process.env.TURN_REST_SECRET = "integration-test-secret";
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });

  await assert.rejects(
    getTurnCredentials.run(
      fakeRequest(
        {
          cameraDeviceId: CAMERA_ID,
          purpose: "LIVE_VIEW",
          // A stale/malicious client's alternative top-level fields -- none of these are ever
          // read as proof material; since there is no `deviceProof` key at all, this is exactly
          // the same rejection as the no-fields-at-all case above.
          signature: "AAAA",
          challengeId: "some-challenge-id",
          protocolVersion: 1,
          homeDeviceId: "some-home-device-id",
          deviceId: "some-device-id",
        },
        OWNER_UID
      )
    ),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_PROOF_REQUIRED"
  );
});

test("getTurnCredentials: the Home fail-closed rejection performs no write and never reaches credential issuance", async () => {
  // Regression / call-count proxy (node:test integration style, no mocked seams -- see this
  // repo's own test conventions): deleting TURN_REST_SECRET means the only way this call could
  // still resolve or throw "internal" is if it reached buildTurnCredentialsResponse (the credential
  // issuer). Getting DEVICE_PROOF_REQUIRED instead of "internal" proves neither the issuer nor the
  // deviceProof verifier (never entered at all, since deviceProof is absent) was ever reached --
  // "verifier calls = 0, issuer calls = 0" for this exact request.
  delete process.env.TURN_REST_SECRET;
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });

  await assert.rejects(
    getTurnCredentials.run(fakeRequest({ cameraDeviceId: CAMERA_ID, purpose: "LIVE_VIEW" }, OWNER_UID)),
    (err) => err.code === "failed-precondition" && err.message === "DEVICE_PROOF_REQUIRED"
  );
});

test("getTurnCredentials: DEVICE_PROOF_REQUIRED rejection never logs cameraDeviceId or uid", async () => {
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });

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
    await assert.rejects(
      getTurnCredentials.run(fakeRequest({ cameraDeviceId: CAMERA_ID, purpose: "LIVE_VIEW" }, OWNER_UID)),
      (err) => err.code === "failed-precondition" && err.message === "DEVICE_PROOF_REQUIRED"
    );
  } finally {
    process.stdout.write = originalStdoutWrite;
    process.stderr.write = originalStderrWrite;
  }

  // Inspect the specific new GET_TURN_CREDENTIALS_DEVICE_PROOF_REQUIRED log entry's own fields --
  // not the entire captured output, which also (legitimately, unchanged, out of this task's
  // scope) includes the pre-existing GET_TURN_CREDENTIALS_START line logging uid/cameraDeviceId,
  // same as every other pre-existing log line in this callable.
  const rejectionLine = lines.find((line) => line.includes("GET_TURN_CREDENTIALS_DEVICE_PROOF_REQUIRED"));
  assert.ok(rejectionLine, "the rejection log line should still fire");
  const rejectionEntry = JSON.parse(rejectionLine);
  assert.deepEqual(Object.keys(rejectionEntry).sort(), ["message", "purpose", "severity"].sort());
  assert.equal(rejectionEntry.purpose, "LIVE_VIEW");
});

// getTurnCredentials: successful response for the linked Camera identity -- Camera's own legacy,
// unsigned path is deliberately preserved (see this file's own comment above): Camera does not yet
// send a deviceProof, so this must keep working exactly as before the Home fail-closed change, with
// the exact same response schema.
test("getTurnCredentials: successful response for the linked Camera identity (preserved legacy path)", async () => {
  process.env.TURN_REST_SECRET = "integration-test-secret";
  await claimRef().set({ uid: OWNER_UID, cameraAuthUid: CAMERA_AUTH_UID });

  const response = await getTurnCredentials.run(
    fakeRequest({ cameraDeviceId: CAMERA_ID, purpose: "LIVE_VIEW" }, CAMERA_AUTH_UID)
  );

  assert.equal(response.iceServers.length, 1);
  assert.deepEqual(response.iceServers[0].urls, [
    "stun:turn.edgeguard.cc:3478",
    "turn:turn.edgeguard.cc:3478?transport=udp",
    "turn:turn.edgeguard.cc:3478?transport=tcp",
    "turns:turn.edgeguard.cc:5349?transport=tcp",
  ]);
  assert.match(response.iceServers[0].username, /^\d+:camera-auth-uid$/);
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
