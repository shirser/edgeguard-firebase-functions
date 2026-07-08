const test = require("node:test");
const assert = require("node:assert/strict");

// Requiring lib/index.js runs admin.initializeApp() once; requires npm run
// build to have produced lib/ from src/ first (source of truth stays src).
const { sendCameraNotification } = require("../lib/index.js");
const admin = require("firebase-admin");

const db = admin.firestore();
const CAMERA_ID = "camera-notif-test";

function targetRef() {
  return db.collection("cameraLinks").doc(CAMERA_ID).collection("notificationTarget").doc("home");
}

function queueRef(eventId) {
  return db.collection("cameraLinks").doc(CAMERA_ID).collection("notificationQueue").doc(eventId);
}

async function clearCameraLinksData() {
  for (const sub of ["notificationTarget", "notificationQueue"]) {
    const snap = await db.collection("cameraLinks").doc(CAMERA_ID).collection(sub).get();
    await Promise.all(snap.docs.map((d) => d.ref.delete()));
  }
}

test.beforeEach(clearCameraLinksData);
test.after(clearCameraLinksData);

test("successful send: queue -> sent, token left untouched", async () => {
  await targetRef().set({ fcmToken: "valid-token-1" });
  const ref = queueRef("evt-success");
  await ref.set({ status: "pending", type: "camera_offline", title: "Camera offline", body: "body" });

  const fakeSend = async (message) => {
    assert.equal(message.token, "valid-token-1");
    return "fake-message-id-1";
  };

  await sendCameraNotification(db, CAMERA_ID, "evt-success", (await ref.get()).data(), ref, fakeSend);

  const queueSnap = await ref.get();
  assert.equal(queueSnap.get("status"), "sent");
  assert.equal(queueSnap.get("messageId"), "fake-message-id-1");

  const targetSnap = await targetRef().get();
  assert.equal(targetSnap.get("fcmToken"), "valid-token-1");
});

test("registration-token-not-registered: token field is deleted, queue marked failed", async () => {
  await targetRef().set({ fcmToken: "dead-token", homeDeviceId: "home-1" });
  const ref = queueRef("evt-dead-token");
  await ref.set({ status: "pending", type: "camera_offline", title: "t", body: "b" });

  const err = Object.assign(new Error("not registered"), {
    code: "messaging/registration-token-not-registered",
  });
  const fakeSend = async () => {
    throw err;
  };

  await sendCameraNotification(db, CAMERA_ID, "evt-dead-token", (await ref.get()).data(), ref, fakeSend);

  const queueSnap = await ref.get();
  assert.equal(queueSnap.get("status"), "failed");

  const targetSnap = await targetRef().get();
  assert.equal(targetSnap.exists, true, "notificationTarget/home doc itself should survive");
  assert.equal(targetSnap.get("fcmToken"), undefined, "fcmToken field should be removed");
  assert.equal(targetSnap.get("homeDeviceId"), "home-1", "unrelated fields must be preserved");
});

test("invalid-registration-token: token field is deleted too", async () => {
  await targetRef().set({ fcmToken: "malformed-token" });
  const ref = queueRef("evt-invalid-token");
  await ref.set({ status: "pending", type: "camera_offline", title: "t", body: "b" });

  const err = Object.assign(new Error("invalid"), { code: "messaging/invalid-registration-token" });
  const fakeSend = async () => {
    throw err;
  };

  await sendCameraNotification(db, CAMERA_ID, "evt-invalid-token", (await ref.get()).data(), ref, fakeSend);

  const targetSnap = await targetRef().get();
  assert.equal(targetSnap.get("fcmToken"), undefined);
});

test("race: Home saves a new token during the failed send -> new token is preserved", async () => {
  await targetRef().set({ fcmToken: "old-token" });
  const ref = queueRef("evt-race");
  await ref.set({ status: "pending", type: "camera_offline", title: "t", body: "b" });

  const fakeSend = async () => {
    // Simulate the Home App saving a fresh token concurrently with this
    // failed send/cleanup — must not be clobbered by the old token's cleanup.
    await targetRef().set({ fcmToken: "new-token" }, { merge: true });
    throw Object.assign(new Error("not registered"), {
      code: "messaging/registration-token-not-registered",
    });
  };

  await sendCameraNotification(db, CAMERA_ID, "evt-race", (await ref.get()).data(), ref, fakeSend);

  const targetSnap = await targetRef().get();
  assert.equal(targetSnap.get("fcmToken"), "new-token");
});

for (const errorCode of [
  "messaging/internal-error",
  "messaging/server-unavailable",
  "messaging/message-rate-exceeded",
  "messaging/third-party-auth-error",
]) {
  test(`temporary error (${errorCode}): token is not deleted`, async () => {
    await targetRef().set({ fcmToken: "still-valid-token" });
    const ref = queueRef(`evt-temp-${errorCode.replace("/", "-")}`);
    await ref.set({ status: "pending", type: "camera_offline", title: "t", body: "b" });

    const fakeSend = async () => {
      throw Object.assign(new Error("temporary"), { code: errorCode });
    };

    await sendCameraNotification(
      db,
      CAMERA_ID,
      ref.id,
      (await ref.get()).data(),
      ref,
      fakeSend
    );

    const queueSnap = await ref.get();
    assert.equal(queueSnap.get("status"), "failed");

    const targetSnap = await targetRef().get();
    assert.equal(targetSnap.get("fcmToken"), "still-valid-token");
  });
}
