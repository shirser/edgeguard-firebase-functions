import { before, after, beforeEach, describe, it } from "node:test";
import { assertSucceeds, assertFails } from "@firebase/rules-unit-testing";
import { doc, getDoc, setDoc, updateDoc, deleteDoc } from "firebase/firestore";
import {
  CAMERA_ID,
  CAMERA_UID,
  HOME_UID,
  createTestEnv,
  seedClaim,
  seedDoc,
  mergeDoc,
  validCommand,
  validConfirmPlacementCommand,
  validSession,
  validCandidate,
  homeDb,
  cameraDb,
  strangerDb,
  unauthedDb,
} from "./helpers.js";

let testEnv;

before(async () => {
  testEnv = await createTestEnv();
});

after(async () => {
  await testEnv.cleanup();
});

beforeEach(async () => {
  await testEnv.clearFirestore();
});

describe("Home owner", () => {
  beforeEach(() => seedClaim(testEnv));

  it("reads activityEvents of its own camera", async () => {
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "activityEvents", "evt1"], {
      type: "camera_offline",
      createdAt: new Date(),
    });
    await assertSucceeds(
      getDoc(doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "activityEvents", "evt1"))
    );
  });

  it("reads and updates notificationSettings", async () => {
    const db = homeDb(testEnv);
    const ref = doc(db, "cameraLinks", CAMERA_ID, "notificationSettings", "camera_offline");
    await assertSucceeds(setDoc(ref, { enabled: false }));
    await assertSucceeds(getDoc(ref));
    await assertSucceeds(updateDoc(ref, { enabled: true }));
  });

  it("writes notificationTarget/home", async () => {
    await assertSucceeds(
      setDoc(doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "notificationTarget", "home"), {
        fcmToken: "home-fcm-token",
      })
    );
  });

  it("creates a command using the exact fields the Home App writes", async () => {
    await assertSucceeds(
      setDoc(doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd1"), validCommand())
    );
  });

  it("creates a CONFIRM_PLACEMENT command carrying sessionId/transferId", async () => {
    await assertSucceeds(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd1"),
        validConfirmPlacementCommand()
      )
    );
  });

  it("cannot create a CONFIRM_PLACEMENT command missing sessionId/transferId", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd1"),
        validCommand({ type: "CONFIRM_PLACEMENT" })
      )
    );
  });

  it("cannot create a CONFIRM_PLACEMENT command with an empty sessionId", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd1"),
        validConfirmPlacementCommand({ sessionId: "" })
      )
    );
  });

  it("cannot create a CONFIRM_PLACEMENT command with an empty transferId", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd1"),
        validConfirmPlacementCommand({ transferId: "" })
      )
    );
  });

  it("cannot create a UNPAIR command carrying sessionId/transferId", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd1"),
        validCommand({ sessionId: "session-1", transferId: "transfer-1" })
      )
    );
  });

  it("cannot create a command with a field the Home App never writes", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd1"),
        validCommand({ extra: "not part of the real schema" })
      )
    );
  });

  it("cannot create a command with a non-pending initial status", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd1"),
        validCommand({ status: "completed" })
      )
    );
  });

  it("cannot create a command with an unrecognized type", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd1"),
        validCommand({ type: "REBOOT" })
      )
    );
  });

  it("cannot create a command claiming to be created by someone else", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd1"),
        validCommand({ createdBy: "someone-else-uid" })
      )
    );
  });

  it("cannot write notificationQueue", async () => {
    await assertFails(
      setDoc(doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "notificationQueue", "n1"), {
        status: "pending",
      })
    );
  });

  it("cannot write activityEvents", async () => {
    await assertFails(
      setDoc(doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "activityEvents", "evtX"), {
        type: "spoofed",
      })
    );
  });

  it("cannot write pairingState", async () => {
    await assertFails(
      setDoc(doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "pairingState", "current"), {
        status: "paired",
      })
    );
  });
});

describe("Linked Camera", () => {
  beforeEach(() => seedClaim(testEnv));

  it("reads pairingState", async () => {
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "pairingState", "current"], {
      status: "paired",
    });
    await assertSucceeds(
      getDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "pairingState", "current"))
    );
  });

  it("reads commands", async () => {
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "commands", "cmd1"], validCommand());
    await assertSucceeds(
      getDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd1"))
    );
  });

  it("performs the exact completeCommand update the Camera App does (status + completedAt)", async () => {
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "commands", "cmd1"], validCommand());
    await assertSucceeds(
      updateDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd1"), {
        status: "completed",
        completedAt: new Date(),
      })
    );
  });

  it("cannot modify command-definition fields it does not own (type/createdBy)", async () => {
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "commands", "cmd1"], validCommand());
    await assertFails(
      updateDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd1"), {
        type: "factory_reset",
        createdBy: CAMERA_UID,
      })
    );
  });

  it("cannot add an arbitrary new field while completing a command", async () => {
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "commands", "cmd1"], validCommand());
    await assertFails(
      updateDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd1"), {
        status: "completed",
        completedAt: new Date(),
        result: "ok",
      })
    );
  });

  it("cannot transition status to anything other than completed", async () => {
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "commands", "cmd1"], validCommand());
    await assertFails(
      updateDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd1"), {
        status: "cancelled",
      })
    );
  });

  it("cannot re-complete a command that is already completed", async () => {
    await seedDoc(
      testEnv,
      ["cameraLinks", CAMERA_ID, "commands", "cmd1"],
      validCommand({ status: "completed", completedAt: new Date() })
    );
    await assertFails(
      updateDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd1"), {
        status: "completed",
        completedAt: new Date(),
      })
    );
  });

  it("cannot create commands", async () => {
    await assertFails(
      setDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd2"), validCommand())
    );
  });

  it("cannot write notificationQueue", async () => {
    await assertFails(
      setDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "notificationQueue", "n1"), {
        status: "pending",
      })
    );
  });

  it("cannot write activityEvents", async () => {
    await assertFails(
      setDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "activityEvents", "evtX"), {
        type: "spoofed",
      })
    );
  });

  it("cannot read notificationTarget/home", async () => {
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "notificationTarget", "home"], {
      fcmToken: "home-fcm-token",
    });
    await assertFails(
      getDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "notificationTarget", "home"))
    );
  });
});

describe("Stranger authenticated user", () => {
  beforeEach(async () => {
    await seedClaim(testEnv);
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "activityEvents", "evt1"], {
      type: "camera_offline",
    });
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "notificationTarget", "home"], {
      fcmToken: "home-fcm-token",
    });
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "pairingState", "current"], {
      status: "paired",
    });
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "commands", "cmd1"], validCommand());
  });

  it("cannot read the parent cameraLinks document", async () => {
    await assertFails(getDoc(doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID)));
  });

  it("cannot read the FCM token", async () => {
    await assertFails(
      getDoc(doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID, "notificationTarget", "home"))
    );
  });

  it("cannot read activityEvents", async () => {
    await assertFails(
      getDoc(doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID, "activityEvents", "evt1"))
    );
  });

  it("cannot change notificationSettings", async () => {
    await assertFails(
      setDoc(doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID, "notificationSettings", "camera_offline"), {
        enabled: false,
      })
    );
  });

  it("cannot create or update commands", async () => {
    await assertFails(
      setDoc(doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd2"), validCommand())
    );
    await assertFails(
      updateDoc(doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd1"), {
        status: "completed",
        completedAt: new Date(),
      })
    );
  });

  it("cannot read pairingState after pairing", async () => {
    await assertFails(
      getDoc(doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID, "pairingState", "current"))
    );
  });
});

describe("Pre-claim pairing (no cameraClaims yet)", () => {
  // Mirrors the write createCameraPairingSession performs before any claim
  // exists: cameraAuthUid recorded directly on pairingState/current.
  beforeEach(() =>
    seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "pairingState", "current"], {
      cameraDeviceId: CAMERA_ID,
      cameraAuthUid: CAMERA_UID,
      pairingRequestedAt: new Date(),
    })
  );

  it("the Camera uid recorded in pairingState.cameraAuthUid can read it", async () => {
    await assertSucceeds(
      getDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "pairingState", "current"))
    );
  });

  it("another authenticated uid cannot read it", async () => {
    await assertFails(
      getDoc(doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID, "pairingState", "current"))
    );
  });
});

describe("Post-unpair pairingState (former Camera fallback listener)", () => {
  // Mirrors the state releaseCameraForUser now leaves behind: cameraClaims is
  // gone (so isLinkedIdentity() can no longer vouch for anyone), but
  // pairingState/current carries the old cameraAuthUid forward alongside
  // status:"unpaired" — this is exactly what lets the Camera's pairingState
  // listener (MainActivity.kt's fallback for a server-side unpair) still
  // read the doc and clear its local paired state.
  beforeEach(() =>
    seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "pairingState", "current"], {
      status: "unpaired",
      cameraDeviceId: CAMERA_ID,
      cameraAuthUid: CAMERA_UID,
      unpairedAt: new Date(),
      unpairedByUid: "home-owner-uid",
      unpairedBy: "home",
    })
  );

  it("the former linked Camera can read pairingState (status=unpaired) via its own cameraAuthUid", async () => {
    const snap = await assertSucceeds(
      getDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "pairingState", "current"))
    );
    if (snap.data().status !== "unpaired") {
      throw new Error("expected status to be unpaired");
    }
  });

  it("a stranger cannot read it", async () => {
    await assertFails(
      getDoc(doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID, "pairingState", "current"))
    );
  });

  it("the former Camera does not regain access to other subcollections", async () => {
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "commands", "cmd1"], validCommand());
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "activityEvents", "evt1"], {
      type: "camera_offline",
    });
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "notificationTarget", "home"], {
      fcmToken: "home-fcm-token",
    });

    await assertFails(
      getDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "commands", "cmd1"))
    );
    await assertFails(
      getDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "activityEvents", "evt1"))
    );
    await assertFails(
      getDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "notificationTarget", "home"))
    );
  });

  it("a fresh pairing session's cameraAuthUid correctly replaces the stale one", async () => {
    const NEW_CAMERA_UID = "new-camera-auth-uid";

    // Simulates createCameraPairingSession's guarded merge write: cameraClaims
    // still doesn't exist, so the function overwrites cameraAuthUid with the
    // new pairing attempt's own uid (merge, not replace — the stale
    // status:"unpaired" doc from beforeEach is exactly what's being merged onto).
    await mergeDoc(testEnv, ["cameraLinks", CAMERA_ID, "pairingState", "current"], {
      cameraDeviceId: CAMERA_ID,
      cameraAuthUid: NEW_CAMERA_UID,
      pairingRequestedAt: new Date(),
    });

    await assertFails(
      getDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "pairingState", "current"))
    );
    await assertSucceeds(
      getDoc(
        doc(
          testEnv.authenticatedContext(NEW_CAMERA_UID).firestore(),
          "cameraLinks",
          CAMERA_ID,
          "pairingState",
          "current"
        )
      )
    );
  });
});

describe("Parent cameraLinks/{cameraDeviceId} document", () => {
  beforeEach(() => seedClaim(testEnv));

  it("owner can create/update with only cameraDeviceId, homeDeviceId, updatedAt", async () => {
    await assertSucceeds(
      setDoc(doc(homeDb(testEnv), "cameraLinks", CAMERA_ID), {
        cameraDeviceId: CAMERA_ID,
        homeDeviceId: "home-device-1",
        updatedAt: new Date(),
      })
    );
  });

  it("owner cannot write extra fields", async () => {
    await assertFails(
      setDoc(doc(homeDb(testEnv), "cameraLinks", CAMERA_ID), {
        cameraDeviceId: CAMERA_ID,
        homeDeviceId: "home-device-1",
        updatedAt: new Date(),
        extra: "not allowed",
      })
    );
  });

  it("Camera cannot write the parent document", async () => {
    await assertFails(
      setDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID), {
        cameraDeviceId: CAMERA_ID,
        homeDeviceId: "home-device-1",
        updatedAt: new Date(),
      })
    );
  });

  it("stranger cannot write the parent document", async () => {
    await assertFails(
      setDoc(doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID), {
        cameraDeviceId: CAMERA_ID,
        homeDeviceId: "home-device-1",
        updatedAt: new Date(),
      })
    );
  });
});

describe("webrtcSessions: Home (linked)", () => {
  beforeEach(() => seedClaim(testEnv));

  it("creates a signaling session in waiting_for_offer", async () => {
    await assertSucceeds(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession()
      )
    );
  });

  it("cannot create a session with a purpose other than PLACEMENT_IMAGE", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession({ purpose: "REMOTE_VIEW" })
      )
    );
  });

  it("cannot create a session with an initial status other than waiting_for_offer", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession({ status: "connected" })
      )
    );
  });

  it("cannot create a session with a bogus status value", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession({ status: "bogus" })
      )
    );
  });

  it("cannot create a session whose cameraDeviceId field spoofs a different camera", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession({ cameraDeviceId: "some-other-camera" })
      )
    );
  });

  it("cannot create a session claiming to be created by someone else", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession({ createdBy: "someone-else-uid" })
      )
    );
  });

  it("cannot create a session with an already-expired expiresAt", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession({ expiresAt: new Date(Date.now() - 1000) })
      )
    );
  });

  it("cannot create a session carrying an extra field (e.g. an inlined image)", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession({ photoBase64: "/9j/4AAQSkZJRgABAQAAAQABAAD..." })
      )
    );
  });

  it("attaches its own offer and advances status", async () => {
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"], validSession());
    await assertSucceeds(
      updateDoc(doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"), {
        offerSdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n...",
        offerType: "offer",
        status: "waiting_for_answer",
        updatedAt: new Date(),
      })
    );
  });

  it("cannot attach an oversized offer SDP", async () => {
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"], validSession());
    await assertFails(
      updateDoc(doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"), {
        offerSdp: "x".repeat(10001),
        offerType: "offer",
        status: "waiting_for_answer",
        updatedAt: new Date(),
      })
    );
  });

  it("cannot write the answer fields", async () => {
    await seedDoc(
      testEnv,
      ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"],
      validSession({ status: "waiting_for_answer", offerSdp: "offer-sdp", offerType: "offer" })
    );
    await assertFails(
      updateDoc(doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"), {
        answerSdp: "answer-sdp",
        answerType: "answer",
        status: "connecting",
      })
    );
  });

  it("cannot change identity fields after creation", async () => {
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"], validSession());
    await assertFails(
      updateDoc(doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"), {
        homeDeviceId: "some-other-home-device",
      })
    );
  });

  it("can write its own ICE candidates to homeCandidates", async () => {
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"], validSession());
    await assertSucceeds(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1", "homeCandidates", "c1"),
        validCandidate()
      )
    );
  });

  it("cannot write ICE candidates to cameraCandidates", async () => {
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"], validSession());
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1", "cameraCandidates", "c1"),
        validCandidate()
      )
    );
  });

  it("cannot write an ICE candidate with an empty candidate string", async () => {
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"], validSession());
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1", "homeCandidates", "c1"),
        validCandidate({ candidate: "" })
      )
    );
  });

  it("cannot write an oversized ICE candidate string", async () => {
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"], validSession());
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1", "homeCandidates", "c1"),
        validCandidate({ candidate: "x".repeat(2001) })
      )
    );
  });

  it("reads both candidate subcollections", async () => {
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"], validSession());
    await seedDoc(
      testEnv,
      ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1", "cameraCandidates", "c1"],
      validCandidate()
    );
    await assertSucceeds(
      getDoc(doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1", "cameraCandidates", "c1"))
    );
  });
});

describe("webrtcSessions: Camera (linked)", () => {
  beforeEach(async () => {
    await seedClaim(testEnv);
    await seedDoc(
      testEnv,
      ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"],
      validSession({ status: "waiting_for_answer", offerSdp: "offer-sdp", offerType: "offer" })
    );
  });

  it("reads its own session", async () => {
    await assertSucceeds(
      getDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"))
    );
  });

  it("writes its own answer and advances status", async () => {
    await assertSucceeds(
      updateDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"), {
        answerSdp: "v=0\r\no=- 2 1 IN IP4 127.0.0.1\r\n...",
        answerType: "answer",
        status: "connecting",
        updatedAt: new Date(),
      })
    );
  });

  it("cannot create a session", async () => {
    await assertFails(
      setDoc(
        doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s2"),
        validSession()
      )
    );
  });

  it("cannot change identity fields (cameraDeviceId, homeDeviceId, createdBy)", async () => {
    await assertFails(
      updateDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"), {
        cameraDeviceId: "some-other-camera",
      })
    );
    await assertFails(
      updateDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"), {
        homeDeviceId: "some-other-home-device",
      })
    );
    await assertFails(
      updateDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"), {
        createdBy: CAMERA_UID,
      })
    );
  });

  it("cannot write the offer fields", async () => {
    await assertFails(
      updateDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"), {
        offerSdp: "tampered-offer",
        status: "waiting_for_answer",
      })
    );
  });

  it("cannot add an arbitrary field (e.g. an inlined image)", async () => {
    await assertFails(
      updateDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"), {
        answerSdp: "answer-sdp",
        answerType: "answer",
        status: "connecting",
        photoBase64: "/9j/4AAQSkZJRgABAQAAAQABAAD...",
      })
    );
  });

  it("can write its own ICE candidates to cameraCandidates", async () => {
    await assertSucceeds(
      setDoc(
        doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1", "cameraCandidates", "c1"),
        validCandidate()
      )
    );
  });

  it("cannot write ICE candidates to homeCandidates", async () => {
    await assertFails(
      setDoc(
        doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1", "homeCandidates", "c1"),
        validCandidate()
      )
    );
  });
});

describe("webrtcSessions: ACTIVITY_ZONE purpose", () => {
  beforeEach(() => seedClaim(testEnv));

  it("linked Home creates an ACTIVITY_ZONE signaling session", async () => {
    await assertSucceeds(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession({ purpose: "ACTIVITY_ZONE" })
      )
    );
  });

  it("stranger cannot create an ACTIVITY_ZONE session", async () => {
    await assertFails(
      setDoc(
        doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession({ purpose: "ACTIVITY_ZONE" })
      )
    );
  });

  it("cannot create an ACTIVITY_ZONE session whose cameraDeviceId field spoofs a different camera", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession({ purpose: "ACTIVITY_ZONE", cameraDeviceId: "some-other-camera" })
      )
    );
  });

  it("cannot create an ACTIVITY_ZONE session with a non-string homeDeviceId", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession({ purpose: "ACTIVITY_ZONE", homeDeviceId: 12345 })
      )
    );
  });

  it("cannot create a session with an unrecognized purpose", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession({ purpose: "REMOTE_VIEW_LIVE" })
      )
    );
  });

  it("cannot create an ACTIVITY_ZONE session carrying zone coordinates or any extra field", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession({
          purpose: "ACTIVITY_ZONE",
          zoneCoordinates: [{ x: 0.1, y: 0.2 }, { x: 0.4, y: 0.6 }],
        })
      )
    );
  });

  it("Home attaches its offer and advances status on an ACTIVITY_ZONE session", async () => {
    await seedDoc(
      testEnv,
      ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"],
      validSession({ purpose: "ACTIVITY_ZONE" })
    );
    await assertSucceeds(
      updateDoc(doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"), {
        offerSdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n...",
        offerType: "offer",
        status: "waiting_for_answer",
        updatedAt: new Date(),
      })
    );
  });

  it("Home cannot smuggle zone coordinates into an update", async () => {
    await seedDoc(
      testEnv,
      ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"],
      validSession({ purpose: "ACTIVITY_ZONE" })
    );
    await assertFails(
      updateDoc(doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"), {
        status: "waiting_for_answer",
        updatedAt: new Date(),
        zoneCoordinates: [{ x: 0.1, y: 0.2 }],
      })
    );
  });

  it("linked Camera reads and writes its answer on an ACTIVITY_ZONE session", async () => {
    await seedDoc(
      testEnv,
      ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"],
      validSession({
        purpose: "ACTIVITY_ZONE",
        status: "waiting_for_answer",
        offerSdp: "offer-sdp",
        offerType: "offer",
      })
    );
    await assertSucceeds(
      getDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"))
    );
    await assertSucceeds(
      updateDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"), {
        answerSdp: "v=0\r\no=- 2 1 IN IP4 127.0.0.1\r\n...",
        answerType: "answer",
        status: "connecting",
        updatedAt: new Date(),
      })
    );
  });

  it("Camera writes its own ICE candidates to cameraCandidates on an ACTIVITY_ZONE session", async () => {
    await seedDoc(
      testEnv,
      ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"],
      validSession({ purpose: "ACTIVITY_ZONE" })
    );
    await assertSucceeds(
      setDoc(
        doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1", "cameraCandidates", "c1"),
        validCandidate()
      )
    );
  });

  it("Home writes its own ICE candidates to homeCandidates on an ACTIVITY_ZONE session", async () => {
    await seedDoc(
      testEnv,
      ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"],
      validSession({ purpose: "ACTIVITY_ZONE" })
    );
    await assertSucceeds(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1", "homeCandidates", "c1"),
        validCandidate()
      )
    );
  });

  it("stranger cannot write ICE candidates on an ACTIVITY_ZONE session", async () => {
    await seedDoc(
      testEnv,
      ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"],
      validSession({ purpose: "ACTIVITY_ZONE" })
    );
    await assertFails(
      setDoc(
        doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1", "homeCandidates", "c1"),
        validCandidate()
      )
    );
    await assertFails(
      setDoc(
        doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1", "cameraCandidates", "c1"),
        validCandidate()
      )
    );
  });
});

describe("webrtcSessions: ENTRY_EXIT_LINE purpose", () => {
  beforeEach(() => seedClaim(testEnv));

  it("linked Home creates an ENTRY_EXIT_LINE signaling session", async () => {
    await assertSucceeds(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession({ purpose: "ENTRY_EXIT_LINE" })
      )
    );
  });

  it("foreign/stranger Home cannot create an ENTRY_EXIT_LINE session", async () => {
    await assertFails(
      setDoc(
        doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession({ purpose: "ENTRY_EXIT_LINE" })
      )
    );
  });

  it("cannot create an ENTRY_EXIT_LINE session whose cameraDeviceId field spoofs a different camera", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession({ purpose: "ENTRY_EXIT_LINE", cameraDeviceId: "some-other-camera" })
      )
    );
  });

  it("cannot create a session with an unrecognized purpose", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession({ purpose: "SOME_UNKNOWN_PURPOSE" })
      )
    );
  });

  it("cannot create an ENTRY_EXIT_LINE session carrying line coordinates or any extra field", async () => {
    await assertFails(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"),
        validSession({
          purpose: "ENTRY_EXIT_LINE",
          startPoint: { x: 0.12, y: 0.34 },
          endPoint: { x: 0.56, y: 0.78 },
        })
      )
    );
  });

  it("Home cannot smuggle line coordinates into an update", async () => {
    await seedDoc(
      testEnv,
      ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"],
      validSession({ purpose: "ENTRY_EXIT_LINE" })
    );
    await assertFails(
      updateDoc(doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"), {
        status: "waiting_for_answer",
        updatedAt: new Date(),
        startPoint: { x: 0.12, y: 0.34 },
      })
    );
  });

  it("linked Camera reads and writes its answer on an ENTRY_EXIT_LINE session", async () => {
    await seedDoc(
      testEnv,
      ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"],
      validSession({
        purpose: "ENTRY_EXIT_LINE",
        status: "waiting_for_answer",
        offerSdp: "offer-sdp",
        offerType: "offer",
      })
    );
    await assertSucceeds(
      getDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"))
    );
    await assertSucceeds(
      updateDoc(doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"), {
        answerSdp: "v=0\r\no=- 2 1 IN IP4 127.0.0.1\r\n...",
        answerType: "answer",
        status: "connecting",
        updatedAt: new Date(),
      })
    );
  });

  it("Camera writes its own ICE candidates to cameraCandidates on an ENTRY_EXIT_LINE session", async () => {
    await seedDoc(
      testEnv,
      ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"],
      validSession({ purpose: "ENTRY_EXIT_LINE" })
    );
    await assertSucceeds(
      setDoc(
        doc(cameraDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1", "cameraCandidates", "c1"),
        validCandidate()
      )
    );
  });

  it("Home writes its own ICE candidates to homeCandidates on an ENTRY_EXIT_LINE session", async () => {
    await seedDoc(
      testEnv,
      ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"],
      validSession({ purpose: "ENTRY_EXIT_LINE" })
    );
    await assertSucceeds(
      setDoc(
        doc(homeDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1", "homeCandidates", "c1"),
        validCandidate()
      )
    );
  });

  it("stranger cannot write ICE candidates on an ENTRY_EXIT_LINE session", async () => {
    await seedDoc(
      testEnv,
      ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"],
      validSession({ purpose: "ENTRY_EXIT_LINE" })
    );
    await assertFails(
      setDoc(
        doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1", "homeCandidates", "c1"),
        validCandidate()
      )
    );
    await assertFails(
      setDoc(
        doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1", "cameraCandidates", "c1"),
        validCandidate()
      )
    );
  });
});

describe("webrtcSessions: stranger authenticated user", () => {
  beforeEach(async () => {
    await seedClaim(testEnv);
    await seedDoc(testEnv, ["cameraLinks", CAMERA_ID, "webrtcSessions", "s1"], validSession());
  });

  it("cannot create a session for someone else's camera", async () => {
    await assertFails(
      setDoc(
        doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s2"),
        validSession()
      )
    );
  });

  it("cannot read the session", async () => {
    await assertFails(
      getDoc(doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1"))
    );
  });

  it("cannot write candidates to either subcollection", async () => {
    await assertFails(
      setDoc(
        doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1", "homeCandidates", "c1"),
        validCandidate()
      )
    );
    await assertFails(
      setDoc(
        doc(strangerDb(testEnv), "cameraLinks", CAMERA_ID, "webrtcSessions", "s1", "cameraCandidates", "c1"),
        validCandidate()
      )
    );
  });
});

// userEntitlements/{uid}: server-managed plan/limits/TURN-access model (see
// functions/src/entitlements.ts, docs/USER_ENTITLEMENTS.md) -- Functions
// (Admin SDK) only in both directions. No client, including the document's
// own uid owner, may read, create, update, or delete it; a user must never
// be able to grant/inflate their own entitlements or even learn their raw
// stored values by reading the document directly.
describe("userEntitlements", () => {
  const validEntitlementsDoc = () => ({
    schemaVersion: 1,
    plan: "free",
    subscriptionStatus: "active",
    maxCameras: 1,
    maxHomeDevices: 1,
    maxConcurrentLiveSessions: 1,
    turnAccessAllowed: true,
    source: "default",
    validUntil: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  beforeEach(async () => {
    await seedDoc(testEnv, ["userEntitlements", HOME_UID], validEntitlementsDoc());
  });

  it("an unauthenticated client cannot read", async () => {
    await assertFails(getDoc(doc(unauthedDb(testEnv), "userEntitlements", HOME_UID)));
  });

  it("the document's own uid owner cannot read it", async () => {
    await assertFails(getDoc(doc(homeDb(testEnv), "userEntitlements", HOME_UID)));
  });

  it("another authenticated user cannot read it either", async () => {
    await assertFails(getDoc(doc(strangerDb(testEnv), "userEntitlements", HOME_UID)));
  });

  it("the owner cannot create their own entitlements document", async () => {
    await assertFails(
      setDoc(doc(homeDb(testEnv), "userEntitlements", HOME_UID), validEntitlementsDoc())
    );
  });

  it("the owner cannot update their own entitlements document", async () => {
    await assertFails(
      updateDoc(doc(homeDb(testEnv), "userEntitlements", HOME_UID), { turnAccessAllowed: false })
    );
  });

  it("the owner cannot delete their own entitlements document", async () => {
    await assertFails(deleteDoc(doc(homeDb(testEnv), "userEntitlements", HOME_UID)));
  });
});

// registeredDevices: global device registry (see functions/src/deviceRegistry.ts,
// docs/DEVICE_REGISTRY.md) -- Functions (Admin SDK) only in both directions, mirroring
// userEntitlements above exactly. No client, including the device's own owner, may read,
// create, update, or delete it.
describe("registeredDevices", () => {
  const validRegisteredDeviceDoc = () => ({
    schemaVersion: 1,
    deviceId: CAMERA_ID,
    role: "CAMERA",
    authUid: CAMERA_UID,
    ownerUid: HOME_UID,
    status: "active",
    suspensionReason: null,
    identityMode: "legacy",
    publicKey: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSeenAt: new Date(),
    revokedAt: null,
  });

  beforeEach(async () => {
    await seedDoc(testEnv, ["registeredDevices", CAMERA_ID], validRegisteredDeviceDoc());
  });

  it("an unauthenticated client cannot read", async () => {
    await assertFails(getDoc(doc(unauthedDb(testEnv), "registeredDevices", CAMERA_ID)));
  });

  it("the device's own owner cannot read it", async () => {
    await assertFails(getDoc(doc(homeDb(testEnv), "registeredDevices", CAMERA_ID)));
  });

  it("another authenticated user cannot read it either", async () => {
    await assertFails(getDoc(doc(strangerDb(testEnv), "registeredDevices", CAMERA_ID)));
  });

  it("a client cannot create a registered-device document", async () => {
    await assertFails(
      setDoc(doc(homeDb(testEnv), "registeredDevices", CAMERA_ID), validRegisteredDeviceDoc())
    );
  });

  it("a client cannot update a registered-device document", async () => {
    await assertFails(
      updateDoc(doc(homeDb(testEnv), "registeredDevices", CAMERA_ID), { status: "revoked" })
    );
  });

  it("a client cannot delete a registered-device document", async () => {
    await assertFails(deleteDoc(doc(homeDb(testEnv), "registeredDevices", CAMERA_ID)));
  });
});

// deviceChallenges: device-signature challenge protocol (see functions/src/deviceChallenges.ts).
// Functions (Admin SDK) only in both directions, mirroring cameraClaims/cameraPairingSessions/
// registeredDevices exactly -- no client, including the device that owns the challenge, may read
// or write it.
describe("deviceChallenges", () => {
  const CHALLENGE_ID = "challenge-1";

  const validChallengeDoc = () => ({
    schemaVersion: 1,
    challengeId: CHALLENGE_ID,
    deviceId: CAMERA_ID,
    role: "CAMERA",
    authUid: CAMERA_UID,
    purpose: "TURN_CREDENTIALS",
    nonce: "a".repeat(43),
    requestHash: "b".repeat(64),
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 90 * 1000),
    usedAt: null,
    usedByFunction: null,
  });

  beforeEach(async () => {
    await seedDoc(testEnv, ["deviceChallenges", CHALLENGE_ID], validChallengeDoc());
  });

  it("an unauthenticated client cannot read", async () => {
    await assertFails(getDoc(doc(unauthedDb(testEnv), "deviceChallenges", CHALLENGE_ID)));
  });

  it("the device that owns the challenge cannot read it", async () => {
    await assertFails(getDoc(doc(cameraDb(testEnv), "deviceChallenges", CHALLENGE_ID)));
  });

  it("another authenticated user cannot read it either", async () => {
    await assertFails(getDoc(doc(strangerDb(testEnv), "deviceChallenges", CHALLENGE_ID)));
  });

  it("a client cannot create a challenge document", async () => {
    await assertFails(
      setDoc(doc(homeDb(testEnv), "deviceChallenges", "client-created"), validChallengeDoc())
    );
  });

  it("a client cannot update a challenge document (e.g. forge usedAt)", async () => {
    await assertFails(
      updateDoc(doc(cameraDb(testEnv), "deviceChallenges", CHALLENGE_ID), { usedAt: new Date() })
    );
  });

  it("a client cannot delete a challenge document", async () => {
    await assertFails(deleteDoc(doc(cameraDb(testEnv), "deviceChallenges", CHALLENGE_ID)));
  });
});
