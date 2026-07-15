import { before, after, beforeEach, describe, it } from "node:test";
import { assertSucceeds, assertFails } from "@firebase/rules-unit-testing";
import { doc, getDoc, setDoc, updateDoc } from "firebase/firestore";
import {
  CAMERA_ID,
  CAMERA_UID,
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
