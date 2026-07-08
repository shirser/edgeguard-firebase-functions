import { onDocumentCreated } from "firebase-functions/v2/firestore";
import { onValueWritten } from "firebase-functions/v2/database";
import { onCall, HttpsError } from "firebase-functions/v2/https";
import * as logger from "firebase-functions/logger";
import * as admin from "firebase-admin";
import * as crypto from "crypto";

admin.initializeApp();

function hashSecret(secret: string): string {
  return crypto.createHash("sha256").update(secret).digest("hex");
}

async function isNotificationEnabled(
  cameraDeviceId: string,
  type: string
): Promise<boolean> {
  logger.info("FUNCTION_NOTIFICATION_SETTING_CHECK", { cameraDeviceId, type });
  try {
    const snap = await admin
      .firestore()
      .collection("cameraLinks")
      .doc(cameraDeviceId)
      .collection("notificationSettings")
      .doc(type)
      .get();

    if (!snap.exists) {
      logger.info("FUNCTION_NOTIFICATION_SETTING_MISSING_DEFAULT_TRUE", {
        cameraDeviceId,
        type,
      });
      return true;
    }

    const enabled = snap.get("enabled");
    const result = enabled !== false;

    logger.info("FUNCTION_NOTIFICATION_SETTING_ENABLED", {
      cameraDeviceId,
      type,
      enabled: result,
    });

    return result;
  } catch (error: any) {
    logger.error("FUNCTION_NOTIFICATION_SETTING_ERROR_DEFAULT_TRUE", {
      cameraDeviceId,
      type,
      error: error?.message ?? String(error),
    });
    return true;
  }
}

async function handleCameraEvent(
  db: admin.firestore.Firestore,
  cameraDeviceId: string,
  type: string,
  title: string,
  body: string,
  severity: string
): Promise<void> {
  const pushEnabled = await isNotificationEnabled(cameraDeviceId, type);

  let pushQueued = false;

  if (pushEnabled) {
    const queueRef = db
      .collection("cameraLinks")
      .doc(cameraDeviceId)
      .collection("notificationQueue")
      .doc();

    await queueRef.set({
      type,
      title,
      body,
      status: "pending",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    pushQueued = true;
    logger.info("NOTIFICATION_QUEUE_CREATED", {
      cameraDeviceId,
      type,
      eventId: queueRef.id,
    });
  } else {
    logger.info("FUNCTION_NOTIFICATION_SETTING_SKIP", {
      cameraDeviceId,
      type,
      enabled: false,
    });
  }

  const activityRef = db
    .collection("cameraLinks")
    .doc(cameraDeviceId)
    .collection("activityEvents")
    .doc();

  await activityRef.set({
    type,
    title,
    body,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    source: "function",
    severity,
    pushEnabled,
    pushQueued,
  });

  logger.info("ACTIVITY_EVENT_CREATED", {
    cameraDeviceId,
    type,
    eventId: activityRef.id,
    pushEnabled,
    pushQueued,
  });
}

// NOTE: consumed/expired cameraPairingSessions documents are never deleted
// today, so this collection grows unbounded. Recommend adding a scheduled
// (e.g. daily) cleanup function that deletes documents where
// `status != "pending"` or `expiresAt < now`. Not implemented here since it
// is out of scope for this security pass — no client can read/write this
// collection (see firestore.rules), so the growth is a cost/hygiene concern,
// not a security one.
export const createCameraPairingSession = onCall(
  { region: "europe-west1" },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "UNAUTHENTICATED");
    }

    const { cameraDeviceId, pairingSecretHash } = request.data as {
      cameraDeviceId?: string;
      pairingSecretHash?: string;
    };

    if (!cameraDeviceId || !pairingSecretHash) {
      throw new HttpsError("invalid-argument", "INVALID_PAIRING");
    }

    logger.info("CREATE_PAIRING_SESSION_START", { cameraDeviceId });

    const db = admin.firestore();
    const pairingRef = db.collection("cameraPairingSessions").doc();
    const pairingId = pairingRef.id;
    const expiresAt = admin.firestore.Timestamp.fromMillis(
      Date.now() + 10 * 60 * 1000
    );

    await pairingRef.set({
      cameraDeviceId,
      pairingSecretHash,
      cameraAuthUid: request.auth.uid,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt,
      consumedAt: null,
      status: "pending",
    });

    // Record the initiating Camera's own auth uid on pairingState/current so
    // Firestore rules can let this same Camera identity read its own
    // pairingState before any cameraClaims doc exists (first-listener case,
    // before Home finishes claimCameraForUser). Only written pre-claim: if
    // the device is already claimed, claimCameraForUser's own (non-merge)
    // writes to this doc are the sole source of truth, and we must not let
    // a fresh pairing session hijack read access to an already-paired
    // camera's pairingState by overwriting cameraAuthUid here.
    const claimSnap = await db.collection("cameraClaims").doc(cameraDeviceId).get();
    if (!claimSnap.exists) {
      const pairingStateRef = db
        .collection("cameraLinks")
        .doc(cameraDeviceId)
        .collection("pairingState")
        .doc("current");

      await pairingStateRef.set(
        {
          cameraDeviceId,
          cameraAuthUid: request.auth.uid,
          pairingRequestedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );
    }

    logger.info("CREATE_PAIRING_SESSION_SUCCESS", { pairingId });

    return { pairingId, expiresAt: expiresAt.toDate().toISOString() };
  }
);

export const claimCameraForUser = onCall(
  { region: "europe-west1" },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "UNAUTHENTICATED");
    }

    const uid = request.auth.uid;
    const { cameraDeviceId, pairingId, pairingSecret, homeDeviceId } =
      request.data as {
        cameraDeviceId?: string;
        pairingId?: string;
        pairingSecret?: string;
        homeDeviceId?: string;
      };

    if (!cameraDeviceId || !pairingId || !pairingSecret || !homeDeviceId) {
      throw new HttpsError("invalid-argument", "INVALID_PAIRING");
    }

    logger.info("CLAIM_CAMERA_START", { uid, cameraDeviceId, pairingId });

    const db = admin.firestore();
    const userRef = db.collection("users").doc(uid);
    const claimRef = db.collection("cameraClaims").doc(cameraDeviceId);
    const pairingRef = db.collection("cameraPairingSessions").doc(pairingId);
    const cameraDeviceRef = userRef
      .collection("cameraDevices")
      .doc(cameraDeviceId);
    const pairingStateRef = db
      .collection("cameraLinks")
      .doc(cameraDeviceId)
      .collection("pairingState")
      .doc("current");

    const secretHash = hashSecret(pairingSecret);

    const txResult = await db.runTransaction(async (t) => {
      const [userSnap, claimSnap, pairingSnap] = await Promise.all([
        t.get(userRef),
        t.get(claimRef),
        t.get(pairingRef),
      ]);

      // Validate pairing session
      const sessionExpiresAt = pairingSnap.get(
        "expiresAt"
      ) as admin.firestore.Timestamp | undefined;

      const pairingValid =
        pairingSnap.exists &&
        pairingSnap.get("status") === "pending" &&
        !pairingSnap.get("consumedAt") &&
        sessionExpiresAt != null &&
        sessionExpiresAt.toMillis() > Date.now() &&
        pairingSnap.get("cameraDeviceId") === cameraDeviceId &&
        pairingSnap.get("pairingSecretHash") === secretHash;

      if (!pairingValid) {
        logger.info("CLAIM_CAMERA_INVALID_PAIRING", { cameraDeviceId, pairingId });
        throw new HttpsError("failed-precondition", "INVALID_PAIRING");
      }

      // Idempotent: already claimed by this user
      if (claimSnap.exists) {
        const claimedUid = claimSnap.get("uid") as string;
        if (claimedUid === uid) {
          logger.info("CLAIM_CAMERA_IDEMPOTENT_OWNER", { cameraDeviceId });

          const idempotentNow = admin.firestore.FieldValue.serverTimestamp();

          logger.info("CLAIM_CAMERA_PAIRING_STATE_WRITE_START", {
            cameraDeviceId,
            path: `cameraLinks/${cameraDeviceId}/pairingState/current`,
          });

          t.set(
            pairingStateRef,
            {
              status: "paired",
              cameraDeviceId,
              homeDeviceId,
              pairedAt: idempotentNow,
              pairedByUid: uid,
            },
            { merge: true }
          );

          logger.info("CLAIM_CAMERA_PAIRING_STATE_WRITE_QUEUED", { cameraDeviceId });

          const subscriptionUnits: number =
            (userSnap.get("subscriptionUnits") as number) ?? 0;
          return {
            cameraCount: (userSnap.get("cameraCount") as number) ?? 0,
            cameraLimit: 1 + subscriptionUnits * 5,
            pairingStateWritten: true,
          };
        }
        logger.info("CLAIM_CAMERA_ALREADY_CLAIMED", { cameraDeviceId });
        throw new HttpsError("failed-precondition", "CAMERA_ALREADY_CLAIMED");
      }

      const subscriptionUnits: number = userSnap.exists
        ? ((userSnap.get("subscriptionUnits") as number) ?? 0)
        : 0;
      const currentCameraCount: number = userSnap.exists
        ? ((userSnap.get("cameraCount") as number) ?? 0)
        : 0;
      const allowedCameraCount = 1 + subscriptionUnits * 5;
      const nextCameraCount = currentCameraCount + 1;

      logger.info("CAMERA_LIMIT_CHECK", {
        uid,
        cameraDeviceId,
        currentCameraCount,
        nextCameraCount,
        subscriptionUnits,
        allowedCameraCount,
      });

      if (nextCameraCount > allowedCameraCount) {
        logger.info("CAMERA_LIMIT_REACHED", {
          uid,
          cameraDeviceId,
          currentCameraCount,
          nextCameraCount,
          subscriptionUnits,
          allowedCameraCount,
        });
        throw new HttpsError("resource-exhausted", "Camera limit reached", {
          code: "CAMERA_LIMIT_REACHED",
          currentCameraCount,
          nextCameraCount,
          allowedCameraCount,
          subscriptionUnits,
        });
      }

      logger.info("CAMERA_LIMIT_OK", { uid, cameraDeviceId, nextCameraCount });

      const cameraCount = currentCameraCount;
      const cameraLimit = allowedCameraCount;

      const now = admin.firestore.FieldValue.serverTimestamp();
      const newCameraCount = cameraCount + 1;

      if (!userSnap.exists) {
        t.set(userRef, {
          subscriptionUnits: 0,
          cameraLimit,
          cameraCount: newCameraCount,
          createdAt: now,
          updatedAt: now,
        });
      } else {
        t.update(userRef, {
          cameraCount: admin.firestore.FieldValue.increment(1),
          cameraLimit,
          updatedAt: now,
        });
      }

      t.set(cameraDeviceRef, {
        cameraDeviceId,
        homeDeviceId,
        pairedAt: now,
        status: "active",
      });

      const cameraAuthUid = pairingSnap.get("cameraAuthUid") as
        | string
        | undefined;

      t.set(claimRef, {
        uid,
        cameraAuthUid: cameraAuthUid ?? null,
        claimedAt: now,
      });

      t.update(pairingRef, {
        status: "consumed",
        consumedAt: now,
        consumedByUid: uid,
      });

      logger.info("CLAIM_CAMERA_PAIRING_STATE_WRITE_START", {
        cameraDeviceId,
        path: `cameraLinks/${cameraDeviceId}/pairingState/current`,
      });

      t.set(pairingStateRef, {
        status: "paired",
        cameraDeviceId,
        homeDeviceId,
        pairedAt: now,
        pairedByUid: uid,
      });

      logger.info("CLAIM_CAMERA_PAIRING_STATE_WRITE_QUEUED", { cameraDeviceId });

      return { cameraCount: newCameraCount, cameraLimit, pairingStateWritten: true };
    });

    logger.info("CLAIM_CAMERA_TRANSACTION_DONE", {
      cameraDeviceId,
      pairingStateWritten: txResult.pairingStateWritten,
    });

    if (txResult.pairingStateWritten) {
      logger.info("CLAIM_CAMERA_PAIRING_STATE_WRITTEN", { cameraDeviceId });
    }

    const pairingStateSnap = await pairingStateRef.get();

    logger.info("CLAIM_CAMERA_PAIRING_STATE_VERIFY", {
      cameraDeviceId,
      exists: pairingStateSnap.exists,
      status: pairingStateSnap.get("status") ?? null,
    });

    if (!pairingStateSnap.exists) {
      logger.error("CLAIM_CAMERA_PAIRING_STATE_MISSING_AFTER_SUCCESS", { cameraDeviceId });
    }

    logger.info("CLAIM_CAMERA_SUCCESS", {
      uid,
      cameraCount: txResult.cameraCount,
      cameraLimit: txResult.cameraLimit,
    });

    return {
      success: true,
      cameraLimit: txResult.cameraLimit,
      cameraCount: txResult.cameraCount,
    };
  }
);

export const releaseCameraForUser = onCall(
  { region: "europe-west1" },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "UNAUTHENTICATED");
    }

    const uid = request.auth.uid;
    const { cameraDeviceId } = request.data as { cameraDeviceId?: string };

    if (!cameraDeviceId) {
      throw new HttpsError("invalid-argument", "INVALID_PAIRING");
    }

    logger.info("RELEASE_CAMERA_START", { uid, cameraDeviceId });

    const db = admin.firestore();
    const userRef = db.collection("users").doc(uid);
    const claimRef = db.collection("cameraClaims").doc(cameraDeviceId);
    const cameraDeviceRef = userRef
      .collection("cameraDevices")
      .doc(cameraDeviceId);
    const pairingStateRef = db
      .collection("cameraLinks")
      .doc(cameraDeviceId)
      .collection("pairingState")
      .doc("current");

    await db.runTransaction(async (t) => {
      const [claimSnap, userSnap] = await Promise.all([
        t.get(claimRef),
        t.get(userRef),
      ]);

      if (!claimSnap.exists || (claimSnap.get("uid") as string) !== uid) {
        throw new HttpsError("permission-denied", "PERMISSION_DENIED");
      }

      // Read the linked Camera's auth uid before the claim is deleted below.
      // Without this, the pairingState write after release has no
      // cameraAuthUid, and since cameraClaims is gone in this same
      // transaction, firestore.rules' isLinkedIdentity() check also fails —
      // the Camera's pairingState listener (its fallback for detecting a
      // server-side unpair, see MainActivity.kt) gets permission-denied
      // instead of the status:"unpaired" update, and never clears its local
      // paired state. Carrying cameraAuthUid forward lets the rule's
      // `resource.data.cameraAuthUid == request.auth.uid` branch admit the
      // very Camera identity that was just unlinked.
      const cameraAuthUid = claimSnap.get("cameraAuthUid") as
        | string
        | undefined;

      const subscriptionUnits: number =
        (userSnap.get("subscriptionUnits") as number) ?? 0;
      const cameraLimit = 1 + subscriptionUnits * 5;

      const now = admin.firestore.FieldValue.serverTimestamp();

      t.delete(claimRef);
      t.delete(cameraDeviceRef);

      if (userSnap.exists) {
        t.update(userRef, {
          cameraCount: admin.firestore.FieldValue.increment(-1),
          cameraLimit,
          updatedAt: now,
        });
      }

      t.set(pairingStateRef, {
        status: "unpaired",
        cameraDeviceId,
        cameraAuthUid: cameraAuthUid ?? null,
        unpairedAt: now,
        unpairedByUid: uid,
        unpairedBy: "home",
      });
    });

    logger.info("RELEASE_CAMERA_PAIRING_STATE_WRITTEN", { cameraDeviceId });

    logger.info("RELEASE_CAMERA_SUCCESS", { uid, cameraDeviceId });

    return { success: true };
  }
);

// Called by the Camera App itself (e.g. "Unpair camera" in-app) to release its own pairing.
// Authorization requires the caller to be the linked Camera identity
// (cameraAuthUid on the claim) — mirroring releaseCameraFromCamera's check —
// so arbitrary authenticated users can no longer unpair a camera by knowing
// only its cameraDeviceId. Unlike releaseCameraFromCamera, this is a no-op
// (not an error) if the camera is already unclaimed, which is the one
// intentional behavioral difference between the two functions.
export const unpairCameraFromDevice = onCall(
  { region: "europe-west1" },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "UNAUTHENTICATED");
    }

    const callerUid = request.auth.uid;
    const { cameraDeviceId } = request.data as { cameraDeviceId?: string };

    if (!cameraDeviceId) {
      throw new HttpsError("invalid-argument", "INVALID_PAIRING");
    }

    logger.info("UNPAIR_CAMERA_FROM_DEVICE_START", { cameraDeviceId });

    const db = admin.firestore();
    const claimRef = db.collection("cameraClaims").doc(cameraDeviceId);
    const pairingStateRef = db
      .collection("cameraLinks")
      .doc(cameraDeviceId)
      .collection("pairingState")
      .doc("current");

    await db.runTransaction(async (t) => {
      const claimSnap = await t.get(claimRef);

      if (!claimSnap.exists) {
        logger.info("UNPAIR_CAMERA_FROM_DEVICE_NOT_CLAIMED", { cameraDeviceId });
        return;
      }

      const ownerUid = claimSnap.get("uid") as string;
      const linkedCameraAuthUid = claimSnap.get("cameraAuthUid") as
        | string
        | undefined;

      if (callerUid !== linkedCameraAuthUid) {
        logger.info("UNPAIR_CAMERA_FROM_DEVICE_PERMISSION_DENIED", {
          cameraDeviceId,
        });
        throw new HttpsError("permission-denied", "PERMISSION_DENIED");
      }

      const userRef = db.collection("users").doc(ownerUid);
      const cameraDeviceRef = userRef.collection("cameraDevices").doc(cameraDeviceId);
      const userSnap = await t.get(userRef);

      const now = admin.firestore.FieldValue.serverTimestamp();

      t.delete(claimRef);
      t.delete(cameraDeviceRef);

      if (userSnap.exists) {
        const subscriptionUnits: number =
          (userSnap.get("subscriptionUnits") as number) ?? 0;
        const cameraLimit = 1 + subscriptionUnits * 5;
        t.update(userRef, {
          cameraCount: admin.firestore.FieldValue.increment(-1),
          cameraLimit,
          updatedAt: now,
        });
      }

      t.set(pairingStateRef, {
        status: "unpaired",
        cameraDeviceId,
        unpairedAt: now,
        unpairedByUid: request.auth!.uid,
        unpairedBy: "camera",
      });
    });

    logger.info("UNPAIR_CAMERA_FROM_DEVICE_SUCCESS", { cameraDeviceId });

    return { success: true };
  }
);

// Called by the Camera App to release its own pairing, proving ownership via the
// cameraAuthUid recorded on cameraClaims at claim time (copied from the pairing session's
// cameraAuthUid, itself set from the Camera App's anonymous auth uid in
// createCameraPairingSession). Unlike unpairCameraFromDevice, this verifies the caller is
// the same Camera App identity that was originally claimed, not just any authenticated user.
export const releaseCameraFromCamera = onCall(
  { region: "europe-west1" },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "UNAUTHENTICATED");
    }

    const cameraAuthUid = request.auth.uid;
    const { cameraDeviceId } = request.data as { cameraDeviceId?: string };

    if (!cameraDeviceId) {
      throw new HttpsError("invalid-argument", "INVALID_PAIRING");
    }

    logger.info("RELEASE_CAMERA_FROM_CAMERA_START", { cameraDeviceId });

    const db = admin.firestore();
    const claimRef = db.collection("cameraClaims").doc(cameraDeviceId);
    const pairingStateRef = db
      .collection("cameraLinks")
      .doc(cameraDeviceId)
      .collection("pairingState")
      .doc("current");

    try {
      const ownerUid = await db.runTransaction(async (t) => {
        const claimSnap = await t.get(claimRef);

        const claimCameraAuthUid = claimSnap.get("cameraAuthUid") as
          | string
          | undefined;
        const cameraAuthUidMatches =
          claimSnap.exists && claimCameraAuthUid === cameraAuthUid;

        logger.info("RELEASE_CAMERA_FROM_CAMERA_AUTH_CHECK", {
          cameraDeviceId,
          cameraAuthUidMatches,
        });

        if (!cameraAuthUidMatches) {
          throw new HttpsError("permission-denied", "PERMISSION_DENIED");
        }

        const ownerUid = claimSnap.get("uid") as string;
        const userRef = db.collection("users").doc(ownerUid);
        const cameraDeviceRef = userRef
          .collection("cameraDevices")
          .doc(cameraDeviceId);

        const [userSnap, cameraDeviceSnap, pairingStateSnap] = await Promise.all([
          t.get(userRef),
          t.get(cameraDeviceRef),
          t.get(pairingStateRef),
        ]);

        logger.info("RELEASE_CAMERA_FROM_CAMERA_READ", {
          cameraDeviceId,
          ownerUid,
          cameraDeviceExists: cameraDeviceSnap.exists,
          previousPairingStatus: pairingStateSnap.get("status") ?? null,
        });

        const now = admin.firestore.FieldValue.serverTimestamp();

        t.delete(claimRef);
        t.delete(cameraDeviceRef);

        if (userSnap.exists) {
          const subscriptionUnits: number =
            (userSnap.get("subscriptionUnits") as number) ?? 0;
          const cameraCount: number =
            (userSnap.get("cameraCount") as number) ?? 0;
          const newCameraCount = Math.max(0, cameraCount - 1);
          const cameraLimit = 1 + subscriptionUnits * 5;

          t.update(userRef, {
            cameraCount: newCameraCount,
            cameraLimit,
            updatedAt: now,
          });
        }

        t.set(pairingStateRef, {
          status: "unpaired",
          cameraDeviceId,
          unpairedAt: now,
          unpairedBy: "camera",
          unpairedByCameraAuthUid: cameraAuthUid,
          previousOwnerUid: ownerUid,
        });

        return ownerUid;
      });

      logger.info("RELEASE_CAMERA_FROM_CAMERA_PAIRING_STATE_WRITTEN", {
        cameraDeviceId,
      });

      logger.info("RELEASE_CAMERA_FROM_CAMERA_SUCCESS", {
        cameraDeviceId,
        ownerUid,
      });

      return { success: true };
    } catch (error: any) {
      logger.error("RELEASE_CAMERA_FROM_CAMERA_FAILED", {
        cameraDeviceId,
        errorClass: error?.constructor?.name ?? "Error",
        message: error?.message ?? String(error),
      });
      throw error;
    }
  }
);

const ALLOWED_CAMERA_EVENT_SEVERITIES = new Set(["info", "warning", "critical"]);

// Called by the Camera App to report an event (e.g. motion detected) that
// should be recorded as an activity event and, if enabled, queued for push
// notification. Replaces direct client writes to
// cameraLinks/{cameraDeviceId}/activityEvents and .../notificationQueue,
// both of which are function-only in firestore.rules — notificationQueue in
// particular must never be client-writable, since sendNotificationOnCreate
// fires on any document created there. Authorization mirrors
// releaseCameraFromCamera: the caller must be the cameraAuthUid linked to
// this cameraDeviceId in cameraClaims. Reuses handleCameraEvent so the
// notification-enabled/queue/activity-event logic isn't duplicated.
export const submitCameraEvent = onCall(
  { region: "europe-west1" },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "UNAUTHENTICATED");
    }

    const { cameraDeviceId, type, title, body, severity } = request.data as {
      cameraDeviceId?: string;
      type?: string;
      title?: string;
      body?: string;
      severity?: string;
    };

    if (
      typeof cameraDeviceId !== "string" ||
      !cameraDeviceId ||
      typeof type !== "string" ||
      !type ||
      type.length > 64 ||
      typeof title !== "string" ||
      !title ||
      title.length > 200 ||
      typeof body !== "string" ||
      !body ||
      body.length > 2000 ||
      typeof severity !== "string" ||
      !ALLOWED_CAMERA_EVENT_SEVERITIES.has(severity)
    ) {
      throw new HttpsError("invalid-argument", "INVALID_EVENT");
    }

    logger.info("SUBMIT_CAMERA_EVENT_START", { cameraDeviceId, type, severity });

    const db = admin.firestore();
    const claimSnap = await db.collection("cameraClaims").doc(cameraDeviceId).get();
    const linkedCameraAuthUid = claimSnap.get("cameraAuthUid") as
      | string
      | undefined;

    if (!claimSnap.exists || linkedCameraAuthUid !== request.auth.uid) {
      logger.info("SUBMIT_CAMERA_EVENT_PERMISSION_DENIED", { cameraDeviceId });
      throw new HttpsError("permission-denied", "PERMISSION_DENIED");
    }

    await handleCameraEvent(db, cameraDeviceId, type, title, body, severity);

    logger.info("SUBMIT_CAMERA_EVENT_SUCCESS", { cameraDeviceId, type });

    return { success: true };
  }
);

export const enqueueCameraStatusNotification = onValueWritten(
  {
    ref: "cameraStatus/{cameraDeviceId}",
    region: "europe-west1",
  },
  async (event) => {
    const { cameraDeviceId } = event.params;
    const before = event.data.before.val();
    const after = event.data.after.val();

    const beforeConnectionState: string = before?.connectionState ?? "";
    const afterConnectionState: string = after?.connectionState ?? "";
    const beforeAppState: string = before?.appState ?? "";
    const afterAppState: string = after?.appState ?? "";

    const isAppClosed =
      beforeAppState === "running" && afterAppState === "stopped";

    const isOffline =
      beforeConnectionState === "connected" &&
      afterConnectionState === "disconnected" &&
      afterAppState !== "stopped";

    if (!isAppClosed && !isOffline) {
      logger.info("CAMERA_STATUS_SKIP", {
        cameraDeviceId,
        beforeAppState,
        afterAppState,
        beforeConnectionState,
        afterConnectionState,
      });
      return;
    }

    const db = admin.firestore();

    if (isOffline) {
      logger.info("CAMERA_OFFLINE_DETECTED", { cameraDeviceId });
      await handleCameraEvent(
        db,
        cameraDeviceId,
        "camera_offline",
        "Camera offline",
        "Your Camera connection was lost.",
        "warning"
      );
    }

    if (isAppClosed) {
      logger.info("CAMERA_APP_CLOSED_DETECTED", { cameraDeviceId });
      await handleCameraEvent(
        db,
        cameraDeviceId,
        "camera_app_closed",
        "Camera app was closed",
        "Your Camera app was closed.",
        "warning"
      );
    }
  }
);

// FCM error codes that mean the token itself is permanently dead — the
// device/app was uninstalled or the token was rotated/revoked server-side.
// Only these two trigger token cleanup. Every other code (including the
// transient ones called out below) is deliberately NOT in this set, so
// cleanup fails safe/closed: an unrecognized or future error code never
// deletes a token, only these two explicitly known-dead codes do.
//
// Transient FCM errors that must NOT clear the token (kept only as
// documentation of intent — they already fall through untouched since
// they're absent from the set above): messaging/internal-error,
// messaging/server-unavailable, messaging/quota-exceeded (and the
// rate-exceeded variants), messaging/third-party-auth-error.
const FCM_TOKEN_DEAD_ERROR_CODES = new Set([
  "messaging/registration-token-not-registered",
  "messaging/invalid-registration-token",
]);

// Extracted from the onDocumentCreated handler so it can be exercised by
// unit tests against the Firestore emulator with a fake sendMessage — real
// admin.messaging().send() calls require production FCM connectivity.
export async function sendCameraNotification(
  db: admin.firestore.Firestore,
  cameraDeviceId: string,
  eventId: string,
  data: FirebaseFirestore.DocumentData,
  queueRef: admin.firestore.DocumentReference,
  sendMessage: (message: admin.messaging.Message) => Promise<string> = (message) =>
    admin.messaging().send(message)
): Promise<void> {
  if (data.status !== "pending") {
    logger.info("Skip non-pending notification", {
      cameraDeviceId,
      eventId,
      status: data.status,
    });
    return;
  }

  const title = data.title;
  const body = data.body;

  if (!title || !body) {
    await queueRef.update({
      status: "failed",
      error: "Missing title or body",
      failedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    return;
  }

  const targetRef = db
    .collection("cameraLinks")
    .doc(cameraDeviceId)
    .collection("notificationTarget")
    .doc("home");

  const targetSnap = await targetRef.get();
  const fcmToken = targetSnap.get("fcmToken");

  if (!fcmToken) {
    await queueRef.update({
      status: "failed",
      error: "Missing Home FCM token",
      failedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    return;
  }

  try {
    const messageId = await sendMessage({
      token: fcmToken,
      notification: {
        title,
        body,
      },
      data: {
        type: String(data.type ?? ""),
        cameraDeviceId: String(cameraDeviceId),
        eventId: String(eventId),
        title: String(title),
        body: String(body),
      },
      android: {
        priority: "high",
        notification: {
          channelId: "edgeguard_alerts_v1",
          priority: "high",
          defaultSound: true,
          defaultVibrateTimings: true,
        },
      },
    });

    await queueRef.update({
      status: "sent",
      sentAt: admin.firestore.FieldValue.serverTimestamp(),
      messageId,
    });

    logger.info("Push sent", { cameraDeviceId, eventId, messageId });
  } catch (error: any) {
    const errorCode = error?.code as string | undefined;

    await queueRef.update({
      status: "failed",
      error: error?.message ?? String(error),
      failedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    logger.error("Push failed", { cameraDeviceId, eventId, errorCode });

    if (!errorCode || !FCM_TOKEN_DEAD_ERROR_CODES.has(errorCode)) {
      return;
    }

    // Re-read before deleting: Home may have saved a new token for this
    // camera in the time between the send attempt and this cleanup, and
    // that new token must never be clobbered by a failure tied to the old one.
    const currentTargetSnap = await targetRef.get();
    const currentToken = currentTargetSnap.get("fcmToken");

    if (currentTargetSnap.exists && currentToken === fcmToken) {
      await targetRef.update({
        fcmToken: admin.firestore.FieldValue.delete(),
      });
      logger.info("FCM_TOKEN_REMOVED_INVALID", { cameraDeviceId, errorCode });
    } else {
      logger.info("FCM_TOKEN_CHANGED_SKIP_DELETE", { cameraDeviceId, errorCode });
    }
  }
}

export const sendNotificationOnCreate = onDocumentCreated(
  {
    document: "cameraLinks/{cameraDeviceId}/notificationQueue/{eventId}",
    region: "europe-west1",
  },
  async (event) => {
    const snapshot = event.data;
    if (!snapshot) return;

    const { cameraDeviceId, eventId } = event.params;

    await sendCameraNotification(
      admin.firestore(),
      cameraDeviceId,
      eventId,
      snapshot.data(),
      snapshot.ref
    );
  }
);
