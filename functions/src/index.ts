import { onDocumentCreated, onDocumentWritten } from "firebase-functions/v2/firestore";
import { onValueWritten } from "firebase-functions/v2/database";
import { onCall, HttpsError } from "firebase-functions/v2/https";
import { defineSecret } from "firebase-functions/params";
import * as logger from "firebase-functions/logger";
import * as admin from "firebase-admin";
import * as crypto from "crypto";
import { getEffectiveUserEntitlements, planDeviceLimitsFromEntitlementsData } from "./entitlements";
import {
  registerLegacyCamera,
  registerLegacyHome,
  attachCameraOwner,
  detachCameraOwner,
  SUPPORTED_DEVICE_KEY_ALGORITHM,
  validateEcP256PublicKey,
  applyPublicKeyRegistration,
  applyCameraPublicKeyRegistration,
  applyRevokeRegisteredDevice,
  checkRegisteredDeviceOperational,
  reconcileUserDeviceLimits,
} from "./deviceRegistry";
import type { PublicKeyRegistrationOutcome, RegisteredDevice, RevokeDeviceDecision } from "./deviceRegistry";
import {
  DEVICE_CHALLENGE_PURPOSES,
  isDeviceChallengePurpose,
  validateTurnCredentialsRequestPayload,
  buildCanonicalTurnCredentialsRequestPayload,
  sha256Hex,
  buildCanonicalDeviceProofPayload,
  generateChallengeNonce,
  checkDeviceChallengeEligibility,
  buildDeviceChallengeDocument,
  CHALLENGE_TTL_SECONDS,
  validateTurnCredentialsDeviceProof,
  consumeVerifiedTurnCredentialsChallenge,
} from "./deviceChallenges";
import type {
  DeviceChallengePurpose,
  TurnChallengePurpose,
  TurnCredentialsChallengeVerificationFailureReason,
} from "./deviceChallenges";

admin.initializeApp();

export {
  ENTITLEMENTS_SCHEMA_VERSION,
  getEffectiveUserEntitlements,
  getPlanDeviceLimits,
  planDeviceLimitsFromEntitlementsData,
  isExpired as isUserEntitlementsExpired,
} from "./entitlements";
export type {
  EntitlementPlan,
  EntitlementSubscriptionStatus,
  EntitlementSource,
  UserEntitlements,
  EffectiveUserEntitlements,
  CorruptEntitlementsReason,
  DeviceLimits,
} from "./entitlements";

export {
  DEVICE_REGISTRY_SCHEMA_VERSION,
  identityConflictReason,
  registerLegacyCamera,
  registerLegacyHome,
  attachCameraOwner,
  detachCameraOwner,
  touchRegisteredDevice,
  SUPPORTED_DEVICE_KEY_ALGORITHM,
  validateEcP256PublicKey,
  applyPublicKeyRegistration,
  applyCameraPublicKeyRegistration,
  decideRevokeRegisteredDevice,
  applyRevokeRegisteredDevice,
  checkRegisteredDeviceOperational,
  planDeviceLimitDecision,
  reconcileUserDeviceLimits,
  checkAuthTimeFreshness,
  HOME_KEY_REGISTRATION_MAX_AUTH_AGE_SECONDS,
  AUTH_TIME_FUTURE_SKEW_SECONDS,
} from "./deviceRegistry";
export type {
  DeviceRole,
  DeviceStatus,
  DeviceSuspensionReason,
  DeviceIdentityMode,
  RegisteredDevice,
  DeviceIdentityConflictReason,
  PublicKeyInvalidReason,
  PublicKeyValidation,
  PublicKeyRegistrationOutcome,
  RevokeDeviceDecision,
  DeviceOperationalReason,
  DeviceOperationalDecision,
  DeviceLimitReconciliation,
  AuthTimeFreshnessReason,
  AuthTimeFreshnessResult,
} from "./deviceRegistry";

export {
  DEVICE_CHALLENGE_PURPOSES,
  isDeviceChallengePurpose,
  validateTurnCredentialsRequestPayload,
  buildCanonicalTurnCredentialsRequestPayload,
  sha256Hex,
  buildCanonicalDeviceProofPayload,
  generateChallengeNonce,
  checkDeviceChallengeEligibility,
  buildDeviceChallengeDocument,
  CHALLENGE_NONCE_BYTE_LENGTH,
  CHALLENGE_TTL_SECONDS,
  DEVICE_CHALLENGE_SCHEMA_VERSION,
  DEVICE_PROOF_MAX_BYTES,
  DEVICE_PROOF_SUPPORTED_PROTOCOL_VERSION,
  DEVICE_PROOF_SIGNATURE_MAX_BYTES,
  DEVICE_PROOF_VERSION,
  validateDeviceProofSignatureBase64,
  validateTurnCredentialsDeviceProof,
  verifyDeviceProofSignature,
  consumeVerifiedTurnCredentialsChallenge,
} from "./deviceChallenges";
export type {
  DeviceChallengePurpose,
  TurnChallengePurpose,
  TurnCredentialsChallengeRequestPayload,
  RequestPayloadInvalidReason,
  TurnCredentialsRequestPayloadValidation,
  DeviceChallengeEligibilityReason,
  DeviceChallengeEligibilityDecision,
  CanonicalDeviceProofFields,
  DeviceChallengeDocument,
  TurnCredentialsDeviceProof,
  DeviceProofInvalidReason,
  TurnCredentialsDeviceProofValidation,
  SignatureInvalidReason,
  SignatureBase64Validation,
  TurnCredentialsChallengeVerificationFailureReason,
  TurnCredentialsChallengeConsumptionOutcome,
} from "./deviceChallenges";
export { effectiveUserEntitlementsFromData } from "./entitlements";

function hashSecret(secret: string): string {
  return crypto.createHash("sha256").update(secret).digest("hex");
}

// Throwing wrapper around deviceRegistry.ts's checkRegisteredDeviceOperational -- deviceRegistry.ts
// itself deliberately never imports HttpsError (every operation there returns a plain outcome, so
// its business logic stays testable without the Functions SDK), so the actual HttpsError mapping
// lives here, mirroring how registerDevicePublicKey's own switch statement maps
// PublicKeyRegistrationOutcome onto HttpsError below.
//
// Reads registeredDevices/{deviceId} fresh (not via a transaction) -- every call site below
// already completed its own authorization transaction/read (attachCameraOwner's lazy migration,
// or the claim transaction itself) before reaching this check, so this is a best-effort-adjacent
// read consistent with how the rest of this stage's lazy migration already treats the registry:
// authoritative for status/suspensionReason, but never the FIRST or ONLY check standing between a
// request and the operation it performs.
//
// options.requireRegistered defaults to false (permissive on a missing document) -- see
// checkRegisteredDeviceOperational's own doc for why every call site below relies on that default.
async function assertRegisteredDeviceOperational(
  db: admin.firestore.Firestore,
  deviceId: string,
  options: { requireRegistered?: boolean } = {}
): Promise<void> {
  const snap = await db.collection("registeredDevices").doc(deviceId).get();
  const existing = snap.exists ? (snap.data() as RegisteredDevice) : null;
  const decision = checkRegisteredDeviceOperational(existing, options);
  if (decision.operational) return;

  logger.info("DEVICE_OPERATIONAL_CHECK_DENIED", { deviceId, reason: decision.reason });
  throw new HttpsError(decision.reason === "DEVICE_NOT_REGISTERED" ? "not-found" : "failed-precondition", decision.reason);
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

    // Best-effort device-registry bookkeeping (see deviceRegistry.ts) -- registers this Camera
    // installation, pre-pairing, with ownerUid null. Never blocks or changes this function's
    // response, and never touches an already-attached owner if this fires again for an
    // already-paired Camera (e.g. reopening the pairing screen without unpairing first).
    await registerLegacyCamera(db, cameraDeviceId, request.auth.uid);

    // Device-status enforcement: a suspended/revoked Camera may not start a new pairing session
    // (this would otherwise let a lost/stolen, already-revoked Camera re-pair to a brand-new Home
    // account). Permissive on a missing registry document (see
    // assertRegisteredDeviceOperational's own doc) -- a brand-new Camera's very first pairing
    // request is never blocked by this.
    await assertRegisteredDeviceOperational(db, cameraDeviceId);

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

    const registryRef = db.collection("registeredDevices").doc(cameraDeviceId);

    const txResult = await db.runTransaction(async (t) => {
      const [userSnap, claimSnap, pairingSnap, registrySnap] = await Promise.all([
        t.get(userRef),
        t.get(claimRef),
        t.get(pairingRef),
        t.get(registryRef),
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

      // Device-status enforcement: a suspended/revoked Camera may not complete a claim (covers
      // both a brand-new claim and the idempotent already-claimed-by-this-owner branch below).
      // Read inside this same transaction (not via assertRegisteredDeviceOperational's own
      // separate read) so this decision is atomic with the rest of the claim. Permissive on a
      // missing registry document -- see checkRegisteredDeviceOperational's own doc.
      const registryExisting = registrySnap.exists ? (registrySnap.data() as RegisteredDevice) : null;
      const operational = checkRegisteredDeviceOperational(registryExisting);
      if (!operational.operational) {
        logger.info("CLAIM_CAMERA_DEVICE_STATUS_DENIED", { cameraDeviceId, reason: operational.reason });
        throw new HttpsError(
          operational.reason === "DEVICE_NOT_REGISTERED" ? "not-found" : "failed-precondition",
          operational.reason
        );
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
            cameraAuthUid: claimSnap.get("cameraAuthUid") as string | null | undefined,
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

      return {
        cameraCount: newCameraCount,
        cameraLimit,
        pairingStateWritten: true,
        cameraAuthUid,
      };
    });

    // Best-effort device-registry bookkeeping (see deviceRegistry.ts), run only after the claim
    // transaction above has already committed -- Firestore does not support nesting one
    // transaction inside another, and registerLegacyHome()/attachCameraOwner() each run their own.
    // Never blocks or changes this function's response. homeDeviceId's authUid/ownerUid are taken
    // from the already-authenticated request (`uid`), never trusted from the client as-is beyond
    // that. `cameraAuthUid` is the Camera's own auth uid as already verified by the pairing
    // session validated inside the transaction above -- never `uid` (the Home caller).
    await registerLegacyHome(db, homeDeviceId, uid);
    if (txResult.cameraAuthUid) {
      await attachCameraOwner(db, cameraDeviceId, txResult.cameraAuthUid, uid);
    }

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

export const updateCameraNameForUser = onCall(
  { region: "europe-west1", invoker: "public" },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "UNAUTHENTICATED");
    }

    const uid = request.auth.uid;
    const { cameraDeviceId, cameraName } = request.data as {
      cameraDeviceId?: string;
      cameraName?: string;
    };

    if (typeof cameraDeviceId !== "string" || cameraDeviceId.length === 0) {
      throw new HttpsError("invalid-argument", "INVALID_CAMERA_DEVICE_ID");
    }

    if (typeof cameraName !== "string") {
      throw new HttpsError("invalid-argument", "INVALID_CAMERA_NAME");
    }

    const trimmedCameraName = cameraName.trim();
    if (trimmedCameraName.length === 0 || trimmedCameraName.length > 50) {
      throw new HttpsError("invalid-argument", "INVALID_CAMERA_NAME");
    }

    logger.info("UPDATE_CAMERA_NAME_START", { uid, cameraDeviceId });

    const db = admin.firestore();
    const claimRef = db.collection("cameraClaims").doc(cameraDeviceId);
    const pairingStateRef = db
      .collection("cameraLinks")
      .doc(cameraDeviceId)
      .collection("pairingState")
      .doc("current");
    const cameraDeviceRef = db
      .collection("users")
      .doc(uid)
      .collection("cameraDevices")
      .doc(cameraDeviceId);

    await db.runTransaction(async (t) => {
      const claimSnap = await t.get(claimRef);

      if (!claimSnap.exists) {
        logger.info("UPDATE_CAMERA_NAME_NOT_FOUND", { cameraDeviceId });
        throw new HttpsError("not-found", "CAMERA_NOT_FOUND");
      }

      if ((claimSnap.get("uid") as string) !== uid) {
        logger.info("UPDATE_CAMERA_NAME_PERMISSION_DENIED", { cameraDeviceId });
        throw new HttpsError("permission-denied", "PERMISSION_DENIED");
      }

      t.set(
        pairingStateRef,
        { cameraName: trimmedCameraName },
        { merge: true }
      );
      t.set(
        cameraDeviceRef,
        { cameraName: trimmedCameraName },
        { merge: true }
      );
    });

    logger.info("UPDATE_CAMERA_NAME_SUCCESS", { uid, cameraDeviceId });

    return { success: true, cameraName: trimmedCameraName };
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

    // Best-effort device-registry bookkeeping (see deviceRegistry.ts) -- a normal unpair clears
    // ownerUid back to null but is never a revocation (status/identityMode/publicKey/authUid/
    // revokedAt are untouched). Run after the transaction above has already committed (Firestore
    // does not support nesting one transaction inside another); never blocks or changes this
    // function's response.
    await detachCameraOwner(db, cameraDeviceId);

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

    // Best-effort device-registry bookkeeping (see deviceRegistry.ts) -- see releaseCameraForUser
    // above for why this always runs (even the "already unclaimed" no-op branch of the
    // transaction) and what it does/doesn't touch.
    await detachCameraOwner(db, cameraDeviceId);

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

      // Best-effort device-registry bookkeeping (see deviceRegistry.ts) -- see
      // releaseCameraForUser above for why this always runs and what it does/doesn't touch.
      await detachCameraOwner(db, cameraDeviceId);

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

    // Best-effort device-registry lazy migration (see deviceRegistry.ts) for an already-paired
    // Camera that predates this registry -- only reached once the cameraClaims-based ownership
    // check above has already succeeded. Never blocks or changes this function's response.
    await attachCameraOwner(db, cameraDeviceId, linkedCameraAuthUid, claimSnap.get("uid") as string);

    // Device-status enforcement: a suspended/revoked Camera may not submit an event.
    await assertRegisteredDeviceOperational(db, cameraDeviceId);

    await handleCameraEvent(db, cameraDeviceId, type, title, body, severity);

    logger.info("SUBMIT_CAMERA_EVENT_SUCCESS", { cameraDeviceId, type });

    return { success: true };
  }
);

const ALLOWED_TURN_PURPOSES = new Set([
  "LIVE_VIEW",
  "PLACEMENT_PREVIEW",
  "ACTIVITY_ZONE",
  "ENTRY_EXIT_LINE",
  "MEDIA_TRANSFER",
]);

const TURN_CREDENTIAL_TTL_SECONDS = 10 * 60;

const TURN_ICE_URLS = [
  "stun:turn.edgeguard.cc:3478",
  "turn:turn.edgeguard.cc:3478?transport=udp",
  "turn:turn.edgeguard.cc:3478?transport=tcp",
  "turns:turn.edgeguard.cc:5349?transport=tcp",
];

// Cloud Secret Manager-backed TURN_REST_SECRET, shared with the coturn
// server's own REST API secret (see buildTurnCredentialsResponse below).
// Declared at module scope per firebase-functions v7's Secret Manager
// convention (firebase-functions/params defineSecret) and attached via the
// `secrets` option on the onCall below so it's mounted at runtime.
const turnRestSecret = defineSecret("TURN_REST_SECRET");

export function isValidTurnPurpose(purpose: unknown): boolean {
  return typeof purpose === "string" && ALLOWED_TURN_PURPOSES.has(purpose);
}

// Pure coturn TURN REST API credential derivation
// (https://github.com/coturn/coturn/blob/master/docs/turn_rest_api.md) --
// kept free of Secret Manager/Firestore access so it's directly unit
// testable.
export function buildTurnUsername(expiresAtSeconds: number, uid: string): string {
  return `${expiresAtSeconds}:${uid}`;
}

export function computeTurnCredential(secret: string, username: string): string {
  return crypto.createHmac("sha1", secret).update(username).digest("base64");
}

// Builds the full getTurnCredentials response, given an already-resolved
// secret value and the caller's uid. Takes `nowSeconds` as a parameter
// (defaulting to the real clock) purely so tests can assert the exact
// expiresAt value without a clock race. Throws internal/INTERNAL if the
// secret hasn't been provisioned -- callers must not fall back to any
// unauthenticated/default credential.
export function buildTurnCredentialsResponse(
  secret: string | undefined,
  uid: string,
  nowSeconds: number = Math.floor(Date.now() / 1000)
): {
  iceServers: Array<{ urls: string[]; username: string; credential: string }>;
  expiresAt: number;
} {
  if (!secret) {
    throw new HttpsError("internal", "INTERNAL");
  }

  const expiresAt = nowSeconds + TURN_CREDENTIAL_TTL_SECONDS;
  const username = buildTurnUsername(expiresAt, uid);
  const credential = computeTurnCredential(secret, username);

  return {
    iceServers: [
      {
        urls: TURN_ICE_URLS,
        username,
        credential,
      },
    ],
    expiresAt,
  };
}

// Reuses the exact same cameraClaims-based pairing/ownership model as the
// rest of this file (mirrors firestore.rules' isLinkedIdentity(): the caller
// must be either the linked Home owner (`uid`) or the linked Camera identity
// (`cameraAuthUid`) for this cameraDeviceId) -- no parallel access model.
// Takes `db` explicitly (same pattern as sendCameraNotification below) so it
// can be exercised directly against the Firestore emulator in tests.
export async function verifyCameraAccess(
  db: admin.firestore.Firestore,
  cameraDeviceId: string,
  callerUid: string
): Promise<"ok" | "not-found" | "denied"> {
  const claimSnap = await db.collection("cameraClaims").doc(cameraDeviceId).get();

  if (!claimSnap.exists) {
    return "not-found";
  }

  const ownerUid = claimSnap.get("uid") as string | undefined;
  const cameraAuthUid = claimSnap.get("cameraAuthUid") as string | undefined;

  if (callerUid !== ownerUid && callerUid !== cameraAuthUid) {
    return "denied";
  }

  return "ok";
}

// Same access check as verifyCameraAccess, but reads cameraClaims exactly once and returns the
// verified cameraAuthUid/ownerUid alongside it -- used by callables (getTurnCredentials) that
// need both the access decision and those two fields for the device registry's lazy migration
// (see deviceRegistry.ts), so they never have to read cameraClaims a second, potentially
// inconsistent time right after verifyCameraAccess's own internal read. Kept separate from
// verifyCameraAccess itself (rather than widening its return shape) so verifyCameraAccess's
// existing "ok"|"not-found"|"denied" contract, and its own tests, are untouched.
export async function getVerifiedCameraClaim(
  db: admin.firestore.Firestore,
  cameraDeviceId: string,
  callerUid: string
): Promise<{
  access: "ok" | "not-found" | "denied";
  cameraAuthUid?: string | null;
  ownerUid?: string;
}> {
  const claimSnap = await db.collection("cameraClaims").doc(cameraDeviceId).get();

  if (!claimSnap.exists) {
    return { access: "not-found" };
  }

  const ownerUid = claimSnap.get("uid") as string | undefined;
  const cameraAuthUid = claimSnap.get("cameraAuthUid") as string | null | undefined;

  if (callerUid !== ownerUid && callerUid !== cameraAuthUid) {
    return { access: "denied" };
  }

  return { access: "ok", cameraAuthUid, ownerUid };
}

// Vends short-lived (10 minute) coturn TURN REST credentials for a specific
// paired camera. Called by either the Home App (as the WebRTC session
// initiator, e.g. Live View) or the Camera App (as the session responder)
// instead of each app baking a long-lived static TURN secret into its own
// BuildConfig. `purpose` is required and validated against the same set of
// WebRTC session purposes used elsewhere in this project's signaling schema,
// but does not otherwise change the credentials issued -- it exists so
// access requests are self-describing in logs/audits.
//
// Optionally accepts a `deviceProof` field (see deviceChallenges.ts) -- when present, the whole
// call is authorized by a verified Keystore signature instead of (or in addition to, for the
// registry-bookkeeping side effects) the plain cameraClaims/entitlements checks below. See the
// callable's own body for the exact branch; when `deviceProof` is entirely absent, behavior is
// byte-for-byte identical to before this was added.

// Every TurnCredentialsChallengeVerificationFailureReason mapped to a deliberately narrow set of
// public (code, message) pairs -- see deviceChallenges.ts's own doc on
// TurnCredentialsChallengeVerificationFailureReason for why. Distinguishable, already-safe
// business states (not found / expired / already used / not provisioned / identity corrupt /
// device status / TURN access) keep their own specific message, reusing the exact same strings
// this project already surfaces elsewhere (DEVICE_NOT_PROVISIONED, DEVICE_IDENTITY_CORRUPT,
// DEVICE_SUSPENDED[..._PLAN], DEVICE_REVOKED, TURN_ACCESS_DENIED) for consistency. Every reason
// that could function as a signature/authorization oracle (challenge id/purpose/authUid/schema/
// nonce/requestHash format, role mismatch, request-hash-after-tampering mismatch, camera target
// mismatch, camera claim/access denial, and the signature itself) collapses to one generic
// permission-denied/DEVICE_PROOF_DENIED -- a caller can never use the response to tell "almost a
// valid signature" apart from "wrong challenge" or "wrong camera".
function mapTurnCredentialsChallengeDenialToHttpsError(
  reason: TurnCredentialsChallengeVerificationFailureReason
): HttpsError {
  switch (reason) {
    case "CHALLENGE_NOT_FOUND":
      return new HttpsError("not-found", "CHALLENGE_NOT_FOUND");
    case "REQUESTING_DEVICE_NOT_REGISTERED":
      return new HttpsError("not-found", "DEVICE_NOT_REGISTERED");
    case "CHALLENGE_EXPIRED":
      return new HttpsError("failed-precondition", "CHALLENGE_EXPIRED");
    case "CHALLENGE_ALREADY_USED":
      return new HttpsError("failed-precondition", "CHALLENGE_ALREADY_USED");
    case "REQUESTING_DEVICE_NOT_PROVISIONED":
      return new HttpsError("failed-precondition", "DEVICE_NOT_PROVISIONED");
    case "REQUESTING_DEVICE_IDENTITY_CORRUPT":
      return new HttpsError("failed-precondition", "DEVICE_IDENTITY_CORRUPT");
    case "DEVICE_SUSPENDED":
    case "DEVICE_SUSPENDED_PLAN":
    case "DEVICE_REVOKED":
      return new HttpsError("permission-denied", reason);
    case "TURN_ACCESS_DENIED":
      return new HttpsError("permission-denied", "TURN_ACCESS_DENIED");
    default:
      return new HttpsError("permission-denied", "DEVICE_PROOF_DENIED");
  }
}

export const getTurnCredentials = onCall(
  { region: "europe-west1", secrets: [turnRestSecret] },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "UNAUTHENTICATED");
    }

    const uid = request.auth.uid;
    const { cameraDeviceId, purpose, deviceProof } = request.data as {
      cameraDeviceId?: string;
      purpose?: string;
      deviceProof?: unknown;
    };

    if (typeof cameraDeviceId !== "string" || cameraDeviceId.length === 0) {
      throw new HttpsError("invalid-argument", "INVALID_CAMERA_DEVICE_ID");
    }

    if (!isValidTurnPurpose(purpose)) {
      throw new HttpsError("invalid-argument", "INVALID_PURPOSE");
    }
    // isValidTurnPurpose returns a plain boolean (not a type predicate) so as not to change its
    // existing signature/behavior -- this cast is safe only because the check just above already
    // confirmed, at runtime, that `purpose` is one of the same 5 values TurnChallengePurpose
    // names.
    const turnPurpose = purpose as TurnChallengePurpose;

    logger.info("GET_TURN_CREDENTIALS_START", { uid, cameraDeviceId, purpose });

    const db = admin.firestore();

    // Optional device-proof path (see deviceChallenges.ts). A request that omits `deviceProof`
    // entirely falls straight through to the exact, unmodified pre-existing flow below -- old
    // clients are completely unaffected. A request that INCLUDES the field -- even an explicit
    // `null`, which is a malformed attempt, not "absent" -- must fully verify, or the call is
    // denied outright; there is no fallback to the old flow once a client attempts a proof.
    const hasDeviceProofField =
      request.data !== null && typeof request.data === "object" && "deviceProof" in request.data;

    if (hasDeviceProofField) {
      const proofValidation = validateTurnCredentialsDeviceProof(deviceProof);
      if (!proofValidation.valid) {
        logger.info("TURN_DEVICE_PROOF_VERIFY_DENIED", {
          cameraDeviceId,
          turnPurpose: purpose,
          reason: proofValidation.reason,
        });
        throw new HttpsError("invalid-argument", "INVALID_DEVICE_PROOF");
      }
      const proof = proofValidation.proof;

      logger.info("TURN_DEVICE_PROOF_VERIFY_START", {
        challengeId: proof.challengeId,
        cameraDeviceId,
        turnPurpose: purpose,
        protocolVersion: proof.protocolVersion,
      });

      const consumption = await consumeVerifiedTurnCredentialsChallenge(db, {
        requestAuthUid: uid,
        cameraDeviceId,
        turnPurpose,
        deviceProof: proof,
        nowMillis: Date.now(),
      });

      if (consumption.outcome !== "verified") {
        logger.info("TURN_DEVICE_PROOF_VERIFY_DENIED", {
          challengeId: proof.challengeId,
          cameraDeviceId,
          turnPurpose: purpose,
          reason: consumption.reason,
        });
        throw mapTurnCredentialsChallengeDenialToHttpsError(consumption.reason);
      }

      logger.info("TURN_DEVICE_PROOF_VERIFY_SUCCESS", {
        challengeId: proof.challengeId,
        deviceId: consumption.deviceId,
        role: consumption.role,
        cameraDeviceId,
        turnPurpose: purpose,
      });

      // Best-effort device-registry lazy migration -- same call, same non-blocking semantics, as
      // the existing flow below; cameraAuthUid/ownerUid come from the SAME cameraClaims read the
      // transaction above already performed, never a second, separately-timed read.
      await attachCameraOwner(db, cameraDeviceId, consumption.cameraAuthUid, consumption.ownerUid);

      let proofResponse;
      try {
        proofResponse = buildTurnCredentialsResponse(turnRestSecret.value(), uid);
      } catch (error) {
        logger.error("GET_TURN_CREDENTIALS_MISSING_SECRET", { uid, cameraDeviceId, purpose });
        throw error;
      }

      logger.info("GET_TURN_CREDENTIALS_SUCCESS", { uid, cameraDeviceId, purpose });

      return proofResponse;
    }

    // ---------------------------------------------------------------------------------------
    // Existing flow, byte-for-byte unchanged -- reached only when `deviceProof` is entirely
    // absent from the request. See this function's own top-level doc.
    // ---------------------------------------------------------------------------------------
    const claim = await getVerifiedCameraClaim(db, cameraDeviceId, uid);

    if (claim.access === "not-found") {
      logger.info("GET_TURN_CREDENTIALS_NOT_FOUND", { uid, cameraDeviceId, purpose });
      throw new HttpsError("not-found", "CAMERA_NOT_FOUND");
    }

    if (claim.access === "denied") {
      logger.info("GET_TURN_CREDENTIALS_PERMISSION_DENIED", { uid, cameraDeviceId, purpose });
      throw new HttpsError("permission-denied", "PERMISSION_DENIED");
    }

    // Best-effort device-registry lazy migration (see deviceRegistry.ts) for an already-paired
    // Camera that predates this registry -- only reached once getVerifiedCameraClaim above has
    // already confirmed `uid` is a linked identity (Home owner or Camera) for this camera, using
    // the SAME cameraClaims read that access check already performed (no second, potentially
    // inconsistent read). getTurnCredentials is called by both Home and Camera, so the Camera's
    // authUid is always read from cameraClaims itself, never from `uid` (the caller). Never
    // blocks or changes this function's response.
    await attachCameraOwner(db, cameraDeviceId, claim.cameraAuthUid, claim.ownerUid as string);

    // Device-status enforcement: a suspended/revoked Camera may not vend TURN credentials to
    // either side of the call (Home requesting as viewer, or Camera requesting as responder).
    await assertRegisteredDeviceOperational(db, cameraDeviceId);

    // Entitlements gate: only turnAccessAllowed is enforced here today.
    // maxCameras/maxHomeDevices/maxConcurrentLiveSessions are intentionally
    // NOT checked yet -- concurrent Live View session tracking doesn't exist yet (later work).
    // Never surface *why* TURN was denied (plan, blocked status, expiry) to the
    // client -- only the generic TURN_ACCESS_DENIED code.
    const entitlements = await getEffectiveUserEntitlements(uid, db);
    if (!entitlements.turnAccessAllowed) {
      logger.info("GET_TURN_CREDENTIALS_TURN_ACCESS_DENIED", { uid, cameraDeviceId, purpose });
      throw new HttpsError("permission-denied", "TURN_ACCESS_DENIED");
    }

    let response;
    try {
      response = buildTurnCredentialsResponse(turnRestSecret.value(), uid);
    } catch (error) {
      logger.error("GET_TURN_CREDENTIALS_MISSING_SECRET", { uid, cameraDeviceId, purpose });
      throw error;
    }

    logger.info("GET_TURN_CREDENTIALS_SUCCESS", { uid, cameraDeviceId, purpose });

    return response;
  }
);

const MAX_DEVICE_ID_LENGTH = 128;
const MAX_DEVICE_PUBLIC_KEY_LENGTH = 512;

// Android Keystore identity, stage 1: registers a device's real cryptographic public key,
// flipping registeredDevices/{deviceId}.identityMode from "legacy" to "keystore" -- see
// docs/DEVICE_REGISTRY.md. Deliberately does NOT verify a signature over anything yet (no
// challenge/proof-of-possession) -- that is an explicitly separate, later task; this stage only
// gets a real key safely on file, tied to whichever identity the registry already trusts.
//
// Never creates registeredDevices/{deviceId} -- registering a device (registerLegacyCamera/
// registerLegacyHome/attachCameraOwner, all pre-existing) and registering its cryptographic
// identity are different operations; a missing document is CAMERA_NOT_CLAIMED/DEVICE_NOT_REGISTERED,
// never silently created here.
export const registerDevicePublicKey = onCall(
  { region: "europe-west1" },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "UNAUTHENTICATED");
    }
    const callerUid = request.auth.uid;

    const { deviceId, role, publicKey, algorithm } = request.data as {
      deviceId?: string;
      role?: string;
      publicKey?: string;
      algorithm?: string;
    };

    if (typeof deviceId !== "string" || deviceId.trim().length === 0 || deviceId.length > MAX_DEVICE_ID_LENGTH) {
      throw new HttpsError("invalid-argument", "INVALID_DEVICE_ID");
    }

    if (role !== "HOME" && role !== "CAMERA") {
      throw new HttpsError("invalid-argument", "INVALID_ROLE");
    }

    if (algorithm !== SUPPORTED_DEVICE_KEY_ALGORITHM) {
      throw new HttpsError("invalid-argument", "INVALID_ALGORITHM");
    }

    if (typeof publicKey !== "string" || publicKey.length === 0 || publicKey.length > MAX_DEVICE_PUBLIC_KEY_LENGTH) {
      throw new HttpsError("invalid-argument", "INVALID_PUBLIC_KEY");
    }

    logger.info("REGISTER_DEVICE_PUBLIC_KEY_START", { deviceId, role, algorithm });

    const keyValidation = validateEcP256PublicKey(publicKey);
    if (!keyValidation.valid) {
      logger.info("REGISTER_DEVICE_PUBLIC_KEY_INVALID", { deviceId, role, algorithm, reason: keyValidation.reason });
      throw new HttpsError("invalid-argument", "INVALID_PUBLIC_KEY");
    }

    const db = admin.firestore();

    // Authorization: HOME is authenticated directly via request.auth.uid, checked transactionally
    // against the registry document itself inside applyPublicKeyRegistration. CAMERA is never
    // authenticated via its own request -- it has no separate proof-of-possession yet -- so it is
    // authorized via cameraClaims/{deviceId}.cameraAuthUid, the same server-verified
    // pairing-secret handshake result every other Camera-authenticated callable in this file
    // already relies on (verifyCameraAccess/getVerifiedCameraClaim). ownerUid is never used to
    // authenticate a Camera -- only Home devices are authenticated via their own ownerUid.
    //
    // The CAMERA claim check is NOT a pre-check here: applyCameraPublicKeyRegistration reads
    // cameraClaims AND registeredDevices inside one transaction together with the eventual write,
    // so a concurrent unpair (which deletes cameraClaims) can never race between "verified" and
    // "registered" -- see deviceRegistry.ts's own doc for why an out-of-transaction pre-check was
    // not safe here.
    // request.auth.token.auth_time is the server-verified Firebase Auth claim for "when this
    // session's credential was actually presented" (Unix seconds) -- the ONLY source
    // HOME_KEY_REGISTRATION_MAX_AUTH_AGE_SECONDS is ever checked against below. Read here, raw and
    // unvalidated (deviceRegistry.ts's checkAuthTimeFreshness is what actually validates it) --
    // never taken from request.data, which has no auth_time field at all. nowSeconds is the one
    // real Date.now() read for this whole gate, taken once at this boundary so every layer beneath
    // it (applyPublicKeyRegistration, decidePublicKeyRegistration, checkAuthTimeFreshness) is
    // driven by a plain parameter, not a hidden clock read.
    const authTime = (request.auth.token as Record<string, unknown>)?.auth_time;
    const nowSeconds = Math.floor(Date.now() / 1000);

    let result: PublicKeyRegistrationOutcome;
    try {
      result =
        role === "CAMERA"
          ? await applyCameraPublicKeyRegistration(db, {
              cameraDeviceId: deviceId,
              authenticatedUid: callerUid,
              canonicalPublicKey: keyValidation.canonicalBase64,
            })
          : await applyPublicKeyRegistration(db, {
              deviceId,
              role,
              expectedAuthUid: callerUid,
              expectedOwnerUid: callerUid,
              canonicalPublicKey: keyValidation.canonicalBase64,
              authTime,
              nowSeconds,
            });
    } catch (error: any) {
      logger.error("REGISTER_DEVICE_PUBLIC_KEY_FAILED", {
        deviceId,
        role,
        algorithm,
        errorClass: error?.constructor?.name ?? "Error",
      });
      throw new HttpsError("internal", "REGISTRY_WRITE_FAILED");
    }

    switch (result.outcome) {
      case "not_found":
        logger.info("REGISTER_DEVICE_PUBLIC_KEY_DENIED", { deviceId, role, algorithm, reason: "DEVICE_NOT_REGISTERED" });
        throw new HttpsError("not-found", "DEVICE_NOT_REGISTERED");
      case "camera_not_claimed":
        logger.info("REGISTER_DEVICE_PUBLIC_KEY_DENIED", { deviceId, role, algorithm, reason: "CAMERA_NOT_CLAIMED" });
        throw new HttpsError("not-found", "CAMERA_NOT_CLAIMED");
      case "role_mismatch":
      case "auth_uid_mismatch":
      case "owner_uid_mismatch":
        logger.info("REGISTER_DEVICE_PUBLIC_KEY_DENIED", {
          deviceId,
          role,
          algorithm,
          reason: "DEVICE_IDENTITY_MISMATCH",
        });
        throw new HttpsError("permission-denied", "DEVICE_IDENTITY_MISMATCH");
      case "revoked":
        logger.info("REGISTER_DEVICE_PUBLIC_KEY_DENIED", { deviceId, role, algorithm, reason: "DEVICE_REVOKED" });
        throw new HttpsError("failed-precondition", "DEVICE_REVOKED");
      case "corrupt":
        logger.warn("REGISTER_DEVICE_PUBLIC_KEY_DENIED", {
          deviceId,
          role,
          algorithm,
          reason: "DEVICE_IDENTITY_CORRUPT",
        });
        throw new HttpsError("failed-precondition", "DEVICE_IDENTITY_CORRUPT");
      case "key_conflict":
        logger.info("REGISTER_DEVICE_PUBLIC_KEY_CONFLICT", {
          deviceId,
          role,
          algorithm,
          publicKeyFingerprint: keyValidation.fingerprint,
        });
        throw new HttpsError("failed-precondition", "PUBLIC_KEY_ALREADY_REGISTERED");
      case "idempotent":
        logger.info("REGISTER_DEVICE_PUBLIC_KEY_IDEMPOTENT", {
          deviceId,
          role,
          algorithm,
          publicKeyFingerprint: keyValidation.fingerprint,
        });
        return { success: true, identityMode: "keystore" as const };
      case "registered":
        logger.info("REGISTER_DEVICE_PUBLIC_KEY_SUCCESS", {
          deviceId,
          role,
          algorithm,
          publicKeyFingerprint: keyValidation.fingerprint,
        });
        return { success: true, identityMode: "keystore" as const };
      case "home_created":
        logger.info("REGISTER_DEVICE_PUBLIC_KEY_HOME_CREATED", {
          deviceId,
          role,
          algorithm,
          publicKeyFingerprint: keyValidation.fingerprint,
        });
        return { success: true, identityMode: "keystore" as const };
      case "recent_auth_required":
        // Safe to log: a fixed reason, a fixed auth-age *category* (never the actual auth_time or
        // current timestamp), deviceId, role, algorithm. Never the uid, the ID token, or the
        // public key.
        logger.info("REGISTER_DEVICE_PUBLIC_KEY_DENIED", {
          deviceId,
          role,
          algorithm,
          reason: "RECENT_AUTH_REQUIRED",
          authTimeCategory: result.reason,
        });
        throw new HttpsError("failed-precondition", "RECENT_AUTH_REQUIRED");
      default:
        throw new HttpsError("internal", "INTERNAL");
    }
  }
);

// ---------------------------------------------------------------------------------------------
// Device-signature challenge protocol -- foundation stage (createDeviceChallenge only).
// ---------------------------------------------------------------------------------------------
// Issues a deviceChallenges/{challengeId} document for an already-registered (identityMode:
// "keystore") HOME or CAMERA device to later sign. This stage does NOT accept or verify a
// signature, does NOT consume a challenge (usedAt stays null forever at this stage), and does NOT
// change getTurnCredentials in any way -- getTurnCredentials keeps working exactly as before, and
// no existing client is affected. See functions/src/deviceChallenges.ts for the pure
// types/validation/canonicalization this callable orchestrates.
//
// role and authUid are never accepted from the client: authUid is always request.auth.uid, and
// role is always read from registeredDevices/{deviceId}.role -- request.data itself is restricted
// to exactly {deviceId, purpose, requestPayload}, so a client cannot smuggle in a role, authUid,
// requestHash, nonce, expiresAt, canonicalPayload, or publicKey field to influence what gets
// signed/stored.
const CREATE_DEVICE_CHALLENGE_ALLOWED_REQUEST_KEYS = ["deviceId", "purpose", "requestPayload"];

export const createDeviceChallenge = onCall(
  { region: "europe-west1" },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "UNAUTHENTICATED");
    }
    const authUid = request.auth.uid;

    if (
      typeof request.data !== "object" ||
      request.data === null ||
      Object.keys(request.data as object).some((key) => !CREATE_DEVICE_CHALLENGE_ALLOWED_REQUEST_KEYS.includes(key))
    ) {
      throw new HttpsError("invalid-argument", "INVALID_REQUEST");
    }

    const { deviceId, purpose, requestPayload } = request.data as {
      deviceId?: string;
      purpose?: string;
      requestPayload?: unknown;
    };

    if (typeof deviceId !== "string" || deviceId.trim().length === 0 || deviceId.length > MAX_DEVICE_ID_LENGTH) {
      throw new HttpsError("invalid-argument", "INVALID_DEVICE_ID");
    }

    if (!isDeviceChallengePurpose(purpose)) {
      throw new HttpsError("invalid-argument", "INVALID_PURPOSE");
    }

    logger.info("DEVICE_CHALLENGE_CREATE_START", { deviceId, purpose });

    // Only TURN_CREDENTIALS exists today -- isDeviceChallengePurpose already narrows `purpose` to
    // the single member of DeviceChallengePurpose. Written as a purpose-specific branch anyway so
    // a second purpose can be added later without restructuring this function.
    const payloadValidation = validateTurnCredentialsRequestPayload(requestPayload);
    if (!payloadValidation.valid) {
      logger.info("DEVICE_CHALLENGE_CREATE_DENIED", { deviceId, purpose, reason: payloadValidation.reason });
      throw new HttpsError("invalid-argument", "INVALID_REQUEST_PAYLOAD");
    }
    const turnRequestPayload = payloadValidation.payload;
    const { cameraDeviceId, turnPurpose } = turnRequestPayload;

    const db = admin.firestore();

    const deviceSnap = await db.collection("registeredDevices").doc(deviceId).get();
    const existingDevice = deviceSnap.exists ? (deviceSnap.data() as RegisteredDevice) : null;

    const eligibility = checkDeviceChallengeEligibility(existingDevice, authUid);
    if (!eligibility.eligible) {
      logger.info("DEVICE_CHALLENGE_CREATE_DENIED", {
        deviceId,
        purpose,
        cameraDeviceId,
        turnPurpose,
        reason: eligibility.reason,
      });
      if (eligibility.reason === "DEVICE_NOT_REGISTERED") {
        throw new HttpsError("not-found", "DEVICE_NOT_REGISTERED");
      }
      if (eligibility.reason === "AUTH_UID_MISMATCH") {
        throw new HttpsError("permission-denied", "DEVICE_IDENTITY_MISMATCH");
      }
      throw new HttpsError("failed-precondition", eligibility.reason);
    }
    const role = eligibility.role;

    // A CAMERA may only ever request a challenge about itself -- defense-in-depth on top of the
    // cameraClaims cross-check below (which would already deny a mismatched camera identity via
    // authUid uniqueness), making the invariant explicit rather than incidental.
    if (role === "CAMERA" && deviceId !== cameraDeviceId) {
      logger.info("DEVICE_CHALLENGE_CREATE_DENIED", {
        deviceId,
        role,
        purpose,
        cameraDeviceId,
        turnPurpose,
        reason: "CAMERA_TARGET_MISMATCH",
      });
      throw new HttpsError("permission-denied", "PERMISSION_DENIED");
    }

    // Same preliminary access checks getTurnCredentials itself already performs, reused directly
    // rather than re-implemented -- see getVerifiedCameraClaim's own doc. getTurnCredentials will
    // independently repeat its own checks immediately before actually vending credentials; this
    // callable only ever issues a challenge, never TURN credentials.
    const claim = await getVerifiedCameraClaim(db, cameraDeviceId, authUid);
    if (claim.access === "not-found") {
      logger.info("DEVICE_CHALLENGE_CREATE_DENIED", { deviceId, role, purpose, cameraDeviceId, turnPurpose, reason: "CAMERA_NOT_FOUND" });
      throw new HttpsError("not-found", "CAMERA_NOT_FOUND");
    }
    if (claim.access === "denied") {
      logger.info("DEVICE_CHALLENGE_CREATE_DENIED", { deviceId, role, purpose, cameraDeviceId, turnPurpose, reason: "PERMISSION_DENIED" });
      throw new HttpsError("permission-denied", "PERMISSION_DENIED");
    }

    // Device-status enforcement on the TARGET camera -- reused exactly as getTurnCredentials
    // itself already applies it, unmodified. Throws its own already-safe HttpsError directly
    // (and logs its own DEVICE_OPERATIONAL_CHECK_DENIED event) if the camera is suspended/revoked.
    await assertRegisteredDeviceOperational(db, cameraDeviceId);

    const entitlements = await getEffectiveUserEntitlements(authUid, db);
    if (!entitlements.turnAccessAllowed) {
      logger.info("DEVICE_CHALLENGE_CREATE_DENIED", { deviceId, role, purpose, cameraDeviceId, turnPurpose, reason: "TURN_ACCESS_DENIED" });
      throw new HttpsError("permission-denied", "TURN_ACCESS_DENIED");
    }

    const canonicalRequestPayload = buildCanonicalTurnCredentialsRequestPayload(turnRequestPayload);
    const requestHash = sha256Hex(canonicalRequestPayload);
    const nonce = generateChallengeNonce();
    const expiresAt = admin.firestore.Timestamp.fromMillis(Date.now() + CHALLENGE_TTL_SECONDS * 1000);

    const challengeRef = db.collection("deviceChallenges").doc();
    const challengeId = challengeRef.id;
    const devicePurpose: DeviceChallengePurpose = DEVICE_CHALLENGE_PURPOSES.TURN_CREDENTIALS;

    const canonicalPayload = buildCanonicalDeviceProofPayload({
      challengeId,
      deviceId,
      role,
      purpose: devicePurpose,
      authUid,
      nonce,
      requestHash,
      expiresAtMillis: expiresAt.toMillis(),
    });

    try {
      await challengeRef.set(
        buildDeviceChallengeDocument({
          challengeId,
          deviceId,
          role,
          authUid,
          purpose: devicePurpose,
          nonce,
          requestHash,
          expiresAt,
        })
      );
    } catch {
      logger.error("DEVICE_CHALLENGE_CREATE_DENIED", {
        deviceId,
        role,
        purpose,
        cameraDeviceId,
        turnPurpose,
        reason: "CHALLENGE_WRITE_FAILED",
      });
      throw new HttpsError("internal", "CHALLENGE_CREATE_FAILED");
    }

    logger.info("DEVICE_CHALLENGE_CREATE_SUCCESS", { deviceId, role, purpose, cameraDeviceId, turnPurpose });

    return {
      challengeId,
      nonce,
      purpose: devicePurpose,
      expiresAt: expiresAt.toMillis(),
      canonicalPayload,
    };
  }
);

// Explicit revocation for a lost/stolen device -- a distinct, owner-triggered action, deliberately
// separate from a normal unpair (releaseCameraForUser/unpairCameraFromDevice/
// releaseCameraFromCamera, which only ever clear ownerUid via detachCameraOwner and never touch
// status). See docs/DEVICE_REGISTRY.md.
//
// Authorization: request.auth != null, and the caller's uid must equal the STORED
// registeredDevices/{deviceId}.ownerUid -- never anything the client asserts in the request body
// (only `deviceId` is ever read from it). A device with ownerUid == null (never claimed, or
// already unpaired) can never be revoked this way -- see decideRevokeRegisteredDevice's own doc.
//
// For HOME devices specifically: this creates a correct `revoked` status server-side, but does
// NOT yet cryptographically verify *which* Home installation is making this call -- Home devices
// are not yet authenticated via their own Keystore identity/signature (only Camera is, via
// cameraClaims.cameraAuthUid elsewhere in this file), so `ownerUid` here is only as strong as
// whichever Firebase Auth UID the calling Home app currently holds. See docs/DEVICE_REGISTRY.md's
// "What is enforced today, and what isn't" for the full gap -- this callable does not close it,
// and this comment must not be read as a claim that it does.
export const revokeRegisteredDevice = onCall(
  { region: "europe-west1" },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "UNAUTHENTICATED");
    }

    const { deviceId } = request.data as { deviceId?: string };
    if (typeof deviceId !== "string" || deviceId.trim().length === 0 || deviceId.length > MAX_DEVICE_ID_LENGTH) {
      throw new HttpsError("invalid-argument", "INVALID_DEVICE_ID");
    }

    logger.info("REVOKE_REGISTERED_DEVICE_START", { deviceId });

    const db = admin.firestore();

    let decision: RevokeDeviceDecision;
    try {
      decision = await applyRevokeRegisteredDevice(db, deviceId, request.auth.uid);
    } catch (error: any) {
      logger.error("REVOKE_REGISTERED_DEVICE_FAILED", {
        deviceId,
        errorClass: error?.constructor?.name ?? "Error",
      });
      throw new HttpsError("internal", "REGISTRY_WRITE_FAILED");
    }

    switch (decision.outcome) {
      case "not_found":
        logger.info("REVOKE_REGISTERED_DEVICE_DENIED", { deviceId, reason: "DEVICE_NOT_REGISTERED" });
        throw new HttpsError("not-found", "DEVICE_NOT_REGISTERED");
      case "no_owner":
        logger.info("REVOKE_REGISTERED_DEVICE_DENIED", { deviceId, reason: "DEVICE_NOT_OWNED" });
        throw new HttpsError("failed-precondition", "DEVICE_NOT_OWNED");
      case "owner_mismatch":
        logger.info("REVOKE_REGISTERED_DEVICE_DENIED", { deviceId, reason: "PERMISSION_DENIED" });
        throw new HttpsError("permission-denied", "PERMISSION_DENIED");
      case "revoked":
        logger.info(
          decision.alreadyRevoked ? "REVOKE_REGISTERED_DEVICE_IDEMPOTENT" : "REVOKE_REGISTERED_DEVICE_SUCCESS",
          { deviceId }
        );
        return { success: true, status: "revoked" as const, alreadyRevoked: decision.alreadyRevoked };
      default:
        throw new HttpsError("internal", "INTERNAL");
    }
  }
);

// Automatically brings a user's registeredDevices in line whenever their plan device limits
// (maxCameras/maxHomeDevices) actually change -- create, update, or delete of
// userEntitlements/{uid}. Deliberately does NOT fire reconciliation for a change that leaves both
// limits the same (e.g. subscriptionStatus flipping active <-> blocked alone, or any other field
// changing) -- see entitlements.ts's planDeviceLimitsFromEntitlementsData for why "blocked" is
// never treated as a limit change here. Idempotent and safe under Firestore's at-least-once
// trigger delivery: reconcileUserDeviceLimits itself only ever writes a device that is not
// already in its target state, so a redelivered event (or two of these firing back to back for
// the same uid) converges to the same result without any extra bookkeeping in this handler.
export const reconcileDevicesOnEntitlementChange = onDocumentWritten(
  { document: "userEntitlements/{uid}", region: "europe-west1" },
  async (event) => {
    const beforeData = event.data?.before?.exists ? event.data.before.data() : undefined;
    const afterData = event.data?.after?.exists ? event.data.after.data() : undefined;

    const beforeLimits = planDeviceLimitsFromEntitlementsData(beforeData);
    const afterLimits = planDeviceLimitsFromEntitlementsData(afterData);

    if (beforeLimits.maxCameras === afterLimits.maxCameras && beforeLimits.maxHomeDevices === afterLimits.maxHomeDevices) {
      logger.info("RECONCILE_DEVICES_ON_ENTITLEMENT_CHANGE_SKIPPED_NO_LIMIT_CHANGE", { operation: "entitlement_change" });
      return;
    }

    logger.info("RECONCILE_DEVICES_ON_ENTITLEMENT_CHANGE_START", {
      operation: "entitlement_change",
      maxCameras: afterLimits.maxCameras,
      maxHomeDevices: afterLimits.maxHomeDevices,
    });

    const result = await reconcileUserDeviceLimits(admin.firestore(), event.params.uid, afterLimits);

    logger.info("RECONCILE_DEVICES_ON_ENTITLEMENT_CHANGE_DONE", {
      operation: "entitlement_change",
      changedCount:
        result.camerasSuspended +
        result.camerasReactivated +
        result.homeDevicesSuspended +
        result.homeDevicesReactivated,
    });
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
