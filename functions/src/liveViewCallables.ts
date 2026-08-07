import { onCall, HttpsError } from "firebase-functions/v2/https";
import * as logger from "firebase-functions/logger";
import * as admin from "firebase-admin";
import { validateTurnCredentialsDeviceProof, isValidLiveViewSessionIdFormat } from "./deviceChallenges";
import {
  LIVE_VIEW_LEASE_TTL_MS,
  executeStartLiveViewSession,
  executeRenewLiveViewSession,
  executeEndLiveViewSession,
} from "./liveViewSessions";
import type { LiveViewSessionDenialReason } from "./liveViewSessions";

// ---------------------------------------------------------------------------------------------
// Live View sessions -- stage 1 of coturn abuse protection (see docs/LIVE_VIEW_SESSIONS.md).
// ---------------------------------------------------------------------------------------------
// All business logic (challenge/signature verification, session/allocator transactions) lives in
// liveViewSessions.ts -- these three callables (the only thing this module exports) only parse/
// validate the request shape, map LiveViewSessionDenialReason onto a public HttpsError, and log.
// Never changes getTurnCredentials, the TURN credential format/TTL/secret, or coturn itself -- a
// Live View session is not yet bound to a TURN credential at all (see the doc for why that is
// deliberately deferred). Kept in its own module (not index.ts) so index.ts stays a thin
// import/re-export surface for these three callables -- see index.ts's own comment at the
// re-export site.
//
// Every denial reason collapses to one of a small handful of public codes -- see
// mapLiveViewSessionDenialToHttpsError below -- so a caller can never use the response to learn
// whether a given cameraDeviceId/sessionId exists, who owns it, or which specific internal check
// failed. Only the entitlement limit (the caller's OWN state) gets a distinguishable reason.
//
// Logging contract for every log line in this file: only operation/stage/result/reason/role/
// purpose -- never uid/ownerUid/homeDeviceId/cameraDeviceId/sessionId/challengeId/signature/nonce/
// requestHash/public key/Firebase token/Firestore path/TURN username/TURN credential/TURN secret.
function mapLiveViewSessionDenialToHttpsError(reason: LiveViewSessionDenialReason): HttpsError {
  switch (reason) {
    case "CHALLENGE_NOT_FOUND":
      return new HttpsError("not-found", "CHALLENGE_NOT_FOUND");
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
    case "LIVE_VIEW_LIMIT_REACHED":
      return new HttpsError("resource-exhausted", "LIVE_VIEW_SESSION_LIMIT_REACHED");
    case "LIVE_VIEW_ENTITLEMENT_DENIED":
      return new HttpsError("resource-exhausted", "LIVE_VIEW_ENTITLEMENT_DENIED");
    default:
      return new HttpsError("permission-denied", "LIVE_VIEW_SESSION_DENIED");
  }
}

// Mirrors index.ts's own MAX_DEVICE_ID_LENGTH (128) for registerDevicePublicKey/
// createDeviceChallenge -- kept as an independent constant here (not imported from index.ts) so
// this module has zero dependency on index.ts, avoiding any risk of a circular import (index.ts
// imports the three callables FROM this module).
const MAX_DEVICE_ID_LENGTH = 128;

const START_LIVE_VIEW_SESSION_ALLOWED_KEYS = ["cameraDeviceId", "deviceProof"];

// Canonical Home is NEVER taken from request.data -- only cameraDeviceId (protected by the
// challenge's own requestHash binding, see deviceChallenges.ts's LIVE_VIEW_START payload) and the
// deviceProof envelope are ever read from the client here; the actual Home identity comes back
// from executeStartLiveViewSession's own verified challenge, exactly like getTurnCredentials'
// signed path never trusts a client-asserted device identity.
export const startLiveViewSession = onCall(
  { region: "europe-west1" },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "UNAUTHENTICATED");
    }
    const uid = request.auth.uid;

    if (
      typeof request.data !== "object" ||
      request.data === null ||
      Object.keys(request.data as object).some((key) => !START_LIVE_VIEW_SESSION_ALLOWED_KEYS.includes(key))
    ) {
      throw new HttpsError("invalid-argument", "INVALID_REQUEST");
    }

    const { cameraDeviceId, deviceProof } = request.data as { cameraDeviceId?: string; deviceProof?: unknown };

    if (
      typeof cameraDeviceId !== "string" ||
      cameraDeviceId.trim().length === 0 ||
      cameraDeviceId.length > MAX_DEVICE_ID_LENGTH
    ) {
      throw new HttpsError("invalid-argument", "INVALID_CAMERA_DEVICE_ID");
    }

    const proofValidation = validateTurnCredentialsDeviceProof(deviceProof);
    if (!proofValidation.valid) {
      logger.info("LIVE_VIEW_SESSION_DENIED", {
        operation: "startLiveViewSession",
        role: "HOME",
        stage: "envelope",
        result: "denied",
        reason: proofValidation.reason,
      });
      throw new HttpsError("invalid-argument", "INVALID_DEVICE_PROOF");
    }

    logger.info("LIVE_VIEW_SESSION_START", { operation: "startLiveViewSession", role: "HOME", stage: "start" });

    const db = admin.firestore();
    // Generated BEFORE the transaction -- see executeStartLiveViewSession's own doc for why a
    // retried transaction attempt must never produce a different candidate session id.
    const candidateSessionId = db.collection("liveViewSessions").doc().id;

    const outcome = await executeStartLiveViewSession(db, {
      requestAuthUid: uid,
      cameraDeviceId,
      deviceProof: proofValidation.proof,
      candidateSessionId,
      nowMillis: Date.now(),
    });

    if (outcome.outcome !== "started") {
      logger.info("LIVE_VIEW_SESSION_DENIED", {
        operation: "startLiveViewSession",
        role: "HOME",
        stage: "transaction",
        result: "denied",
        reason: outcome.reason,
      });
      throw mapLiveViewSessionDenialToHttpsError(outcome.reason);
    }

    logger.info("LIVE_VIEW_SESSION_SUCCESS", { operation: "startLiveViewSession", role: "HOME", stage: "transaction", result: "success" });

    return {
      sessionId: outcome.sessionId,
      leaseExpiresAt: outcome.leaseExpiresAtMillis,
      leaseDurationMs: LIVE_VIEW_LEASE_TTL_MS,
    };
  }
);

const RENEW_LIVE_VIEW_SESSION_ALLOWED_KEYS = ["sessionId", "deviceProof"];

export const renewLiveViewSession = onCall(
  { region: "europe-west1" },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "UNAUTHENTICATED");
    }
    const uid = request.auth.uid;

    if (
      typeof request.data !== "object" ||
      request.data === null ||
      Object.keys(request.data as object).some((key) => !RENEW_LIVE_VIEW_SESSION_ALLOWED_KEYS.includes(key))
    ) {
      throw new HttpsError("invalid-argument", "INVALID_REQUEST");
    }

    const { sessionId, deviceProof } = request.data as { sessionId?: string; deviceProof?: unknown };

    // Validated BEFORE it is ever used to build a Firestore document reference (both here-adjacent
    // and inside executeRenewLiveViewSession itself) -- see isValidLiveViewSessionIdFormat's own
    // doc for why an unchecked sessionId could otherwise address an arbitrary nested path.
    if (!isValidLiveViewSessionIdFormat(sessionId)) {
      throw new HttpsError("invalid-argument", "INVALID_SESSION_ID");
    }

    const proofValidation = validateTurnCredentialsDeviceProof(deviceProof);
    if (!proofValidation.valid) {
      logger.info("LIVE_VIEW_SESSION_DENIED", {
        operation: "renewLiveViewSession",
        role: "HOME",
        stage: "envelope",
        result: "denied",
        reason: proofValidation.reason,
      });
      throw new HttpsError("invalid-argument", "INVALID_DEVICE_PROOF");
    }

    logger.info("LIVE_VIEW_SESSION_START", { operation: "renewLiveViewSession", role: "HOME", stage: "start" });

    const db = admin.firestore();
    const outcome = await executeRenewLiveViewSession(db, {
      requestAuthUid: uid,
      sessionId,
      deviceProof: proofValidation.proof,
      nowMillis: Date.now(),
    });

    if (outcome.outcome !== "renewed") {
      logger.info("LIVE_VIEW_SESSION_DENIED", {
        operation: "renewLiveViewSession",
        role: "HOME",
        stage: "transaction",
        result: "denied",
        reason: outcome.reason,
      });
      throw mapLiveViewSessionDenialToHttpsError(outcome.reason);
    }

    logger.info("LIVE_VIEW_SESSION_SUCCESS", { operation: "renewLiveViewSession", role: "HOME", stage: "transaction", result: "success" });

    return {
      sessionId: outcome.sessionId,
      leaseExpiresAt: outcome.leaseExpiresAtMillis,
      leaseDurationMs: LIVE_VIEW_LEASE_TTL_MS,
    };
  }
);

const END_LIVE_VIEW_SESSION_ALLOWED_KEYS = ["sessionId", "deviceProof"];

export const endLiveViewSession = onCall(
  { region: "europe-west1" },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "UNAUTHENTICATED");
    }
    const uid = request.auth.uid;

    if (
      typeof request.data !== "object" ||
      request.data === null ||
      Object.keys(request.data as object).some((key) => !END_LIVE_VIEW_SESSION_ALLOWED_KEYS.includes(key))
    ) {
      throw new HttpsError("invalid-argument", "INVALID_REQUEST");
    }

    const { sessionId, deviceProof } = request.data as { sessionId?: string; deviceProof?: unknown };

    if (!isValidLiveViewSessionIdFormat(sessionId)) {
      throw new HttpsError("invalid-argument", "INVALID_SESSION_ID");
    }

    const proofValidation = validateTurnCredentialsDeviceProof(deviceProof);
    if (!proofValidation.valid) {
      logger.info("LIVE_VIEW_SESSION_DENIED", {
        operation: "endLiveViewSession",
        role: "HOME",
        stage: "envelope",
        result: "denied",
        reason: proofValidation.reason,
      });
      throw new HttpsError("invalid-argument", "INVALID_DEVICE_PROOF");
    }

    logger.info("LIVE_VIEW_SESSION_START", { operation: "endLiveViewSession", role: "HOME", stage: "start" });

    const db = admin.firestore();
    const outcome = await executeEndLiveViewSession(db, {
      requestAuthUid: uid,
      sessionId,
      deviceProof: proofValidation.proof,
      nowMillis: Date.now(),
    });

    if (outcome.outcome !== "ended") {
      logger.info("LIVE_VIEW_SESSION_DENIED", {
        operation: "endLiveViewSession",
        role: "HOME",
        stage: "transaction",
        result: "denied",
        reason: outcome.reason,
      });
      throw mapLiveViewSessionDenialToHttpsError(outcome.reason);
    }

    logger.info("LIVE_VIEW_SESSION_SUCCESS", { operation: "endLiveViewSession", role: "HOME", stage: "transaction", result: "success" });

    return { sessionId: outcome.sessionId, success: true };
  }
);
