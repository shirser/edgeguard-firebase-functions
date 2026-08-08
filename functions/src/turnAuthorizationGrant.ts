import { onCall, HttpsError } from "firebase-functions/v2/https";
import * as logger from "firebase-functions/logger";
import * as admin from "firebase-admin";
import * as crypto from "crypto";
import { defineSecret } from "firebase-functions/params";
import type { TurnCredentialsDeviceProof } from "./deviceChallenges";
import {
  isValidLiveViewSessionIdFormat,
  DEVICE_CHALLENGE_PURPOSES,
  DEVICE_PROOF_VERSION,
  buildCanonicalLiveViewSessionIdRequestPayload,
  validateTurnCredentialsDeviceProof,
  verifyDeviceChallengeForConsumption,
} from "./deviceChallenges";
import { parseLiveViewSession, parseAllocatorState, validateAllocatorEntryAgainstSession } from "./liveViewSessions";

// ---------------------------------------------------------------------------------------------
// TURN authorization grant -- the Firebase-side half of the VPS TURN Auth API design (see
// docs/COTURN_AUDIT.md's "Future direction" and the coturn hardening plan). Firebase performs the
// entire authorization decision here, exactly as it already does for every other Live View
// operation -- this callable introduces no new authorization model, it only packages an existing
// "yes" as a signed, short-lived, unforgeable receipt that a VPS-side service can verify without
// ever touching Firestore or holding Admin SDK credentials of its own.
//
// HOME requires a deviceProof (LIVE_VIEW_TURN_GRANT challenge, sessionId-scoped), verified and
// consumed exactly like startLiveViewSession/renewLiveViewSession/endLiveViewSession's own HOME
// device proofs. This is NOT redundant with the session's own existence: `request.auth.uid` proves
// only account-level identity, but the same Google account can be signed into more than one Home
// installation, each with its own registeredDevices document and Keystore key (see
// liveViewSessions.ts's own HOME_CAMERA_LINK_MISMATCH doc). Without a device-bound proof here, any
// authenticated Home under that uid -- not just the specific installation Stage 1's device
// challenge bound the session to -- could request a grant for another Home device's ACTIVE session
// and use it to join that session's WebRTC call. The device proof's verified `deviceId` MUST equal
// `session.homeDeviceId` -- see the HOME branch below. This was a real gap, found and fixed; do not
// reintroduce a uid-only check for HOME.
//
// CAMERA deliberately does NOT require an equivalent deviceProof: unlike Home's Google-account uid
// (shared across installations), a Camera's `request.auth.uid` IS already its own per-installation
// identity -- each Camera App signs in with its own anonymous Firebase Auth uid, unique per physical
// device (see index.ts's releaseCameraFromCamera doc: "cameraAuthUid ... set from the Camera App's
// anonymous auth uid"). `uid === cameraAuthUid` (checked against cameraClaims/{session.cameraDeviceId},
// which is itself keyed by the specific camera this session is bound to) is therefore already the
// device-binding invariant for CAMERA, not merely an account-level check -- there is no "second
// Camera installation under the same identity" case for a deviceProof to guard against.
//
// TURN_GRANT_SIGNING_SECRET is a separate secret from TURN_REST_SECRET (see
// buildTurnCredentialsResponse in index.ts) and never touches coturn: TURN_GRANT_SIGNING_SECRET
// authorizes "call the VPS Auth API with this session/role/uid"; TURN_REST_SECRET (coturn's own,
// held only by the VPS Auth API after the migration this callable is step one of) authorizes "use
// the relay".
// ---------------------------------------------------------------------------------------------

export type TurnAuthorizationGrantRole = "HOME" | "CAMERA";

export interface TurnAuthorizationGrantPayload {
  sessionId: string;
  role: TurnAuthorizationGrantRole;
  uid: string;
  exp: number; // unix seconds
}

// Short on purpose -- a grant only needs to survive the one hop from this callable to the VPS Auth
// API, not the lifetime of a TURN credential. Shortening this number does not, by itself, bound
// the lifetime of an already-established relay allocation -- that is governed by coturn's own
// allocation lifetime, independent of this grant. See docs/COTURN_AUDIT.md's "Credential TTL vs.
// allocation lifetime" section.
export const TURN_GRANT_TTL_SECONDS = 30;

function base64UrlEncode(input: Buffer): string {
  return input.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(input: string): Buffer | null {
  if (!/^[A-Za-z0-9_-]+$/.test(input)) {
    return null;
  }
  const padded = input + "=".repeat((4 - (input.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

// Pure -- no Firestore/Secret Manager access -- so both directions (sign here, verify on the VPS)
// are directly unit testable without an emulator, mirroring buildTurnCredentialsResponse/
// computeTurnCredential's own testability rationale in index.ts. The VPS Auth API is a separate
// deployable (not a shared npm package) and implements this exact format independently -- this
// function pair is the canonical reference that implementation must match byte-for-byte.
export function signTurnAuthorizationGrant(payload: TurnAuthorizationGrantPayload, secret: string): string {
  const payloadB64 = base64UrlEncode(Buffer.from(JSON.stringify(payload), "utf8"));
  const sig = crypto.createHmac("sha256", secret).update(payloadB64).digest();
  return `${payloadB64}.${base64UrlEncode(sig)}`;
}

export type TurnAuthorizationGrantVerification =
  | { valid: true; payload: TurnAuthorizationGrantPayload }
  | { valid: false };

// Included for test symmetry and as the canonical reference for the VPS's independent
// implementation -- production Firebase code never calls this (Firebase only ever signs, never
// verifies its own grants).
export function verifyTurnAuthorizationGrant(
  grant: string,
  secret: string,
  nowSeconds: number
): TurnAuthorizationGrantVerification {
  const parts = grant.split(".");
  if (parts.length !== 2) {
    return { valid: false };
  }
  const [payloadB64, sigB64] = parts;
  const payloadBuf = base64UrlDecode(payloadB64);
  const sigBuf = base64UrlDecode(sigB64);
  if (!payloadBuf || !sigBuf) {
    return { valid: false };
  }
  const expectedSig = crypto.createHmac("sha256", secret).update(payloadB64).digest();
  if (sigBuf.length !== expectedSig.length || !crypto.timingSafeEqual(sigBuf, expectedSig)) {
    return { valid: false };
  }
  let payload: unknown;
  try {
    payload = JSON.parse(payloadBuf.toString("utf8"));
  } catch {
    return { valid: false };
  }
  if (
    typeof payload !== "object" ||
    payload === null ||
    typeof (payload as Record<string, unknown>).sessionId !== "string" ||
    ((payload as Record<string, unknown>).role !== "HOME" && (payload as Record<string, unknown>).role !== "CAMERA") ||
    typeof (payload as Record<string, unknown>).uid !== "string" ||
    typeof (payload as Record<string, unknown>).exp !== "number"
  ) {
    return { valid: false };
  }
  const typedPayload = payload as TurnAuthorizationGrantPayload;
  if (typedPayload.exp <= nowSeconds) {
    return { valid: false };
  }
  return { valid: true, payload: typedPayload };
}

const turnGrantSigningSecret = defineSecret("TURN_GRANT_SIGNING_SECRET");

const GET_TURN_AUTHORIZATION_GRANT_ALLOWED_KEYS = ["sessionId", "role", "deviceProof"];

// Every way the HOME transactional path below can deny a grant -- collapsed, like every other
// denial in this file, onto the one generic permission-denied TURN_GRANT_DENIED response (see this
// callable's own logging-contract doc). `stage` is for internal logging only.
type HomeGrantTransactionOutcome = { ok: true } | { ok: false; stage: "session" | "identity" | "allocator" };

// Every denial collapses to one generic code, exactly like mapLiveViewSessionDenialToHttpsError in
// liveViewCallables.ts and mapTurnCredentialsChallengeDenialToHttpsError in index.ts -- a caller
// must never be able to distinguish "session not found" from "wrong role" from "allocator not
// HEALTHY" from "session ended" from "not your session" from "not your camera". See those two
// functions' own docs for why this collapsing is this project's standing convention for every
// authorization denial in a TURN-adjacent path.
//
// Logging contract matches liveViewCallables.ts: only operation/stage/result/role -- never uid/
// sessionId/ownerUid/homeDeviceId/cameraDeviceId/the grant itself.
export const getTurnAuthorizationGrant = onCall(
  { region: "europe-west1", secrets: [turnGrantSigningSecret] },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "UNAUTHENTICATED");
    }
    const uid = request.auth.uid;

    if (
      typeof request.data !== "object" ||
      request.data === null ||
      Object.keys(request.data as object).some((key) => !GET_TURN_AUTHORIZATION_GRANT_ALLOWED_KEYS.includes(key))
    ) {
      throw new HttpsError("invalid-argument", "INVALID_REQUEST");
    }

    const { sessionId, role, deviceProof } = request.data as { sessionId?: string; role?: string; deviceProof?: unknown };

    if (!isValidLiveViewSessionIdFormat(sessionId)) {
      throw new HttpsError("invalid-argument", "INVALID_SESSION_ID");
    }
    if (role !== "HOME" && role !== "CAMERA") {
      throw new HttpsError("invalid-argument", "INVALID_ROLE");
    }

    // deviceProof is required for HOME (see this file's top-of-file doc for why) and forbidden for
    // CAMERA (whose own equivalent binding -- uid === cameraAuthUid -- needs no signature; accepting
    // and silently ignoring an authentication-adjacent field here would violate this codebase's
    // closed-request-schema convention, so it is rejected outright instead).
    let homeDeviceProof: TurnCredentialsDeviceProof | undefined;
    if (role === "HOME") {
      const proofValidation = validateTurnCredentialsDeviceProof(deviceProof);
      if (!proofValidation.valid) {
        logger.info("TURN_AUTHORIZATION_GRANT_DENIED", {
          operation: "getTurnAuthorizationGrant",
          role,
          stage: "envelope",
          result: "denied",
          reason: proofValidation.reason,
        });
        throw new HttpsError("invalid-argument", "INVALID_DEVICE_PROOF");
      }
      homeDeviceProof = proofValidation.proof;
    } else if (deviceProof !== undefined) {
      throw new HttpsError("invalid-argument", "INVALID_REQUEST");
    }

    logger.info("TURN_AUTHORIZATION_GRANT_START", { operation: "getTurnAuthorizationGrant", role, stage: "start" });

    const db = admin.firestore();
    const nowMillis = Date.now();

    if (role === "HOME") {
      // Session read, device-proof verification/consumption, and allocator-entry validation all run
      // inside ONE transaction -- exactly like startLiveViewSession/renewLiveViewSession's own shape
      // -- so a concurrent unpair/re-claim/second-consumption attempt can never race between
      // "verified" and "consumed", and the challenge is only ever marked used once every other check
      // has also passed.
      const outcome = await db.runTransaction(async (t): Promise<HomeGrantTransactionOutcome> => {
        const sessionSnap = await t.get(db.collection("liveViewSessions").doc(sessionId));
        const sessionParse = parseLiveViewSession(sessionId, sessionSnap.data());
        if (!sessionParse.valid) {
          return { ok: false, stage: "session" };
        }
        const session = sessionParse.session;
        if (session.status !== "ACTIVE" || session.leaseExpiresAt.toMillis() <= nowMillis) {
          return { ok: false, stage: "session" };
        }

        // The device-binding invariant this fix exists to restore: the signature must have been
        // produced by the EXACT Home installation this session itself is bound to (session.homeDeviceId,
        // written once by startLiveViewSession's own verified challenge) -- not just any Home device
        // belonging to the same account. requireOwnerUidEqualsAuthUid additionally re-proves
        // account-level ownership (uid === requestingDevice.ownerUid), matching what the old
        // `uid !== session.ownerUid` check provided, now cryptographically backed rather than
        // trusted from request.auth alone.
        const verification = await verifyDeviceChallengeForConsumption(t, db, {
          requestAuthUid: uid,
          expectedPurpose: DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_TURN_GRANT,
          deviceProof: homeDeviceProof as TurnCredentialsDeviceProof,
          canonicalRequestPayload: buildCanonicalLiveViewSessionIdRequestPayload(DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_TURN_GRANT, {
            sessionId,
          }),
          nowMillis,
          expectedRole: "HOME",
          requireOwnerUidEqualsAuthUid: true,
        });
        if (!verification.verified) {
          return { ok: false, stage: "identity" };
        }
        // Mirrors RENEW's own enforcement (not the old, pre-fix getTurnAuthorizationGrant behavior,
        // which never checked this for HOME at all) -- a suspended/revoked Home must not be able to
        // keep pulling fresh TURN grants for an otherwise-still-ACTIVE session.
        if (!verification.operational.operational) {
          return { ok: false, stage: "identity" };
        }
        if (verification.deviceId !== session.homeDeviceId || session.ownerUid !== uid) {
          return { ok: false, stage: "identity" };
        }

        const allocatorSnap = await t.get(db.collection("liveViewUserStates").doc(session.ownerUid));
        const allocatorParse = parseAllocatorState(allocatorSnap.data());
        if (!allocatorParse.valid) {
          return { ok: false, stage: "allocator" };
        }
        const entry = allocatorParse.activeSessions[sessionId];
        if (!entry || !validateAllocatorEntryAgainstSession(entry, session, session.ownerUid, nowMillis)) {
          return { ok: false, stage: "allocator" };
        }

        const now = admin.firestore.FieldValue.serverTimestamp();
        t.update(verification.challengeRef, { usedAt: now, usedByFunction: "getTurnAuthorizationGrant" });
        const currentDeviceProofVersion = verification.requestingDevice.deviceProofVersion;
        if (!currentDeviceProofVersion || currentDeviceProofVersion < DEVICE_PROOF_VERSION) {
          t.set(
            verification.requestingDeviceRef,
            { deviceProofVersion: DEVICE_PROOF_VERSION, updatedAt: now, lastSeenAt: now },
            { merge: true }
          );
        }

        return { ok: true };
      });

      if (!outcome.ok) {
        logger.info("TURN_AUTHORIZATION_GRANT_DENIED", {
          operation: "getTurnAuthorizationGrant",
          role,
          stage: outcome.stage,
          result: "denied",
        });
        throw new HttpsError("permission-denied", "TURN_GRANT_DENIED");
      }
    } else {
      // CAMERA -- unchanged from before this fix: uid === cameraAuthUid is already this role's own
      // device-binding invariant (see this file's top-of-file doc), so no deviceProof/transaction is
      // needed here.
      const sessionSnap = await db.collection("liveViewSessions").doc(sessionId).get();
      const sessionParse = parseLiveViewSession(sessionId, sessionSnap.data());
      if (!sessionParse.valid) {
        logger.info("TURN_AUTHORIZATION_GRANT_DENIED", {
          operation: "getTurnAuthorizationGrant",
          role,
          stage: "session",
          result: "denied",
        });
        throw new HttpsError("permission-denied", "TURN_GRANT_DENIED");
      }
      const session = sessionParse.session;

      if (session.status !== "ACTIVE" || session.leaseExpiresAt.toMillis() <= nowMillis) {
        logger.info("TURN_AUTHORIZATION_GRANT_DENIED", {
          operation: "getTurnAuthorizationGrant",
          role,
          stage: "session",
          result: "denied",
        });
        throw new HttpsError("permission-denied", "TURN_GRANT_DENIED");
      }

      const claimSnap = await db.collection("cameraClaims").doc(session.cameraDeviceId).get();
      const cameraAuthUid = claimSnap.exists ? (claimSnap.get("cameraAuthUid") as string | undefined) : undefined;
      if (!cameraAuthUid || uid !== cameraAuthUid) {
        logger.info("TURN_AUTHORIZATION_GRANT_DENIED", {
          operation: "getTurnAuthorizationGrant",
          role,
          stage: "identity",
          result: "denied",
        });
        throw new HttpsError("permission-denied", "TURN_GRANT_DENIED");
      }

      const allocatorSnap = await db.collection("liveViewUserStates").doc(session.ownerUid).get();
      const allocatorParse = parseAllocatorState(allocatorSnap.data());
      if (!allocatorParse.valid) {
        logger.info("TURN_AUTHORIZATION_GRANT_DENIED", {
          operation: "getTurnAuthorizationGrant",
          role,
          stage: "allocator",
          result: "denied",
        });
        throw new HttpsError("permission-denied", "TURN_GRANT_DENIED");
      }

      const entry = allocatorParse.activeSessions[sessionId];
      if (!entry || !validateAllocatorEntryAgainstSession(entry, session, session.ownerUid, nowMillis)) {
        logger.info("TURN_AUTHORIZATION_GRANT_DENIED", {
          operation: "getTurnAuthorizationGrant",
          role,
          stage: "allocator",
          result: "denied",
        });
        throw new HttpsError("permission-denied", "TURN_GRANT_DENIED");
      }
    }

    // .value() returns "" (not undefined/throw) when the secret isn't provisioned -- mirrors
    // buildTurnCredentialsResponse's own explicit guard in index.ts for turnRestSecret; a falsy
    // secret must never silently sign a grant with an empty-string key.
    const secretValue = turnGrantSigningSecret.value();
    if (!secretValue) {
      logger.error("TURN_AUTHORIZATION_GRANT_MISSING_SECRET", { operation: "getTurnAuthorizationGrant", role });
      throw new HttpsError("internal", "INTERNAL");
    }

    const exp = Math.floor(nowMillis / 1000) + TURN_GRANT_TTL_SECONDS;
    const grant = signTurnAuthorizationGrant({ sessionId, role, uid, exp }, secretValue);

    logger.info("TURN_AUTHORIZATION_GRANT_SUCCESS", {
      operation: "getTurnAuthorizationGrant",
      role,
      stage: "issue",
      result: "success",
    });

    return { grant, expiresAt: exp };
  }
);
