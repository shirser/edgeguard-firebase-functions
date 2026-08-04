import * as admin from "firebase-admin";
import * as crypto from "crypto";
import type { DeviceRole, RegisteredDevice } from "./deviceRegistry";
import { checkRegisteredDeviceOperational } from "./deviceRegistry";

// ---------------------------------------------------------------------------------------------
// Device-signature challenge protocol -- foundation stage (TURN_CREDENTIALS only).
// ---------------------------------------------------------------------------------------------
// authenticated, already-registered (identityMode: "keystore") device -> createDeviceChallenge ->
// a fresh deviceChallenges/{challengeId} document carrying a server-generated nonce and a
// requestHash binding the eventual signature to specific, already-validated operation parameters.
//
// Deliberately NOT implemented at this stage (a later backend sub-task): signature acceptance,
// signature verification, challenge consumption (usedAt), replay prevention beyond "the challenge
// merely exists and is unexpired", deviceProofVersion, and any change to getTurnCredentials
// itself, which is completely unaffected by this module.
//
// Every type, constant, validator, and pure builder function below has no dependency on the
// Functions SDK (never imports/throws HttpsError, mirroring deviceRegistry.ts's own "never
// imports HttpsError" rule) and no dependency on index.ts (to avoid any circular import) --
// index.ts's createDeviceChallenge callable is the only place that maps these pure decisions onto
// HttpsError and does the actual Firestore reads/writes.

export const DEVICE_CHALLENGE_PURPOSES = {
  TURN_CREDENTIALS: "TURN_CREDENTIALS",
} as const;

export type DeviceChallengePurpose = (typeof DEVICE_CHALLENGE_PURPOSES)[keyof typeof DEVICE_CHALLENGE_PURPOSES];

export function isDeviceChallengePurpose(value: unknown): value is DeviceChallengePurpose {
  return value === DEVICE_CHALLENGE_PURPOSES.TURN_CREDENTIALS;
}

// Mirrors index.ts's own MAX_DEVICE_ID_LENGTH (128) for registerDevicePublicKey/
// revokeRegisteredDevice -- kept as an independent constant here (not imported from index.ts) so
// this module has zero dependency on index.ts, avoiding any risk of a circular import between the
// two files.
const MAX_DEVICE_ID_LENGTH = 128;

// The exact same 5 TURN purposes index.ts's own ALLOWED_TURN_PURPOSES/isValidTurnPurpose already
// accept for getTurnCredentials -- duplicated here (not imported), for the same
// no-circular-import reason as MAX_DEVICE_ID_LENGTH above. If the real set of TURN purposes ever
// changes, both lists must be updated together.
const TURN_CHALLENGE_PURPOSES = [
  "LIVE_VIEW",
  "PLACEMENT_PREVIEW",
  "ACTIVITY_ZONE",
  "ENTRY_EXIT_LINE",
  "MEDIA_TRANSFER",
] as const;

export type TurnChallengePurpose = (typeof TURN_CHALLENGE_PURPOSES)[number];

export interface TurnCredentialsChallengeRequestPayload {
  cameraDeviceId: string;
  turnPurpose: TurnChallengePurpose;
}

export type RequestPayloadInvalidReason =
  | "NOT_AN_OBJECT"
  | "MISSING_FIELDS"
  | "UNEXPECTED_FIELDS"
  | "INVALID_CAMERA_DEVICE_ID"
  | "INVALID_TURN_PURPOSE";

export type TurnCredentialsRequestPayloadValidation =
  | { valid: true; payload: TurnCredentialsChallengeRequestPayload }
  | { valid: false; reason: RequestPayloadInvalidReason };

const TURN_REQUEST_PAYLOAD_ALLOWED_KEYS = ["cameraDeviceId", "turnPurpose"] as const;

// Strict, closed validator for TURN_CREDENTIALS' own request payload -- deliberately not a
// Record<string, string>. Rejects a non-object, missing fields, unexpected/extra fields, wrong
// types, empty/blank strings, an over-length cameraDeviceId, and an unknown turnPurpose. Pure --
// no Firestore access, directly unit-testable.
export function validateTurnCredentialsRequestPayload(
  payload: unknown
): TurnCredentialsRequestPayloadValidation {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return { valid: false, reason: "NOT_AN_OBJECT" };
  }

  const data = payload as Record<string, unknown>;
  const keys = Object.keys(data);

  if (keys.some((key) => !(TURN_REQUEST_PAYLOAD_ALLOWED_KEYS as readonly string[]).includes(key))) {
    return { valid: false, reason: "UNEXPECTED_FIELDS" };
  }
  if (!("cameraDeviceId" in data) || !("turnPurpose" in data)) {
    return { valid: false, reason: "MISSING_FIELDS" };
  }

  const cameraDeviceId = data.cameraDeviceId;
  if (
    typeof cameraDeviceId !== "string" ||
    cameraDeviceId.trim().length === 0 ||
    cameraDeviceId.length > MAX_DEVICE_ID_LENGTH
  ) {
    return { valid: false, reason: "INVALID_CAMERA_DEVICE_ID" };
  }

  const turnPurpose = data.turnPurpose;
  if (typeof turnPurpose !== "string" || !(TURN_CHALLENGE_PURPOSES as readonly string[]).includes(turnPurpose)) {
    return { valid: false, reason: "INVALID_TURN_PURPOSE" };
  }

  return { valid: true, payload: { cameraDeviceId, turnPurpose: turnPurpose as TurnChallengePurpose } };
}

// --- Canonical TURN request payload --------------------------------------------------------------
// Deterministic, fixed-order, LF-joined, no trailing newline, UTF-8 -- never JSON.stringify(). This
// is the exact string hashed into requestHash below. Purpose-specific: only TURN_CREDENTIALS exists
// today.

const REQUEST_PAYLOAD_PROTOCOL_VERSION = "EDGEGUARD_REQUEST_V1";

export function buildCanonicalTurnCredentialsRequestPayload(
  payload: TurnCredentialsChallengeRequestPayload
): string {
  return [
    REQUEST_PAYLOAD_PROTOCOL_VERSION,
    `purpose=${DEVICE_CHALLENGE_PURPOSES.TURN_CREDENTIALS}`,
    `cameraDeviceId=${payload.cameraDeviceId}`,
    `turnPurpose=${payload.turnPurpose}`,
  ].join("\n");
}

// Lowercase hex, 64 characters -- Node's Buffer#digest("hex") is already lowercase, matching this
// project's existing SHA-256 convention (deviceRegistry.ts's own key fingerprint,
// createCameraPairingSession's own pairingSecretHash).
export function sha256Hex(input: string): string {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
}

// --- Canonical device-proof payload ---------------------------------------------------------------
// The exact bytes a device will later sign. Fixed field order, LF-joined, no trailing newline,
// UTF-8, ≤ 1024 bytes. Built server-side and returned to the caller as-is (see index.ts's
// createDeviceChallenge) -- verification (a later sub-task) will always independently rebuild this
// same string from the stored challenge document, never trust a client-echoed copy.

const DEVICE_PROOF_PROTOCOL_VERSION = "EDGEGUARD_DEVICE_PROOF_V1";
export const DEVICE_PROOF_MAX_BYTES = 1024;

export interface CanonicalDeviceProofFields {
  challengeId: string;
  deviceId: string;
  role: DeviceRole;
  purpose: DeviceChallengePurpose;
  authUid: string;
  nonce: string;
  requestHash: string;
  expiresAtMillis: number;
}

export function buildCanonicalDeviceProofPayload(fields: CanonicalDeviceProofFields): string {
  return [
    DEVICE_PROOF_PROTOCOL_VERSION,
    `challengeId=${fields.challengeId}`,
    `deviceId=${fields.deviceId}`,
    `role=${fields.role}`,
    `purpose=${fields.purpose}`,
    `authUid=${fields.authUid}`,
    `nonce=${fields.nonce}`,
    `requestHash=${fields.requestHash}`,
    `expiresAt=${fields.expiresAtMillis}`,
  ].join("\n");
}

// --- Nonce -----------------------------------------------------------------------------------

export const CHALLENGE_NONCE_BYTE_LENGTH = 32;
export const CHALLENGE_TTL_SECONDS = 90;

// Cryptographically random -- crypto.randomBytes, never Math.random()/a UUID. Base64url, no
// padding: 32 raw bytes -> exactly 43 characters.
export function generateChallengeNonce(): string {
  return crypto.randomBytes(CHALLENGE_NONCE_BYTE_LENGTH).toString("base64url");
}

// --- registeredDevices eligibility -----------------------------------------------------------
// Pure: takes the already-fetched registeredDevices/{deviceId} document (or null) and the
// authenticated caller's uid, decides whether this device may be issued ANY challenge at all.
// Deliberately stricter than checkRegisteredDeviceOperational's own missing-document default
// (permissive there; a challenge REQUIRES an existing, keystore-provisioned device -- a missing
// document here is always DEVICE_NOT_REGISTERED, never permissive). Never consults ownerUid --
// see deviceRegistry.ts's own "ownerUid is never used to authenticate a Camera" (and,
// symmetrically, a Home device's ownerUid is just its own authUid, already covered by the authUid
// check below).

export type DeviceChallengeEligibilityReason =
  | "DEVICE_NOT_REGISTERED"
  | "DEVICE_NOT_PROVISIONED"
  | "DEVICE_IDENTITY_CORRUPT"
  | "AUTH_UID_MISMATCH"
  | "DEVICE_SUSPENDED"
  | "DEVICE_SUSPENDED_PLAN"
  | "DEVICE_REVOKED";

export type DeviceChallengeEligibilityDecision =
  | { eligible: true; role: DeviceRole }
  | { eligible: false; reason: DeviceChallengeEligibilityReason };

export function checkDeviceChallengeEligibility(
  existing: RegisteredDevice | null,
  authUid: string
): DeviceChallengeEligibilityDecision {
  if (!existing) {
    return { eligible: false, reason: "DEVICE_NOT_REGISTERED" };
  }
  if (existing.identityMode !== "keystore") {
    return { eligible: false, reason: "DEVICE_NOT_PROVISIONED" };
  }
  if (!existing.publicKey) {
    return { eligible: false, reason: "DEVICE_IDENTITY_CORRUPT" };
  }
  if (existing.authUid !== authUid) {
    return { eligible: false, reason: "AUTH_UID_MISMATCH" };
  }

  const operational = checkRegisteredDeviceOperational(existing);
  if (!operational.operational) {
    return { eligible: false, reason: operational.reason };
  }

  return { eligible: true, role: existing.role };
}

// --- deviceChallenges document assembly --------------------------------------------------------
// Guarantees the exact, fixed field set of a deviceChallenges/{challengeId} document in one place
// (rather than an inline object literal in index.ts), so the schema is directly testable.

export const DEVICE_CHALLENGE_SCHEMA_VERSION = 1;

export interface DeviceChallengeDocument {
  schemaVersion: number;
  challengeId: string;
  deviceId: string;
  role: DeviceRole;
  authUid: string;
  purpose: DeviceChallengePurpose;
  nonce: string;
  requestHash: string;
  createdAt: admin.firestore.FieldValue;
  expiresAt: admin.firestore.Timestamp;
  usedAt: null;
  usedByFunction: null;
}

export function buildDeviceChallengeDocument(fields: {
  challengeId: string;
  deviceId: string;
  role: DeviceRole;
  authUid: string;
  purpose: DeviceChallengePurpose;
  nonce: string;
  requestHash: string;
  expiresAt: admin.firestore.Timestamp;
}): DeviceChallengeDocument {
  return {
    schemaVersion: DEVICE_CHALLENGE_SCHEMA_VERSION,
    challengeId: fields.challengeId,
    deviceId: fields.deviceId,
    role: fields.role,
    authUid: fields.authUid,
    purpose: fields.purpose,
    nonce: fields.nonce,
    requestHash: fields.requestHash,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    expiresAt: fields.expiresAt,
    usedAt: null,
    usedByFunction: null,
  };
}
