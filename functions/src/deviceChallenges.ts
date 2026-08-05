import * as admin from "firebase-admin";
import * as crypto from "crypto";
import type { DeviceOperationalReason, DeviceRole, RegisteredDevice } from "./deviceRegistry";
import { checkRegisteredDeviceOperational } from "./deviceRegistry";
import type { EffectiveUserEntitlements } from "./entitlements";
import { effectiveUserEntitlementsFromData } from "./entitlements";

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

// Firestore auto-ids are exactly 20 characters ([A-Za-z0-9]), but this bound is intentionally
// generous rather than pinned to that exact length -- it only needs to keep a client-supplied
// challengeId small and, together with the charset check in validateTurnCredentialsDeviceProof
// below, prevent it from ever containing "/" (which db.collection(...).doc(challengeId) would
// otherwise interpret as a path separator into an arbitrary nested document path).
const MAX_CHALLENGE_ID_LENGTH = 128;

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

// ---------------------------------------------------------------------------------------------
// Device-proof verification -- getTurnCredentials, first protected endpoint.
// ---------------------------------------------------------------------------------------------
// Everything below is used only when a caller's getTurnCredentials request includes an OPTIONAL
// `deviceProof` field. It is never required by identityMode or deviceProofVersion at this stage --
// see index.ts's getTurnCredentials for the exact backward-compatible branch. Still never imports
// HttpsError/the Functions SDK (same rule as the rest of this file) -- index.ts is the only place
// that maps these pure/transactional outcomes onto HttpsError.

// The only client-suppliable envelope wrapping a device signature. Deliberately narrow: deviceId,
// role, authUid, nonce, requestHash, canonicalPayload, publicKey, and expiresAt are NEVER accepted
// here -- every one of them is instead re-derived server-side from deviceChallenges/{challengeId}
// and registeredDevices/{deviceId} inside the same transaction that verifies the signature (see
// consumeVerifiedTurnCredentialsChallenge below).
export interface TurnCredentialsDeviceProof {
  protocolVersion: 1;
  challengeId: string;
  signature: string;
}

export type DeviceProofInvalidReason =
  | "NOT_AN_OBJECT"
  | "MISSING_FIELDS"
  | "UNEXPECTED_FIELDS"
  | "INVALID_PROTOCOL_VERSION"
  | "INVALID_CHALLENGE_ID"
  | "INVALID_SIGNATURE";

export type TurnCredentialsDeviceProofValidation =
  | { valid: true; proof: TurnCredentialsDeviceProof }
  | { valid: false; reason: DeviceProofInvalidReason };

const DEVICE_PROOF_ENVELOPE_ALLOWED_KEYS = ["protocolVersion", "challengeId", "signature"] as const;
export const DEVICE_PROOF_SUPPORTED_PROTOCOL_VERSION = 1;
// Firestore auto-id charset -- see MAX_CHALLENGE_ID_LENGTH's own doc for why this also excludes
// "/" specifically (a path-separator injection concern for db.collection(...).doc(challengeId)).
const CHALLENGE_ID_PATTERN = /^[A-Za-z0-9]{1,128}$/;

export type SignatureInvalidReason =
  | "EMPTY"
  | "CONTAINS_WHITESPACE"
  | "BASE64URL_VARIANT"
  | "NOT_STANDARD_BASE64"
  | "EMPTY_AFTER_DECODE"
  | "NON_CANONICAL_BASE64"
  | "TOO_LARGE";

export type SignatureBase64Validation =
  | { valid: true; derBuffer: Buffer }
  | { valid: false; reason: SignatureInvalidReason };

// Real-world P-256 DER ECDSA signatures are at most ~72 bytes (two ~32-byte INTEGERs plus a few
// bytes of ASN.1 overhead); this bound is generous headroom, not a tight fit -- mirrors
// MAX_DEVICE_PUBLIC_KEY_LENGTH's own "generous, not tight" rationale in index.ts.
export const DEVICE_PROOF_SIGNATURE_MAX_BYTES = 200;

const STANDARD_BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

// Same structure/order as deviceRegistry.ts's own validateEcP256PublicKey (whitespace ->
// Base64URL-variant chars -> standard-alphabet pattern -> decode -> empty-after-decode ->
// canonical-reencoding -> size), reused here for the signature field instead of the public key.
// Never throws. Does NOT check DER structure/ECDSA-Sig-Value validity -- that is left to
// verifyDeviceProofSignature below (crypto.verify itself is what actually parses the DER), so a
// malformed-but-canonical-Base64 signature is only ever distinguished from a
// well-formed-but-cryptographically-invalid one by the caller's own generic "signature invalid"
// outcome, never by this function.
export function validateDeviceProofSignatureBase64(signatureBase64: unknown): SignatureBase64Validation {
  if (typeof signatureBase64 !== "string" || signatureBase64.length === 0) {
    return { valid: false, reason: "EMPTY" };
  }
  if (/\s/.test(signatureBase64)) {
    return { valid: false, reason: "CONTAINS_WHITESPACE" };
  }
  if (signatureBase64.includes("-") || signatureBase64.includes("_")) {
    return { valid: false, reason: "BASE64URL_VARIANT" };
  }
  if (!STANDARD_BASE64_PATTERN.test(signatureBase64)) {
    return { valid: false, reason: "NOT_STANDARD_BASE64" };
  }

  const derBuffer = Buffer.from(signatureBase64, "base64");

  if (derBuffer.length === 0) {
    return { valid: false, reason: "EMPTY_AFTER_DECODE" };
  }
  if (derBuffer.toString("base64") !== signatureBase64) {
    return { valid: false, reason: "NON_CANONICAL_BASE64" };
  }
  if (derBuffer.length > DEVICE_PROOF_SIGNATURE_MAX_BYTES) {
    return { valid: false, reason: "TOO_LARGE" };
  }

  return { valid: true, derBuffer };
}

// Strict, closed validator for the deviceProof envelope itself -- deliberately not a
// Record<string, unknown>. Rejects a non-object, missing fields, unexpected/extra fields
// (deviceId/role/authUid/nonce/requestHash/canonicalPayload/publicKey/expiresAt included), a
// protocolVersion other than exactly 1, a malformed challengeId, and a malformed signature. Pure --
// no Firestore access, directly unit-testable. Never validates the signature CRYPTOGRAPHICALLY --
// only its Base64 shape (see validateDeviceProofSignatureBase64 above).
export function validateTurnCredentialsDeviceProof(value: unknown): TurnCredentialsDeviceProofValidation {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return { valid: false, reason: "NOT_AN_OBJECT" };
  }

  const data = value as Record<string, unknown>;
  const keys = Object.keys(data);

  if (keys.some((key) => !(DEVICE_PROOF_ENVELOPE_ALLOWED_KEYS as readonly string[]).includes(key))) {
    return { valid: false, reason: "UNEXPECTED_FIELDS" };
  }
  if (!("protocolVersion" in data) || !("challengeId" in data) || !("signature" in data)) {
    return { valid: false, reason: "MISSING_FIELDS" };
  }
  if (data.protocolVersion !== DEVICE_PROOF_SUPPORTED_PROTOCOL_VERSION) {
    return { valid: false, reason: "INVALID_PROTOCOL_VERSION" };
  }

  const challengeId = data.challengeId;
  if (
    typeof challengeId !== "string" ||
    challengeId.length > MAX_CHALLENGE_ID_LENGTH ||
    !CHALLENGE_ID_PATTERN.test(challengeId)
  ) {
    return { valid: false, reason: "INVALID_CHALLENGE_ID" };
  }

  const signatureValidation = validateDeviceProofSignatureBase64(data.signature);
  if (!signatureValidation.valid) {
    return { valid: false, reason: "INVALID_SIGNATURE" };
  }

  return {
    valid: true,
    proof: { protocolVersion: 1, challengeId, signature: data.signature as string },
  };
}

// Node-side ECDSA verification, compatible with the Android Keystore's own
// SHA256withECDSA -> ASN.1 DER -> standard Base64 pipeline (see HomeDeviceProofSigner.kt/
// CameraDeviceProofSigner.kt in the Android repos). `publicKeyBase64` must already be the exact,
// already-validated SPKI DER Base64 string stored at registeredDevices/{deviceId}.publicKey --
// this function never accepts a public key from the client. Never throws: a corrupt stored key, a
// malformed DER signature, or any other crypto error all safely resolve to `false`, never an
// uncaught exception -- consumeVerifiedTurnCredentialsChallenge below treats `false` the same as
// any other denial.
export function verifyDeviceProofSignature(
  canonicalPayload: string,
  publicKeyBase64: string,
  signatureBase64: string
): boolean {
  try {
    const publicKeyObject = crypto.createPublicKey({
      key: Buffer.from(publicKeyBase64, "base64"),
      format: "der",
      type: "spki",
    });
    const signatureBuffer = Buffer.from(signatureBase64, "base64");
    return crypto.verify("sha256", Buffer.from(canonicalPayload, "utf8"), publicKeyObject, signatureBuffer);
  } catch {
    return false;
  }
}

// --- Nonce/requestHash STORED-format sanity checks -----------------------------------------------
// Defensive only -- deviceChallenges documents are exclusively written by createDeviceChallenge
// (see buildDeviceChallengeDocument above), so these should never actually fail for a real
// document. Guards against a corrupt/tampered-with-Admin-SDK document rather than anything a
// client can influence.

const CHALLENGE_NONCE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const CHALLENGE_REQUEST_HASH_PATTERN = /^[0-9a-f]{64}$/;

// Every way consumeVerifiedTurnCredentialsChallenge below can deny a TURN_CREDENTIALS device-proof
// verification -- deliberately detailed (mirrors DeviceChallengeEligibilityReason's own
// exhaustiveness) for tests and safe internal logging; index.ts's own error mapping deliberately
// collapses most of these into ONE generic public message (see its own doc) so a caller can never
// use the response to distinguish which specific check failed.
export type TurnCredentialsChallengeVerificationFailureReason =
  | "CHALLENGE_NOT_FOUND"
  | "CHALLENGE_SCHEMA_MISMATCH"
  | "CHALLENGE_ID_MISMATCH"
  | "CHALLENGE_PURPOSE_MISMATCH"
  | "CHALLENGE_AUTH_UID_MISMATCH"
  | "CHALLENGE_ALREADY_USED"
  | "CHALLENGE_EXPIRED"
  | "CHALLENGE_NONCE_MALFORMED"
  | "CHALLENGE_REQUEST_HASH_MALFORMED"
  | "CHALLENGE_ROLE_INVALID"
  | "REQUESTING_DEVICE_NOT_REGISTERED"
  | "REQUESTING_DEVICE_ROLE_MISMATCH"
  | "REQUESTING_DEVICE_AUTH_UID_MISMATCH"
  | "REQUESTING_DEVICE_NOT_PROVISIONED"
  | "REQUESTING_DEVICE_IDENTITY_CORRUPT"
  | "REQUEST_HASH_MISMATCH"
  | "CAMERA_TARGET_MISMATCH"
  | "CAMERA_NOT_CLAIMED"
  | "CAMERA_ACCESS_DENIED"
  | "TURN_ACCESS_DENIED"
  | "SIGNATURE_INVALID"
  | "HOME_CAMERA_LINK_MISMATCH"
  | DeviceOperationalReason;

export type TurnCredentialsChallengeConsumptionOutcome =
  | {
      outcome: "verified";
      role: DeviceRole;
      deviceId: string;
      ownerUid: string;
      cameraAuthUid: string | null | undefined;
    }
  | { outcome: "denied"; reason: TurnCredentialsChallengeVerificationFailureReason };

export const DEVICE_PROOF_VERSION = 1;

// The single, atomic verify-then-consume operation for a TURN_CREDENTIALS device proof --
// implements the full check sequence documented on index.ts's getTurnCredentials, all inside ONE
// Firestore transaction (own db.runTransaction(), mirroring applyCameraPublicKeyRegistration's own
// established shape in deviceRegistry.ts): never a separate verifyChallenge() followed by a
// separate update(), so a concurrent unpair/revoke/entitlement-change/second-consumption attempt
// can never race between "verified" and "consumed".
//
// Never trusts anything about the SIGNING device's state, the target Camera's pairing, or
// entitlements as they were at challenge-creation time -- every one of those is re-read and
// re-checked fresh, inside this same transaction, exactly as if the challenge had just this moment
// been handed a request to authorize.
//
// On success, atomically (same transaction): marks the challenge used
// (usedAt/usedByFunction=getTurnCredentials) and -- only now, only after a fully verified signature
// -- merges deviceProofVersion onto the signing device's own registeredDevices/{deviceId} document,
// never lowering an existing value (forward-compatible with a future higher version), and never
// touching role/authUid/ownerUid/status/publicKey/identityMode. An invalid proof writes nothing at
// all -- the transaction's only writes are inside this exact success path.
export async function consumeVerifiedTurnCredentialsChallenge(
  db: admin.firestore.Firestore,
  params: {
    requestAuthUid: string;
    cameraDeviceId: string;
    turnPurpose: TurnChallengePurpose;
    deviceProof: TurnCredentialsDeviceProof;
    nowMillis: number;
  }
): Promise<TurnCredentialsChallengeConsumptionOutcome> {
  const { requestAuthUid, cameraDeviceId, turnPurpose, deviceProof, nowMillis } = params;
  const challengeRef = db.collection("deviceChallenges").doc(deviceProof.challengeId);

  return db.runTransaction(async (t): Promise<TurnCredentialsChallengeConsumptionOutcome> => {
    // 1. challenge exists.
    const challengeSnap = await t.get(challengeRef);
    if (!challengeSnap.exists) {
      return { outcome: "denied", reason: "CHALLENGE_NOT_FOUND" };
    }
    const challenge = challengeSnap.data() as Record<string, unknown>;

    // 2. schemaVersion == 1.
    if (challenge.schemaVersion !== DEVICE_CHALLENGE_SCHEMA_VERSION) {
      return { outcome: "denied", reason: "CHALLENGE_SCHEMA_MISMATCH" };
    }
    // 3. document id matches the challengeId field stored inside the document.
    if (challenge.challengeId !== deviceProof.challengeId) {
      return { outcome: "denied", reason: "CHALLENGE_ID_MISMATCH" };
    }
    // 4. purpose == TURN_CREDENTIALS.
    if (challenge.purpose !== DEVICE_CHALLENGE_PURPOSES.TURN_CREDENTIALS) {
      return { outcome: "denied", reason: "CHALLENGE_PURPOSE_MISMATCH" };
    }
    // 5. authUid == request.auth.uid.
    const challengeAuthUid = challenge.authUid;
    if (typeof challengeAuthUid !== "string" || challengeAuthUid !== requestAuthUid) {
      return { outcome: "denied", reason: "CHALLENGE_AUTH_UID_MISMATCH" };
    }
    // 6. usedAt == null.
    if (challenge.usedAt != null) {
      return { outcome: "denied", reason: "CHALLENGE_ALREADY_USED" };
    }
    // 7. expiresAt > now.
    const expiresAt = challenge.expiresAt;
    if (!(expiresAt instanceof admin.firestore.Timestamp) || expiresAt.toMillis() <= nowMillis) {
      return { outcome: "denied", reason: "CHALLENGE_EXPIRED" };
    }
    // 8. nonce has the expected Base64URL format.
    const nonce = challenge.nonce;
    if (typeof nonce !== "string" || !CHALLENGE_NONCE_PATTERN.test(nonce)) {
      return { outcome: "denied", reason: "CHALLENGE_NONCE_MALFORMED" };
    }
    // 9. requestHash has the expected 64 lowercase hex chars.
    const storedRequestHash = challenge.requestHash;
    if (typeof storedRequestHash !== "string" || !CHALLENGE_REQUEST_HASH_PATTERN.test(storedRequestHash)) {
      return { outcome: "denied", reason: "CHALLENGE_REQUEST_HASH_MALFORMED" };
    }
    // 10. role is HOME or CAMERA.
    const role = challenge.role;
    if (role !== "HOME" && role !== "CAMERA") {
      return { outcome: "denied", reason: "CHALLENGE_ROLE_INVALID" };
    }
    const deviceId = challenge.deviceId;
    if (typeof deviceId !== "string" || deviceId.length === 0) {
      return { outcome: "denied", reason: "CHALLENGE_SCHEMA_MISMATCH" };
    }

    // 11. the requesting registered device exists; 12/13/14. its role/authUid/identityMode match.
    const requestingDeviceRef = db.collection("registeredDevices").doc(deviceId);
    const requestingDeviceSnap = await t.get(requestingDeviceRef);
    if (!requestingDeviceSnap.exists) {
      return { outcome: "denied", reason: "REQUESTING_DEVICE_NOT_REGISTERED" };
    }
    const requestingDevice = requestingDeviceSnap.data() as RegisteredDevice;

    if (requestingDevice.role !== role) {
      return { outcome: "denied", reason: "REQUESTING_DEVICE_ROLE_MISMATCH" };
    }
    if (requestingDevice.authUid !== requestAuthUid) {
      return { outcome: "denied", reason: "REQUESTING_DEVICE_AUTH_UID_MISMATCH" };
    }
    if (requestingDevice.identityMode !== "keystore") {
      return { outcome: "denied", reason: "REQUESTING_DEVICE_NOT_PROVISIONED" };
    }
    // 14. publicKey exists. Captured into its own const (rather than relying on
    // `requestingDevice.publicKey` narrowing to persist across the several `await`s below) so its
    // non-null, non-empty string type is unambiguous at the point it's actually used for
    // verification further down.
    const requestingDevicePublicKey = requestingDevice.publicKey;
    if (!requestingDevicePublicKey) {
      return { outcome: "denied", reason: "REQUESTING_DEVICE_IDENTITY_CORRUPT" };
    }

    // 15. requesting device is operational.
    const requestingOperational = checkRegisteredDeviceOperational(requestingDevice);
    if (!requestingOperational.operational) {
      return { outcome: "denied", reason: requestingOperational.reason };
    }

    // 16. recomputed requestHash matches -- rebuilt from the ACTUAL request just received (not
    // trusted from the challenge document), so a cameraDeviceId or turnPurpose changed after the
    // challenge was issued is caught here.
    const recomputedRequestHash = sha256Hex(
      buildCanonicalTurnCredentialsRequestPayload({ cameraDeviceId, turnPurpose })
    );
    if (recomputedRequestHash !== storedRequestHash) {
      return { outcome: "denied", reason: "REQUEST_HASH_MISMATCH" };
    }

    // Role-specific: a CAMERA may only ever sign a challenge about itself.
    if (role === "CAMERA" && deviceId !== cameraDeviceId) {
      return { outcome: "denied", reason: "CAMERA_TARGET_MISMATCH" };
    }

    // 17. Camera pairing/access still holds, checked fresh (never trusted from challenge-creation
    // time -- an unpair between challenge issuance and this call must be caught here).
    const claimRef = db.collection("cameraClaims").doc(cameraDeviceId);
    const claimSnap = await t.get(claimRef);
    if (!claimSnap.exists) {
      return { outcome: "denied", reason: "CAMERA_NOT_CLAIMED" };
    }
    const claimOwnerUid = claimSnap.get("uid") as string | undefined;
    const claimCameraAuthUid = claimSnap.get("cameraAuthUid") as string | null | undefined;

    if (!claimOwnerUid) {
      return { outcome: "denied", reason: "CAMERA_ACCESS_DENIED" };
    }
    if (role === "HOME" && claimOwnerUid !== requestAuthUid) {
      return { outcome: "denied", reason: "CAMERA_ACCESS_DENIED" };
    }
    if (role === "CAMERA" && claimCameraAuthUid !== requestAuthUid) {
      return { outcome: "denied", reason: "CAMERA_ACCESS_DENIED" };
    }

    // 18. target Camera is operational -- same document as the requesting device when role ==
    // CAMERA (no second read needed); a separate read for HOME, whose own deviceId differs from
    // cameraDeviceId. Missing-document is permissive by default, exactly matching
    // assertRegisteredDeviceOperational's own existing behavior for getTurnCredentials today.
    let targetCameraDevice: RegisteredDevice | null;
    if (deviceId === cameraDeviceId) {
      targetCameraDevice = requestingDevice;
    } else {
      const targetCameraRef = db.collection("registeredDevices").doc(cameraDeviceId);
      const targetCameraSnap = await t.get(targetCameraRef);
      targetCameraDevice = targetCameraSnap.exists ? (targetCameraSnap.data() as RegisteredDevice) : null;
    }
    const targetOperational = checkRegisteredDeviceOperational(targetCameraDevice);
    if (!targetOperational.operational) {
      return { outcome: "denied", reason: targetOperational.reason };
    }

    // 19. entitlement still allows TURN -- owner uid taken from the JUST-READ cameraClaims.uid
    // (never from the challenge document), read inside this same transaction, using the same pure
    // resolution rules getEffectiveUserEntitlements itself uses (see entitlements.ts's
    // effectiveUserEntitlementsFromData) rather than a second, divergent copy of that logic.
    const entitlementsRef = db.collection("userEntitlements").doc(claimOwnerUid);
    const entitlementsSnap = await t.get(entitlementsRef);
    const effectiveEntitlements: EffectiveUserEntitlements = effectiveUserEntitlementsFromData(
      entitlementsSnap.exists ? entitlementsSnap.data() : undefined
    );
    if (!effectiveEntitlements.turnAccessAllowed) {
      return { outcome: "denied", reason: "TURN_ACCESS_DENIED" };
    }

    // 20. signature is valid -- the last check that can be decided from data already read above;
    // deliberately checked before the HOME-device-link lookup just below, so an invalid signature
    // (proof of possession never established) is denied without ever performing that lookup --
    // whatever it might reveal about this camera's pairing stays unreached for a request that
    // never proved which key it was signed with. The canonical device-proof payload is rebuilt
    // entirely server-side from already-verified, already-read fields -- the client's request
    // never contains (and this function never trusts) a canonicalPayload string.
    const canonicalDeviceProofPayload = buildCanonicalDeviceProofPayload({
      challengeId: deviceProof.challengeId,
      deviceId,
      role,
      purpose: DEVICE_CHALLENGE_PURPOSES.TURN_CREDENTIALS,
      authUid: requestAuthUid,
      nonce,
      requestHash: storedRequestHash,
      expiresAtMillis: expiresAt.toMillis(),
    });
    const signatureValid = verifyDeviceProofSignature(
      canonicalDeviceProofPayload,
      requestingDevicePublicKey,
      deviceProof.signature
    );
    if (!signatureValid) {
      return { outcome: "denied", reason: "SIGNATURE_INVALID" };
    }

    // 21. HOME-specific device-level authorization. Step 17 above (cameraClaims.uid ===
    // requestAuthUid) only proves ACCOUNT-level ownership -- the same Google account can be
    // signed into more than one Home installation, each with its own registeredDevices document
    // and Keystore key, and nothing checked so far proves THIS specific verified `deviceId` (not
    // just "some Home device this account owns") is the installation that actually claimed this
    // Camera. users/{claimOwnerUid}/cameraDevices/{cameraDeviceId}.homeDeviceId is the existing
    // canonical record of exactly that: written exactly once, only by claimCameraForUser, at the
    // moment a specific Home installation genuinely claimed this camera -- function-only-writable
    // (firestore.rules: `allow write: if false` on this subcollection; the client cannot forge or
    // alter it directly), and never touched by any other code path except a full unpair (delete)
    // followed by a fresh re-claim. A missing document (never claimed under this owner, or
    // already unpaired) or a mismatched homeDeviceId both deny -- fail closed, no permissive
    // default (unlike checkRegisteredDeviceOperational's own missing-document leniency, which is
    // about operational STATUS, not identity/authorization). CAMERA's own device-level identity
    // is already fully established above (CAMERA_TARGET_MISMATCH requires deviceId ===
    // cameraDeviceId), so this lookup only runs for role === "HOME". No new Firestore collection:
    // this reuses the existing users/{uid}/cameraDevices/{cameraDeviceId} document
    // claimCameraForUser (index.ts) already writes.
    if (role === "HOME") {
      const homeCameraLinkRef = db
        .collection("users")
        .doc(claimOwnerUid)
        .collection("cameraDevices")
        .doc(cameraDeviceId);
      const homeCameraLinkSnap = await t.get(homeCameraLinkRef);
      const linkedHomeDeviceId = homeCameraLinkSnap.exists
        ? (homeCameraLinkSnap.get("homeDeviceId") as string | undefined)
        : undefined;
      if (!linkedHomeDeviceId || linkedHomeDeviceId !== deviceId) {
        return { outcome: "denied", reason: "HOME_CAMERA_LINK_MISMATCH" };
      }
    }

    // Atomic consumption -- only reached once every check above has passed.
    const now = admin.firestore.FieldValue.serverTimestamp();
    t.update(challengeRef, {
      usedAt: now,
      usedByFunction: "getTurnCredentials",
    });

    // deviceProofVersion: set only now, on the SIGNING device's own registry document -- never
    // lowered if a future version is already stored higher, and merged so role/authUid/ownerUid/
    // status/publicKey/identityMode are completely untouched.
    const currentDeviceProofVersion = requestingDevice.deviceProofVersion;
    if (!currentDeviceProofVersion || currentDeviceProofVersion < DEVICE_PROOF_VERSION) {
      t.set(
        requestingDeviceRef,
        {
          deviceProofVersion: DEVICE_PROOF_VERSION,
          updatedAt: now,
          lastSeenAt: now,
        },
        { merge: true }
      );
    }

    return {
      outcome: "verified",
      role,
      deviceId,
      ownerUid: claimOwnerUid,
      cameraAuthUid: claimCameraAuthUid,
    };
  });
}
