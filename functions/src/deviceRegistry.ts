import * as admin from "firebase-admin";
import * as logger from "firebase-functions/logger";
import * as crypto from "crypto";
import type { DeviceLimits } from "./entitlements";

// Stage 1 of the EdgeGuard device registry: a single global, Admin-SDK-only collection that
// records every known Camera/Home installation ("device") independently of cameraClaims/
// pairingState. This module ONLY creates and maintains registeredDevices/{deviceId} -- it is not
// yet consulted anywhere to limit device counts, deny Live View, or verify Keystore signatures,
// and it does not replace cameraClaims (still the ownership source of truth) or pairingState
// (still the pairing-lifecycle source of truth). See docs/DEVICE_REGISTRY.md.

export const DEVICE_REGISTRY_SCHEMA_VERSION = 1;

export type DeviceRole = "HOME" | "CAMERA";
export type DeviceStatus = "active" | "suspended" | "revoked";
// Why a device is suspended -- distinct from DeviceStatus itself so a future revocation/suspension
// operation (not implemented in this stage) can record *why* without overloading `status`. Only
// meaningful while status == "suspended"; every device this stage creates has status "active" and
// suspensionReason null, and nothing in this stage ever sets it to anything else.
export type DeviceSuspensionReason = "plan" | "manual" | "security" | null;
export type DeviceIdentityMode = "legacy" | "keystore";

// The exact shape of a registeredDevices/{deviceId} document -- see docs/DEVICE_REGISTRY.md for
// what each field means. deviceId is the installation's own self-generated id (Camera's
// cameraDeviceId / Home's homeDeviceId, unchanged by this module) and is also this document's own
// id. ownerUid is null for a HOME device only in the sense that HOME devices set it to their own
// authUid (self-owned) -- see registerLegacyHome() -- and null for a CAMERA before it is claimed
// (or again after a normal unpair) -- see attachCameraOwner()/detachCameraOwner().
export interface RegisteredDevice {
  schemaVersion: number;
  deviceId: string;
  role: DeviceRole;
  authUid: string;
  ownerUid: string | null;
  status: DeviceStatus;
  suspensionReason: DeviceSuspensionReason;
  identityMode: DeviceIdentityMode;
  publicKey: string | null;
  createdAt: admin.firestore.Timestamp;
  updatedAt: admin.firestore.Timestamp;
  lastSeenAt: admin.firestore.Timestamp;
  revokedAt: admin.firestore.Timestamp | null;
  // Set only once a device's device-proof (Keystore-signed challenge) has been successfully
  // verified at least once -- see deviceChallenges.ts's consumeVerifiedTurnCredentialsChallenge.
  // Absent (undefined at runtime, despite this non-optional type -- matching every other field's
  // existing "as RegisteredDevice" cast looseness in this file) on every document created before
  // this stage, and on any document that has never yet completed a verified proof. Never set by
  // registerLegacyCamera/registerLegacyHome/attachCameraOwner/detachCameraOwner/
  // touchRegisteredDevice/applyPublicKeyRegistration/applyCameraPublicKeyRegistration -- this
  // field is purely informational at this stage, not yet consulted by any enforcement decision.
  deviceProofVersion: number | null;
}

const REGISTERED_DEVICES_COLLECTION = "registeredDevices";

function registeredDeviceRef(
  db: admin.firestore.Firestore,
  deviceId: string
): admin.firestore.DocumentReference {
  return db.collection(REGISTERED_DEVICES_COLLECTION).doc(deviceId);
}

// The only three ways an already-registered device's identity can conflict with what a caller is
// now asserting about it -- deviceId mismatch is a defensive check against document corruption
// (this collection has exactly one writer, this module, so it should never actually happen);
// role/authUid mismatch are the real-world cases this stage's spec calls out explicitly ("HOME
// нельзя превратить в CAMERA", "существующий authUid нельзя заменить другим UID"). Exported as a
// fixed, stable enum -- the only thing about *why* an identity write was skipped that is ever
// allowed into a log line (see logIdentityConflict below), mirroring
// entitlements.ts's CorruptEntitlementsReason.
export type DeviceIdentityConflictReason = "DEVICE_ID_MISMATCH" | "ROLE_MISMATCH" | "AUTH_UID_MISMATCH";

// Pure: does an already-stored document (or null if none exists yet) allow a caller asserting
// this deviceId/role/authUid to proceed? null means "no conflict" -- either nothing is stored yet
// (fresh registration) or the stored identity matches exactly. Exported for direct unit testing
// without a Firestore emulator.
export function identityConflictReason(
  existing: Pick<RegisteredDevice, "deviceId" | "role" | "authUid"> | null,
  incoming: { deviceId: string; role: DeviceRole; authUid: string }
): DeviceIdentityConflictReason | null {
  if (!existing) return null;
  if (existing.deviceId !== incoming.deviceId) return "DEVICE_ID_MISMATCH";
  if (existing.role !== incoming.role) return "ROLE_MISMATCH";
  if (existing.authUid !== incoming.authUid) return "AUTH_UID_MISMATCH";
  return null;
}

// Deliberately narrow, matching entitlements.ts's own corrupt-document warning: a fixed event
// name, deviceId (a self-generated installation id, not personal data -- already logged
// unredacted everywhere else in this file as cameraDeviceId), role, and the fixed conflict-reason
// enum. Never the Firebase UID (existing or incoming), never publicKey, never any other document
// field.
function logIdentityConflict(
  eventName: string,
  deviceId: string,
  role: DeviceRole,
  reason: DeviceIdentityConflictReason
): void {
  logger.warn(eventName, { deviceId, role, reason });
}

// Same narrowness for a registry write failure: fixed event name, deviceId, an optional role
// (omitted where the caller doesn't already know it, e.g. touchRegisteredDevice), and the error's
// class name only -- never the error message (which could, in principle, echo back request data)
// and never any document field.
function logWriteFailed(eventName: string, deviceId: string, role: DeviceRole | undefined, error: unknown): void {
  logger.error(eventName, {
    deviceId,
    ...(role ? { role } : {}),
    errorClass: (error as { constructor?: { name?: string } })?.constructor?.name ?? "Error",
  });
}

// Shared upsert core for registerLegacyCamera/registerLegacyHome/attachCameraOwner -- the three
// operations that assert "this deviceId is a <role> device authenticated as <authUid>" and differ
// only in what ownerUid should be on first creation, and whether an *existing* document's
// ownerUid should also be updated (attachCameraOwner: yes: everyone else: no, so a later call
// can never silently reset an already-attached owner back to whatever this call's own intent
// was).
//
// Never throws: every Firestore/logic error is caught and logged, and the caller-visible response
// this module is invoked from (createCameraPairingSession/claimCameraForUser/getTurnCredentials/
// submitCameraEvent) always continues exactly as if this call had succeeded. Runs in its own
// transaction (read-then-conditionally-write) so two racing calls for the same deviceId can never
// both create a duplicate document, and reading the same value twice always agrees.
//
// On an existing, identity-matching document: only updatedAt/lastSeenAt (and, if
// setOwnerOnExisting, ownerUid) are ever written -- status/suspensionReason/identityMode/
// publicKey/revokedAt/createdAt are never touched on this path, which is what guarantees an
// administrative status (suspended/revoked), its suspensionReason, or an already-provisioned
// Keystore identity can never be silently reverted by a later legacy registration/attach call.
async function upsertRegisteredDevice(
  db: admin.firestore.Firestore,
  intent: { deviceId: string; role: DeviceRole; authUid: string; ownerUid: string | null },
  options: { eventPrefix: string; setOwnerOnExisting: boolean }
): Promise<void> {
  const ref = registeredDeviceRef(db, intent.deviceId);
  try {
    await db.runTransaction(async (t) => {
      const snap = await t.get(ref);
      const existing = snap.exists ? (snap.data() as RegisteredDevice) : null;

      const conflict = identityConflictReason(existing, intent);
      if (conflict) {
        logIdentityConflict(`${options.eventPrefix}_IDENTITY_CONFLICT`, intent.deviceId, intent.role, conflict);
        return;
      }

      const now = admin.firestore.FieldValue.serverTimestamp();

      if (!existing) {
        t.set(ref, {
          schemaVersion: DEVICE_REGISTRY_SCHEMA_VERSION,
          deviceId: intent.deviceId,
          role: intent.role,
          authUid: intent.authUid,
          ownerUid: intent.ownerUid,
          status: "active",
          suspensionReason: null,
          identityMode: "legacy",
          publicKey: null,
          createdAt: now,
          updatedAt: now,
          lastSeenAt: now,
          revokedAt: null,
        });
        return;
      }

      const fields: Record<string, unknown> = { updatedAt: now, lastSeenAt: now };
      if (options.setOwnerOnExisting) {
        fields.ownerUid = intent.ownerUid;
      }
      t.set(ref, fields, { merge: true });
    });
  } catch (error) {
    logWriteFailed(`${options.eventPrefix}_WRITE_FAILED`, intent.deviceId, intent.role, error);
  }
}

// Registers a Camera installation before it has ever been claimed -- called from
// createCameraPairingSession right after its existing auth/validation checks succeed.
// ownerUid is null on first creation (no owner yet). If a document already exists for this
// cameraDeviceId (e.g. the Camera opened the pairing screen again without unpairing first), this
// never touches its ownerUid either way -- only attachCameraOwner()/detachCameraOwner() ever set
// it, so an already-paired Camera re-requesting a pairing session can never have its registry
// ownership silently reset to null.
export async function registerLegacyCamera(
  db: admin.firestore.Firestore,
  cameraDeviceId: string,
  authUid: string
): Promise<void> {
  await upsertRegisteredDevice(
    db,
    { deviceId: cameraDeviceId, role: "CAMERA", authUid, ownerUid: null },
    { eventPrefix: "DEVICE_REGISTRY_REGISTER_LEGACY_CAMERA", setOwnerOnExisting: false }
  );
}

// Registers a Home installation -- called from claimCameraForUser right after a claim succeeds
// (the first point at which the Home App is both authenticated and actively participating in a
// server-verified flow). A HOME device's ownerUid is always its own authUid (self-owned); there
// is no separate "attach/detach owner" concept for HOME, since HOME's authUid is itself already
// identity-protected by upsertRegisteredDevice's conflict check.
export async function registerLegacyHome(
  db: admin.firestore.Firestore,
  homeDeviceId: string,
  authUid: string
): Promise<void> {
  await upsertRegisteredDevice(
    db,
    { deviceId: homeDeviceId, role: "HOME", authUid, ownerUid: authUid },
    { eventPrefix: "DEVICE_REGISTRY_REGISTER_LEGACY_HOME", setOwnerOnExisting: false }
  );
}

// Sets (or creates-with) a Camera's ownerUid -- called both from claimCameraForUser right after a
// successful claim, and from getTurnCredentials/submitCameraEvent's lazy migration of an
// already-paired Camera that predates this registry. `authUid` must be the Camera's own auth uid
// as already verified server-side (cameraClaims.cameraAuthUid / the pairing session's
// cameraAuthUid) -- never the calling user's own uid, since both call sites can be reached by
// either the Home or the Camera identity. If `authUid` is null/empty (the one pre-existing edge
// case where a claim's cameraAuthUid was never recorded), this is a no-op: writing a
// registeredDevices document with no authUid would violate the schema, and there is nothing
// trustworthy to attach.
export async function attachCameraOwner(
  db: admin.firestore.Firestore,
  cameraDeviceId: string,
  cameraAuthUid: string | null | undefined,
  ownerUid: string
): Promise<void> {
  if (!cameraAuthUid) {
    logger.warn("DEVICE_REGISTRY_ATTACH_CAMERA_OWNER_MISSING_AUTH_UID", { deviceId: cameraDeviceId });
    return;
  }
  await upsertRegisteredDevice(
    db,
    { deviceId: cameraDeviceId, role: "CAMERA", authUid: cameraAuthUid, ownerUid },
    { eventPrefix: "DEVICE_REGISTRY_ATTACH_CAMERA_OWNER", setOwnerOnExisting: true }
  );
}

// Clears a Camera's ownerUid back to null -- called from every existing unpair/release path
// (releaseCameraForUser, unpairCameraFromDevice, releaseCameraFromCamera) right after the
// existing cameraClaims deletion succeeds. A normal unpair is never a revocation: status,
// suspensionReason, identityMode, publicKey, authUid, and revokedAt are never touched here. Safe
// no-op if the device was never registered, or if it's registered under a different role
// (defensive only -- cameraDeviceId/homeDeviceId occupy the same registeredDevices id space in
// principle, though in practice they're generated independently and collisions are not expected).
//
// `revoked` is the one status this never clears ownerUid for -- see docs/DEVICE_REGISTRY.md's
// "unpair ≠ suspend ≠ revoke" section. Revoked is a terminal security state: the pairing/link
// cleanup this function's callers already perform (deleting cameraClaims, writing
// pairingState:"unpaired", etc., all done before this runs) is fine and expected -- Home must
// still be able to remove a revoked camera from its device list -- but that is cleaning up
// *pairing artifacts*, not the registry's own audit trail. If this cleared ownerUid the same way
// it does for an active/suspended device, the registry would permanently lose the record of who
// owned a revoked device, exactly the "who reported this device lost/stolen" fact revoke exists
// to preserve. This is a complete no-op for a revoked device -- not even updatedAt/lastSeenAt are
// touched -- so a repeated unpair/cleanup call against an already-revoked device is trivially
// idempotent (nothing to converge to; there was never a write in the first place).
export async function detachCameraOwner(db: admin.firestore.Firestore, cameraDeviceId: string): Promise<void> {
  const ref = registeredDeviceRef(db, cameraDeviceId);
  try {
    await db.runTransaction(async (t) => {
      const snap = await t.get(ref);
      if (!snap.exists) return;

      const existing = snap.data() as RegisteredDevice;
      if (existing.role !== "CAMERA") {
        logIdentityConflict("DEVICE_REGISTRY_DETACH_CAMERA_OWNER", cameraDeviceId, existing.role, "ROLE_MISMATCH");
        return;
      }

      if (existing.status === "revoked") {
        logger.info("DEVICE_REGISTRY_DETACH_CAMERA_OWNER_SKIPPED_REVOKED", { deviceId: cameraDeviceId });
        return;
      }

      t.set(
        ref,
        {
          ownerUid: null,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          lastSeenAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );
    });
  } catch (error) {
    logWriteFailed("DEVICE_REGISTRY_DETACH_CAMERA_OWNER_WRITE_FAILED", cameraDeviceId, "CAMERA", error);
  }
}

// Bumps lastSeenAt/updatedAt on an already-registered device, without asserting or changing any
// identity/ownership/administrative field. No-op if the device isn't registered yet -- this is a
// heartbeat, not a registration path. Exported as its own small, directly testable primitive
// (matching this stage's minimal required API); not yet wired into any specific call site beyond
// what registerLegacyCamera/registerLegacyHome/attachCameraOwner already do internally for their
// own "already exists" case.
export async function touchRegisteredDevice(db: admin.firestore.Firestore, deviceId: string): Promise<void> {
  const ref = registeredDeviceRef(db, deviceId);
  try {
    await db.runTransaction(async (t) => {
      const snap = await t.get(ref);
      if (!snap.exists) return;

      t.set(
        ref,
        {
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          lastSeenAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );
    });
  } catch (error) {
    logWriteFailed("DEVICE_REGISTRY_TOUCH_WRITE_FAILED", deviceId, undefined, error);
  }
}

// ---------------------------------------------------------------------------------------------
// Android Keystore identity: registerDevicePublicKey (legacy -> keystore)
// ---------------------------------------------------------------------------------------------
// Everything below is deliberately NOT part of the best-effort upsertRegisteredDevice() core
// above: registering a device's real cryptographic identity is a one-time, user-triggered,
// security-relevant action, not a passive side effect of some other call succeeding. A caller
// needs to know for certain whether it worked, so none of this ever swallows a Firestore error --
// see applyPublicKeyRegistration()'s own doc for exactly what it does and does not catch.

// The only fixed set of algorithms this stage accepts. Exported so the callable and its tests
// share one source of truth for "ES256" instead of re-typing the literal string.
export const SUPPORTED_DEVICE_KEY_ALGORITHM = "ES256" as const;

// Every way validateEcP256PublicKey() below can reject an incoming key -- a fixed, stable enum,
// safe to log (see its own doc): it describes *which check* failed, never any part of the key
// itself.
export type PublicKeyInvalidReason =
  | "CONTAINS_WHITESPACE"
  | "BASE64URL_VARIANT"
  | "NOT_STANDARD_BASE64"
  | "NON_CANONICAL_BASE64"
  | "EMPTY_AFTER_DECODE"
  | "MALFORMED_DER"
  | "UNSUPPORTED_KEY_TYPE"
  | "UNSUPPORTED_CURVE";

export type PublicKeyValidation =
  | { valid: true; derBuffer: Buffer; canonicalBase64: string; fingerprint: string }
  | { valid: false; reason: PublicKeyInvalidReason };

// Standard (non-URL-safe) Base64 alphabet, with optional padding -- matched *before* attempting
// to decode anything, so an obviously-wrong input (whitespace, base64url `-`/`_`) is rejected with
// a precise reason rather than falling through to a generic decode failure.
const STANDARD_BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

// Validates an incoming SPKI-DER-as-Base64 public key against exactly what this stage accepts:
// EC on the P-256 (secp256r1/prime256v1) curve, nothing else. Never throws -- every failure mode
// (malformed Base64, malformed DER, wrong key type, wrong curve, a private key instead of a
// public one, PEM instead of raw DER, RSA/Ed25519 keys) returns { valid: false, reason }.
//
// Base64 canonicality: Buffer.from(str, "base64") is lenient -- it silently drops characters it
// doesn't understand instead of rejecting them -- so the character-set regex above is not enough
// on its own to catch a malformed string. Re-encoding the decoded bytes and comparing the result
// back to the exact original input string is what actually proves the input was a canonical,
// well-formed Base64 encoding of those bytes.
//
// Curve check: P-256 is verified via JWK export (`crv === "P-256"`), not via
// `asymmetricKeyDetails.namedCurve` (which returns OpenSSL's own curve alias, e.g.
// "prime256v1", requiring the reader to already know that name *is* P-256/secp256r1). JWK's `crv`
// value is pinned by RFC 7518 to the literal string "P-256" for this curve, which is the more
// standards-anchored, unambiguous check to rely on.
export function validateEcP256PublicKey(publicKeyBase64: string): PublicKeyValidation {
  if (/\s/.test(publicKeyBase64)) {
    return { valid: false, reason: "CONTAINS_WHITESPACE" };
  }
  if (publicKeyBase64.includes("-") || publicKeyBase64.includes("_")) {
    return { valid: false, reason: "BASE64URL_VARIANT" };
  }
  if (!STANDARD_BASE64_PATTERN.test(publicKeyBase64)) {
    return { valid: false, reason: "NOT_STANDARD_BASE64" };
  }

  const derBuffer = Buffer.from(publicKeyBase64, "base64");

  if (derBuffer.length === 0) {
    return { valid: false, reason: "EMPTY_AFTER_DECODE" };
  }

  if (derBuffer.toString("base64") !== publicKeyBase64) {
    return { valid: false, reason: "NON_CANONICAL_BASE64" };
  }

  let keyObject: crypto.KeyObject;
  try {
    keyObject = crypto.createPublicKey({ key: derBuffer, format: "der", type: "spki" });
  } catch {
    return { valid: false, reason: "MALFORMED_DER" };
  }

  if (keyObject.asymmetricKeyType !== "ec") {
    return { valid: false, reason: "UNSUPPORTED_KEY_TYPE" };
  }

  // `crv` is read into a plain local rather than naming KeyObject.export({format:"jwk"})'s own
  // return type explicitly -- it resolves to crypto.webcrypto.JsonWebKey, which TypeScript infers
  // fine on its own but is awkward to spell out by hand.
  let curveName: string | undefined;
  try {
    curveName = keyObject.export({ format: "jwk" }).crv;
  } catch {
    return { valid: false, reason: "UNSUPPORTED_CURVE" };
  }

  if (curveName !== "P-256") {
    return { valid: false, reason: "UNSUPPORTED_CURVE" };
  }

  const fingerprint = crypto.createHash("sha256").update(derBuffer).digest("hex");

  return { valid: true, derBuffer, canonicalBase64: publicKeyBase64, fingerprint };
}

// --- HOME first-key freshness gate --------------------------------------------------------------
// Protects the FIRST assignment of a HOME device's public key (missing document -> keystore, or
// existing legacy+null -> keystore) with a requirement that the caller's Firebase session is
// recent. An already-registered HOME device resubmitting its already-stored key (idempotent) never
// goes through this gate -- see decidePublicKeyRegistration below, which only ever consults it on
// the legacy->keystore first-write branch, never on the keystore/idempotent or keystore/conflict
// branches. CAMERA never consults this at all -- applyCameraPublicKeyRegistration never populates
// the `freshAuthCheck` parameter (see its own doc).

// How old request.auth.token.auth_time (Unix seconds) may be, relative to the server's own clock,
// for a first HOME key assignment to proceed.
export const HOME_KEY_REGISTRATION_MAX_AUTH_AGE_SECONDS = 300;

// How far into the future auth_time may appear to still be accepted -- accounts for ordinary clock
// skew between the token-issuing server and this function's own clock, never a reason to accept an
// auth_time that is *older* than HOME_KEY_REGISTRATION_MAX_AUTH_AGE_SECONDS.
export const AUTH_TIME_FUTURE_SKEW_SECONDS = 30;

// Every way an auth_time claim can fail the freshness check -- a fixed, stable enum, safe to log
// (an "age category", never the actual auth_time or current timestamp).
export type AuthTimeFreshnessReason = "MISSING" | "NOT_A_NUMBER" | "NOT_FINITE" | "TOO_FAR_IN_FUTURE" | "TOO_OLD";

export type AuthTimeFreshnessResult = { fresh: true } | { fresh: false; reason: AuthTimeFreshnessReason };

// Pure: validates a Firebase Auth `auth_time` claim (Unix seconds, as found on
// request.auth.token.auth_time) against the current server time. `authTime` is deliberately typed
// `unknown` -- this claim comes from a decoded ID token and this function must not assume it is
// even a number before checking. `nowSeconds` is an explicit parameter, never computed via
// Date.now() inside this function, so a test can pin the exact boundary instant instead of racing
// the real clock (same pattern as entitlements.ts's isExpired(stored, nowMillis)) -- the one real
// Date.now() read for this gate happens once, at the callable's own top level (index.ts).
export function checkAuthTimeFreshness(authTime: unknown, nowSeconds: number): AuthTimeFreshnessResult {
  if (authTime === undefined || authTime === null) {
    return { fresh: false, reason: "MISSING" };
  }
  if (typeof authTime !== "number") {
    return { fresh: false, reason: "NOT_A_NUMBER" };
  }
  if (!Number.isFinite(authTime)) {
    return { fresh: false, reason: "NOT_FINITE" };
  }
  if (authTime > nowSeconds + AUTH_TIME_FUTURE_SKEW_SECONDS) {
    return { fresh: false, reason: "TOO_FAR_IN_FUTURE" };
  }
  if (nowSeconds - authTime > HOME_KEY_REGISTRATION_MAX_AUTH_AGE_SECONDS) {
    return { fresh: false, reason: "TOO_OLD" };
  }
  return { fresh: true };
}

// Every outcome the registerDevicePublicKey transactions below can resolve to. Deliberately not
// exceptions -- these are all *expected*, named business outcomes the caller (the
// registerDevicePublicKey callable) maps onto specific client-facing HttpsErrors; only a genuine
// Firestore/infrastructure failure is left to propagate as a real thrown error (see below).
// "camera_not_claimed" is CAMERA-specific (see applyCameraPublicKeyRegistration); "recent_auth_required"
// is HOME-first-key-specific (see the freshness gate above); every other outcome is shared between
// both roles.
export type PublicKeyRegistrationOutcome =
  | { outcome: "registered" }
  | { outcome: "idempotent" }
  | { outcome: "home_created" }
  | { outcome: "not_found" }
  | { outcome: "camera_not_claimed" }
  | { outcome: "role_mismatch" }
  | { outcome: "auth_uid_mismatch" }
  | { outcome: "owner_uid_mismatch" }
  | { outcome: "revoked" }
  | { outcome: "key_conflict" }
  | { outcome: "corrupt" }
  | { outcome: "recent_auth_required"; reason: AuthTimeFreshnessReason };

// Same shape as PublicKeyRegistrationOutcome, but the two outcomes that require a write
// (idempotent/registered) also carry the exact fields to write -- kept internal (not exported)
// since callers only ever need the plain outcome; the fields are consumed immediately by
// finalizePublicKeyRegistrationDecision below, inside the same transaction that produced them.
type PublicKeyRegistrationDecision =
  | { outcome: "registered"; writeFields: Record<string, unknown> }
  | { outcome: "idempotent"; writeFields: Record<string, unknown> }
  | { outcome: "not_found" }
  | { outcome: "role_mismatch" }
  | { outcome: "auth_uid_mismatch" }
  | { outcome: "owner_uid_mismatch" }
  | { outcome: "revoked" }
  | { outcome: "key_conflict" }
  | { outcome: "corrupt" }
  | { outcome: "recent_auth_required"; reason: AuthTimeFreshnessReason };

// The single, shared decision core for legacy -> keystore registration -- used by BOTH
// applyPublicKeyRegistration (HOME) and applyCameraPublicKeyRegistration (CAMERA) so neither
// duplicates corruption handling, revoked handling, idempotency, first-write-wins, timestamp
// behavior, or key-conflict behavior (see docs/DEVICE_REGISTRY.md). Pure: takes an
// already-fetched document snapshot (or null) and never touches Firestore itself -- the caller is
// responsible for the actual read (inside its own transaction) and for applying `writeFields` via
// that same transaction (see finalizePublicKeyRegistrationDecision below). Directly unit-testable
// without a Firestore emulator.
//
// `expectedAuthUid`/`expectedOwnerUid` are supplied by the caller, already verified against
// whatever source is appropriate for the role (HOME: request.auth.uid directly; CAMERA:
// cameraClaims.cameraAuthUid, itself already cross-checked against request.auth.uid by the
// caller, in the same transaction -- see applyCameraPublicKeyRegistration) -- this function only
// ever re-verifies them against the stored document, it never derives them itself and never
// trusts anything the client asserts about its own identity. `expectedOwnerUid: null` skips the
// ownerUid check entirely (CAMERA's ownerUid is never used for authentication).
//
// `freshAuthCheck`, when present, is consulted ONLY on the legacy->keystore first-write branch at
// the bottom of this function -- never on the keystore/idempotent or keystore/key_conflict
// branches (an already-registered device resubmitting its own stored key, or a genuinely
// different key, both resolve exactly as before, regardless of session age) -- see the freshness
// gate's own doc above. `applyCameraPublicKeyRegistration` never populates this parameter, so
// CAMERA's own legacy->keystore transition is completely unaffected by this gate.
function decidePublicKeyRegistration(
  existing: RegisteredDevice | null,
  params: {
    role: DeviceRole;
    expectedAuthUid: string;
    expectedOwnerUid: string | null;
    canonicalPublicKey: string;
    freshAuthCheck?: { authTime: unknown; nowSeconds: number };
  }
): PublicKeyRegistrationDecision {
  if (!existing) {
    return { outcome: "not_found" };
  }

  if (existing.role !== params.role) {
    return { outcome: "role_mismatch" };
  }
  if (existing.authUid !== params.expectedAuthUid) {
    return { outcome: "auth_uid_mismatch" };
  }
  if (params.expectedOwnerUid !== null && existing.ownerUid !== params.expectedOwnerUid) {
    return { outcome: "owner_uid_mismatch" };
  }
  if (existing.status === "revoked") {
    return { outcome: "revoked" };
  }

  // Never auto-repair an inconsistent document -- see docs/DEVICE_REGISTRY.md.
  const isCorrupt =
    (existing.identityMode === "legacy" && existing.publicKey !== null) ||
    (existing.identityMode === "keystore" && existing.publicKey === null);
  if (isCorrupt) {
    return { outcome: "corrupt" };
  }

  if (existing.identityMode === "keystore") {
    // existing.publicKey is guaranteed non-null here -- the corruption check above already ruled
    // out identityMode:"keystore" with publicKey:null. Neither branch below ever consults
    // freshAuthCheck -- an idempotent resubmit of the already-stored key must keep working on an
    // old session (see the freshness gate's own doc), and a conflicting key is rejected the same
    // way regardless of session age.
    if (existing.publicKey === params.canonicalPublicKey) {
      return { outcome: "idempotent", writeFields: { lastSeenAt: admin.firestore.FieldValue.serverTimestamp() } };
    }
    return { outcome: "key_conflict" };
  }

  // identityMode === "legacy" and publicKey === null (corruption already ruled out) -- the one and
  // only first-registration path for an EXISTING document. This is a first-key migration exactly
  // like the missing-document HOME bootstrap in applyPublicKeyRegistration below, so it is gated
  // by the same freshness requirement whenever the caller populated freshAuthCheck (HOME only).
  if (params.freshAuthCheck) {
    const freshness = checkAuthTimeFreshness(params.freshAuthCheck.authTime, params.freshAuthCheck.nowSeconds);
    if (!freshness.fresh) {
      return { outcome: "recent_auth_required", reason: freshness.reason };
    }
  }

  // Only identityMode/publicKey/updatedAt/lastSeenAt are ever written -- deviceId/role/authUid/
  // ownerUid/status/suspensionReason/createdAt/revokedAt are never part of this write (so an
  // existing suspension, for example, survives this exact same as before).
  const now = admin.firestore.FieldValue.serverTimestamp();
  return {
    outcome: "registered",
    writeFields: { identityMode: "keystore", publicKey: params.canonicalPublicKey, updatedAt: now, lastSeenAt: now },
  };
}

// Applies a decidePublicKeyRegistration() result inside the caller's own transaction: performs
// the merge-write for "registered"/"idempotent" (nothing else ever writes), logs the one warning
// a "corrupt" outcome needs (deviceId/role only -- see docs/DEVICE_REGISTRY.md), and returns the
// plain outcome for the callable to map onto an HttpsError -- preserving `reason` for
// "recent_auth_required", the one outcome that carries extra data beyond the discriminant itself.
function finalizePublicKeyRegistrationDecision(
  t: admin.firestore.Transaction,
  ref: admin.firestore.DocumentReference,
  identity: { deviceId: string; role: DeviceRole },
  decision: PublicKeyRegistrationDecision
): PublicKeyRegistrationOutcome {
  if (decision.outcome === "corrupt") {
    logger.warn("DEVICE_REGISTRY_PUBLIC_KEY_CORRUPT", { deviceId: identity.deviceId, role: identity.role });
  }
  if (decision.outcome === "registered" || decision.outcome === "idempotent") {
    t.set(ref, decision.writeFields, { merge: true });
  }
  if (decision.outcome === "recent_auth_required") {
    return { outcome: "recent_auth_required", reason: decision.reason };
  }
  return { outcome: decision.outcome };
}

// The strict, transactional legacy -> keystore registration operation for HOME. Unlike every
// best-effort function above, this is NOT best-effort: it never catches or swallows a Firestore
// error -- a failed transaction (contention exhausted, a genuine write failure) propagates as a
// real rejected promise, and it is the caller's job (the callable) to turn that into a controlled
// internal/INTERNAL response rather than silently reporting success.
//
// HOME bootstrap: unlike CAMERA (always registered "legacy" first, by registerLegacyCamera during
// createCameraPairingSession, long before any key is ever submitted), a HOME installation has no
// earlier lazy-registration step -- registerLegacyHome only runs inside claimCameraForUser, which
// requires a Camera to already be paired. A HOME device that calls registerDevicePublicKey before
// ever pairing a camera would otherwise always hit a missing registeredDevices/{deviceId} document.
// So, for role "HOME" only, a missing document is created directly here -- inside this same
// transaction, atomically with the decision to do so -- as a complete, already-`"keystore"`
// document, never a "legacy" intermediate. `role !== "HOME"` still returns `{ outcome: "not_found"
// }` unconditionally (this function is only ever invoked for HOME from the real callable --
// see index.ts -- but this guard keeps that guarantee explicit here too, not just implied by the
// caller). CAMERA's own missing-document behavior is entirely unaffected: it never reaches this
// function at all -- see applyCameraPublicKeyRegistration below, which additionally verifies
// cameraClaims inside the same transaction as the registry read/write (verifying it outside,
// beforehand, would leave a window where an unpair between the check and the write could remove
// cameraClaims while the key registration still went through).
export async function applyPublicKeyRegistration(
  db: admin.firestore.Firestore,
  params: {
    deviceId: string;
    role: DeviceRole;
    expectedAuthUid: string;
    expectedOwnerUid: string | null;
    canonicalPublicKey: string;
    // request.auth.token.auth_time (raw, unvalidated) and the current server time in Unix
    // seconds -- see the freshness gate's own doc above. Required here (not optional) since this
    // function is only ever invoked for HOME, where every first-key path (bootstrap below, or the
    // legacy->keystore branch inside decidePublicKeyRegistration) needs it; an already-keystore
    // device's idempotent/conflict paths simply never consult it.
    authTime: unknown;
    nowSeconds: number;
  }
): Promise<PublicKeyRegistrationOutcome> {
  const ref = registeredDeviceRef(db, params.deviceId);

  return db.runTransaction(async (t): Promise<PublicKeyRegistrationOutcome> => {
    const snap = await t.get(ref);
    const existing = snap.exists ? (snap.data() as RegisteredDevice) : null;

    if (!existing) {
      if (params.role !== "HOME") {
        return { outcome: "not_found" };
      }

      // First-key migration #1: missing document -> keystore. Requires a recent Firebase session
      // -- see the freshness gate's own doc above -- checked here, inside this same transaction,
      // strictly after the registry read above and strictly before the write below (see this
      // module's "Important order" doc / docs/DEVICE_REGISTRY.md): the current registry state is
      // what determines whether this is a first-key migration at all, so freshness is never
      // required for a call this function doesn't even recognize as one.
      const freshness = checkAuthTimeFreshness(params.authTime, params.nowSeconds);
      if (!freshness.fresh) {
        return { outcome: "recent_auth_required", reason: freshness.reason };
      }

      // Validation (deviceId/role/algorithm/Base64/SPKI DER/EC/P-256/canonical Base64) has
      // already happened in the callable before this transaction ever starts -- an invalid key
      // never reaches here, so a document is never created for one. The uid never comes from
      // request body: expectedAuthUid/expectedOwnerUid are both request.auth.uid as already
      // established by the callable, never anything the client asserts about its own identity.
      const now = admin.firestore.FieldValue.serverTimestamp();
      t.set(ref, {
        schemaVersion: DEVICE_REGISTRY_SCHEMA_VERSION,
        deviceId: params.deviceId,
        role: params.role,
        authUid: params.expectedAuthUid,
        ownerUid: params.expectedOwnerUid,
        status: "active",
        suspensionReason: null,
        identityMode: "keystore",
        publicKey: params.canonicalPublicKey,
        createdAt: now,
        updatedAt: now,
        lastSeenAt: now,
        revokedAt: null,
      });
      return { outcome: "home_created" };
    }

    // First-key migration #2: existing legacy+null -> keystore, gated the same way inside
    // decidePublicKeyRegistration itself (only on that specific branch -- never on idempotent/
    // conflict). role is always "HOME" here (this function is HOME-only, per its own doc), so
    // this always populates freshAuthCheck; still spelled out explicitly rather than assumed.
    const decision = decidePublicKeyRegistration(existing, {
      ...params,
      freshAuthCheck: params.role === "HOME" ? { authTime: params.authTime, nowSeconds: params.nowSeconds } : undefined,
    });
    return finalizePublicKeyRegistrationDecision(t, ref, { deviceId: params.deviceId, role: params.role }, decision);
  });
}

// The strict, transactional legacy -> keystore registration operation for CAMERA. Reads
// cameraClaims/{cameraDeviceId} AND registeredDevices/{cameraDeviceId} inside the SAME
// transaction as the eventual write -- unlike an out-of-transaction pre-check, this makes the
// whole "claim still exists and matches, therefore the key may be registered" decision atomic
// with the write itself: a concurrent unpair (which deletes cameraClaims) can no longer race
// between "verified" and "written", because both reads and the write share one transaction and
// Firestore's own contention/retry guarantees a consistent view throughout.
//
// `authenticatedUid` is `request.auth.uid` as already verified by the callable (a real
// Firebase Auth session existed) -- never anything the client asserts about its own identity
// beyond that. Never reveals the expected/actual uid or any claim contents to the caller; only
// the fixed outcome enum crosses this function's boundary.
//
// Same never-swallows-Firestore-errors contract as applyPublicKeyRegistration, and reuses the
// exact same decidePublicKeyRegistration()/finalizePublicKeyRegistrationDecision() core, so
// corruption handling, revoked handling, idempotency, first-write-wins, timestamp behavior, and
// key-conflict behavior are identical between the two roles -- never duplicated.
export async function applyCameraPublicKeyRegistration(
  db: admin.firestore.Firestore,
  params: {
    cameraDeviceId: string;
    authenticatedUid: string;
    canonicalPublicKey: string;
  }
): Promise<PublicKeyRegistrationOutcome> {
  const claimRef = db.collection("cameraClaims").doc(params.cameraDeviceId);
  const ref = registeredDeviceRef(db, params.cameraDeviceId);

  return db.runTransaction(async (t): Promise<PublicKeyRegistrationOutcome> => {
    const claimSnap = await t.get(claimRef);
    if (!claimSnap.exists) {
      return { outcome: "camera_not_claimed" };
    }

    const cameraAuthUid = claimSnap.get("cameraAuthUid") as string | undefined;
    if (!cameraAuthUid || cameraAuthUid !== params.authenticatedUid) {
      return { outcome: "auth_uid_mismatch" };
    }

    const snap = await t.get(ref);
    const existing = snap.exists ? (snap.data() as RegisteredDevice) : null;
    const decision = decidePublicKeyRegistration(existing, {
      role: "CAMERA",
      expectedAuthUid: cameraAuthUid,
      expectedOwnerUid: null,
      canonicalPublicKey: params.canonicalPublicKey,
    });
    return finalizePublicKeyRegistrationDecision(t, ref, { deviceId: params.cameraDeviceId, role: "CAMERA" }, decision);
  });
}

// ---------------------------------------------------------------------------------------------
// Explicit revoke: revokeRegisteredDevice
// ---------------------------------------------------------------------------------------------
// A distinct, explicit, owner-triggered action ("this specific credential must never be trusted
// again") -- deliberately separate from a normal unpair (detachCameraOwner above), which only
// ever clears ownerUid and never touches status. See docs/DEVICE_REGISTRY.md.

export type RevokeDeviceDecision =
  | { outcome: "revoked"; alreadyRevoked: true }
  | { outcome: "revoked"; alreadyRevoked: false; writeFields: Record<string, unknown> }
  | { outcome: "not_found" }
  | { outcome: "no_owner" }
  | { outcome: "owner_mismatch" };

// Pure decision core for revokeRegisteredDevice -- takes the already-fetched document (or null)
// and the authenticated caller's uid, never touches Firestore itself. Exported for direct unit
// testing without a Firestore emulator.
//
// ownerUid is never cleared by revoke (unlike a normal unpair) -- it is the only record of who
// revoked this device and remains needed for an owner's device list / audit trail. A device with
// ownerUid == null (never claimed, or already unpaired) can never be revoked by a client: there is
// no owner to authorize the caller against, and "revoke my lost device" only makes sense for a
// device the caller currently owns.
export function decideRevokeRegisteredDevice(
  existing: RegisteredDevice | null,
  requestingUid: string
): RevokeDeviceDecision {
  if (!existing) {
    return { outcome: "not_found" };
  }
  if (existing.ownerUid === null) {
    return { outcome: "no_owner" };
  }
  if (existing.ownerUid !== requestingUid) {
    return { outcome: "owner_mismatch" };
  }
  if (existing.status === "revoked") {
    // Idempotent: the original revokedAt is never touched, and updatedAt is not bumped for a
    // no-op repeat call.
    return { outcome: "revoked", alreadyRevoked: true };
  }

  const now = admin.firestore.FieldValue.serverTimestamp();
  return {
    outcome: "revoked",
    alreadyRevoked: false,
    writeFields: {
      status: "revoked",
      revokedAt: now,
      suspensionReason: null,
      updatedAt: now,
    },
  };
}

// The strict, transactional revoke operation -- owner-only, idempotent, and never touches
// deviceId/role/authUid/ownerUid/identityMode/publicKey/createdAt/lastSeenAt. Same
// never-swallows-a-Firestore-error contract as applyPublicKeyRegistration: a genuine transaction
// failure propagates as a real rejected promise, never silently reported as success.
export async function applyRevokeRegisteredDevice(
  db: admin.firestore.Firestore,
  deviceId: string,
  requestingUid: string
): Promise<RevokeDeviceDecision> {
  const ref = registeredDeviceRef(db, deviceId);

  return db.runTransaction(async (t): Promise<RevokeDeviceDecision> => {
    const snap = await t.get(ref);
    const existing = snap.exists ? (snap.data() as RegisteredDevice) : null;
    const decision = decideRevokeRegisteredDevice(existing, requestingUid);

    if (decision.outcome === "revoked" && !decision.alreadyRevoked) {
      t.set(ref, decision.writeFields, { merge: true });
    }

    return decision;
  });
}

// ---------------------------------------------------------------------------------------------
// Centralized operational-status enforcement: checkRegisteredDeviceOperational
// ---------------------------------------------------------------------------------------------
// The single, shared decision for "is this device currently allowed to perform an operational
// action" (issuing TURN credentials, accepting a submitted event, completing a pairing/claim,
// etc.) -- see docs/DEVICE_REGISTRY.md's operation/status matrix for exactly which call sites use
// this and how. Every reason string here is fixed and safe to log/return to a client verbatim --
// never includes a UID, a key, or any other document field.

export type DeviceOperationalReason =
  | "DEVICE_SUSPENDED"
  | "DEVICE_SUSPENDED_PLAN"
  | "DEVICE_REVOKED"
  | "DEVICE_NOT_REGISTERED";

export type DeviceOperationalDecision = { operational: true } | { operational: false; reason: DeviceOperationalReason };

// Pure: `existing` is the already-fetched registeredDevices/{deviceId} document, or null if none
// exists. `requireRegistered` (default false) controls what a MISSING document means:
//  - false (every operational enforcement call site in index.ts) treats "not yet registered" as
//    operational. This registry is still best-effort bookkeeping layered on top of
//    cameraClaims/pairingState (the real sources of truth) -- a device that predates the registry,
//    or whose lazy-migration write simply hasn't landed yet, must never be newly blocked because
//    of that.
//  - true (revokeRegisteredDevice's own "can't revoke what was never registered" check, handled
//    separately in decideRevokeRegisteredDevice -- not routed through this function at all) is
//    documented here only so DEVICE_NOT_REGISTERED's meaning is defined in exactly one place.
export function checkRegisteredDeviceOperational(
  existing: Pick<RegisteredDevice, "status" | "suspensionReason"> | null,
  options: { requireRegistered?: boolean } = {}
): DeviceOperationalDecision {
  if (!existing) {
    return options.requireRegistered ? { operational: false, reason: "DEVICE_NOT_REGISTERED" } : { operational: true };
  }
  if (existing.status === "revoked") {
    return { operational: false, reason: "DEVICE_REVOKED" };
  }
  if (existing.status === "suspended") {
    return {
      operational: false,
      reason: existing.suspensionReason === "plan" ? "DEVICE_SUSPENDED_PLAN" : "DEVICE_SUSPENDED",
    };
  }
  return { operational: true };
}

// ---------------------------------------------------------------------------------------------
// Plan-based suspension: reconcileUserDeviceLimits
// ---------------------------------------------------------------------------------------------
// Brings a user's owned, non-revoked registeredDevices in line with their current plan limits,
// independently per role (CAMERA/HOME each counted on their own) -- see
// docs/DEVICE_REGISTRY.md's "Plan suspension" section for the full selection rule. Called from
// reconcileDevicesOnEntitlementChange (index.ts) whenever maxCameras/maxHomeDevices actually
// change; never itself reacts to subscriptionStatus (see entitlements.ts's
// getPlanDeviceLimits/planDeviceLimitsFromEntitlementsData for why "blocked" must never reach
// here as a limit change).

// Deterministic tie-break: createdAt ascending, deviceId ascending on an exact tie -- never
// lastSeenAt (that would make the active set drift every time a device happens to be used),
// making a repeated reconcile with the same limit fully idempotent and its device selection
// reproducible.
function compareByCreatedAtThenDeviceId(a: RegisteredDevice, b: RegisteredDevice): number {
  const aMillis = a.createdAt.toMillis();
  const bMillis = b.createdAt.toMillis();
  if (aMillis !== bMillis) return aMillis - bMillis;
  if (a.deviceId < b.deviceId) return -1;
  if (a.deviceId > b.deviceId) return 1;
  return 0;
}

export interface DeviceLimitReconciliation {
  toSuspendPlan: string[]; // deviceIds that should become status=suspended/suspensionReason=plan
  toReactivate: string[]; // deviceIds that should become status=active/suspensionReason=null
}

// Pure: given ONE user's ONE role's already-fetched, non-revoked owned devices and that role's
// limit, decides which deviceIds need a write.
//
// EVERY non-revoked device the caller passes in occupies a plan slot -- active, suspended/plan,
// suspended/manual, and suspended/security all count toward `limit` (only `revoked` and
// `ownerUid == null` devices, both already excluded by the caller's own query, are outside any
// limit entirely). Sorted by createdAt ascending, deviceId ascending on an exact tie, the first
// `limit` devices are "within plan"; the rest are "excess". Within that framing:
//
//  - `active`, within plan -> stays active (no-op).
//  - `suspended`/`"plan"`, within plan -> reactivated to active.
//  - `active`, excess -> suspended, reason "plan".
//  - `suspended`/`"plan"`, excess -> stays suspended/plan (no-op).
//  - `suspended`/`"manual"` or `suspended`/`"security"`, within plan OR excess -> **never
//    touched**, either direction. A manual/security suspension still occupies (or, if excess,
//    still vacates a would-be slot for) its position in the ordering -- it can push a later
//    device into "excess" or free up a slot for an earlier one exactly like any other device
//    would -- but its own status/suspensionReason is never the thing this function changes.
//
// A device already in its correct target state is never included in either output list, so a
// caller applying these decisions never bumps `updatedAt` on a no-op.
export function planDeviceLimitDecision(devices: RegisteredDevice[], limit: number): DeviceLimitReconciliation {
  const sorted = [...devices].sort(compareByCreatedAtThenDeviceId);
  const withinPlanIds = new Set(sorted.slice(0, Math.max(0, limit)).map((d) => d.deviceId));

  const toSuspendPlan: string[] = [];
  const toReactivate: string[] = [];

  for (const device of sorted) {
    if (device.status === "suspended" && (device.suspensionReason === "manual" || device.suspensionReason === "security")) {
      continue;
    }

    const withinPlan = withinPlanIds.has(device.deviceId);
    if (withinPlan && device.status === "suspended" && device.suspensionReason === "plan") {
      toReactivate.push(device.deviceId);
    } else if (!withinPlan && device.status === "active") {
      toSuspendPlan.push(device.deviceId);
    }
  }

  return { toSuspendPlan, toReactivate };
}

// Re-validates and applies ONE device's plan-limit state change inside its own small transaction
// -- never trusts the plan-limit decision's input snapshot (from reconcileUserDeviceLimits' own
// query, read before this runs) as still current. If the device's status has concurrently changed
// to something this reconcile must never override (revoked, or a manual/security suspension that
// landed after that query), the write is silently skipped: the device is left exactly as the
// concurrent operation left it, never reverted back toward what this reconcile pass originally
// computed. Returns whether a write actually happened, so the caller can log an accurate count.
async function applyDevicePlanLimitChange(
  db: admin.firestore.Firestore,
  deviceId: string,
  targetStatus: "active" | "suspended",
  targetSuspensionReason: DeviceSuspensionReason
): Promise<boolean> {
  const ref = registeredDeviceRef(db, deviceId);

  return db.runTransaction(async (t): Promise<boolean> => {
    const snap = await t.get(ref);
    if (!snap.exists) return false;

    const existing = snap.data() as RegisteredDevice;
    const stillEligible =
      existing.status === "active" || (existing.status === "suspended" && existing.suspensionReason === "plan");
    if (!stillEligible) return false;

    if (existing.status === targetStatus && existing.suspensionReason === targetSuspensionReason) {
      return false;
    }

    t.set(
      ref,
      {
        status: targetStatus,
        suspensionReason: targetSuspensionReason,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
    return true;
  });
}

// Applies planDeviceLimitDecision's selection for ONE role, one device at a time (never batched
// into a single multi-document transaction/batch) -- see docs/DEVICE_REGISTRY.md's "Consistency
// model" for why: a user's total owned-device count is expected to stay small (single digits to
// low tens) in practice, so sequential per-device transactions keep the write ordering simple and
// predictable without needing Firestore's 500-operation batch limit or a large multi-document
// transaction that would contend with every other concurrent operation touching any of these
// documents at once. Each device's own transaction independently re-validates it is still
// eligible for an automatic plan-based change (see applyDevicePlanLimitChange above), so a
// concurrent revoke or manual/security suspension landing on any ONE device mid-reconcile can
// never be overridden by this pass, regardless of how many other devices it also touches.
async function reconcileRoleDeviceLimit(
  db: admin.firestore.Firestore,
  devices: RegisteredDevice[],
  limit: number
): Promise<{ suspendedCount: number; reactivatedCount: number }> {
  const { toSuspendPlan, toReactivate } = planDeviceLimitDecision(devices, limit);

  let suspendedCount = 0;
  for (const deviceId of toSuspendPlan) {
    if (await applyDevicePlanLimitChange(db, deviceId, "suspended", "plan")) {
      suspendedCount++;
    }
  }

  let reactivatedCount = 0;
  for (const deviceId of toReactivate) {
    if (await applyDevicePlanLimitChange(db, deviceId, "active", null)) {
      reactivatedCount++;
    }
  }

  return { suspendedCount, reactivatedCount };
}

// Reconciles one user's CAMERA and HOME device counts (independently) against `limits`. Reads
// every registeredDevices document with ownerUid == ownerUid via a single-field query (a device
// with ownerUid == null never belongs to any user's limit, and is excluded by this query by
// construction) -- role and revoked-status filtering happen in memory afterward, deliberately
// avoiding a multi-field composite query that would require a new Firestore index this project
// does not otherwise need. Never throws for an individual device's own transaction failing to
// apply (Firestore's own transaction retry already handles ordinary contention); a genuine,
// repeated failure surfaces as that device simply not being included in the returned count, safe
// to retry on the next entitlement change or a future explicit reconcile trigger.
export async function reconcileUserDeviceLimits(
  db: admin.firestore.Firestore,
  ownerUid: string,
  limits: DeviceLimits
): Promise<{
  camerasSuspended: number;
  camerasReactivated: number;
  homeDevicesSuspended: number;
  homeDevicesReactivated: number;
}> {
  const snap = await db.collection(REGISTERED_DEVICES_COLLECTION).where("ownerUid", "==", ownerUid).get();
  const all = snap.docs.map((d) => d.data() as RegisteredDevice);

  const cameras = all.filter((d) => d.role === "CAMERA" && d.status !== "revoked");
  const homes = all.filter((d) => d.role === "HOME" && d.status !== "revoked");

  const [cameraResult, homeResult] = await Promise.all([
    reconcileRoleDeviceLimit(db, cameras, limits.maxCameras),
    reconcileRoleDeviceLimit(db, homes, limits.maxHomeDevices),
  ]);

  logger.info("DEVICE_REGISTRY_RECONCILE_USER_LIMITS", {
    operation: "plan_reconcile",
    camerasSuspended: cameraResult.suspendedCount,
    camerasReactivated: cameraResult.reactivatedCount,
    homeDevicesSuspended: homeResult.suspendedCount,
    homeDevicesReactivated: homeResult.reactivatedCount,
  });

  return {
    camerasSuspended: cameraResult.suspendedCount,
    camerasReactivated: cameraResult.reactivatedCount,
    homeDevicesSuspended: homeResult.suspendedCount,
    homeDevicesReactivated: homeResult.reactivatedCount,
  };
}
