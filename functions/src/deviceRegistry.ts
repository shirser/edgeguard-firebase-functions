import * as admin from "firebase-admin";
import * as logger from "firebase-functions/logger";
import * as crypto from "crypto";

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
// no-op if the
// device was never registered, or if it's registered under a different role (defensive only --
// cameraDeviceId/homeDeviceId occupy the same registeredDevices id space in principle, though in
// practice they're generated independently and collisions are not expected).
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

// Every outcome the registerDevicePublicKey transactions below can resolve to. Deliberately not
// exceptions -- these are all *expected*, named business outcomes the caller (the
// registerDevicePublicKey callable) maps onto specific client-facing HttpsErrors; only a genuine
// Firestore/infrastructure failure is left to propagate as a real thrown error (see below).
// "camera_not_claimed" is CAMERA-specific (see applyCameraPublicKeyRegistration); every other
// outcome is shared between both roles.
export type PublicKeyRegistrationOutcome =
  | { outcome: "registered" }
  | { outcome: "idempotent" }
  | { outcome: "not_found" }
  | { outcome: "camera_not_claimed" }
  | { outcome: "role_mismatch" }
  | { outcome: "auth_uid_mismatch" }
  | { outcome: "owner_uid_mismatch" }
  | { outcome: "revoked" }
  | { outcome: "key_conflict" }
  | { outcome: "corrupt" };

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
  | { outcome: "corrupt" };

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
function decidePublicKeyRegistration(
  existing: RegisteredDevice | null,
  params: { role: DeviceRole; expectedAuthUid: string; expectedOwnerUid: string | null; canonicalPublicKey: string }
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
    // out identityMode:"keystore" with publicKey:null.
    if (existing.publicKey === params.canonicalPublicKey) {
      return { outcome: "idempotent", writeFields: { lastSeenAt: admin.firestore.FieldValue.serverTimestamp() } };
    }
    return { outcome: "key_conflict" };
  }

  // identityMode === "legacy" and publicKey === null (corruption already ruled out) -- the one and
  // only first-registration path. Only identityMode/publicKey/updatedAt/lastSeenAt are ever
  // written -- deviceId/role/authUid/ownerUid/status/suspensionReason/createdAt/revokedAt are
  // never part of this write.
  const now = admin.firestore.FieldValue.serverTimestamp();
  return {
    outcome: "registered",
    writeFields: { identityMode: "keystore", publicKey: params.canonicalPublicKey, updatedAt: now, lastSeenAt: now },
  };
}

// Applies a decidePublicKeyRegistration() result inside the caller's own transaction: performs
// the merge-write for "registered"/"idempotent" (nothing else ever writes), logs the one warning
// a "corrupt" outcome needs (deviceId/role only -- see docs/DEVICE_REGISTRY.md), and returns the
// plain outcome (dropping `writeFields`, an internal-only detail) for the callable to map onto an
// HttpsError.
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
  return { outcome: decision.outcome };
}

// The strict, transactional legacy -> keystore registration operation for HOME. Unlike every
// best-effort function above, this is NOT best-effort: it never catches or swallows a Firestore
// error -- a failed transaction (contention exhausted, a genuine write failure) propagates as a
// real rejected promise, and it is the caller's job (the callable) to turn that into a controlled
// internal/INTERNAL response rather than silently reporting success.
//
// Never creates registeredDevices/{deviceId} -- registering a device and registering its
// cryptographic identity are different operations (see docs/DEVICE_REGISTRY.md); a missing
// document is reported back as { outcome: "not_found" }, never created here.
//
// CAMERA registration does NOT use this function -- see applyCameraPublicKeyRegistration, which
// additionally verifies cameraClaims inside the same transaction as the registry read/write
// (verifying it outside, beforehand, would leave a window where an unpair between the check and
// the write could remove cameraClaims while the key registration still went through).
export async function applyPublicKeyRegistration(
  db: admin.firestore.Firestore,
  params: {
    deviceId: string;
    role: DeviceRole;
    expectedAuthUid: string;
    expectedOwnerUid: string | null;
    canonicalPublicKey: string;
  }
): Promise<PublicKeyRegistrationOutcome> {
  const ref = registeredDeviceRef(db, params.deviceId);

  return db.runTransaction(async (t): Promise<PublicKeyRegistrationOutcome> => {
    const snap = await t.get(ref);
    const existing = snap.exists ? (snap.data() as RegisteredDevice) : null;
    const decision = decidePublicKeyRegistration(existing, params);
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
