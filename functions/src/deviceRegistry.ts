import * as admin from "firebase-admin";
import * as logger from "firebase-functions/logger";

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
