import * as admin from "firebase-admin";
import * as logger from "firebase-functions/logger";

// Server-side user entitlements model (plan/limits/TURN access), stored at
// userEntitlements/{uid} -- see docs/USER_ENTITLEMENTS.md for the full field
// reference, defaults, and example documents. Deliberately does NOT cover
// Google Play Billing, purchase token verification, a device registry,
// Android Keystore, actual Camera/Home counting, concurrent Live View
// session limits, or rate limiting -- those are later work built on top of
// this model, not part of it.

export const ENTITLEMENTS_SCHEMA_VERSION = 1;

export type EntitlementPlan = "free" | "premium" | "custom";
export type EntitlementSubscriptionStatus = "active" | "expired" | "blocked";
export type EntitlementSource = "default" | "manual" | "promo" | "google_play";

const VALID_PLANS: ReadonlySet<string> = new Set<EntitlementPlan>(["free", "premium", "custom"]);
const VALID_STATUSES: ReadonlySet<string> = new Set<EntitlementSubscriptionStatus>([
  "active",
  "expired",
  "blocked",
]);
const VALID_SOURCES: ReadonlySet<string> = new Set<EntitlementSource>([
  "default",
  "manual",
  "promo",
  "google_play",
]);

// The raw shape of a userEntitlements/{uid} document exactly as it must be
// stored -- see docs/USER_ENTITLEMENTS.md for what each field means.
// validUntil is null for a grant with no expiry (e.g. a manual lifetime
// grant); createdAt/updatedAt are always Firestore Timestamps, never a
// client-suppliable value (this collection is never client-writable, see
// firestore.rules).
export interface UserEntitlements {
  schemaVersion: number;
  plan: EntitlementPlan;
  subscriptionStatus: EntitlementSubscriptionStatus;
  maxCameras: number;
  maxHomeDevices: number;
  maxConcurrentLiveSessions: number;
  turnAccessAllowed: boolean;
  source: EntitlementSource;
  validUntil: admin.firestore.Timestamp | null;
  createdAt: admin.firestore.Timestamp;
  updatedAt: admin.firestore.Timestamp;
}

// The already-resolved rights a caller actually has right now, after
// applying the active/expired/blocked/corrupt-document rules below -- what
// every consumer (e.g. getTurnCredentials) should read, never the raw
// UserEntitlements document. Narrower than UserEntitlements on purpose: no
// schemaVersion/source/timestamps, since callers only ever need the
// resolved numbers/flags.
export interface EffectiveUserEntitlements {
  plan: EntitlementPlan;
  subscriptionStatus: EntitlementSubscriptionStatus;
  maxCameras: number;
  maxHomeDevices: number;
  maxConcurrentLiveSessions: number;
  turnAccessAllowed: boolean;
}

// The single centralized Free-tier definition. Every "no document" /
// "expired" / "corrupt document" path below returns exactly this object (a
// fresh copy each time, since callers must never be able to mutate the
// shared default) -- these numbers must never be duplicated or
// re-hardcoded anywhere else in this project.
const FREE_ENTITLEMENTS: EffectiveUserEntitlements = Object.freeze({
  plan: "free",
  subscriptionStatus: "active",
  maxCameras: 1,
  maxHomeDevices: 1,
  maxConcurrentLiveSessions: 1,
  turnAccessAllowed: true,
});

function freeEntitlements(): EffectiveUserEntitlements {
  return { ...FREE_ENTITLEMENTS };
}

function isValidPlan(value: unknown): value is EntitlementPlan {
  return typeof value === "string" && VALID_PLANS.has(value);
}

function isValidSubscriptionStatus(value: unknown): value is EntitlementSubscriptionStatus {
  return typeof value === "string" && VALID_STATUSES.has(value);
}

function isValidSource(value: unknown): value is EntitlementSource {
  return typeof value === "string" && VALID_SOURCES.has(value);
}

// A limit must be a whole, non-negative number -- neither a fraction (e.g.
// "1.5 cameras") nor negative makes sense for any of the three limit
// fields, so either is treated as document corruption, not clamped/rounded.
function isValidLimit(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function isValidValidUntil(value: unknown): value is admin.firestore.Timestamp | null {
  return value === null || value instanceof admin.firestore.Timestamp;
}

// Fixed, stable set of corruption categories -- the only thing about *why*
// a document was rejected that is ever allowed into a log line (see
// parseUserEntitlements/getEffectiveUserEntitlements below). Deliberately
// never a free-form string built from the document's own field names/
// values: a fixed enum can never leak document content, no matter how the
// document was malformed.
export type CorruptEntitlementsReason =
  | "MISSING_DATA"
  | "INVALID_SCHEMA_VERSION"
  | "INVALID_PLAN"
  | "INVALID_SUBSCRIPTION_STATUS"
  | "INVALID_SOURCE"
  | "INVALID_LIMIT"
  | "INVALID_TURN_ACCESS_ALLOWED"
  | "INVALID_VALID_UNTIL"
  | "INVALID_CREATED_AT"
  | "INVALID_UPDATED_AT";

type ParsedUserEntitlements =
  | { valid: true; value: UserEntitlements }
  | { valid: false; reason: CorruptEntitlementsReason; schemaVersion: number | null };

// Parses a raw Firestore document's data() into a UserEntitlements, or a
// { valid: false, reason, schemaVersion } describing *why* it was rejected
// -- see docs/USER_ENTITLEMENTS.md's "Повреждённый документ" section for
// the full rule list this enforces (unknown plan/subscriptionStatus/
// source, a missing required field -- including createdAt/updatedAt, both
// required and both must be an actual Firestore Timestamp -- a negative or
// non-integer limit, a wrong validUntil type, or a wrong schemaVersion).
// `schemaVersion` is carried separately (not part of `reason`) so the
// caller can log it only when it is itself a safe plain number -- never
// when it's missing or some other, potentially unsafe, type/value. Never
// throws -- a corrupt document can never crash a caller.
function parseUserEntitlements(data: FirebaseFirestore.DocumentData | undefined): ParsedUserEntitlements {
  const schemaVersion = typeof data?.schemaVersion === "number" ? data.schemaVersion : null;

  if (!data) return { valid: false, reason: "MISSING_DATA", schemaVersion };
  if (data.schemaVersion !== ENTITLEMENTS_SCHEMA_VERSION) {
    return { valid: false, reason: "INVALID_SCHEMA_VERSION", schemaVersion };
  }
  if (!isValidPlan(data.plan)) return { valid: false, reason: "INVALID_PLAN", schemaVersion };
  if (!isValidSubscriptionStatus(data.subscriptionStatus)) {
    return { valid: false, reason: "INVALID_SUBSCRIPTION_STATUS", schemaVersion };
  }
  if (!isValidSource(data.source)) return { valid: false, reason: "INVALID_SOURCE", schemaVersion };
  if (!isValidLimit(data.maxCameras)) return { valid: false, reason: "INVALID_LIMIT", schemaVersion };
  if (!isValidLimit(data.maxHomeDevices)) return { valid: false, reason: "INVALID_LIMIT", schemaVersion };
  if (!isValidLimit(data.maxConcurrentLiveSessions)) {
    return { valid: false, reason: "INVALID_LIMIT", schemaVersion };
  }
  if (typeof data.turnAccessAllowed !== "boolean") {
    return { valid: false, reason: "INVALID_TURN_ACCESS_ALLOWED", schemaVersion };
  }
  if (!isValidValidUntil(data.validUntil)) return { valid: false, reason: "INVALID_VALID_UNTIL", schemaVersion };
  // createdAt/updatedAt are both required and must each be an actual
  // Firestore Timestamp -- this applies only to a *stored* document; the
  // Free defaults returned when no document exists at all have no
  // timestamps and are never run through this parser.
  if (!(data.createdAt instanceof admin.firestore.Timestamp)) {
    return { valid: false, reason: "INVALID_CREATED_AT", schemaVersion };
  }
  if (!(data.updatedAt instanceof admin.firestore.Timestamp)) {
    return { valid: false, reason: "INVALID_UPDATED_AT", schemaVersion };
  }

  return {
    valid: true,
    value: {
      schemaVersion: data.schemaVersion,
      plan: data.plan,
      subscriptionStatus: data.subscriptionStatus,
      maxCameras: data.maxCameras,
      maxHomeDevices: data.maxHomeDevices,
      maxConcurrentLiveSessions: data.maxConcurrentLiveSessions,
      turnAccessAllowed: data.turnAccessAllowed,
      source: data.source,
      validUntil: data.validUntil,
      createdAt: data.createdAt,
      updatedAt: data.updatedAt,
    },
  };
}

// `nowMillis` defaults to the real clock but is an explicit parameter (same
// pattern as index.ts's buildTurnCredentialsResponse(..., nowSeconds)) so a
// test can pin the exact boundary instant instead of racing the real clock
// against a Firestore round-trip. validUntil == nowMillis counts as expired
// (strict "<=", not "<"): only a *strictly future* validUntil is active.
// Exported (in addition to being used internally) purely for that
// boundary-condition test -- callers other than getEffectiveUserEntitlements
// below should not need it.
export function isExpired(stored: UserEntitlements, nowMillis: number = Date.now()): boolean {
  if (stored.subscriptionStatus === "expired") return true;
  return stored.validUntil !== null && stored.validUntil.toMillis() <= nowMillis;
}

// Resolves a RAW userEntitlements document's data (or undefined, meaning "no document") to the
// stored-or-Free-fallback rules shared by every consumer below (missing/corrupt/expired -> Free) --
// WITHOUT touching Firestore itself. `subscriptionStatus` is carried on the return value so
// getEffectiveUserEntitlements (the only caller that cares) can still apply its own "blocked ->
// zeroed rights" rule on top; every other field already reflects the fully-resolved rights.
// Exported as planDeviceLimitsFromEntitlementsData below for callers (e.g. a Firestore trigger's
// event.data.before/after) that already have a raw snapshot's data() in hand and must not
// re-fetch it -- by the time such a handler runs, "before" is no longer the live document.
function resolveEntitlementsData(
  data: FirebaseFirestore.DocumentData | undefined
): { subscriptionStatus: EntitlementSubscriptionStatus } & EffectiveUserEntitlements {
  if (!data) {
    return { ...freeEntitlements() };
  }

  const parsed = parseUserEntitlements(data);

  if (!parsed.valid) {
    logger.warn("USER_ENTITLEMENTS_CORRUPT_DOCUMENT_FALLBACK_FREE", {
      reason: parsed.reason,
      ...(parsed.schemaVersion !== null ? { schemaVersion: parsed.schemaVersion } : {}),
    });
    return { ...freeEntitlements() };
  }

  const stored = parsed.value;

  if (isExpired(stored)) {
    return { ...freeEntitlements() };
  }

  return {
    plan: stored.plan,
    subscriptionStatus: stored.subscriptionStatus,
    maxCameras: stored.maxCameras,
    maxHomeDevices: stored.maxHomeDevices,
    maxConcurrentLiveSessions: stored.maxConcurrentLiveSessions,
    turnAccessAllowed: stored.turnAccessAllowed,
  };
}

async function resolveStoredOrFreeEntitlements(
  uid: string,
  db: admin.firestore.Firestore
): Promise<{ subscriptionStatus: EntitlementSubscriptionStatus } & EffectiveUserEntitlements> {
  const snap = await db.collection("userEntitlements").doc(uid).get();
  return resolveEntitlementsData(snap.exists ? snap.data() : undefined);
}

// Reads userEntitlements/{uid} and returns the already-safe effective
// rights this uid actually has right now:
//  - No document at all -> Free defaults. Never creates the document as a
//    side effect of reading it.
//  - subscriptionStatus == "blocked" -> zeroed-out rights, TURN denied,
//    regardless of any other field on the document (checked before expiry,
//    so a blocked-and-also-expired document is still just "blocked").
//  - Expired (subscriptionStatus == "expired", or validUntil is in the
//    past) -> Free defaults. This is a downgrade, not a lockout: an expired
//    Premium grant simply becomes Free, exactly like having no document.
//  - Otherwise (subscriptionStatus == "active" and validUntil is null or in
//    the future) -> the stored rights, verbatim, including a stored
//    turnAccessAllowed == false (an explicit TURN deny is never relaxed).
//  - A corrupt document (see parseUserEntitlements) logs one structured
//    warning and falls back to Free defaults -- never a partial mix of
//    whatever corrupt fields did parse plus Free defaults for the rest,
//    and never an unhandled exception. The warning is deliberately narrow:
//    only the fixed event name, a fixed CorruptEntitlementsReason enum
//    value, and schemaVersion (only when it is itself a safe plain
//    number) -- never the uid, never an email, never the document path,
//    never any purchase token/TURN credential/TURN secret, and never any
//    other raw field value from the document. The uid this corrupt
//    document belongs to must never appear in this log line.
export async function getEffectiveUserEntitlements(
  uid: string,
  db: admin.firestore.Firestore = admin.firestore()
): Promise<EffectiveUserEntitlements> {
  const resolved = await resolveStoredOrFreeEntitlements(uid, db);

  if (resolved.subscriptionStatus === "blocked") {
    return {
      plan: resolved.plan,
      subscriptionStatus: "blocked",
      maxCameras: 0,
      maxHomeDevices: 0,
      maxConcurrentLiveSessions: 0,
      turnAccessAllowed: false,
    };
  }

  return {
    plan: resolved.plan,
    subscriptionStatus: resolved.subscriptionStatus,
    maxCameras: resolved.maxCameras,
    maxHomeDevices: resolved.maxHomeDevices,
    maxConcurrentLiveSessions: resolved.maxConcurrentLiveSessions,
    turnAccessAllowed: resolved.turnAccessAllowed,
  };
}

// The device-count limits (only) a user's plan actually entitles them to -- for device registry
// reconciliation (deviceRegistry.ts's reconcileUserDeviceLimits) ONLY, never for operational
// access decisions (use getEffectiveUserEntitlements/turnAccessAllowed for those). Deliberately
// does NOT apply getEffectiveUserEntitlements' "blocked -> zeroed rights" rule:
// subscriptionStatus == "blocked" is an operational access gate (denies TURN issuance etc.), not a
// change to how many devices the user's plan actually allows -- conflating the two would turn a
// simple subscription block into wrongly suspending every device the user owns, which this
// project's device-status model explicitly keeps separate (pairing state, device status, and
// subscription status are three independent axes -- see docs/DEVICE_REGISTRY.md). Still applies
// the same missing-document/corrupt-document/expired -> Free fallback as
// getEffectiveUserEntitlements (an expired grant is a REAL downgrade, unlike blocked), sharing the
// exact same resolution logic so Free's definition is never duplicated.
export interface DeviceLimits {
  maxCameras: number;
  maxHomeDevices: number;
}

export async function getPlanDeviceLimits(
  uid: string,
  db: admin.firestore.Firestore = admin.firestore()
): Promise<DeviceLimits> {
  const resolved = await resolveStoredOrFreeEntitlements(uid, db);
  return { maxCameras: resolved.maxCameras, maxHomeDevices: resolved.maxHomeDevices };
}

// Pure variant of getPlanDeviceLimits for a caller that already has a raw userEntitlements
// document's data() in hand (or undefined for "no document") and must not perform a fresh
// Firestore read -- see resolveEntitlementsData's own doc for why. Exported for direct unit
// testing without a Firestore emulator, and used by reconcileDevicesOnEntitlementChange
// (index.ts) to compute both the "before" and "after" limits from a single trigger event without
// re-fetching either state from Firestore.
export function planDeviceLimitsFromEntitlementsData(
  data: FirebaseFirestore.DocumentData | undefined
): DeviceLimits {
  const resolved = resolveEntitlementsData(data);
  return { maxCameras: resolved.maxCameras, maxHomeDevices: resolved.maxHomeDevices };
}
