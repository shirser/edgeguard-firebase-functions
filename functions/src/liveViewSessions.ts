import * as admin from "firebase-admin";
import type { DeviceOperationalDecision, RegisteredDevice } from "./deviceRegistry";
import { checkRegisteredDeviceOperational } from "./deviceRegistry";
import { effectiveUserEntitlementsFromData } from "./entitlements";
import type {
  DeviceChallengePurpose,
  DeviceChallengeVerificationResult,
  TurnCredentialsChallengeVerificationFailureReason,
  TurnCredentialsDeviceProof,
} from "./deviceChallenges";
import {
  DEVICE_CHALLENGE_PURPOSES,
  DEVICE_PROOF_VERSION,
  buildCanonicalLiveViewStartRequestPayload,
  buildCanonicalLiveViewSessionIdRequestPayload,
  verifyDeviceChallengeForConsumption,
  isValidLiveViewSessionIdFormat,
} from "./deviceChallenges";

// ---------------------------------------------------------------------------------------------
// Live View sessions -- stage 1 of coturn abuse protection.
// ---------------------------------------------------------------------------------------------
// A server-issued, short (90s), renewable lease binding {ownerUid, homeDeviceId, cameraDeviceId}.
// This module deliberately never imports the Functions SDK (no HttpsError) -- same rule as
// deviceRegistry.ts/deviceChallenges.ts -- so every function here stays directly unit/integration
// testable without an onCall wrapper; index.ts's startLiveViewSession/renewLiveViewSession/
// endLiveViewSession callables are the only place a LiveViewSessionDenialReason is ever mapped onto
// a public HttpsError. See docs/LIVE_VIEW_SESSIONS.md for the full design, threat model, and why
// this is explicitly NOT yet bound to a TURN credential.

export const LIVE_VIEW_SESSION_SCHEMA_VERSION = 1;
export const LIVE_VIEW_USER_STATE_SCHEMA_VERSION = 1;

// Server-side only -- never derived from or extendable by a client-supplied timestamp. See
// docs/LIVE_VIEW_SESSIONS.md's "Lease semantics" section for why this is short and why renew always
// resets from now(), never from the old leaseExpiresAt (accumulation would let a client build an
// arbitrarily long-lived lease one renew at a time).
export const LIVE_VIEW_LEASE_TTL_MS = 90_000;

const LIVE_VIEW_SESSIONS_COLLECTION = "liveViewSessions";
const LIVE_VIEW_USER_STATES_COLLECTION = "liveViewUserStates";

export type LiveViewSessionStatus = "ACTIVE" | "ENDED";

export interface LiveViewSession {
  schemaVersion: number;
  sessionId: string;
  ownerUid: string;
  homeDeviceId: string;
  cameraDeviceId: string;
  status: LiveViewSessionStatus;
  createdAt: admin.firestore.Timestamp;
  updatedAt: admin.firestore.Timestamp;
  leaseExpiresAt: admin.firestore.Timestamp;
  endedAt: admin.firestore.Timestamp | null;
}

// One entry per currently-tracked session -- see parseAllocatorState below for the exact validity
// rules a stored entry must satisfy to be trusted at all.
export interface LiveViewUserStateActiveEntry {
  sessionId: string;
  homeDeviceId: string;
  cameraDeviceId: string;
  createdAt: admin.firestore.Timestamp;
  leaseExpiresAt: admin.firestore.Timestamp;
}

// liveViewUserStates/{uid} -- the per-user coordination/allocator document that serializes every
// start/renew/end for one user (see docs/LIVE_VIEW_SESSIONS.md's "Allocator invariant" section for
// why this must be a single document with a bounded map, never a query-derived count and never an
// unbounded log).
//
// `integrityStatus` is the explicit corruption state machine (see docs/LIVE_VIEW_SESSIONS.md's
// "Corrupt allocator handling" section for the full rationale). CRITICAL INVARIANT: once a
// document is marked "CORRUPT", `activeSessions` on that SAME write is never touched/replaced --
// only integrityStatus/corruptAt/corruptionReason/updatedAt are merged in. A structurally-corrupt
// `activeSessions` map can still contain entries for OTHER, canonically-ACTIVE sessions that simply
// could not be safely parsed as a whole (e.g. one bad entry among several good ones -- parsing
// fails the entire map, not just the bad entry); resetting it to `{}` would make those sessions
// silently vanish from allocator-based counting while remaining canonically ACTIVE, which is
// exactly the session-limit-bypass bug this state machine exists to prevent. "CORRUPT" therefore
// means "this document's activeSessions can no longer be trusted for counting or lookup, in either
// direction" -- not "empty".
export type LiveViewAllocatorIntegrityStatus = "HEALTHY" | "CORRUPT";
// A fixed, generic reason enum -- never a free-form string derived from the document's own corrupt
// content (same "never leak document content" rule entitlements.ts's own CorruptEntitlementsReason
// follows).
export type LiveViewAllocatorCorruptionReason = "PARSE_FAILED";

export interface LiveViewUserState {
  schemaVersion: number;
  updatedAt: admin.firestore.Timestamp;
  integrityStatus: LiveViewAllocatorIntegrityStatus;
  corruptAt: admin.firestore.Timestamp | null;
  corruptionReason: LiveViewAllocatorCorruptionReason | null;
  activeSessions: Record<string, LiveViewUserStateActiveEntry>;
}

// Every way the challenge/device-proof/session/allocator/entitlement checks below can deny a
// request -- deliberately detailed (mirrors TurnCredentialsChallengeVerificationFailureReason's own
// exhaustiveness) for tests and safe internal logging; index.ts's own error mapping collapses
// almost all of these into one generic public reason so a caller can never use the response to
// learn whether a given cameraDeviceId/sessionId exists, who owns it, or why exactly it failed.
// Reuses TurnCredentialsChallengeVerificationFailureReason as-is for every reason the shared
// verifyDeviceChallengeForConsumption primitive can itself return (challenge/identity/signature) --
// never a second, divergent copy of that taxonomy -- and adds only the reasons genuinely specific
// to the Live View domain (camera binding, allocator/session consistency, entitlement limit).
export type LiveViewSessionDenialReason =
  | TurnCredentialsChallengeVerificationFailureReason
  | "CAMERA_NOT_REGISTERED"
  | "CAMERA_NOT_OWNED_BY_CALLER"
  | "CAMERA_NOT_LINKED_TO_HOME"
  | "LIVE_VIEW_LIMIT_REACHED"
  | "LIVE_VIEW_ENTITLEMENT_DENIED"
  | "ALLOCATOR_STATE_INVALID"
  | "ALLOCATOR_SESSION_MISMATCH"
  | "SESSION_NOT_FOUND"
  | "SESSION_MALFORMED"
  | "SESSION_OWNER_MISMATCH"
  | "SESSION_HOME_MISMATCH"
  | "SESSION_NOT_ACTIVE"
  | "SESSION_LEASE_EXPIRED"
  | "SESSION_NOT_IN_ALLOCATOR";

export type StartLiveViewSessionOutcome =
  | { outcome: "started"; sessionId: string; leaseExpiresAtMillis: number }
  | { outcome: "denied"; reason: LiveViewSessionDenialReason };

export type RenewLiveViewSessionOutcome =
  | { outcome: "renewed"; sessionId: string; leaseExpiresAtMillis: number }
  | { outcome: "denied"; reason: LiveViewSessionDenialReason };

export type EndLiveViewSessionOutcome =
  | { outcome: "ended"; sessionId: string }
  | { outcome: "denied"; reason: LiveViewSessionDenialReason };

// Mirrors deviceChallenges.ts's own MAX_DEVICE_ID_LENGTH (kept as an independent constant, not
// imported, for the same no-circular-import/module-independence reason every other module in this
// project already follows for this exact bound).
const MAX_DEVICE_ID_LENGTH = 128;

function isNonEmptyBoundedString(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength;
}

// Defensive hard ceiling on how many entries a single allocator document may ever contain --
// independent of any user's actual maxConcurrentLiveSessions entitlement (which is typically 1-5
// and enforced separately, see executeStartLiveViewSession). This exists purely to bound how much
// work a single transaction ever does parsing/pruning/rewriting the map, and to make an
// unboundedly-growing (corrupted or attacker-influenced) map fail closed rather than silently
// accepted -- see docs/LIVE_VIEW_SESSIONS.md's "Allocator invariant" section.
export const LIVE_VIEW_ALLOCATOR_MAX_ENTRIES = 32;

export type SessionParseResult = { valid: true; session: LiveViewSession } | { valid: false };

// ---------------------------------------------------------------------------------------------
// Strict liveViewSessions/{sessionId} parsing -- pure, defensive. Every field is validated; any
// shape mismatch, unexpected field, or state combination that cannot legally occur (e.g. an ACTIVE
// session with a non-null endedAt) is rejected wholesale -- never a partial acceptance of "the
// fields that did parse". See docs/LIVE_VIEW_SESSIONS.md.
// ---------------------------------------------------------------------------------------------
const LIVE_VIEW_SESSION_ALLOWED_KEYS = [
  "schemaVersion",
  "sessionId",
  "ownerUid",
  "homeDeviceId",
  "cameraDeviceId",
  "status",
  "createdAt",
  "updatedAt",
  "leaseExpiresAt",
  "endedAt",
] as const;

export function parseLiveViewSession(sessionId: string, data: FirebaseFirestore.DocumentData | undefined): SessionParseResult {
  if (!data) {
    return { valid: false };
  }
  // Defense-in-depth: every caller of this function already only ever passes a sessionId that
  // came from either a validated request (isValidLiveViewSessionIdFormat, checked at the callable
  // layer) or an allocator entry's own sessionId (validated by parseAllocatorState using the SAME
  // canonical validator) -- but this function never trusts that upstream guarantee silently.
  if (!isValidLiveViewSessionIdFormat(sessionId)) {
    return { valid: false };
  }
  if (Object.keys(data).some((key) => !(LIVE_VIEW_SESSION_ALLOWED_KEYS as readonly string[]).includes(key))) {
    return { valid: false };
  }
  if (data.schemaVersion !== LIVE_VIEW_SESSION_SCHEMA_VERSION) {
    return { valid: false };
  }
  if (data.sessionId !== sessionId) {
    return { valid: false };
  }
  if (!isNonEmptyBoundedString(data.ownerUid, MAX_DEVICE_ID_LENGTH)) {
    return { valid: false };
  }
  if (!isNonEmptyBoundedString(data.homeDeviceId, MAX_DEVICE_ID_LENGTH)) {
    return { valid: false };
  }
  if (!isNonEmptyBoundedString(data.cameraDeviceId, MAX_DEVICE_ID_LENGTH)) {
    return { valid: false };
  }
  if (data.status !== "ACTIVE" && data.status !== "ENDED") {
    return { valid: false };
  }
  if (!(data.createdAt instanceof admin.firestore.Timestamp)) {
    return { valid: false };
  }
  if (!(data.updatedAt instanceof admin.firestore.Timestamp)) {
    return { valid: false };
  }
  if (!(data.leaseExpiresAt instanceof admin.firestore.Timestamp)) {
    return { valid: false };
  }
  if (data.status === "ACTIVE" && data.endedAt !== null) {
    return { valid: false };
  }
  if (data.status === "ENDED" && !(data.endedAt instanceof admin.firestore.Timestamp)) {
    return { valid: false };
  }

  return {
    valid: true,
    session: {
      schemaVersion: data.schemaVersion,
      sessionId: data.sessionId,
      ownerUid: data.ownerUid,
      homeDeviceId: data.homeDeviceId,
      cameraDeviceId: data.cameraDeviceId,
      status: data.status,
      createdAt: data.createdAt,
      updatedAt: data.updatedAt,
      leaseExpiresAt: data.leaseExpiresAt,
      endedAt: data.status === "ENDED" ? data.endedAt : null,
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Allocator parsing -- pure, defensive. A missing document is a valid, empty, HEALTHY allocator
// (first-ever session for this user). Any other shape mismatch -- including exceeding
// LIVE_VIEW_ALLOCATOR_MAX_ENTRIES, a malformed entry, or two entries sharing the same
// (homeDeviceId, cameraDeviceId) pair under different session ids -- is treated as fully corrupt
// (never a partial salvage of "the entries that did parse") -- see docs/LIVE_VIEW_SESSIONS.md's
// "Allocator invariant" for why a partial recovery would be exactly the kind of self-invented
// repair mechanism this design deliberately avoids. Uses Object.create(null) for the parsed map so
// a stored key can never collide with/shadow a JS object prototype property.
//
// `alreadyMarkedCorrupt` distinguishes two flavors of "not valid", both of which deny START/RENEW
// identically, but which the one caller that may WRITE a corruption flag (executeEndLiveViewSession,
// via maybeMarkAllocatorCorrupt below) must treat differently: `true` means the document ALREADY
// carries `integrityStatus: "CORRUPT"` -- a previous operation already discovered and flagged this,
// so nothing more is ever written to it (not even `updatedAt`); `false` means this is the FIRST time
// corruption was observed on this read, and the caller discovering it may flag it, exactly once,
// WITHOUT ever touching `activeSessions`. See docs/LIVE_VIEW_SESSIONS.md's "Corrupt allocator
// handling" section for the full rationale -- this exists specifically because resetting a corrupt
// allocator's `activeSessions` to `{}` can silently make OTHER, canonically-ACTIVE sessions vanish
// from allocator-based counting while remaining ACTIVE, enabling a maxConcurrentLiveSessions bypass.
// ---------------------------------------------------------------------------------------------

type AllocatorParseResult =
  | { valid: true; activeSessions: Record<string, LiveViewUserStateActiveEntry> }
  | { valid: false; alreadyMarkedCorrupt: boolean };

const ALLOCATOR_ALLOWED_KEYS = [
  "schemaVersion",
  "updatedAt",
  "integrityStatus",
  "corruptAt",
  "corruptionReason",
  "activeSessions",
] as const;

function parseAllocatorState(data: FirebaseFirestore.DocumentData | undefined): AllocatorParseResult {
  if (!data) {
    return { valid: true, activeSessions: Object.create(null) as Record<string, LiveViewUserStateActiveEntry> };
  }
  // Sticky corruption flag -- checked FIRST, immediately once there is a document to inspect at
  // all, strictly before schemaVersion, unexpected-key, updatedAt, activeSessions, or any other
  // structural check. Once corrupt, ALWAYS corrupt -- never re-derived from (and never able to be
  // contradicted by) the document's own other fields, so a document already marked CORRUPT can
  // never be treated as freshly/differently corrupt on a later read, and never auto-heals just
  // because activeSessions happens to look structurally parseable again (see
  // docs/LIVE_VIEW_SESSIONS.md's "Corrupt allocator handling" section for why).
  if (data.integrityStatus === "CORRUPT") {
    return { valid: false, alreadyMarkedCorrupt: true };
  }
  if (Object.keys(data).some((key) => !(ALLOCATOR_ALLOWED_KEYS as readonly string[]).includes(key))) {
    return { valid: false, alreadyMarkedCorrupt: false };
  }
  if (data.schemaVersion !== LIVE_VIEW_USER_STATE_SCHEMA_VERSION) {
    return { valid: false, alreadyMarkedCorrupt: false };
  }
  if (data.integrityStatus !== "HEALTHY") {
    return { valid: false, alreadyMarkedCorrupt: false };
  }
  // A HEALTHY document must have both corruption fields explicitly null -- any other value is
  // itself an impossible/tampered state, treated as a freshly-discovered corruption.
  if (data.corruptAt !== null || data.corruptionReason !== null) {
    return { valid: false, alreadyMarkedCorrupt: false };
  }
  if (!(data.updatedAt instanceof admin.firestore.Timestamp)) {
    return { valid: false, alreadyMarkedCorrupt: false };
  }
  const rawActive = data.activeSessions;
  if (typeof rawActive !== "object" || rawActive === null || Array.isArray(rawActive)) {
    return { valid: false, alreadyMarkedCorrupt: false };
  }
  const rawEntries = Object.entries(rawActive as Record<string, unknown>);
  if (rawEntries.length > LIVE_VIEW_ALLOCATOR_MAX_ENTRIES) {
    return { valid: false, alreadyMarkedCorrupt: false };
  }

  const result: Record<string, LiveViewUserStateActiveEntry> = Object.create(null);
  const seenPairs = new Set<string>();
  for (const [sessionId, rawEntry] of rawEntries) {
    if (!isValidLiveViewSessionIdFormat(sessionId)) {
      return { valid: false, alreadyMarkedCorrupt: false };
    }
    if (typeof rawEntry !== "object" || rawEntry === null) {
      return { valid: false, alreadyMarkedCorrupt: false };
    }
    const entry = rawEntry as Record<string, unknown>;
    if (
      entry.sessionId !== sessionId ||
      !isNonEmptyBoundedString(entry.homeDeviceId, MAX_DEVICE_ID_LENGTH) ||
      !isNonEmptyBoundedString(entry.cameraDeviceId, MAX_DEVICE_ID_LENGTH) ||
      !(entry.createdAt instanceof admin.firestore.Timestamp) ||
      !(entry.leaseExpiresAt instanceof admin.firestore.Timestamp)
    ) {
      return { valid: false, alreadyMarkedCorrupt: false };
    }
    // No duplicate active (homeDeviceId, cameraDeviceId) pair may exist under two different
    // session ids -- that would mean two "slots" are simultaneously claimed for the exact same
    // pair, violating idempotent START's own one-slot-per-pair invariant. JSON.stringify of the
    // tuple (never a delimiter-joined string) -- device IDs are otherwise-unrestricted strings and
    // may themselves contain any character, including whatever separator a joined string would
    // use, so e.g. homeDeviceId="a b"/cameraDeviceId="c" and homeDeviceId="a"/cameraDeviceId="b c"
    // must never collide onto the same key.
    const pairKey = JSON.stringify([entry.homeDeviceId, entry.cameraDeviceId]);
    if (seenPairs.has(pairKey)) {
      return { valid: false, alreadyMarkedCorrupt: false };
    }
    seenPairs.add(pairKey);

    result[sessionId] = {
      sessionId,
      homeDeviceId: entry.homeDeviceId,
      cameraDeviceId: entry.cameraDeviceId,
      createdAt: entry.createdAt,
      leaseExpiresAt: entry.leaseExpiresAt,
    };
  }
  return { valid: true, activeSessions: result };
}

// Lazy cleanup -- every start/renew/end reads the allocator, drops every entry whose own
// leaseExpiresAt <= now, and never counts a dropped entry toward the concurrent-session limit. No
// scheduled/background job exists or is required for correctness -- see docs/LIVE_VIEW_SESSIONS.md.
function pruneExpiredEntries(
  activeSessions: Record<string, LiveViewUserStateActiveEntry>,
  nowMillis: number
): Record<string, LiveViewUserStateActiveEntry> {
  const result: Record<string, LiveViewUserStateActiveEntry> = Object.create(null);
  for (const [sessionId, entry] of Object.entries(activeSessions)) {
    if (entry.leaseExpiresAt.toMillis() > nowMillis) {
      result[sessionId] = entry;
    }
  }
  return result;
}

// ---------------------------------------------------------------------------------------------
// Strict allocator-entry <-> canonical-session consistency check -- required for BOTH idempotent
// START (does the pair's cached allocator entry actually match a genuinely active session?) and
// RENEW (does the target session's own allocator entry actually match it?). Deliberately checks
// EVERY shared field, not just "does a session exist with this id and say ACTIVE" -- an allocator
// entry that merely happens to reference an existing, ACTIVE, unexpired session but disagrees on
// sessionId/homeDeviceId/cameraDeviceId/createdAt/leaseExpiresAt is exactly the kind of silent
// drift this function exists to catch and fail closed on, never silently trust.
// ---------------------------------------------------------------------------------------------
export function validateAllocatorEntryAgainstSession(
  entry: LiveViewUserStateActiveEntry,
  session: LiveViewSession,
  allocatorOwnerUid: string,
  nowMillis: number
): boolean {
  return (
    entry.sessionId === session.sessionId &&
    session.ownerUid === allocatorOwnerUid &&
    entry.homeDeviceId === session.homeDeviceId &&
    entry.cameraDeviceId === session.cameraDeviceId &&
    entry.createdAt.isEqual(session.createdAt) &&
    entry.leaseExpiresAt.isEqual(session.leaseExpiresAt) &&
    session.status === "ACTIVE" &&
    session.endedAt === null &&
    session.leaseExpiresAt.toMillis() > nowMillis
  );
}

// ---------------------------------------------------------------------------------------------
// Shared HOME device-proof challenge verification -- a thin, Live-View-specific adapter around
// deviceChallenges.ts's ONE shared, transaction-local verifyDeviceChallengeForConsumption
// primitive (expectedRole: "HOME", requireOwnerUidEqualsAuthUid: true -- HOME is always
// self-owned). There is no second, parallel signature/proof-verification implementation here --
// see deviceChallenges.ts's own doc for the full check sequence this delegates to. Still performs
// no writes itself (not even challenge.usedAt/deviceProofVersion) -- see
// maybeUpdateDeviceProofVersion below for the shared write helper each exec*LiveViewSession
// function calls only once its OWN additional checks have also passed.
type HomeChallengeVerification =
  | {
      verified: true;
      homeDeviceId: string;
      ownerUid: string;
      requestingDevice: RegisteredDevice;
      requestingDeviceRef: admin.firestore.DocumentReference;
      challengeRef: admin.firestore.DocumentReference;
      homeOperational: DeviceOperationalDecision;
    }
  | { verified: false; reason: LiveViewSessionDenialReason };

async function verifyHomeDeviceChallenge(
  t: admin.firestore.Transaction,
  db: admin.firestore.Firestore,
  params: {
    requestAuthUid: string;
    expectedPurpose: DeviceChallengePurpose;
    deviceProof: TurnCredentialsDeviceProof;
    canonicalRequestPayload: string;
    nowMillis: number;
  }
): Promise<HomeChallengeVerification> {
  const result: DeviceChallengeVerificationResult = await verifyDeviceChallengeForConsumption(t, db, {
    ...params,
    expectedRole: "HOME",
    requireOwnerUidEqualsAuthUid: true,
  });
  if (!result.verified) {
    return { verified: false, reason: result.reason };
  }
  return {
    verified: true,
    homeDeviceId: result.deviceId,
    ownerUid: params.requestAuthUid,
    requestingDevice: result.requestingDevice,
    requestingDeviceRef: result.requestingDeviceRef,
    challengeRef: result.challengeRef,
    // Operational status (suspended/revoked) is DELIBERATELY NOT enforced by the shared primitive
    // -- it is computed and returned instead, so START/RENEW (which allocate or extend access) can
    // enforce it while END (which must always be reachable once identity is proven, even for a
    // since-suspended/revoked Home -- see docs/LIVE_VIEW_SESSIONS.md's threat model) can
    // deliberately skip it.
    homeOperational: result.operational,
  };
}

// Shared write helper -- mirrors consumeVerifiedTurnCredentialsChallenge's own deviceProofVersion
// update EXACTLY (same condition: never lowered if a higher version is already stored; same
// merged fields: deviceProofVersion/updatedAt/lastSeenAt only, never role/authUid/ownerUid/status/
// publicKey/identityMode) -- called by each exec*LiveViewSession function only once, alongside
// consuming the challenge, i.e. only on that operation's own full success (never merely because
// the signature verified) -- exactly matching the TURN proof flow's own timing.
function maybeUpdateDeviceProofVersion(
  t: admin.firestore.Transaction,
  requestingDeviceRef: admin.firestore.DocumentReference,
  requestingDevice: RegisteredDevice,
  now: admin.firestore.FieldValue
): void {
  const currentDeviceProofVersion = requestingDevice.deviceProofVersion;
  if (!currentDeviceProofVersion || currentDeviceProofVersion < DEVICE_PROOF_VERSION) {
    t.set(requestingDeviceRef, { deviceProofVersion: DEVICE_PROOF_VERSION, updatedAt: now, lastSeenAt: now }, { merge: true });
  }
}

// The ONLY place this module ever writes `integrityStatus: "CORRUPT"` -- called exclusively by
// executeEndLiveViewSession when it discovers a corrupt allocator while ending an already fully
// identity/ownership-verified session. CRITICAL: this merge deliberately NEVER includes
// `activeSessions` -- whatever that field currently holds (however malformed) is left completely
// untouched, so any OTHER canonically-ACTIVE session's allocator entry that happens to be mixed in
// with the corruption is never silently erased. If the document was already marked CORRUPT, this
// is a genuine no-op (no write at all) -- corruptAt/corruptionReason must keep reflecting the
// ORIGINAL discovery, and a repeat END must not touch the document a second time. See
// docs/LIVE_VIEW_SESSIONS.md's "Corrupt allocator handling" section.
function maybeMarkAllocatorCorrupt(
  t: admin.firestore.Transaction,
  allocatorRef: admin.firestore.DocumentReference,
  allocatorParse: AllocatorParseResult,
  now: admin.firestore.FieldValue
): void {
  if (allocatorParse.valid || allocatorParse.alreadyMarkedCorrupt) {
    return;
  }
  t.set(
    allocatorRef,
    {
      schemaVersion: LIVE_VIEW_USER_STATE_SCHEMA_VERSION,
      integrityStatus: "CORRUPT",
      corruptAt: now,
      corruptionReason: "PARSE_FAILED",
      updatedAt: now,
      // activeSessions deliberately omitted -- see this function's own doc above.
    },
    { merge: true }
  );
}

// Shared Camera-side checks for START/RENEW: the target Camera must exist, be role CAMERA, be
// operational, be owned (cameraClaims.uid) by this exact ownerUid, and be linked (the existing
// users/{uid}/cameraDevices/{cameraDeviceId}.homeDeviceId record claimCameraForUser itself writes)
// to this exact verified Home -- never a second, divergent copy of
// consumeVerifiedTurnCredentialsChallenge's own equivalent checks, just re-expressed against
// already-read-in-this-transaction snapshots instead of performing its own reads.
type CameraBindingCheck = { ok: true } | { ok: false; reason: LiveViewSessionDenialReason };

function checkCameraBinding(params: {
  cameraSnap: FirebaseFirestore.DocumentSnapshot;
  claimSnap: FirebaseFirestore.DocumentSnapshot;
  linkSnap: FirebaseFirestore.DocumentSnapshot;
  ownerUid: string;
  homeDeviceId: string;
}): CameraBindingCheck {
  const { cameraSnap, claimSnap, linkSnap, ownerUid, homeDeviceId } = params;

  // Ownership/link (identity) is confirmed BEFORE operational status is ever revealed -- mirrors
  // claimCameraForUser's own ownership/role audit fix: DEVICE_SUSPENDED/DEVICE_REVOKED map to a
  // distinguishable public error (unlike almost everything else here), so revealing that reason
  // for a camera the caller does NOT own/it is not linked to would let a non-owner probe an
  // arbitrary cameraDeviceId and learn its status. Existence/role alone is checked first only
  // because it is required to even read a role field -- but "not registered" and "wrong role"
  // still both collapse to the SAME generic denial as ownership/link failures (see
  // mapLiveViewSessionDenialToHttpsError's default case), so this ordering leaks nothing extra.
  const cameraDevice = cameraSnap.exists ? (cameraSnap.data() as RegisteredDevice) : null;
  if (!cameraDevice || cameraDevice.role !== "CAMERA") {
    return { ok: false, reason: "CAMERA_NOT_REGISTERED" };
  }

  const claimOwnerUid = claimSnap.exists ? (claimSnap.get("uid") as string | undefined) : undefined;
  if (!claimSnap.exists || claimOwnerUid !== ownerUid) {
    return { ok: false, reason: "CAMERA_NOT_OWNED_BY_CALLER" };
  }

  const linkedHomeDeviceId = linkSnap.exists ? (linkSnap.get("homeDeviceId") as string | undefined) : undefined;
  if (!linkedHomeDeviceId || linkedHomeDeviceId !== homeDeviceId) {
    return { ok: false, reason: "CAMERA_NOT_LINKED_TO_HOME" };
  }

  // Only reached for a Camera already confirmed to be owned by this caller and linked to their
  // own verified Home -- safe to reveal its own suspended/revoked status now.
  const cameraOperational = checkRegisteredDeviceOperational(cameraDevice);
  if (!cameraOperational.operational) {
    return { ok: false, reason: cameraOperational.reason };
  }

  return { ok: true };
}

// ---------------------------------------------------------------------------------------------
// runLiveViewTransaction -- a thin wrapper around db.runTransaction that retries exactly ONE,
// precisely-identified, evidence-confirmed condition the Admin SDK's own retry logic fails to
// recognize when talking to the Firestore emulator specifically. See
// docs/LIVE_VIEW_SESSIONS.md's "Concurrency: emulator transaction-retry gap" section for the full
// root-cause writeup; summary:
//
// @google-cloud/firestore's transaction.js (isRetryableTransactionError) already retries a
// transaction whose ID the backend reports as invalidated by contention -- but only when the
// error is gRPC code 3 (INVALID_ARGUMENT) AND its message matches /transaction has expired/,
// which is production Firestore's exact wording for this condition. The local Firestore emulator
// reports the SAME legitimate, expected condition (this transaction's ID was invalidated by a
// competing transaction's commit, under genuine write contention on a shared document -- e.g. the
// allocator document two racing operations both touch) with DIFFERENT wording -- "Transaction is
// invalid or closed" -- which that regex does not match. The SDK's own retry loop therefore
// treats it as non-retryable and gives up after exactly one attempt (confirmed via temporary
// instrumentation: every observed occurrence was attempt=1, ~9-9.6s elapsed, never attempt 2+).
// Increasing `maxAttempts` has no effect on this: the SDK's loop calls `break` on a non-retryable
// error before `maxAttempts` is ever consulted again.
//
// EMULATOR-ONLY: production Firestore already uses the SDK-recognized "transaction has expired"
// wording and needs no help from this wrapper -- it is not part of production Live View
// transaction semantics. Gated on the standard Firestore Admin SDK environment variable
// (`FIRESTORE_EMULATOR_HOST`, the same variable the SDK itself reads to decide whether it is
// talking to the emulator) -- never a custom flag. When that variable is unset, this function is
// a pure passthrough to `db.runTransaction` (no try/catch, no wrapping at all), so production
// error propagation is byte-for-byte unchanged. When set, it retries ONLY this one exact
// code+message combination -- never any other error, and never "any rejection" -- for a small,
// bounded number of additional attempts. Each retry re-invokes db.runTransaction from scratch: the
// callback re-verifies the challenge/signature/device identity, re-reads current ownership/
// binding/entitlement/allocator/session state, and re-decides atomically, exactly as a normal
// ABORTED-triggered retry would. No invariant is weakened -- nothing is cached, skipped, or reused
// across a retry; this only changes whether a second, fully-independent attempt is made at all.
export const EMULATOR_TRANSACTION_INVALID_MESSAGE = /transaction is invalid or closed/i;
export const MAX_EMULATOR_TRANSACTION_RETRY_ATTEMPTS = 3;

export function isEmulatorTransactionInvalidError(err: unknown): boolean {
  const e = err as { code?: unknown; message?: unknown } | null | undefined;
  return e?.code === 3 && typeof e.message === "string" && EMULATOR_TRANSACTION_INVALID_MESSAGE.test(e.message);
}

export async function runLiveViewTransaction<T>(
  db: admin.firestore.Firestore,
  updateFunction: (t: admin.firestore.Transaction) => Promise<T>
): Promise<T> {
  if (!process.env.FIRESTORE_EMULATOR_HOST) {
    // Production (or any environment not talking to the emulator): no outer wrapping at all --
    // Firestore's own native transaction retry behavior (maxAttempts, backoff, etc.) is completely
    // unchanged, and every error propagates exactly as db.runTransaction itself would produce it.
    return db.runTransaction(updateFunction);
  }
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await db.runTransaction(updateFunction);
    } catch (err) {
      if (attempt >= MAX_EMULATOR_TRANSACTION_RETRY_ATTEMPTS || !isEmulatorTransactionInvalidError(err)) {
        throw err;
      }
    }
  }
}

// ---------------------------------------------------------------------------------------------
// START
// ---------------------------------------------------------------------------------------------
// candidateSessionId MUST be generated by the caller (index.ts) BEFORE calling this function, via
// db.collection("liveViewSessions").doc().id -- never inside the transaction callback below.
// Firestore retries this callback verbatim on contention; a fresh random id generated on each
// retry would silently allocate a different session id per attempt, breaking the "one sessionId
// per successful start" guarantee this whole design (and its own idempotency) depends on.
export async function executeStartLiveViewSession(
  db: admin.firestore.Firestore,
  params: {
    requestAuthUid: string;
    cameraDeviceId: string;
    deviceProof: TurnCredentialsDeviceProof;
    candidateSessionId: string;
    nowMillis: number;
  }
): Promise<StartLiveViewSessionOutcome> {
  const { requestAuthUid, cameraDeviceId, deviceProof, candidateSessionId, nowMillis } = params;
  const canonicalRequestPayload = buildCanonicalLiveViewStartRequestPayload({ cameraDeviceId });

  return runLiveViewTransaction(db, async (t): Promise<StartLiveViewSessionOutcome> => {
    const verification = await verifyHomeDeviceChallenge(t, db, {
      requestAuthUid,
      expectedPurpose: DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_START,
      deviceProof,
      canonicalRequestPayload,
      nowMillis,
    });
    if (!verification.verified) {
      return { outcome: "denied", reason: verification.reason };
    }
    const { homeDeviceId, ownerUid, requestingDevice, requestingDeviceRef, challengeRef, homeOperational } = verification;
    if (!homeOperational.operational) {
      return { outcome: "denied", reason: homeOperational.reason };
    }

    const cameraRegistryRef = db.collection("registeredDevices").doc(cameraDeviceId);
    const claimRef = db.collection("cameraClaims").doc(cameraDeviceId);
    const homeCameraLinkRef = db.collection("users").doc(ownerUid).collection("cameraDevices").doc(cameraDeviceId);
    const entitlementsRef = db.collection("userEntitlements").doc(ownerUid);
    const allocatorRef = db.collection(LIVE_VIEW_USER_STATES_COLLECTION).doc(ownerUid);

    const [cameraSnap, claimSnap, linkSnap, entitlementsSnap, allocatorSnap] = await Promise.all([
      t.get(cameraRegistryRef),
      t.get(claimRef),
      t.get(homeCameraLinkRef),
      t.get(entitlementsRef),
      t.get(allocatorRef),
    ]);

    const bindingCheck = checkCameraBinding({ cameraSnap, claimSnap, linkSnap, ownerUid, homeDeviceId });
    if (!bindingCheck.ok) {
      return { outcome: "denied", reason: bindingCheck.reason };
    }

    // Canonical, single source of truth for the limit -- reused as-is, never a second copy of the
    // resolution rules (missing/malformed document -> Free, legacy fields never consulted).
    const effectiveEntitlements = effectiveUserEntitlementsFromData(
      entitlementsSnap.exists ? entitlementsSnap.data() : undefined
    );
    const maxConcurrentLiveSessions = effectiveEntitlements.maxConcurrentLiveSessions;

    const allocatorParse = parseAllocatorState(allocatorSnap.exists ? allocatorSnap.data() : undefined);
    if (!allocatorParse.valid) {
      return { outcome: "denied", reason: "ALLOCATOR_STATE_INVALID" };
    }
    const prunedActive = pruneExpiredEntries(allocatorParse.activeSessions, nowMillis);

    // Idempotent START: an already-active entry for this EXACT (homeDeviceId, cameraDeviceId)
    // pair never takes a second slot -- re-verified field-for-field against the canonical session
    // document itself via validateAllocatorEntryAgainstSession (never just "does a document exist
    // with status ACTIVE and an unexpired lease" -- see that function's own doc), fail-closed on
    // any discrepancy.
    const existingEntry = Object.values(prunedActive).find(
      (entry) => entry.homeDeviceId === homeDeviceId && entry.cameraDeviceId === cameraDeviceId
    );

    const now = admin.firestore.FieldValue.serverTimestamp();

    if (existingEntry) {
      const existingSessionRef = db.collection(LIVE_VIEW_SESSIONS_COLLECTION).doc(existingEntry.sessionId);
      const existingSessionSnap = await t.get(existingSessionRef);
      const sessionParse = parseLiveViewSession(
        existingEntry.sessionId,
        existingSessionSnap.exists ? existingSessionSnap.data() : undefined
      );
      const consistent =
        sessionParse.valid && validateAllocatorEntryAgainstSession(existingEntry, sessionParse.session, ownerUid, nowMillis);

      if (!consistent) {
        return { outcome: "denied", reason: "ALLOCATOR_SESSION_MISMATCH" };
      }

      t.set(allocatorRef, {
        schemaVersion: LIVE_VIEW_USER_STATE_SCHEMA_VERSION,
        updatedAt: now,
        integrityStatus: "HEALTHY",
        corruptAt: null,
        corruptionReason: null,
        activeSessions: prunedActive,
      });
      t.update(challengeRef, { usedAt: now, usedByFunction: "startLiveViewSession" });
      maybeUpdateDeviceProofVersion(t, requestingDeviceRef, requestingDevice, now);

      return {
        outcome: "started",
        sessionId: existingEntry.sessionId,
        leaseExpiresAtMillis: sessionParse.session.leaseExpiresAt.toMillis(),
      };
    }

    // The effective ceiling for allocating a NEW slot is never just maxConcurrentLiveSessions --
    // it is also capped by LIVE_VIEW_ALLOCATOR_MAX_ENTRIES, the allocator's own hard, defensive
    // ceiling (see that constant's own doc). Without this, an entitlement above 32 combined with
    // an allocator already at exactly 32 entries would let this write add a 33rd, producing a
    // document parseAllocatorState itself would then reject as corrupt on the very next read --
    // self-inflicted corruption, not a second counter: this reuses the SAME prunedActive count
    // already computed above, just compared against a tighter of the two limits.
    const currentActiveCount = Object.keys(prunedActive).length;
    const effectiveMaxActiveSessions = Math.min(maxConcurrentLiveSessions, LIVE_VIEW_ALLOCATOR_MAX_ENTRIES);
    if (currentActiveCount >= effectiveMaxActiveSessions) {
      return { outcome: "denied", reason: "LIVE_VIEW_LIMIT_REACHED" };
    }

    const leaseExpiresAtMillis = nowMillis + LIVE_VIEW_LEASE_TTL_MS;
    const leaseExpiresAt = admin.firestore.Timestamp.fromMillis(leaseExpiresAtMillis);
    const newSessionRef = db.collection(LIVE_VIEW_SESSIONS_COLLECTION).doc(candidateSessionId);

    // createdAt is deterministic (Timestamp.fromMillis(nowMillis)), NOT FieldValue.serverTimestamp()
    // -- it must be byte-identical between this session document and its own allocator entry (see
    // validateAllocatorEntryAgainstSession, which compares them field-for-field) -- a server-
    // resolved sentinel would resolve to two microscopically different instants for the two writes
    // even though both happen in the same transaction/commit, permanently breaking that equality
    // check for every session ever created. `updatedAt` has no such cross-document equality
    // requirement and stays a normal server timestamp.
    const createdAt = admin.firestore.Timestamp.fromMillis(nowMillis);

    t.set(newSessionRef, {
      schemaVersion: LIVE_VIEW_SESSION_SCHEMA_VERSION,
      sessionId: candidateSessionId,
      ownerUid,
      homeDeviceId,
      cameraDeviceId,
      status: "ACTIVE",
      createdAt,
      updatedAt: now,
      leaseExpiresAt,
      endedAt: null,
    });

    t.set(allocatorRef, {
      schemaVersion: LIVE_VIEW_USER_STATE_SCHEMA_VERSION,
      updatedAt: now,
      integrityStatus: "HEALTHY",
      corruptAt: null,
      corruptionReason: null,
      activeSessions: {
        ...prunedActive,
        [candidateSessionId]: {
          sessionId: candidateSessionId,
          homeDeviceId,
          cameraDeviceId,
          createdAt,
          leaseExpiresAt,
        },
      },
    });

    t.update(challengeRef, { usedAt: now, usedByFunction: "startLiveViewSession" });
    maybeUpdateDeviceProofVersion(t, requestingDeviceRef, requestingDevice, now);

    return { outcome: "started", sessionId: candidateSessionId, leaseExpiresAtMillis };
  });
}

// ---------------------------------------------------------------------------------------------
// RENEW
// ---------------------------------------------------------------------------------------------
export async function executeRenewLiveViewSession(
  db: admin.firestore.Firestore,
  params: {
    requestAuthUid: string;
    sessionId: string;
    deviceProof: TurnCredentialsDeviceProof;
    nowMillis: number;
  }
): Promise<RenewLiveViewSessionOutcome> {
  const { requestAuthUid, sessionId, deviceProof, nowMillis } = params;
  const canonicalRequestPayload = buildCanonicalLiveViewSessionIdRequestPayload(DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_RENEW, {
    sessionId,
  });

  return runLiveViewTransaction(db, async (t): Promise<RenewLiveViewSessionOutcome> => {
    const verification = await verifyHomeDeviceChallenge(t, db, {
      requestAuthUid,
      expectedPurpose: DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_RENEW,
      deviceProof,
      canonicalRequestPayload,
      nowMillis,
    });
    if (!verification.verified) {
      return { outcome: "denied", reason: verification.reason };
    }
    const { homeDeviceId, ownerUid, requestingDevice, requestingDeviceRef, challengeRef, homeOperational } = verification;
    if (!homeOperational.operational) {
      return { outcome: "denied", reason: homeOperational.reason };
    }

    const sessionRef = db.collection(LIVE_VIEW_SESSIONS_COLLECTION).doc(sessionId);
    const allocatorRef = db.collection(LIVE_VIEW_USER_STATES_COLLECTION).doc(ownerUid);
    const entitlementsRef = db.collection("userEntitlements").doc(ownerUid);
    const [sessionSnap, allocatorSnap, entitlementsSnap] = await Promise.all([
      t.get(sessionRef),
      t.get(allocatorRef),
      t.get(entitlementsRef),
    ]);

    const sessionParse = parseLiveViewSession(sessionId, sessionSnap.exists ? sessionSnap.data() : undefined);
    if (!sessionParse.valid) {
      return { outcome: "denied", reason: sessionSnap.exists ? "SESSION_MALFORMED" : "SESSION_NOT_FOUND" };
    }
    const session = sessionParse.session;
    if (session.ownerUid !== ownerUid) {
      return { outcome: "denied", reason: "SESSION_OWNER_MISMATCH" };
    }
    if (session.homeDeviceId !== homeDeviceId) {
      return { outcome: "denied", reason: "SESSION_HOME_MISMATCH" };
    }
    if (session.status !== "ACTIVE") {
      return { outcome: "denied", reason: "SESSION_NOT_ACTIVE" };
    }
    if (session.leaseExpiresAt.toMillis() <= nowMillis) {
      return { outcome: "denied", reason: "SESSION_LEASE_EXPIRED" };
    }
    const cameraDeviceId = session.cameraDeviceId;

    const cameraRegistryRef = db.collection("registeredDevices").doc(cameraDeviceId);
    const claimRef = db.collection("cameraClaims").doc(cameraDeviceId);
    const homeCameraLinkRef = db.collection("users").doc(ownerUid).collection("cameraDevices").doc(cameraDeviceId);
    const [cameraSnap, claimSnap, linkSnap] = await Promise.all([
      t.get(cameraRegistryRef),
      t.get(claimRef),
      t.get(homeCameraLinkRef),
    ]);

    const bindingCheck = checkCameraBinding({ cameraSnap, claimSnap, linkSnap, ownerUid, homeDeviceId });
    if (!bindingCheck.ok) {
      return { outcome: "denied", reason: bindingCheck.reason };
    }

    const allocatorParse = parseAllocatorState(allocatorSnap.exists ? allocatorSnap.data() : undefined);
    if (!allocatorParse.valid) {
      return { outcome: "denied", reason: "ALLOCATOR_STATE_INVALID" };
    }
    const prunedActive = pruneExpiredEntries(allocatorParse.activeSessions, nowMillis);
    const allocatorEntry = prunedActive[sessionId];
    if (!allocatorEntry) {
      return { outcome: "denied", reason: "SESSION_NOT_IN_ALLOCATOR" };
    }
    if (!validateAllocatorEntryAgainstSession(allocatorEntry, session, ownerUid, nowMillis)) {
      return { outcome: "denied", reason: "ALLOCATOR_SESSION_MISMATCH" };
    }

    // Canonical entitlement re-check -- see docs/LIVE_VIEW_SESSIONS.md's "RENEW entitlement
    // behavior" section. Resolved via the SAME canonical resolver every other consumer in this
    // project uses (missing/malformed -> Free, legacy fields never consulted, blocked -> zeroed
    // rights). RENEW is denied whenever the account's CURRENT limit can no longer accommodate the
    // number of sessions presently occupying a slot (this one included) -- deliberately not
    // limited to "this one specific session's own rank"; a downgrade that leaves the account over
    // its new limit blocks renewal of ALL of that account's sessions equally until enough expire/
    // end on their own to bring the count back within the new limit. maxConcurrentLiveSessions ===
    // 0 is simply the special case where any positive active count is already over the limit.
    const effectiveEntitlements = effectiveUserEntitlementsFromData(
      entitlementsSnap.exists ? entitlementsSnap.data() : undefined
    );
    if (Object.keys(prunedActive).length > effectiveEntitlements.maxConcurrentLiveSessions) {
      return { outcome: "denied", reason: "LIVE_VIEW_ENTITLEMENT_DENIED" };
    }

    // Always resets from now() -- never oldLeaseExpiresAt + TTL -- so a chain of renews can never
    // accumulate into an unbounded lease.
    const newLeaseExpiresAtMillis = nowMillis + LIVE_VIEW_LEASE_TTL_MS;
    const newLeaseExpiresAt = admin.firestore.Timestamp.fromMillis(newLeaseExpiresAtMillis);
    const now = admin.firestore.FieldValue.serverTimestamp();

    t.update(sessionRef, { leaseExpiresAt: newLeaseExpiresAt, updatedAt: now });
    t.set(allocatorRef, {
      schemaVersion: LIVE_VIEW_USER_STATE_SCHEMA_VERSION,
      updatedAt: now,
      integrityStatus: "HEALTHY",
      corruptAt: null,
      corruptionReason: null,
      activeSessions: {
        ...prunedActive,
        [sessionId]: { ...allocatorEntry, leaseExpiresAt: newLeaseExpiresAt },
      },
    });
    t.update(challengeRef, { usedAt: now, usedByFunction: "renewLiveViewSession" });
    maybeUpdateDeviceProofVersion(t, requestingDeviceRef, requestingDevice, now);

    return { outcome: "renewed", sessionId, leaseExpiresAtMillis: newLeaseExpiresAtMillis };
  });
}

// ---------------------------------------------------------------------------------------------
// END
// ---------------------------------------------------------------------------------------------
// Idempotent: a repeat END of an already-ENDED session (same owner/Home) is a safe success, not an
// error -- the user must always be able to confirm/re-confirm a session is over. Reachable even if
// the Home/Camera has since become suspended/revoked, or the plan was downgraded -- END never
// re-checks Home/Camera operational status or entitlements, only identity/ownership (who is ending
// which session) -- see docs/LIVE_VIEW_SESSIONS.md's threat model for why this is intentional, not
// an oversight: closing your own already-authorized session can never itself be the abuse this
// module exists to prevent.
//
// Every successful END -- including a repeated, idempotent one -- attempts a FULL allocator
// cleanup, not just a surgical removal of the target sessionId: when the allocator parses cleanly,
// it prunes every expired entry (regardless of which session they belong to), removes the target
// sessionId if still present, and writes the complete cleaned map back with a fresh updatedAt.
//
// If the allocator does NOT parse (or is already known not to), END does NOT repair it by
// resetting activeSessions -- see maybeMarkAllocatorCorrupt's own doc for why that would be unsafe
// (it could silently erase OTHER canonically-ACTIVE sessions from allocator-based counting while
// leaving them ACTIVE, enabling a maxConcurrentLiveSessions bypass on a later START). Instead, END
// marks the allocator explicitly CORRUPT (once, on first discovery -- a document already marked
// CORRUPT is left byte-for-byte untouched on every subsequent END) and leaves activeSessions
// completely alone. START/RENEW continue to fail-closed-deny for as long as the allocator remains
// CORRUPT; recovering from CORRUPT requires a separate, safe, bounded reconstruction (out of scope
// for this stage -- see docs/LIVE_VIEW_SESSIONS.md's "Corrupt allocator handling" section). The
// target session is still marked ENDED regardless of allocator health -- END's identity/ownership
// verification never depended on the allocator being readable in the first place.
export async function executeEndLiveViewSession(
  db: admin.firestore.Firestore,
  params: {
    requestAuthUid: string;
    sessionId: string;
    deviceProof: TurnCredentialsDeviceProof;
    nowMillis: number;
  }
): Promise<EndLiveViewSessionOutcome> {
  const { requestAuthUid, sessionId, deviceProof, nowMillis } = params;
  const canonicalRequestPayload = buildCanonicalLiveViewSessionIdRequestPayload(DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_END, {
    sessionId,
  });

  return runLiveViewTransaction(db, async (t): Promise<EndLiveViewSessionOutcome> => {
    const verification = await verifyHomeDeviceChallenge(t, db, {
      requestAuthUid,
      expectedPurpose: DEVICE_CHALLENGE_PURPOSES.LIVE_VIEW_END,
      deviceProof,
      canonicalRequestPayload,
      nowMillis,
    });
    if (!verification.verified) {
      return { outcome: "denied", reason: verification.reason };
    }
    const { homeDeviceId, ownerUid, requestingDevice, requestingDeviceRef, challengeRef } = verification;

    const sessionRef = db.collection(LIVE_VIEW_SESSIONS_COLLECTION).doc(sessionId);
    const allocatorRef = db.collection(LIVE_VIEW_USER_STATES_COLLECTION).doc(ownerUid);
    const [sessionSnap, allocatorSnap] = await Promise.all([
      t.get(sessionRef),
      t.get(allocatorRef),
    ]);

    const sessionParse = parseLiveViewSession(sessionId, sessionSnap.exists ? sessionSnap.data() : undefined);
    if (!sessionParse.valid) {
      return { outcome: "denied", reason: sessionSnap.exists ? "SESSION_MALFORMED" : "SESSION_NOT_FOUND" };
    }
    const session = sessionParse.session;
    if (session.ownerUid !== ownerUid) {
      return { outcome: "denied", reason: "SESSION_OWNER_MISMATCH" };
    }
    if (session.homeDeviceId !== homeDeviceId) {
      return { outcome: "denied", reason: "SESSION_HOME_MISMATCH" };
    }

    const now = admin.firestore.FieldValue.serverTimestamp();

    // Allocator cleanup -- always attempted, on every successful END, including a repeat one, but
    // NEVER by resetting a corrupt document's activeSessions to {}. See maybeMarkAllocatorCorrupt's
    // own doc and docs/LIVE_VIEW_SESSIONS.md's "Corrupt allocator handling" section for why: a
    // corrupt activeSessions map can still contain entries for OTHER, canonically-ACTIVE sessions
    // that simply couldn't be safely parsed as a whole (one bad entry fails the entire map, not
    // just itself) -- blindly overwriting it with {} would make those sessions silently vanish from
    // allocator-based counting while remaining ACTIVE, enabling a maxConcurrentLiveSessions bypass
    // on a subsequent START. If the allocator is (or becomes known to be) corrupt, this transaction
    // marks it CORRUPT (first discovery only -- see maybeMarkAllocatorCorrupt) and does NOT touch
    // activeSessions at all; START/RENEW continue to deny while CORRUPT (see parseAllocatorState),
    // and only a safe, explicit, bounded reconstruction (out of scope for this stage -- see the doc)
    // may ever clear it. The target session is still marked ENDED below regardless -- END's own
    // identity/ownership verification never depended on the allocator being readable.
    const allocatorParse = parseAllocatorState(allocatorSnap.exists ? allocatorSnap.data() : undefined);
    if (allocatorParse.valid) {
      const prunedActive = pruneExpiredEntries(allocatorParse.activeSessions, nowMillis);
      delete prunedActive[sessionId];
      t.set(allocatorRef, {
        schemaVersion: LIVE_VIEW_USER_STATE_SCHEMA_VERSION,
        updatedAt: now,
        integrityStatus: "HEALTHY",
        corruptAt: null,
        corruptionReason: null,
        activeSessions: prunedActive,
      });
    } else {
      maybeMarkAllocatorCorrupt(t, allocatorRef, allocatorParse, now);
    }
    t.update(challengeRef, { usedAt: now, usedByFunction: "endLiveViewSession" });
    maybeUpdateDeviceProofVersion(t, requestingDeviceRef, requestingDevice, now);

    if (session.status === "ENDED") {
      return { outcome: "ended", sessionId };
    }

    t.update(sessionRef, { status: "ENDED", endedAt: now, updatedAt: now });

    return { outcome: "ended", sessionId };
  });
}
