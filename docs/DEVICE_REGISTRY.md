# Device Registry — Stage 1 + Android Keystore identity (stage 2) + status enforcement (stage 3)

A single global, Admin-SDK-only Firestore collection that records every known Camera/Home
installation ("device"), independently of `cameraClaims`/`pairingState`. Implemented in
`functions/src/deviceRegistry.ts`.

**Stage 1** only creates and maintains the registry with `identityMode: "legacy"`. **Stage 2** lets
a device upgrade itself from `"legacy"` to `"keystore"` by registering a real Android
Keystore-backed public key, via the `registerDevicePublicKey` callable. **Stage 3** (this addition)
makes `status` a real, enforced, three-way state (`active`/`suspended`/`revoked`) — explicit
owner-triggered revocation (`revokeRegisteredDevice`), automatic plan-based suspension
(`reconcileUserDeviceLimits`, triggered by `reconcileDevicesOnEntitlementChange`), and centralized
operational enforcement (`checkRegisteredDeviceOperational`) wired into every server operation
that requires a working device. None of the three stages:

- **verify a signature over any request** (registering a key is not the same as proving
  possession of it on every subsequent call — see "What is enforced today, and what isn't" below);
- replace `cameraClaims` (still the ownership source of truth);
- replace `pairingState` (still the pairing-lifecycle source of truth);
- cryptographically verify *which* Home installation is calling — see "Camera vs. Home status
  enforcement" below, a real, currently-open gap.

Existing pairing, unpair, notifications, TURN, and Live View *behavior* (the WebRTC/signaling
mechanics themselves) is unchanged; this stage only adds a new way for an operation to be denied
before it would otherwise have proceeded. See [`docs/USER_ENTITLEMENTS.md`](USER_ENTITLEMENTS.md)
for the separate plan/limits model this stage's plan-based suspension reads from (via
`getPlanDeviceLimits`/`planDeviceLimitsFromEntitlementsData`), never from
`getEffectiveUserEntitlements` directly — see "Plan-based suspension" below for why.

## Firestore document

Path:

```
registeredDevices/{deviceId}
```

`{deviceId}` is the installation's own self-generated id — a Camera's `cameraDeviceId` or a Home's
`homeDeviceId`, exactly as those already exist today. This module does not change how either id is
generated, stored, or formatted on the client.

The collection is **function-only**: `firestore.rules` denies all client read and write access
(`allow read: if false; allow create, update, delete: if false;`), mirroring `userEntitlements`
exactly. Only server code (Admin SDK) may read or write it.

### Fields

| Field | Type | Meaning |
|---|---|---|
| `schemaVersion` | number | Always `1` today. |
| `deviceId` | string | Same value as the document id. |
| `role` | `"HOME" \| "CAMERA"` | Which kind of installation this is. Immutable once set — a device can never change role. |
| `authUid` | string | The Firebase Auth UID of *this specific installation*. For Camera, this is `cameraAuthUid` (the anonymous auth identity created by `createCameraPairingSession`); for Home, it's whichever Firebase Auth UID (anonymous or Google-linked) was active when the device was first registered. Immutable once set — see "Identity is never overwritten" below. |
| `ownerUid` | string \| null | For `HOME`: always equal to `authUid` (a Home device is self-owned). For `CAMERA`: `null` before pairing, the linked Home owner's uid after a successful claim, `null` again after a normal unpair. |
| `status` | `"active" \| "suspended" \| "revoked"` | Administrative trust state — see "status vs. pairing status" below. |
| `suspensionReason` | `"plan" \| "manual" \| "security" \| null` | *Why* the device is suspended — only meaningful while `status == "suspended"`. `null` for a device with `status != "suspended"`. `"plan"` is the only value any server code sets automatically today (`reconcileUserDeviceLimits`, see "Plan-based suspension" below); `"manual"`/`"security"` exist in the schema for a human operator to set directly (e.g. via the Firebase console/Admin SDK, not through any callable in this project) and are never touched, set, or interpreted by anything in this file except to guarantee they are never auto-reactivated. |
| `identityMode` | `"legacy" \| "keystore"` | Every device is created `"legacy"` (see "Legacy has no cryptographic proof" below). Flips to `"keystore"` exactly once, atomically with `publicKey`, via `registerDevicePublicKey` — see "Android Keystore identity" below. Never flips back. |
| `publicKey` | string \| null | `null` until the device registers a real key. From then on, the canonical Base64 (standard alphabet, no wrapping) encoding of the device's X.509 SubjectPublicKeyInfo (SPKI) DER bytes — the full public key, not a fingerprint (see "Key format" below). Never replaced, cleared, or downgraded back to `null` once set. |
| `createdAt` | Timestamp | Set once, at first creation. Never changes after. |
| `updatedAt` | Timestamp | Bumped on every meaningful change (including a lazy-migration touch). |
| `lastSeenAt` | Timestamp | Bumped whenever the device is confirmed active through an authenticated server call. |
| `revokedAt` | Timestamp \| null | Set once, only by `revokeRegisteredDevice` (see "Explicit revoke" below), and never changed again — a repeat revoke is idempotent and leaves the original value untouched. `null` for every device that has never been revoked. |

## `status` vs. pairing status

`registeredDevices.status` answers a different question than `pairingState/current.status`
("waiting"/"paired"/"unpaired"):

- `pairingState` (unchanged by this stage) describes **whether this specific Camera is currently
  paired, and to which Home** — a pairing-lifecycle fact, scoped to Cameras only.
- `registeredDevices.status` describes **whether this device's identity is still trusted at all**
  — applicable to both roles, and orthogonal to pairing. A Camera can be `status: "active"` while
  unpaired (`ownerUid: null`), and a Home device (which has no `pairingState` of its own) still has
  a `registeredDevices.status`.

The two are deliberately kept separate and are not cross-referenced by this stage.

## `unpair` ≠ `suspend` ≠ `revoke`

Three genuinely different operations, easy to conflate, kept strictly separate:

- **Unpair** (`releaseCameraForUser`/`unpairCameraFromDevice`/`releaseCameraFromCamera`, all via
  `detachCameraOwner()`) is an everyday, expected action (the user removing a camera, or a camera
  being re-purposed) — it says nothing about whether the physical device or its credentials should
  ever be trusted again. For an `active` or `suspended` device it only ever clears `ownerUid` back
  to `null` and bumps `updatedAt`/`lastSeenAt`. `status`, `suspensionReason`, `identityMode`,
  `publicKey`, and `revokedAt` are never touched — an unpaired device stays exactly as trusted (or
  untrusted) as it was the moment before.

  **`revoked` cleanup ≠ registry detach.** For a `revoked` device, `detachCameraOwner()` is a
  complete no-op on `registeredDevices` — `ownerUid` (and every other field, including
  `updatedAt`/`lastSeenAt`) is left untouched. The *pairing* artifacts (`cameraClaims`,
  `pairingState`, the owner's `cameraDevices` entry) are still deleted/updated normally by the
  caller before `detachCameraOwner()` even runs — Home must still be able to remove a revoked
  camera from its device list — but that is cleaning up pairing state, not the registry's own
  audit trail. Revoked is a terminal security state: clearing `ownerUid` here would permanently
  erase the record of who owned/reported the device, exactly the fact `revokeRegisteredDevice`
  exists to preserve. See "Explicit revoke" below.
- **Suspend** (`reconcileUserDeviceLimits`, always with `suspensionReason: "plan"` when set
  automatically) is a *reversible*, plan-driven state: the owner currently has more devices of one
  role than their plan allows, so the newest excess devices are suspended until the limit rises
  again (or the owner removes/revokes enough others). `ownerUid` is never touched — a suspended
  device still belongs to its owner, it just can't perform operational actions right now (see
  "Centralized operational enforcement" below).
- **Revoke** (`revokeRegisteredDevice`) is the *irreversible* one: "this specific credential must
  never be trusted again, even if presented for a brand-new pairing." Explicit and owner-triggered
  only — nothing in this project ever revokes a device automatically. See "Explicit revoke" below.

## Explicit revoke: `revokeRegisteredDevice`

A callable Cloud Function, region `europe-west1`, that lets a device's current owner mark it
permanently untrusted (e.g. the physical device was lost or stolen).

Request/response:

```typescript
// request
{ deviceId: string }

// response
{ success: true, status: "revoked", alreadyRevoked: boolean }
```

**Authorization**: `request.auth != null`, and the caller's uid must equal the *stored*
`registeredDevices/{deviceId}.ownerUid` — never anything the client asserts about role, authUid, or
status in the request body (only `deviceId` is ever read from it). A device with `ownerUid == null`
(never claimed, or already unpaired) can never be revoked by a client — there is no owner to
authorize the caller against.

**Errors** (`HttpsError`, code / message):

| Code | Message | Meaning |
|---|---|---|
| `unauthenticated` | `UNAUTHENTICATED` | No `request.auth`. |
| `invalid-argument` | `INVALID_DEVICE_ID` | Not a string, blank after trim, or over 128 characters. |
| `not-found` | `DEVICE_NOT_REGISTERED` | `registeredDevices/{deviceId}` does not exist. |
| `failed-precondition` | `DEVICE_NOT_OWNED` | The stored document's `ownerUid` is `null`. |
| `permission-denied` | `PERMISSION_DENIED` | The caller's uid does not match the stored `ownerUid`. |
| `internal` | `REGISTRY_WRITE_FAILED` | A genuine Firestore/transaction failure — never silently reported as success. |

**Transaction** (`applyRevokeRegisteredDevice`/`decideRevokeRegisteredDevice` in
`deviceRegistry.ts`): sets `status: "revoked"`, `revokedAt: <server timestamp>`,
`suspensionReason: null`, `updatedAt: <server timestamp>`. Every other field — `deviceId`, `role`,
`authUid`, `ownerUid`, `identityMode`, `publicKey`, `createdAt`, `lastSeenAt` — is left completely
untouched. `ownerUid` in particular is **never** cleared by revoke (unlike unpair) — it remains the
record of who revoked the device, needed for an owner's device list and for audit purposes.

**Idempotent**: revoking an already-`revoked` device returns `{ success: true, status: "revoked",
alreadyRevoked: true }`, and neither `revokedAt` nor `updatedAt` is touched on the repeat.

**Forbidden, by construction** — there is no `unrevokeDevice` callable, and nothing in this project
ever transitions a device `revoked → active` or `revoked → suspended`, automatically or via any
client-reachable path:

- a client cannot restore a revoked device to active;
- a client cannot change `revokedAt` once set;
- a client cannot revoke a device it does not own;
- a client cannot revoke a device with `ownerUid == null`;
- a client cannot clear a revoked device's `ownerUid` via unpair/cleanup either — see "`revoked`
  cleanup ≠ registry detach" above;
- `reconcileUserDeviceLimits` (see below) excludes `revoked` devices from its selection entirely —
  they are never counted toward a limit and never reactivated by a limit increase (this is
  different from `suspended`/`"manual"`/`"security"` devices, which **do** count toward the limit
  but are likewise never auto-reactivated — see "Plan-based suspension" below for the distinction);
- every lazy-registration path (`registerLegacyCamera`/`registerLegacyHome`/`attachCameraOwner`/
  `touchRegisteredDevice`) already never writes `status` on an existing document (see
  "Administrative status and Keystore identity are never downgraded" below) — this was true before
  revoke existed and remains the reason a revoked device can't be silently resurrected by an
  ordinary pairing/TURN/event call either.

## Plan-based suspension: `reconcileUserDeviceLimits`

A server-only helper (`functions/src/deviceRegistry.ts`, not a callable — only ever invoked by
`reconcileDevicesOnEntitlementChange`, see below) that brings one user's owned, non-`revoked`
devices in line with their current plan limits, **independently per role**:

```typescript
reconcileUserDeviceLimits(
  db: admin.firestore.Firestore,
  ownerUid: string,
  limits: { maxCameras: number; maxHomeDevices: number }
): Promise<{
  camerasSuspended: number;
  camerasReactivated: number;
  homeDevicesSuspended: number;
  homeDevicesReactivated: number;
}>
```

**Counted devices** (occupy a plan slot): every device with `ownerUid == ownerUid` and `status !=
"revoked"` — that includes `active`, `suspended`/`"plan"`, `suspended`/`"manual"`, **and**
`suspended`/`"security"`. A device with `ownerUid == null` never belongs to any user's limit and is
excluded by the query itself; `revoked` devices are excluded explicitly (never counted, never
reactivated, regardless of how high the limit rises).

**`suspended`/`"manual"` and `suspended`/`"security"` devices count toward the limit, but their own
status is never automatically changed, in either direction.** This is a real, deliberate
distinction from `revoked` — do not read "manual/security are excluded from selection" anywhere in
this document as "excluded from the count": they occupy a slot exactly like an `active` device
does, which can push a *later* device into excess, or leave a slot open for an *earlier* one — they
are simply never themselves the thing this function suspends further or reactivates. See the
worked example below.

**Deterministic selection** (`planDeviceLimitDecision`, a pure function directly unit-testable),
per role:

1. Sort every counted device by `createdAt` ascending, `deviceId` ascending on an exact tie —
   **never** `lastSeenAt` (using recency would make the "within plan" set drift every time a
   device happens to be used, breaking reproducibility).
2. The first `limit` devices in that order are **within plan**; the rest are **excess**.
3. Within plan: `active` stays `active`; `suspended`/`"plan"` is reactivated to `active`;
   `suspended`/`"manual"` and `suspended`/`"security"` stay exactly as they are.
4. Excess: `active` becomes `suspended`/`"plan"`; `suspended`/`"plan"` stays `suspended`/`"plan"`;
   `suspended`/`"manual"` and `suspended`/`"security"` stay exactly as they are.

A manual/security reason is **never** rewritten to `"plan"`, in either direction, regardless of
whether the device ends up within plan or excess. A device already in its correct target state
produces no write at all (no `updatedAt` bump on a no-op), which is what makes a repeated reconcile
with the same limit fully idempotent.

**Worked example** (`limit = 1`): `A` (`suspended`/`"manual"`, created first), `B` (`active`,
created second). `A` occupies the only slot (it's oldest) — result: `A` stays
`suspended`/`"manual"` (within plan, but manual is never auto-reactivated), `B` becomes
`suspended`/`"plan"` (excess, since `A` took the slot) — even though `A` itself never stops being
operationally suspended. Raising the limit to `2`: both are now within plan — `A` still stays
`suspended`/`"manual"` (never auto-reactivated), `B` (whose reason is `"plan"`) becomes `active`.

**Consistency model**: the counted-device set is read with one non-transactional, single-field
query (`where("ownerUid", "==", ownerUid)`, filtered further to role/non-revoked in memory —
deliberately avoiding a multi-field composite query, which would require a new Firestore index this
project does not otherwise have). Each individual device's actual state change is then applied in
its **own** small transaction (`applyDevicePlanLimitChange`), which **re-reads that device fresh**
and re-validates it is still eligible for an *automatic* transition (still `active` or still
`suspended`/`"plan"` — never a manual/security suspension, which this never touches regardless)
before writing — never trusting the earlier query snapshot as still current. This means a
concurrent `revoke` or a concurrent manual/security suspension landing on any one device
mid-reconcile can never be overridden by this pass, regardless of how many other devices the same
reconcile also touches. Not a single all-or-nothing transaction across every device: a user's
total owned-device count is expected to stay small (single digits to low tens) in practice, and
per-device transactions keep write ordering simple without contending with every other concurrent
operation on any of these
documents at once, or needing Firestore's 500-operation batch/transaction limit.

**Never touched by this function, for any device**: `ownerUid`, `authUid`, `role`, `identityMode`,
`publicKey`, `createdAt`, `lastSeenAt`, `revokedAt`.

## Automatic reconciliation on entitlement change: `reconcileDevicesOnEntitlementChange`

A Firestore trigger (`onDocumentWritten`, region `europe-west1`) on `userEntitlements/{uid}` —
fires on create, update, *and* delete.

1. Computes `maxCameras`/`maxHomeDevices` for both the "before" and "after" state via
   `planDeviceLimitsFromEntitlementsData` (a pure function — see "Plan device limits vs. effective
   entitlements" below) — for delete, "after" naturally resolves to the Free defaults, the same
   fallback `getPlanDeviceLimits` itself uses for "no document"; no separate Free-model duplication.
2. **If both limits are unchanged, does nothing** — no read of `registeredDevices`, no write,
   regardless of what else changed on the document (including `subscriptionStatus`).
3. Otherwise calls `reconcileUserDeviceLimits(db, uid, afterLimits)`.

**Idempotent and safe under at-least-once trigger delivery**: `reconcileUserDeviceLimits` itself
only ever writes a device that is not already in its target state, so a redelivered event (or two
firing back-to-back for the same uid) converges to the same result without any extra bookkeeping in
this handler.

## Plan device limits vs. effective entitlements

Two deliberately different resolutions of the same `userEntitlements/{uid}` document, in
`functions/src/entitlements.ts`:

- **`getEffectiveUserEntitlements`** (pre-existing, unchanged) — the *operational* rights a caller
  has right now. `subscriptionStatus == "blocked"` zeroes out `maxCameras`/`maxHomeDevices`/
  `maxConcurrentLiveSessions` and denies `turnAccessAllowed`, on top of the missing/corrupt/expired
  → Free fallback.
- **`getPlanDeviceLimits`** / **`planDeviceLimitsFromEntitlementsData`** (new) — the *plan* device
  limits only (`maxCameras`/`maxHomeDevices`), used **exclusively** by device-registry
  reconciliation. Deliberately does **not** apply the `"blocked" → zero` rule:
  `subscriptionStatus == "blocked"` is an operational access gate (denies TURN issuance etc.
  through `getEffectiveUserEntitlements`), not a change to how many devices the user's plan
  actually allows. Conflating the two would turn a simple subscription block into wrongly
  suspending every device the user owns — exactly the `subscription blocked != device suspended`
  distinction this stage keeps strict. An **expired** grant *is* still treated as a real downgrade
  to Free device limits (unlike `blocked`) by both helpers, since expiry genuinely ends the grant
  rather than merely gating access to it.

Both share one internal resolution core (`resolveEntitlementsData`/`resolveStoredOrFreeEntitlements`
in `entitlements.ts`) for the missing-document/corrupt-document/expired → Free fallback, so Free's
definition is never duplicated between them.

## Centralized operational enforcement: `checkRegisteredDeviceOperational`

A pure function (`deviceRegistry.ts`) — `existing: RegisteredDevice | null` (the already-fetched
document) in, a decision out:

```typescript
type DeviceOperationalReason =
  | "DEVICE_SUSPENDED" | "DEVICE_SUSPENDED_PLAN" | "DEVICE_REVOKED" | "DEVICE_NOT_REGISTERED";

type DeviceOperationalDecision =
  | { operational: true }
  | { operational: false; reason: DeviceOperationalReason };
```

| Stored state | Decision |
|---|---|
| `active` | operational |
| `suspended`, `suspensionReason: "plan"` | not operational — `DEVICE_SUSPENDED_PLAN` |
| `suspended`, `suspensionReason: "manual"` or `"security"` | not operational — `DEVICE_SUSPENDED` |
| `revoked` | not operational — `DEVICE_REVOKED` |
| no document at all | operational by default (`requireRegistered: false`) — see below |

A missing document is **permissive by default**: this registry is still best-effort bookkeeping
layered on top of `cameraClaims`/`pairingState` (the real sources of truth), not a hard
prerequisite for every operation. A device that predates the registry, or whose lazy-migration
write simply hasn't landed yet, must never be newly blocked because of that. (`requireRegistered:
true` exists for a future call site that genuinely needs "must already be registered" — no current
call site sets it; `revokeRegisteredDevice`'s own "can't revoke what doesn't exist" check is handled
directly in `decideRevokeRegisteredDevice`, not routed through this function.)

The actual `HttpsError` mapping (`assertRegisteredDeviceOperational` in `index.ts`) is deliberately
**not** in `deviceRegistry.ts` — that module never imports `HttpsError`, so its business logic stays
testable without the Functions SDK, exactly like `PublicKeyRegistrationOutcome`'s own mapping in
`registerDevicePublicKey`. `DEVICE_SUSPENDED`/`DEVICE_SUSPENDED_PLAN`/`DEVICE_REVOKED` map to
`failed-precondition`; `DEVICE_NOT_REGISTERED` maps to `not-found`. None of these reasons ever
include a UID, a key, or any other document field — safe to return to the client verbatim.

## Where operational enforcement is applied

| Operation | `active` | `suspended` | `revoked` |
|---|---|---|---|
| `createCameraPairingSession` (start a new pairing) | allowed | **denied** | **denied** |
| `claimCameraForUser` (complete a pairing) | allowed | **denied** | **denied** |
| `getTurnCredentials` | allowed | **denied** | **denied** |
| `submitCameraEvent` | allowed | **denied** | **denied** |
| `registerDevicePublicKey` | allowed | **allowed** (completes the Keystore migration even while suspended) | **denied** |
| `releaseCameraForUser` / `unpairCameraFromDevice` / `releaseCameraFromCamera` (unpair) | allowed — clears `ownerUid` | allowed — clears `ownerUid` | allowed, but **cleans up pairing artifacts only** — `registeredDevices.ownerUid`/`status`/`revokedAt`/`publicKey`/`identityMode` are left untouched (see "`revoked` cleanup ≠ registry detach") |
| `revokeRegisteredDevice` | allowed | allowed | allowed (idempotent) |
| WebRTC session / command creation (`webrtcSessions`, `commands`) | *(no server Function exists for this yet — see below)* | | |

`registerDevicePublicKey`'s `suspended → allowed` behavior is intentional and unchanged from stage
2 (`decidePublicKeyRegistration` in `deviceRegistry.ts` never checks `suspended` at all, only
`revoked`) — a suspended device must still be able to finish proving its real cryptographic
identity; that migration is exactly what stage 2 exists for, and blocking it would leave a
suspended device permanently stuck in `"legacy"` even after the owner fixes their plan.

Unpair, release, and revoke are **never** gated by device status — a lost/stolen/suspended device
must always be removable/revocable, since blocking cleanup on the very state that motivates the
cleanup would be a lockout, not a safeguard. For a `revoked` device specifically, "removable" means
the *pairing* (Home's link to it) is removable — the registry's own record of `ownerUid`/`status`/
`revokedAt`/the Keystore identity is not, and is never cleared by unpair/release. **`revoked`
cleanup ≠ registry detach** — see above.

`webrtcSessions`/`commands` (ACTIVITY_ZONE/ENTRY_EXIT_LINE/LIVE_VIEW signaling, UNPAIR/
CONFIRM_PLACEMENT commands) are written directly by Home/Camera against Firestore, validated by
`firestore.rules`, not through any Cloud Function — there is currently no server-side callable to
apply this enforcement to for those paths. Documented here as a known, current gap rather than
silently unaddressed: if a server-side function is ever added for that signaling, it should apply
`assertRegisteredDeviceOperational` the same way `getTurnCredentials`/`submitCameraEvent` do.

## Camera vs. Home status enforcement

**Camera**: fully enforced. Every operational check above resolves the Camera's identity via
`cameraClaims/{cameraDeviceId}.cameraAuthUid` — a server-verified value set once, at claim time,
from the Camera's own authenticated pairing-session handshake. A request's `cameraDeviceId` is only
ever trusted after this cross-check, never taken at face value.

**Home: enforcement is intentionally NOT relied upon per-device today, and this is a real, open
gap, not a solved problem.** The Home App does not yet have its own Keystore identity, challenge, or
signed-request mechanism — Home requests are authenticated only by `request.auth.uid`, which today
can be a Google-linked UID *shared across every Home installation signed into the same Google
account*. Nothing server-side can yet cryptographically distinguish *which specific Home phone*
issued a given request. Concretely:

- `request.data.homeDeviceId == registeredDevices/{homeDeviceId}.someField` is **not**, on its own,
  a safe per-device check — a client can assert any `homeDeviceId` string it wants, and nothing
  proves the calling installation is the one that actually owns it.
- `revokeRegisteredDevice` **does** correctly create `status: "revoked"` for a `HOME` device (the
  callable and its authorization — `ownerUid == request.auth.uid` — are role-agnostic), which is
  useful and real: it durably marks that specific `deviceId` as revoked in Firestore, and any
  *future* per-device Home enforcement would immediately honor it retroactively. But **no code in
  this project today denies any operation to a specific Home *installation* based on that revoked
  status** — there is no server-side operation gated on "this specific calling Home device," only
  account-level (`request.auth.uid`) checks, which revoking a `registeredDevices` document does not
  touch or weaken.
- Closing this gap requires: a Home Keystore identity (mirroring Camera's `identityMode: "keystore"`
  migration), a challenge/signature scheme proving possession of that key on each sensitive
  request, and anti-replay protection, followed by making the account-level checks (`isOwnerUid`
  equivalents) *additionally* require that signature. None of that exists yet.

This document must not be read as claiming Home devices are individually revocable/enforceable
today — only that the **status itself** is now representable and durable, ready for the day
per-device Home authentication exists. Existing account-level checks (`request.auth.uid ==
cameraClaims.uid`, Firestore Rules' `isOwnerUid`) are unchanged and unweakened by any of this
stage's work.

## Why `authUid` doesn't yet protect against copying a `deviceId`

`authUid` records *which Firebase Auth identity* last legitimately registered as this `deviceId`,
and this stage's identity-conflict check (`identityConflictReason`) refuses to let a *different*
`authUid` silently overwrite it. But nothing here cryptographically proves that the caller
presenting a given `deviceId` in a request actually created it — `cameraDeviceId`/`homeDeviceId`
remain plain, client-generated strings, and Firebase Auth's own anonymous-identity model means nothing
stops a second installation from generating a colliding id and authenticating separately. What this
stage *does* guarantee is that once a `deviceId` is registered under a specific `authUid`, that
pairing between id and identity is durable (a conflicting later request is rejected, not silently
accepted) — real, cryptographic proof-of-possession is exactly what `identityMode: "keystore"`
(a future stage) is for.

## `legacy` has no cryptographic proof

Every device is *created* `identityMode: "legacy"`, `publicKey: null`. "Legacy" means "identified
only by a Firebase Auth UID, the same way every device has worked until now" — it is *not* a
lesser-trust flag in the sense of being second-class, but it does mean there is no signature or
hardware-backed proof that the installation claiming a given `deviceId`/`authUid` is who it says
it is beyond having a valid Firebase Auth session. A device can upgrade itself to
`identityMode: "keystore"` via `registerDevicePublicKey` (below) — but registering a key is still
not the same as *proving possession of it on every request*; that (a challenge/signature
verification step on sensitive calls) is an explicitly separate, later task — see "What is
enforced today, and what isn't".

## Android Keystore identity: `registerDevicePublicKey`

A callable Cloud Function, region `europe-west1`, that lets an already-registered `"legacy"`
device upgrade itself to `"keystore"` by submitting its real Android Keystore public key.
Implemented as the callable itself in `functions/src/index.ts` plus a dedicated, strict (not
best-effort) registry operation, `applyPublicKeyRegistration()`, in `functions/src/deviceRegistry.ts`
— unlike every Stage 1 operation, this one never swallows a Firestore error, and never creates
`registeredDevices/{deviceId}` itself (see "Bootstrap trust model" below).

### Callable contract

Request:

```typescript
{
  deviceId: string;       // the device's own existing cameraDeviceId/homeDeviceId, unchanged
  role: "HOME" | "CAMERA";
  publicKey: string;      // canonical Base64 (standard alphabet) of X.509 SPKI DER, ≤ 512 chars
  algorithm: "ES256";     // the only value accepted today
}
```

Response (identical shape for a brand-new registration and an idempotent repeat of the same key):

```typescript
{
  success: true;
  identityMode: "keystore";
}
```

Errors (`HttpsError`, code / message):

| Code | Message | Meaning |
|---|---|---|
| `unauthenticated` | `UNAUTHENTICATED` | No `request.auth`. |
| `invalid-argument` | `INVALID_DEVICE_ID` | Not a string, blank after trim, or over 128 characters. |
| `invalid-argument` | `INVALID_ROLE` | Not exactly `"HOME"` or `"CAMERA"`. |
| `invalid-argument` | `INVALID_ALGORITHM` | Not exactly `"ES256"`. |
| `invalid-argument` | `INVALID_PUBLIC_KEY` | Empty, over 512 characters, not standard/canonical Base64, contains whitespace or Base64URL characters, not a well-formed SPKI DER structure, not an EC key, or not on the P-256 curve — see `validateEcP256PublicKey()`, which never reveals *which* of these failed to the client, only internally (see "Logging"). |
| `not-found` | `DEVICE_NOT_REGISTERED` | `registeredDevices/{deviceId}` does not exist — see "Bootstrap trust model". |
| `not-found` | `CAMERA_NOT_CLAIMED` | Role `CAMERA`, and `cameraClaims/{deviceId}` does not exist. |
| `permission-denied` | `DEVICE_IDENTITY_MISMATCH` | The caller's identity does not match what's required for this role/device (see "Authorization" below) — one generic message for every kind of mismatch (role, authUid, ownerUid), deliberately not distinguished for the client. |
| `failed-precondition` | `DEVICE_REVOKED` | The device's `status` is `"revoked"`. |
| `failed-precondition` | `DEVICE_IDENTITY_CORRUPT` | The stored document is internally inconsistent (`legacy` with a non-null `publicKey`, or `keystore` with a null `publicKey`) — never auto-repaired. |
| `failed-precondition` | `PUBLIC_KEY_ALREADY_REGISTERED` | Already `identityMode: "keystore"` with a *different* key than the one submitted. |
| `internal` | `REGISTRY_WRITE_FAILED` | A genuine Firestore/transaction failure — never silently reported as success. |

No challenge/signature fields exist in this request — deliberately out of scope for this stage.

### Bootstrap trust model

Registering a device and registering its cryptographic identity are different operations:
`registerDevicePublicKey` **never creates** `registeredDevices/{deviceId}` — a missing document is
always rejected (`DEVICE_NOT_REGISTERED`), never silently created with attacker-supplied role/key
data. A device must already have gone through Stage 1's own registration
(`registerLegacyCamera`/`registerLegacyHome`/`attachCameraOwner`) before it can ever upgrade to
`"keystore"`.

There is no cryptographic proof possible for the *first* key a legacy device ever registers —
bootstrap trust is necessarily anchored to whichever identity mechanism already exists. This stage
anchors it to the *strongest already-available* corroboration for each role, then makes that
registration permanent (see "First-write-wins" below); closing the remaining gap is explicitly the
next stage (challenge/signature verification on every sensitive request from then on).

- **CAMERA — authorized via `cameraClaims`, not `ownerUid`, checked atomically with the write.**
  `cameraClaims/{deviceId}` must exist, and `cameraClaims.cameraAuthUid` must equal
  `request.auth.uid` — the same server-verified pairing-secret handshake result every other
  Camera-authenticated callable in this file already relies on
  (`verifyCameraAccess`/`getVerifiedCameraClaim`). This means registration is only possible
  **post-claim** — a Camera cannot register a key before it has been paired, since `cameraClaims`
  doesn't exist yet at that point. `ownerUid` is never consulted for a Camera's own authentication.
  As a defense-in-depth cross-check, the stored registry document must *also* already have
  `role: "CAMERA"` and `authUid` equal to that same `cameraClaims.cameraAuthUid` — catching any
  historical drift between the two records, not just a mismatched caller.

  Critically, `applyCameraPublicKeyRegistration()` reads `cameraClaims` **and**
  `registeredDevices` inside **one** Firestore transaction, together with the eventual write —
  never as a separate pre-check followed by a different transaction. An earlier version of this
  callable checked `cameraClaims` outside any transaction and then ran a separate transaction just
  for the registry update; that left a real window where a concurrent unpair (which deletes
  `cameraClaims`) could land between the check and the write, letting a public key register even
  though the claim backing it no longer existed by the time the write actually happened. Because
  both reads and the write now share one transaction, Firestore's own contention/retry guarantees
  that the whole "claim still exists and matches, therefore the key may be registered" decision is
  atomic with the write itself.
- **HOME — authorized via the registry document itself.** `registeredDevices/{deviceId}` must
  already have `role: "HOME"`, `authUid == request.auth.uid`, **and** `ownerUid ==
  request.auth.uid` (a Home device is always self-owned). Since `registerLegacyHome` only ever
  runs inside `claimCameraForUser`, and `claimCameraForUser` is itself only reachable once the
  Home App's own client-side gate requires a durable, Google-linked `request.auth.uid` (never the
  throwaway anonymous bootstrap identity), a Home key registration is likewise only meaningful
  **post-first-claim** in practice, even though nothing here reads `cameraClaims` for the HOME
  case directly.

### Key format

EC, curve **P-256** (secp256r1/prime256v1), algorithm identifier **ES256** — verified via
`crypto.createPublicKey({ key: derBuffer, format: "der", type: "spki" })` then
`keyObject.asymmetricKeyType === "ec"` and a JWK export's `crv === "P-256"` (JWK's curve name is
pinned by RFC 7518, unlike `asymmetricKeyDetails.namedCurve`'s OpenSSL alias `"prime256v1"`, which
requires the reader to already know that alias *is* P-256 — the JWK check is the more
standards-anchored, unambiguous one to rely on). Encoding: X.509 SubjectPublicKeyInfo (SPKI) DER,
Base64 with the **standard** alphabet (not Base64URL), no line wrapping, no PEM headers, canonical
(re-encoding the decoded bytes must reproduce the exact submitted string — `Buffer.from(str,
"base64")` is lenient and silently drops characters it doesn't understand, so this round-trip
check is what actually catches a malformed/non-canonical input). Maximum 512 characters (a real
P-256 SPKI key is ~124 Base64 characters; the bound is generous headroom, not a tight fit).

The full canonical Base64 public key is what's stored in Firestore — never a fingerprint in its
place. A SHA-256 hex digest of the raw DER bytes (`publicKeyFingerprint`) is computed only for safe
log correlation (see "Logging").

### First-write-wins, never replaced

Once `identityMode: "keystore"`, the stored `publicKey` can never be changed by
`registerDevicePublicKey` again:

- The exact same key, resubmitted → **idempotent success** (`{ success: true, identityMode:
  "keystore" }`), `lastSeenAt` refreshed, `updatedAt` **not** touched.
- A *different* key → **rejected** (`failed-precondition` / `PUBLIC_KEY_ALREADY_REGISTERED`), the
  stored key is left completely unchanged.

Two concurrent first-registration requests for the same device are resolved by Firestore's own
transaction contention/retry mechanism (the same mechanism `claimCameraForUser`'s own idempotent
claim branch already relies on): whichever transaction commits first wins; the other is
automatically retried, re-reads the now-`"keystore"` document, and resolves to either the
idempotent-success or the conflict path above depending on whether it submitted the same or a
different key. There is never a last-write-wins replacement.

### `suspended`/`revoked` behavior

- `active` — registration proceeds normally.
- `suspended` — registration is **still allowed** (a suspended device must be able to complete its
  cryptographic migration), and `status`/`suspensionReason` are left completely untouched by it.
- `revoked` — registration is **rejected** (`failed-precondition` / `DEVICE_REVOKED`) and the
  document is left completely unchanged.

### Logging

Events: `REGISTER_DEVICE_PUBLIC_KEY_START/SUCCESS/IDEMPOTENT/DENIED/CONFLICT/INVALID/FAILED`, plus
`DEVICE_REGISTRY_PUBLIC_KEY_CORRUPT` from inside `applyPublicKeyRegistration()` itself. Allowed
metadata: `deviceId`, `role`, `algorithm`, `publicKeyFingerprint`, `reason`, `errorClass`. **Never**
logged: the raw `publicKey`, the raw DER bytes, `request.auth.uid`, `ownerUid`, `cameraAuthUid`, the
full request body, or the full Firestore document. On an invalid key, `publicKeyFingerprint` is
simply absent (the DER couldn't be safely decoded to fingerprint in the first place).

## Device-signature challenge protocol: `createDeviceChallenge` + verified `getTurnCredentials`

Implemented in `functions/src/deviceChallenges.ts`. Lets a device that has already completed
`registerDevicePublicKey` (`identityMode: "keystore"`) prove, per-request, that it still holds the
matching Keystore private key — closing the gap the previous section calls out ("registering a key
is not the same as proving possession of it on every request"). **`getTurnCredentials` is the
first, and so far only, endpoint that accepts this proof.**

### `createDeviceChallenge`

A callable (region `europe-west1`) that issues a `deviceChallenges/{challengeId}` document for the
single supported purpose today, `TURN_CREDENTIALS`. Request: `{ deviceId, purpose, requestPayload:
{ cameraDeviceId, turnPurpose } }` — `role`/`authUid` are never accepted from the client (`role`
comes from `registeredDevices/{deviceId}.role`, `authUid` from `request.auth.uid`). Response:
`{ challengeId, nonce, purpose, expiresAt, canonicalPayload }`. Requires the calling device to
already be `identityMode: "keystore"`, operational, and linked to the target Camera (same
`cameraClaims`/entitlement checks `getTurnCredentials` itself performs). TTL is 90 seconds. See
`createDeviceChallenge`'s own doc comment in `index.ts` for the full eligibility sequence — this
stage does not accept or verify a signature at all; it only issues the challenge.

### Canonical formats

Two fixed, versioned, LF-joined, UTF-8, never-`JSON.stringify()`d formats — the same on the backend
(TypeScript) and both Android apps (Kotlin `HomeDeviceProofSigner`/`CameraDeviceProofSigner`):

```
EDGEGUARD_REQUEST_V1
purpose=TURN_CREDENTIALS
cameraDeviceId=<cameraDeviceId>
turnPurpose=<turnPurpose>
```

hashed (`sha256`, lowercase hex) into `requestHash`, and

```
EDGEGUARD_DEVICE_PROOF_V1
challengeId=<challengeId>
deviceId=<deviceId>
role=<HOME|CAMERA>
purpose=TURN_CREDENTIALS
authUid=<authUid>
nonce=<nonce>
requestHash=<requestHash>
expiresAt=<epochMillis>
```

which is the exact byte string a device signs (`SHA256withECDSA` → ASN.1 DER → standard, non-URL-
safe Base64, `Base64.NO_WRAP` on Android). Verified server-side via `crypto.verify("sha256", ...)`
against `registeredDevices/{deviceId}.publicKey` (SPKI DER, standard Base64) — **never** a
client-supplied public key, and **never** a client-supplied `canonicalPayload`: the server always
rebuilds both canonical strings itself, entirely from already-verified, freshly-read Firestore
state, inside the same transaction that checks the signature.

### Verified `getTurnCredentials`

`getTurnCredentials`'s request may optionally include:

```typescript
{
  cameraDeviceId: string;
  purpose: "LIVE_VIEW" | "PLACEMENT_PREVIEW" | "ACTIVITY_ZONE" | "ENTRY_EXIT_LINE" | "MEDIA_TRANSFER";
  deviceProof?: { protocolVersion: 1; challengeId: string; signature: string };
}
```

**Optional, not required by `identityMode` or `deviceProofVersion` at this stage.** `deviceProof`
entirely absent → the pre-existing `cameraClaims`/`assertRegisteredDeviceOperational`/
`turnAccessAllowed` flow runs completely unchanged — old clients are unaffected. `deviceProof`
present (including an explicit `null`, which is malformed, not "absent") → the whole call is
authorized by `consumeVerifiedTurnCredentialsChallenge()` instead, and **any failure denies the
call outright — there is no fallback to the old flow once a client attempts a proof.**

`consumeVerifiedTurnCredentialsChallenge()` runs entirely inside **one** Firestore transaction —
verify and consume are never split into a separate check followed by a separate update, the same
"claim + registry read together" atomicity `applyCameraPublicKeyRegistration()` already established
for `registerDevicePublicKey`. Inside that one transaction it reads and re-checks, fresh (never
trusting challenge-creation-time state): `deviceChallenges/{challengeId}` (schema, challenge-id/
purpose/authUid match, unused, unexpired, well-formed nonce/requestHash/role), `registeredDevices/
{challenge.deviceId}` (exists, role/authUid match, `identityMode: "keystore"`, `publicKey` present,
operational), a **recomputed** `requestHash` from the actual request just received (catches a
`cameraDeviceId`/`turnPurpose` changed after the challenge was issued), `cameraClaims/
{cameraDeviceId}` (HOME: `uid == authUid`; CAMERA: `deviceId == cameraDeviceId` and
`cameraAuthUid == authUid`), the target Camera's own `registeredDevices` document (operational —
permissive on a missing document, exactly like the existing non-proof path), and `userEntitlements/
{ownerUid}` (`turnAccessAllowed`, via the same pure resolution `getEffectiveUserEntitlements` itself
uses — `entitlements.ts`'s `effectiveUserEntitlementsFromData`, never a second copy of that logic).
Signature verification is the last, most expensive check, exactly in that order.

**Errors are deliberately coarse.** Distinguishable, already-safe business states keep their own
message (`CHALLENGE_NOT_FOUND`, `CHALLENGE_EXPIRED`, `CHALLENGE_ALREADY_USED`,
`DEVICE_NOT_PROVISIONED`, `DEVICE_IDENTITY_CORRUPT`, `DEVICE_SUSPENDED[_PLAN]`, `DEVICE_REVOKED`,
`TURN_ACCESS_DENIED`) — but every reason that could function as a signature/authorization oracle
(challenge id/purpose/authUid/schema mismatch, role mismatch, request-hash-after-tampering
mismatch, camera-target mismatch, camera claim/access denial, and an invalid signature itself)
collapses to one generic `permission-denied`/`DEVICE_PROOF_DENIED`, so a caller can never use the
response to tell "almost a valid signature" apart from "wrong challenge" or "wrong camera".

### Replay protection

A challenge can be consumed at most once: `usedAt`/`usedByFunction` are set only inside the same
transaction that verified everything else, so two concurrent consumption attempts for the same
challenge are serialized by Firestore's own transaction contention/retry — exactly one succeeds,
the other sees `usedAt != null` and is denied, never a silent double-apply (mirrors
`registerDevicePublicKey`'s own proven "two concurrent first-key requests" guarantee). A second
call reusing the same signature — for the same camera or a different one — is rejected the same
way. An **invalid** proof never marks the challenge used and never touches `deviceProofVersion` —
only a fully verified signature writes anything at all.

### `deviceProofVersion`

`registeredDevices/{deviceId}.deviceProofVersion` (`number | null`) is set to `1` only once, only
on the **signing** device's own document, only after its very first successfully verified device
proof — merged (`role`/`authUid`/`ownerUid`/`status`/`publicKey`/`identityMode` untouched), and
never lowered if a future version is ever stored higher. **Purely informational at this stage — not
yet consulted by any enforcement decision, and not set by `registerDevicePublicKey` or any other
existing lazy-migration path.** It exists so a future rollout stage can require a proof based on
"this device has already completed one successfully" without needing a bulk backfill.

### Rollout

Exactly one stage implemented so far: `deviceProof` accepted and, when present, fully enforced;
absent, the old flow is untouched. **Proof is not required by `identityMode` or
`deviceProofVersion` in this stage** — requiring it would break every Home/Camera app build that
predates this feature. A future stage may progressively require it (mirroring how `identityMode:
"keystore"` itself was rolled out) — not implemented here.

## Identity is never overwritten

If a `registeredDevices/{deviceId}` document already exists, none of the operations below will
change its `deviceId`, `role`, or `authUid`. A write that would require doing so (a different
`authUid` presenting itself for the same `deviceId`, or a `HOME` device id being registered as
`CAMERA` or vice versa) is entirely skipped — not partially applied — and logged as a single
structured warning:

```
DEVICE_REGISTRY_<OPERATION>_IDENTITY_CONFLICT { deviceId, role, reason }
```

where `reason` is one of the fixed `DeviceIdentityConflictReason` values (`DEVICE_ID_MISMATCH`,
`ROLE_MISMATCH`, `AUTH_UID_MISMATCH`) — never the Firebase UID (existing or incoming), never
`publicKey`, never any other document field.

## Administrative status and Keystore identity are never downgraded

None of `registerLegacyCamera`/`registerLegacyHome`/`attachCameraOwner`/`detachCameraOwner`/
`touchRegisteredDevice` ever write `status`/`suspensionReason`/`identityMode`/`publicKey` on an
*existing* document — those fields are only ever set once, at first creation. This is what
guarantees a `suspended` or `revoked` device (and its `suspensionReason`) can never be silently
reactivated/cleared by a later lazy-registration call, and that an already-provisioned Keystore
identity (`identityMode: "keystore"`, a real `publicKey`) can never be downgraded back to
`"legacy"` or have its key erased/replaced by this stage's legacy bookkeeping.

`status`/`suspensionReason`/`revokedAt` are, today, only ever written by three functions total:
`revokeRegisteredDevice` (`status: "revoked"`, one-way), `reconcileUserDeviceLimits`
(`status`/`suspensionReason` toggling only between `active` and `suspended`/`"plan"`, and only for
devices already in one of those two states — see "Plan-based suspension" above), and a device's own
first creation (`status: "active"`, `suspensionReason: null`). No other function in this project
writes any of these three fields.

## Lazy migration

There is no bulk backfill script. Every `registeredDevices` document is created or updated
opportunistically, as a side effect of an already-existing, already-authenticated backend call:

- **`createCameraPairingSession`** — registers a brand-new Camera (`ownerUid: null`) the moment it
  requests its first pairing session.
- **`claimCameraForUser`** — registers the Home device (`authUid == ownerUid == request.auth.uid`)
  and attaches the Camera's owner (`authUid` from the just-verified pairing session, `ownerUid`
  from the authenticated Home caller) the moment a claim succeeds.
- **`getTurnCredentials`** and **`submitCameraEvent`** — lazily attach/refresh an already-paired
  Camera that predates this registry (or whose earlier registration attempt failed), using
  `cameraClaims.cameraAuthUid`/`cameraClaims.uid` — **never** the calling user's own uid, since both
  of these callables are reachable by either the Home or the Camera identity. `getTurnCredentials`
  reads this data via `getVerifiedCameraClaim()` (`functions/src/index.ts`), a small helper that
  performs the access check (`request.auth.uid` is either the linked owner or the linked Camera)
  and returns `cameraAuthUid`/`ownerUid` from that *same* single `cameraClaims` read — avoiding a
  second, separately-timed read of the same document purely to feed the registry. `verifyCameraAccess`
  itself (the original access-check-only function) is untouched and still exported/tested as
  before; `submitCameraEvent` already had its own single `cameraClaims` read for its permission
  check and reuses that directly, with no second helper needed.
- **`releaseCameraForUser`**, **`unpairCameraFromDevice`**, **`releaseCameraFromCamera`** — detach
  the Camera's owner back to `null` once the corresponding `cameraClaims` deletion has succeeded.

Every one of these is a **best-effort side effect**: it runs in its own Firestore transaction
(separate from the calling function's own transaction, since Firestore does not support nesting
one transaction inside another), and any error it raises is caught and logged internally
(`DEVICE_REGISTRY_<OPERATION>_WRITE_FAILED { deviceId, role?, errorClass }`) rather than
propagated. A registry write failing, or being skipped due to an identity conflict, never changes
the response of `createCameraPairingSession`/`claimCameraForUser`/`getTurnCredentials`/
`submitCameraEvent`/the three unpair callables, and never surfaces to the Android clients in any
way.

## What is enforced today, and what isn't

**Enforced:**
- A device can safely and durably register its real Keystore public key
  (`registerDevicePublicKey`), atomically flipping `identityMode` from `"legacy"` to `"keystore"`,
  first-write-wins, never replaceable.
- An owner can explicitly, durably, and idempotently revoke a device they own
  (`revokeRegisteredDevice`) — irreversible, never auto-reactivated.
- A user's device counts are automatically kept in line with their plan's `maxCameras`/
  `maxHomeDevices` (`reconcileUserDeviceLimits`, triggered by `reconcileDevicesOnEntitlementChange`
  whenever those limits actually change) — deterministic selection, per-role, never touching a
  manual/security suspension or a revocation.
- `registeredDevices.status` now actually gates real operations for **Camera**: pairing
  start/completion, TURN credential issuance, and event submission all require `status == "active"`
  (see "Where operational enforcement is applied" above). `registerDevicePublicKey` deliberately
  remains allowed while `suspended` (only `revoked` blocks it), and unpair/release/revoke are never
  gated by status at all.
- `subscriptionStatus == "blocked"` and `registeredDevices.status` are kept strictly independent —
  a subscription block alone never suspends or revokes a device (see "Plan device limits vs.
  effective entitlements" above).

**Not enforced / explicitly out of scope:**
- **Signature verification of any request except `getTurnCredentials`, and only when the caller
  opts in** — `getTurnCredentials` optionally accepts and fully verifies a Keystore-signed
  `deviceProof` (see "Device-signature challenge protocol" above), but proof is not required by
  `identityMode` or `deviceProofVersion` at this stage, and no other callable accepts one yet. Both
  Camera and Home otherwise remain authenticated only by their Firebase Auth uid (Camera's
  cryptographically anchored via `cameraClaims.cameraAuthUid`; Home's not per-device-distinguishable
  at all — see "Camera vs. Home status enforcement" above).
- **Per-device Home enforcement** — `registeredDevices.status` for a `HOME` device is correctly
  representable (including `revoked`, via `revokeRegisteredDevice`) but nothing server-side today
  denies an operation to one specific Home installation based on it. This is the single biggest
  remaining gap in this stage and must not be described as solved.
- **`webrtcSessions`/`commands` enforcement** — these are written directly by clients against
  Firestore Rules, not through a Cloud Function; there is no server-side call site to apply
  `assertRegisteredDeviceOperational` to yet.
- Replacing `cameraClaims` or `pairingState` as the pairing/ownership source of truth.
- Concurrent Live View session limits (`maxConcurrentLiveSessions` remains unread by any server
  code).
