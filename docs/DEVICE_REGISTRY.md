# Device Registry — Stage 1 + Android Keystore identity (stage 2)

A single global, Admin-SDK-only Firestore collection that records every known Camera/Home
installation ("device"), independently of `cameraClaims`/`pairingState`. Implemented in
`functions/src/deviceRegistry.ts`.

**Stage 1** (unchanged by this document's stage-2 addition) only creates and maintains the
registry with `identityMode: "legacy"`. **Stage 2** (this addition) lets a device upgrade itself
from `"legacy"` to `"keystore"` by registering a real Android Keystore-backed public key, via the
`registerDevicePublicKey` callable. Neither stage is yet consulted anywhere to:

- limit device counts;
- deny Live View;
- **verify a signature over any request** (registering a key is not the same as proving
  possession of it on every subsequent call — see "What is enforced today, and what isn't" below);
- replace `cameraClaims` (still the ownership source of truth);
- replace `pairingState` (still the pairing-lifecycle source of truth).

Existing pairing, unpair, notifications, TURN, and Live View behavior is unchanged. See
[`docs/USER_ENTITLEMENTS.md`](USER_ENTITLEMENTS.md) for the separate, also-not-yet-fully-enforced
plan/limits model — the two are unrelated and this stage does not connect them.

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
| `suspensionReason` | `"plan" \| "manual" \| "security" \| null` | *Why* the device is suspended — only meaningful while `status == "suspended"`. `null` for every device this stage creates, and never set to anything else by this stage (there is no suspend operation yet — see "What is enforced today" below). Kept as its own field, separate from `status`, so a future suspend operation can record a reason without overloading `status` itself with more values. |
| `identityMode` | `"legacy" \| "keystore"` | Every device is created `"legacy"` (see "Legacy has no cryptographic proof" below). Flips to `"keystore"` exactly once, atomically with `publicKey`, via `registerDevicePublicKey` — see "Android Keystore identity" below. Never flips back. |
| `publicKey` | string \| null | `null` until the device registers a real key. From then on, the canonical Base64 (standard alphabet, no wrapping) encoding of the device's X.509 SubjectPublicKeyInfo (SPKI) DER bytes — the full public key, not a fingerprint (see "Key format" below). Never replaced, cleared, or downgraded back to `null` once set. |
| `createdAt` | Timestamp | Set once, at first creation. Never changes after. |
| `updatedAt` | Timestamp | Bumped on every meaningful change (including a lazy-migration touch). |
| `lastSeenAt` | Timestamp | Bumped whenever the device is confirmed active through an authenticated server call. |
| `revokedAt` | Timestamp \| null | Set only by an explicit future revocation operation (not implemented in this stage) — never touched by any of the operations described below. |

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

## Why a normal unpair is not `revoked`

Unpairing is an everyday, expected action (the user removing a camera, or a camera being
re-purposed) — it says nothing about whether the physical device or its credentials should ever be
trusted again. `detachCameraOwner()` (called from `releaseCameraForUser`, `unpairCameraFromDevice`,
and `releaseCameraFromCamera`, right after each already deletes the `cameraClaims` ownership link)
only ever clears `ownerUid` back to `null` and bumps `updatedAt`/`lastSeenAt` — `status` is never
touched. `revoked` is reserved for a distinct, explicit, not-yet-implemented action ("this specific
credential must never be trusted again, even if presented for a brand-new pairing").

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

Enforced: a device can safely and durably register its real Keystore public key
(`registerDevicePublicKey`), atomically flipping `identityMode` from `"legacy"` to `"keystore"`,
first-write-wins, never replaceable. Nothing outside `deviceRegistry.ts`/`registerDevicePublicKey`
reads or acts on `registeredDevices` yet.

Not enforced (explicitly out of scope for this stage): device-count limits, Live View denial,
**signature verification of any request** (a registered public key is not yet used to verify
anything — no challenge, no proof-of-possession check on subsequent calls), replacing
`cameraClaims` or `pairingState`, and anything touching
`userEntitlements`/`cameraCount`/`cameraLimit`. Challenge/signature verification, and later,
actual enforcement based on `identityMode`/`status`, are explicitly separate, later tasks.
