# Device Registry — Stage 1

A single global, Admin-SDK-only Firestore collection that records every known Camera/Home
installation ("device"), independently of `cameraClaims`/`pairingState`. Implemented in
`functions/src/deviceRegistry.ts`.

**This stage only creates and maintains the registry.** It is not yet consulted anywhere to:

- limit device counts;
- deny Live View;
- verify Android Keystore signatures;
- replace `cameraClaims` (still the ownership source of truth);
- replace `pairingState` (still the pairing-lifecycle source of truth).

Existing pairing, unpair, notifications, and Live View behavior is unchanged. See
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
| `identityMode` | `"legacy" \| "keystore"` | Whether this device has a cryptographically-verified identity yet. Every device created by this stage is `"legacy"` — see "Legacy has no cryptographic proof" below. |
| `publicKey` | string \| null | Reserved for a future Keystore-based identity. Always `null` today. |
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

Every device this stage creates is `identityMode: "legacy"`, `publicKey: null`. "Legacy" means
"identified only by a Firebase Auth UID, the same way every device has worked until now" — it is
*not* a lesser-trust flag in the sense of being second-class, but it does mean there is no signature
or hardware-backed proof that the installation claiming a given `deviceId`/`authUid` is who it says
it is beyond having a valid Firebase Auth session. Android Keystore signature verification
(`identityMode: "keystore"`, a real, non-null `publicKey`, and a verification step somewhere in the
request path) is an explicitly separate, future task — not implemented, not even sketched at the
Firestore-schema level beyond reserving these two fields.

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

Enforced: nothing outside this module reads `registeredDevices` yet. It exists purely to start
accumulating accurate device-identity data so a future stage can build limits/Keystore
verification/revocation checks on top of real, already-populated data instead of starting from
nothing.

Not enforced (explicitly out of scope for this stage): device-count limits, Live View denial,
Keystore signature verification, replacing `cameraClaims` or `pairingState`, and anything touching
`userEntitlements`/`cameraCount`/`cameraLimit`.
