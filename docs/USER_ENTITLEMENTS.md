# User Entitlements

Server-side model of what a user is allowed to do: their plan, numeric
limits, and whether they may use TURN. Implemented in
`functions/src/entitlements.ts`.

This document covers the entitlements model itself. It does **not** cover
(these are later work, built on top of this model, not part of it):

- Google Play Billing
- purchase token verification
- a device registry
- Android Keystore
- actually counting a user's Cameras/Home devices
- a concurrent Live View session limit
- rate limiting

Today, `turnAccessAllowed` (in `getTurnCredentials`, see below) and
`maxCameras` (in `claimCameraForUser`'s existing, non-transactional-limit
camera-count check) are enforced. `maxHomeDevices` and
`maxConcurrentLiveSessions` are stored and resolved, but nothing checks them
synchronously yet — `maxHomeDevices` is only applied by the best-effort
reconcile pass (`reconcileDevicesOnEntitlementChange` /
`reconcileUserDeviceLimits`, deviceRegistry.ts), and
`maxConcurrentLiveSessions` requires server-side Live View session tracking
listed above. The legacy `users/{uid}.cameraLimit`/`subscriptionUnits`
fields are no longer read for any of these decisions — `cameraLimit` is
still written back as an inert compatibility mirror, always populated from
this canonical `maxCameras`, never the other way around.

## Firestore document

Path:

```
userEntitlements/{uid}
```

`{uid}` is the Firebase Auth uid (same identity space as `users/{uid}`,
`cameraClaims/{cameraDeviceId}.uid`, etc.). One document per user.

The collection is **function-only**: `firestore.rules` denies all client
read and write access (`allow read, write: if false`). Only server code
(Admin SDK, which bypasses rules) may read or write it. A user can never see
or change their own plan, limits, `subscriptionStatus`, `turnAccessAllowed`,
or `validUntil` directly — they only observe the effect of their
entitlements through what server-side callables allow or deny.

### Fields

| Field | Type | Meaning |
|---|---|---|
| `schemaVersion` | number | Must be exactly `1` today. Any other value makes the document invalid (see "Corrupt document" below). |
| `plan` | `"free" \| "premium" \| "custom"` | Which plan this grant represents. `"custom"` is for a manually-tuned grant that doesn't fit the free/premium numbers. |
| `subscriptionStatus` | `"active" \| "expired" \| "blocked"` | Whether the grant is currently in effect, has lapsed, or the user has been explicitly blocked. |
| `maxCameras` | non-negative integer | Camera limit. Not yet enforced anywhere. |
| `maxHomeDevices` | non-negative integer | Home device limit. Not yet enforced anywhere. |
| `maxConcurrentLiveSessions` | non-negative integer | Concurrent Live View session limit. Not yet enforced anywhere. |
| `turnAccessAllowed` | boolean | Whether this user may obtain TURN credentials at all. Enforced today in `getTurnCredentials`. |
| `source` | `"default" \| "manual" \| "promo" \| "google_play"` | Where this grant came from — bookkeeping/audit only, never used to change behavior. |
| `validUntil` | Firestore `Timestamp` \| `null` | When this grant expires. `null` means it never expires (e.g. a manual lifetime grant). |
| `createdAt` | Firestore `Timestamp` | Must be an actual Firestore `Timestamp`, not a client-suppliable value (this collection is never client-written, so in practice it's always set via `admin.firestore.FieldValue.serverTimestamp()` or `admin.firestore.Timestamp`). |
| `updatedAt` | Firestore `Timestamp` | Same requirement as `createdAt`. |

## Free defaults

One centralized constant (`functions/src/entitlements.ts`, not duplicated
in any function):

```
plan: "free"
subscriptionStatus: "active"
maxCameras: 1
maxHomeDevices: 1
maxConcurrentLiveSessions: 1
turnAccessAllowed: true
```

This is what every user effectively has when nothing says otherwise — see
"No document" below.

## `getEffectiveUserEntitlements(uid)`

Reads `userEntitlements/{uid}` and returns the already-resolved
`EffectiveUserEntitlements` a caller should actually use. Never creates the
document as a side effect of reading it.

### No document

The document is not required to exist. A missing document simply means
Free — this is the normal, expected state for the vast majority of users,
not an error path. Nothing creates the document automatically on read.

### Active document

If `subscriptionStatus == "active"` and (`validUntil == null` or
`validUntil` is in the future), the stored `plan`/limits/`turnAccessAllowed`
are returned as-is. A stored `turnAccessAllowed: false` on an otherwise
active/valid document is honored — an explicit TURN deny always survives
into the effective result (see "Explicit TURN deny" below).

### Expired

If `validUntil` is in the past, or `subscriptionStatus == "expired"`, the
effective result is Free — same numbers as "no document". This is a
**downgrade, not a lockout**: a Premium grant lapsing does not stop the user
from using the app, it just returns them to Free limits.

### Blocked

If `subscriptionStatus == "blocked"`, the effective result is:

```
maxCameras: 0
maxHomeDevices: 0
maxConcurrentLiveSessions: 0
turnAccessAllowed: false
```

regardless of any other field on the document (including `validUntil`) —
`blocked` is checked before the expiry rule, so a blocked-and-also-expired
document is still just "blocked", not "Free".

### Explicit TURN deny

A stored `turnAccessAllowed: false` on an otherwise active, non-blocked
document is preserved into the effective result exactly as stored — it is
never relaxed back to `true`.

### Corrupt document

A document is treated as corrupt (and never partially trusted) if any of:

- `plan` is not one of `"free"`/`"premium"`/`"custom"`
- `subscriptionStatus` is not one of `"active"`/`"expired"`/`"blocked"`
- `source` is not one of `"default"`/`"manual"`/`"promo"`/`"google_play"`
- any required field is missing
- `maxCameras`/`maxHomeDevices`/`maxConcurrentLiveSessions` is negative
- `maxCameras`/`maxHomeDevices`/`maxConcurrentLiveSessions` is not an integer
- `validUntil` is neither `null` nor a Firestore `Timestamp`
- `schemaVersion` is not `1`
- `createdAt` is missing or is not a Firestore `Timestamp`
- `updatedAt` is missing or is not a Firestore `Timestamp`

On a corrupt document: `getEffectiveUserEntitlements` never throws, logs one
structured `USER_ENTITLEMENTS_CORRUPT_DOCUMENT_FALLBACK_FREE` warning, and
returns Free defaults. That warning is deliberately narrow — it contains
only a fixed `CorruptEntitlementsReason` enum value (e.g.
`INVALID_SCHEMA_VERSION`, `INVALID_LIMIT`, `INVALID_CREATED_AT`) describing
*which* check failed, plus `schemaVersion` when (and only when) it is
itself a safe plain number. It never contains the `uid`, an email, the
document path, a purchase token, TURN credentials/secret, or any other raw
value from the document. A corrupt document's individual valid-looking
fields are never mixed into the Free fallback — the fallback is always the complete,
untouched Free default object.

## Enforcement in `getTurnCredentials`

After `getTurnCredentials`' existing Firebase Auth and camera-pairing
checks, it now calls:

```ts
const entitlements = await getEffectiveUserEntitlements(uid, db);
if (!entitlements.turnAccessAllowed) {
  throw new HttpsError("permission-denied", "TURN_ACCESS_DENIED");
}
```

before issuing TURN credentials. The client only ever sees the generic
`permission-denied` / `TURN_ACCESS_DENIED` error — never the internal reason
(plan, blocked status, expiry, or any other document detail).

`maxHomeDevices` and `maxConcurrentLiveSessions` are **not** checked
synchronously here or anywhere else yet (`maxHomeDevices` is only enforced
by the best-effort reconcile pass; `maxConcurrentLiveSessions` needs
server-side Live View session tracking). `maxCameras` is enforced
separately, in `claimCameraForUser` (see its own transaction) -- not part of
this callable.

## Example documents

### Free — no document needed

A Free user simply has no `userEntitlements/{uid}` document at all. Nothing
needs to be written for the default plan to apply.

### Manual lifetime Premium grant

```json
{
  "schemaVersion": 1,
  "plan": "premium",
  "subscriptionStatus": "active",
  "maxCameras": 5,
  "maxHomeDevices": 5,
  "maxConcurrentLiveSessions": 2,
  "turnAccessAllowed": true,
  "source": "manual",
  "validUntil": null,
  "createdAt": "<Firestore Timestamp>",
  "updatedAt": "<Firestore Timestamp>"
}
```

`validUntil: null` means this grant never expires.

### Temporarily blocked user

```json
{
  "schemaVersion": 1,
  "plan": "free",
  "subscriptionStatus": "blocked",
  "maxCameras": 1,
  "maxHomeDevices": 1,
  "maxConcurrentLiveSessions": 1,
  "turnAccessAllowed": false,
  "source": "manual",
  "validUntil": null,
  "createdAt": "<Firestore Timestamp>",
  "updatedAt": "<Firestore Timestamp>"
}
```

The stored `maxCameras`/`maxHomeDevices`/`maxConcurrentLiveSessions`/
`turnAccessAllowed` values here are irrelevant — `subscriptionStatus:
"blocked"` always overrides them to the zeroed-out/denied effective result
described above.

`createdAt` and `updatedAt` **must** be real Firestore `Timestamp` values in
every document above — a string, number, or missing field for either makes
the document corrupt (see "Corrupt document").
