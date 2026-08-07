# Live View Sessions — stage 1 of coturn abuse protection

A server-issued, short (90 second), renewable lease binding **{ownerUid, homeDeviceId,
cameraDeviceId}**. Business logic lives in `functions/src/liveViewSessions.ts`; the three callables
themselves — `startLiveViewSession`, `renewLiveViewSession`, `endLiveViewSession`, including their
own request-shape parsing, logging, and `LiveViewSessionDenialReason` → `HttpsError` mapping — live
in `functions/src/liveViewCallables.ts`. `functions/src/index.ts` only re-exports these three names;
it contains no Live-View-specific logic of its own.

This is explicitly the **first** stage of protecting the external coturn server from being used as
an arbitrary open TURN relay. A Live View session is a server-side authorization record — **it is
not yet bound to a TURN credential at all**. `getTurnCredentials`, the TURN credential
format/TTL/secret, and coturn itself are completely unchanged by this stage; see "What this stage
deliberately does NOT do" below for why that binding is future work, not an oversight.

## Why the challenge/signature mechanism, not a new one

All three callables are authorized by the *existing* HOME challenge/signature/device-proof
mechanism (`functions/src/deviceChallenges.ts`, `createDeviceChallenge`, Android Keystore P-256
signatures) — the same canonical device-proof payload, the same signature verification, the same
challenge invariants (schema/id/purpose/authUid/used/expiry/nonce/requestHash format) already
proven out for `getTurnCredentials`. Concretely, there is exactly **one** shared, transaction-local
verification primitive — `verifyDeviceChallengeForConsumption(t, db, params)` in
`deviceChallenges.ts` — that both `consumeVerifiedTurnCredentialsChallenge` (the existing
`getTurnCredentials` flow) and all three Live View operations call. It accepts the *caller's own*
open transaction (never opens one of its own, never writes anything itself) and performs every
identity/challenge check in one place: challenge existence, `schemaVersion`, `challengeId` identity,
purpose match, `request.auth.uid` match, replay (`usedAt`), expiry (server time), nonce/requestHash
format, the registered device's existence/role/`authUid`/`identityMode === "keystore"`/public key,
the recomputed canonical request hash, and the P-256 signature over the canonical device-proof
payload. Two parameters let each caller narrow it without forking the logic: `expectedRole` (TURN
credentials accept either HOME or CAMERA; Live View passes `"HOME"`) and
`requireOwnerUidEqualsAuthUid` (Live View's HOME-is-always-self-owned invariant; never set for
TURN). Operational status (suspended/revoked) is *computed* by the primitive but deliberately
**not enforced** by it — it is returned to the caller, which decides: `getTurnCredentials` and
Live View `START`/`RENEW` enforce it immediately; `END` deliberately does not (see "Threat model").
There is no second, parallel signature/proof-verification implementation anywhere in this feature —
the module-level `verifyHomeDeviceChallenge` in `liveViewSessions.ts` is a thin, non-verifying
adapter that only narrows the shared primitive's generic result to this module's own types.

Three new challenge purposes were added:
`LIVE_VIEW_START`, `LIVE_VIEW_RENEW`, `LIVE_VIEW_END` — each bound, via the challenge's own
`requestHash`, to a different canonical payload:

| Purpose | Bound to | Why |
|---|---|---|
| `LIVE_VIEW_START` | `cameraDeviceId` | No session exists yet to bind to. |
| `LIVE_VIEW_RENEW` | `sessionId` | The specific existing session being extended. |
| `LIVE_VIEW_END` | `sessionId` | The specific existing session being closed. |

**The canonical Home device is never taken from `request.data`.** A client-supplied `homeDeviceId`
would not even be accepted (`startLiveViewSession`'s request shape is exactly
`{cameraDeviceId, deviceProof}`, `renewLiveViewSession`/`endLiveViewSession`'s is exactly
`{sessionId, deviceProof}` — any other field, including `homeDeviceId` or a timestamp, is rejected
outright as `INVALID_REQUEST` before anything else runs). The Home identity is always the verified
`deviceId` embedded in the signed challenge, cross-checked against `registeredDevices/{deviceId}`
(`role === "HOME"`, `authUid === ownerUid === request.auth.uid`, `identityMode === "keystore"`) —
exactly the same identity-then-role-then-ownership ordering `claimCameraForUser`'s own ownership
audit fix established, applied here from the start.

## Firestore schema

### `liveViewSessions/{sessionId}`

```
{
  schemaVersion: 1,
  sessionId: string,
  ownerUid: string,
  homeDeviceId: string,
  cameraDeviceId: string,
  status: "ACTIVE" | "ENDED",
  createdAt: Timestamp,
  updatedAt: Timestamp,
  leaseExpiresAt: Timestamp,
  endedAt: Timestamp | null,
}
```

`{sessionId}` is always server-generated (`db.collection("liveViewSessions").doc().id`) — never
client-suppliable as a value to create; only ever referenced (by the client, as a request field on
renew/end) after the server has already returned it from a successful `startLiveViewSession` call.
Firestore's own auto-id generator always produces **exactly 20 characters from `[A-Za-z0-9]`** —
`isValidLiveViewSessionIdFormat` (`deviceChallenges.ts`) is pinned to that exact shape
(`/^[A-Za-z0-9]{20}$/`), not a generous upper bound, since a Live View `sessionId`'s generator is
entirely this codebase's own choice with a fully known, fixed output shape. This is the **one**
canonical Live View session-id validator — used by challenge request-payload validation, the
`renewLiveViewSession`/`endLiveViewSession` callables' own request-shape checks (*before* ever using
the value to build a document reference — otherwise a `/`-containing string could address an
arbitrary nested document path, not just a top-level `liveViewSessions/{sessionId}` document),
allocator-entry parsing, and canonical session parsing — never a second, separately-maintained
pattern anywhere in this feature. The document's own `sessionId` field is redundant with its
document ID by construction, but is stored and strictly re-checked (`data.sessionId === sessionId`)
on every read specifically so a session document can never be silently swapped/aliased to a
different id without detection.

**Every read of this document goes through one strict parser, `parseLiveViewSession(sessionId,
data)`.** It rejects wholesale (never a partial acceptance of "the fields that did parse") on: a
`sessionId` argument that does not itself pass `isValidLiveViewSessionIdFormat`; any key outside
the fixed allowed set; wrong `schemaVersion`; `data.sessionId !== sessionId`; an empty or
over-length (>128 char) `ownerUid`/`homeDeviceId`/`cameraDeviceId`; a `status` other than exactly
`"ACTIVE"`/`"ENDED"`; a non-`Timestamp` `createdAt`/`updatedAt`/`leaseExpiresAt`; `status ===
"ACTIVE"` with a non-null `endedAt`; or `status === "ENDED"` with a non-`Timestamp` `endedAt`. A
session that fails this parse is treated exactly like a missing one (`SESSION_MALFORMED` — a
distinct reason from `SESSION_NOT_FOUND`, but both collapse to the same generic public denial) —
never repaired, never partially trusted.

### `liveViewUserStates/{uid}` — the allocator

```
{
  schemaVersion: 1,
  updatedAt: Timestamp,
  integrityStatus: "HEALTHY" | "CORRUPT",
  corruptAt: Timestamp | null,
  corruptionReason: "PARSE_FAILED" | null,
  activeSessions: {
    [sessionId]: {
      sessionId: string,
      homeDeviceId: string,
      cameraDeviceId: string,
      createdAt: Timestamp,
      leaseExpiresAt: Timestamp,
    },
  },
}
```

One document per user, coordinating **every** start/renew/end for that user through a single
document's own optimistic-concurrency conflict detection (see "Transaction boundaries" below).
`activeSessions` is a **bounded map**, not an unbounded log — an entry exists only while its
session is actually occupying a concurrent-session slot, and is removed the moment that slot is
freed (lease expiry, pruned lazily; or an explicit `endLiveViewSession`).

**Strict, bounded parsing (`parseAllocatorState`)**, applied to every read: a missing document
parses as a valid, empty, `HEALTHY` allocator; any other shape mismatch is treated as **fully
corrupt** (`ALLOCATOR_STATE_INVALID` for START/RENEW — see "Corrupt allocator handling" below),
including (once `integrityStatus === "CORRUPT"` — see below — has already been ruled out): wrong
`schemaVersion`; an unrecognized top-level key; `integrityStatus` missing or not exactly
`"HEALTHY"`/`"CORRUPT"`; a `"HEALTHY"` document whose `corruptAt`/`corruptionReason` are not both
`null`; a non-`Timestamp` `updatedAt`; `activeSessions` not a plain object (e.g. an array); more
than `LIVE_VIEW_ALLOCATOR_MAX_ENTRIES` (**32**, a fixed, defensive ceiling independent of any
user's own `maxConcurrentLiveSessions` entitlement — it exists purely to bound how much work one
transaction ever spends parsing/pruning/rewriting the map, not as a plan limit — also enforced on
the *write* side, see "Allocator invariant" above); a map key that does not pass the same canonical
`isValidLiveViewSessionIdFormat` (exactly 20 characters from `[A-Za-z0-9]`) the
`liveViewSessions/{sessionId}` document id itself must satisfy; an entry whose own `sessionId`
field disagrees with its map key; an empty or over-length `homeDeviceId`/`cameraDeviceId`; a
non-`Timestamp` `createdAt`/`leaseExpiresAt`; or two entries under different session ids sharing
the same `(homeDeviceId, cameraDeviceId)` pair — compared via `JSON.stringify([homeDeviceId,
cameraDeviceId])`, never a delimiter-joined string, since device IDs are otherwise-unrestricted and
may themselves contain any character, including whatever separator a joined string would use (two
simultaneously "claimed" slots for the same pair would violate idempotent START's own
one-slot-per-pair invariant). The parsed map itself is built with `Object.create(null)`, never a
plain `{}` literal, so a stored key can never collide with or shadow a JS object prototype
property. `integrityStatus === "CORRUPT"` is checked and short-circuited as the very **first**
thing done once there is a document to inspect at all — strictly before the unexpected-key check,
`schemaVersion`, `updatedAt`, `activeSessions`, or any other structural validation — see "Corrupt
allocator handling" for why this exact ordering is load-bearing, not incidental.

**`validateAllocatorEntryAgainstSession(entry, session, allocatorOwnerUid, nowMillis)`** is the one
function that cross-checks an allocator entry against its own canonical session document — used by
both idempotent START and RENEW, never a looser "does a document exist with `status === "ACTIVE"`
and a future lease" check. It requires *all* of: `entry.sessionId === session.sessionId`,
`session.ownerUid === allocatorOwnerUid`, `entry.homeDeviceId === session.homeDeviceId`,
`entry.cameraDeviceId === session.cameraDeviceId`, `entry.createdAt.isEqual(session.createdAt)`,
`entry.leaseExpiresAt.isEqual(session.leaseExpiresAt)`, `session.status === "ACTIVE"`,
`session.endedAt === null`, and `session.leaseExpiresAt.toMillis() > nowMillis`. Any single
disagreement denies with `ALLOCATOR_SESSION_MISMATCH` (idempotent START) or the equivalent direct
session-state check (RENEW checks `ownerUid`/`homeDeviceId`/`status`/lease-expiry directly against
the session *before* ever consulting the allocator, so those specific mismatches surface as
`SESSION_OWNER_MISMATCH`/`SESSION_HOME_MISMATCH`/`SESSION_NOT_ACTIVE`/`SESSION_LEASE_EXPIRED`
instead — externally indistinguishable, all collapsing to the same generic denial).

Both collections are **function-only**: they are new, top-level collections not mentioned anywhere
in `firestore.rules`, and Firestore denies any request to a path with no matching `match` rule by
default — no rule change was needed or made.

## Session state machine

```
        startLiveViewSession (new pair)
                  │
                  ▼
   (no doc)  ──────────────►  ACTIVE ──────────────►  ENDED
                              │      ▲                  │
                              │      │ renewLiveViewSession
                              │      │ (resets leaseExpiresAt = now + 90s)
                              │      └──────────────────┘
                              │
                              │ lease elapses (leaseExpiresAt <= now)
                              ▼
                        logically inactive
                      (lazily pruned on the
                       next start/renew/end
                       for this owner)
```

`ENDED` is terminal — there is no path back to `ACTIVE`. A session is considered **active** only
when *all three* hold simultaneously:

1. `status === "ACTIVE"`,
2. `leaseExpiresAt > now` (server time),
3. `sessionId` is present in `liveViewUserStates/{uid}.activeSessions`.

Any disagreement between these three (e.g. the allocator lists an entry whose own session document
says `ENDED`, or is missing, or expired) is treated **fail-closed** — see "Fail-closed integrity"
below — never silently resolved in the direction that would grant access.

## Lease semantics

```ts
export const LIVE_VIEW_LEASE_TTL_MS = 90_000;
```

- **START**: `leaseExpiresAt = serverNow() + 90_000`.
- **RENEW**: `leaseExpiresAt = serverNow() + 90_000` — **always reset from the current server
  time, never extended from the old `leaseExpiresAt`**. A chain of renews can therefore never
  accumulate into an arbitrarily long-lived lease; a client that stops renewing loses its slot
  within 90 seconds, deterministically.
- All lease math uses server-side `Date.now()` (or, inside a transaction, the same `nowMillis`
  passed in once at the top of the callable) — never a client-supplied timestamp. Every request
  shape check (`START_LIVE_VIEW_SESSION_ALLOWED_KEYS`, etc.) rejects any extra field outright, so a
  client cannot even attempt to smuggle in a `leaseExpiresAt` value.
- An expired session cannot be renewed (`SESSION_LEASE_EXPIRED`), and is logically inactive even
  before any document is physically touched — see "Lazy cleanup" below.

## Allocator invariant

The limit (`userEntitlements/{uid}.maxConcurrentLiveSessions`, resolved via the existing canonical
`effectiveUserEntitlementsFromData` — see "Entitlements" below) is enforced by counting the
allocator's own `activeSessions` map, **read and pruned inside the same transaction that performs
the allocation**:

1. Read `liveViewUserStates/{uid}` (or default to an empty, valid allocator if the document does
   not exist yet).
2. Parse it strictly (`parseAllocatorState`) — any shape mismatch (wrong `schemaVersion`,
   `activeSessions` not an object, a malformed entry) is treated as **fully corrupt**, never a
   partial salvage of the fields that did parse.
3. Prune every entry whose own `leaseExpiresAt <= now` — these do not count toward the limit.
4. Only *then* is the resulting count compared against the **effective** limit — see below.

**`maxConcurrentLiveSessions` is additionally, always bounded by `LIVE_VIEW_ALLOCATOR_MAX_ENTRIES`
(32).** The effective ceiling a NEW slot is ever allocated against is
`min(maxConcurrentLiveSessions, LIVE_VIEW_ALLOCATOR_MAX_ENTRIES)`, never
`maxConcurrentLiveSessions` alone. Without this, an entitlement above 32 combined with an allocator
already holding exactly 32 (individually valid) entries would let a START write a 33rd —
`parseAllocatorState` would then reject that very document as corrupt on its own next read,
self-inflicted by the write path itself. This reuses the SAME `activeSessions` count already
computed for the ordinary limit check — never a second, separately-maintained counter. Consequence:
**the allocator can never be written above 32 entries by normal server code** — the only way a
stored document can ever exceed 32 is external tampering (e.g. a manual Firestore console edit),
which `parseAllocatorState` itself then correctly rejects as corrupt on the next read (see "Corrupt
allocator handling" below), never silently accepted. The idempotent same-`(homeDeviceId,
cameraDeviceId)` match (see "Idempotency" below) is checked *before* this ceiling, so an
already-active session remains reachable even when all 32 slots are occupied — only a genuinely
*new* slot is capped.

This is deliberately **not**:

- a separate `activeCount` field without the exact list (a counter can drift from reality; the map
  itself is always the ground truth used for the actual count),
- a query-only count of `ACTIVE` documents (a query read outside a transaction cannot be
  atomically combined with the allocation write — see "Transaction boundaries"),
- a read outside a transaction followed by a separate write,
- anything derived from a client-supplied timestamp.

## Entitlements

Only the canonical `userEntitlements/{uid}.maxConcurrentLiveSessions`, resolved via the existing,
unmodified `effectiveUserEntitlementsFromData` (same resolver every other consumer in this project
uses — no second, divergent copy). Legacy `users/{uid}.subscriptionUnits`/`cameraLimit` are never
read. A missing or malformed entitlement document falls back to the existing Free default
(`maxConcurrentLiveSessions: 1`) — the same safe fallback rule already established for
`maxCameras`/`maxHomeDevices`/`turnAccessAllowed`, not a new one invented for this stage.

**`RENEW` re-checks the limit, inside the same transaction as the renewal itself; `END` never
does.** After confirming the session/allocator are otherwise consistent, RENEW reads
`userEntitlements/{uid}` (the same read set as the rest of the transaction — never a second,
separately-timed read) and resolves it via the same canonical `effectiveUserEntitlementsFromData`
(legacy fields never consulted, same missing/malformed/blocked/expired → Free fallback rules as
everywhere else). It denies (`LIVE_VIEW_ENTITLEMENT_DENIED`, `resource-exhausted`) whenever the
account's **current** limit can no longer accommodate the number of sessions presently occupying a
slot — `Object.keys(prunedActive).length > maxConcurrentLiveSessions` — after lazily pruning expired
entries, and *including* the very session being renewed in that count. This is deliberately not
scoped to "does this one session's own rank exceed the limit": a downgrade that leaves an account
over its new limit denies renewal of **all** of that account's currently-active sessions equally,
never picking an arbitrary "winner" to keep renewable. `maxConcurrentLiveSessions === 0` is simply
the case where any positive active count is already over the (zero) limit. `END` never performs
this check — extending is a new grant of continued access and must be re-justified; closing a slot
is not, and must always succeed once identity/ownership are confirmed (see "Threat model").

## Idempotency

**START** is idempotent for the exact pair `(verifiedHomeDeviceId, cameraDeviceId)`: if the pruned
allocator already contains a valid, still-active entry for that pair, `startLiveViewSession`
returns that session's existing `sessionId` and its *current* `leaseExpiresAt` (it does **not**
implicitly renew it — that is `renewLiveViewSession`'s own job) and never allocates a second slot.
Two parallel identical START calls resolve to the same `sessionId` and occupy exactly one slot (see
`CONCURRENCY 1` in the test suite). A *different* camera or a *different* Home always occupies a
separate slot, subject to the same shared per-user limit.

`sessionId` is generated **before** the transaction callback runs (`candidateSessionId =
db.collection("liveViewSessions").doc().id`, computed once in the callable, passed in as a
parameter) — never inside it. Firestore retries a transaction callback verbatim on write conflict;
generating a fresh random id *inside* the callback would allocate a different id on every retry,
breaking "one sessionId per successful start."

**END** is idempotent: ending an already-`ENDED` session is a safe, successful no-op (still
consumes its own challenge, still prunes any stale allocator entry it finds) — never an error.

## Transaction boundaries

All three operations are exactly one `db.runTransaction` each, covering: challenge verification,
device/camera checks, and the allocation/renewal/termination write, in that order (reads before
writes, per Firestore's own requirement) — never a separate "verify" transaction followed by a
separate "act" transaction.

**START**: read challenge → read signing device (`registeredDevices/{homeDeviceId}`) → [verify
signature] → read Camera (`registeredDevices/{cameraDeviceId}`, `cameraClaims/{cameraDeviceId}`,
`users/{uid}/cameraDevices/{cameraDeviceId}`) → read `userEntitlements/{uid}` → read
`liveViewUserStates/{uid}` → decide (idempotent match / limit check / allocate) → write
`liveViewSessions/{sessionId}`, write `liveViewUserStates/{uid}`, mark the challenge used.

**RENEW**: read challenge → read signing device → [verify signature, check Home operational] →
read `liveViewSessions/{sessionId}`, `liveViewUserStates/{uid}`, and `userEntitlements/{uid}`
(same read set) → read Camera (registry/claim/link) → decide (session/allocator consistency, then
the entitlement re-check — see "Entitlements") → write `liveViewSessions/{sessionId}.leaseExpiresAt`,
write `liveViewUserStates/{uid}`, mark the challenge used.

**END**: read challenge → read signing device → [verify signature — Home operational status is
**not** checked] → read `liveViewSessions/{sessionId}` and `liveViewUserStates/{uid}` → decide
(already-ended vs. first end) → write `liveViewUserStates/{uid}` (full prune + target removal when
HEALTHY; `integrityStatus: "CORRUPT"` marked, `activeSessions` untouched, when not — see "Corrupt
allocator handling" — every time, unconditionally), write `liveViewSessions/{sessionId}.status =
"ENDED"` (skipped if already ended), mark the challenge used.

**Challenge consumption is always part of the same transaction and the same commit as the
session/allocator write it authorizes.** A transaction that denies the request performs *no*
writes at all — the challenge document is untouched, `usedAt` stays `null`, and the same
(unexpired) challenge could in principle still be retried with a *different* outcome if the
underlying denial condition is fixed (e.g. the entitlement limit is raised) — but never replayed
for a *different* request, since `requestHash`/`nonce`/`usedAt` are all still checked fresh.

Every read in every branch of every operation happens strictly before that operation's first
write — confirmed by direct inspection of each `t.get`/`t.set`/`t.update` call site, across every
denial branch as well as the success path, not only the normal path. There is no code path where a
write is followed by a later `t.get`.

## Concurrency: emulator transaction-retry gap

**Symptom**: under genuine two-way write contention on the shared `liveViewUserStates/{uid}`
allocator document (e.g. `CONCURRENCY 1`/`2`/`3` in the test suite — identical-pair START vs.
START, different-camera START vs. START at the limit, START vs. END), one side would
intermittently reject with:

```
3 INVALID_ARGUMENT: Transaction is invalid or closed.
```

**Root cause (confirmed via temporary instrumentation, since removed)**: this is not retry
exhaustion, not a bug in this module's transaction lifecycle, and not unsafe cross-attempt mutable
state — a full audit of every `runTransaction` callback (START/RENEW/END and the shared
`verifyDeviceChallengeForConsumption` primitive) found every read properly awaited before any
write, no `Transaction` object ever escaping its callback, no un-awaited promises, and every
retry-visible value (`candidateSessionId`, `nowMillis`, parsed allocator/session maps) either
intentionally stable across retries or freshly recomputed on every attempt. Instrumenting every
`t.get` with a label + attempt counter + elapsed-time confirmed the failure always occurred on
**attempt 1** (never attempt 2+) after roughly **9.0–9.6 seconds** elapsed — never a random or
exponentially-backed-off duration, and never a genuine second attempt being made at all.

The actual cause lives in `@google-cloud/firestore`'s own `transaction.js`
(`isRetryableTransactionError`): the Admin SDK already knows a transaction ID can be invalidated by
contention and already retries that condition automatically — but only when the error is gRPC code
3 (`INVALID_ARGUMENT`) **and** its message matches `/transaction has expired/`, which is
production Firestore's exact wording for this condition. The **local Firestore emulator** reports
the same legitimate, expected condition with **different wording** — `"Transaction is invalid or
closed"` — which that regex does not match. The SDK's retry loop therefore treats it as
non-retryable and gives up after exactly one attempt. Raising `runTransaction`'s `maxAttempts` has
**no effect** on this: the retry loop calls `break` on a non-retryable error before `maxAttempts`
is ever consulted again — confirmed by reading the loop itself, not assumed.

**Fix**: `runLiveViewTransaction` (`liveViewSessions.ts`), a thin wrapper every one of
START/RENEW/END now calls instead of `db.runTransaction` directly. It retries **only** this one,
precisely-identified condition (`err.code === 3` and `err.message` matching
`/transaction is invalid or closed/i`) — never any other error, and never "any rejection is fine"
— for up to `MAX_EMULATOR_TRANSACTION_RETRY_ATTEMPTS` (3) total attempts. Each retry re-invokes
`db.runTransaction` from scratch, so the callback re-verifies the challenge/signature/device
identity and re-reads current ownership/binding/entitlement/allocator/session state on every
attempt — replay protection, challenge-consumption atomicity, current-identity/ownership/binding
re-verification, current-entitlement re-check, and allocator/session atomicity are all fully
preserved; nothing is cached, skipped, or reused across a retry. This exactly mirrors what the
Admin SDK's own native retry would have done had the emulator used production's wording.

**This retry is strictly EMULATOR-ONLY and is not part of production Live View transaction
semantics.** It is gated on `process.env.FIRESTORE_EMULATOR_HOST` — the same standard environment
variable the Firestore Admin SDK itself reads to decide whether it is talking to the emulator,
never a custom configuration flag. When that variable is unset (production, and any environment
not talking to the emulator), `runLiveViewTransaction` is a pure passthrough straight to
`db.runTransaction` — no try/catch, no wrapping of any kind — so production error propagation and
Firestore's own native transaction retry behavior (`maxAttempts`, backoff) are byte-for-byte
unchanged. Production Firestore already uses the SDK-recognized `"transaction has expired"`
wording and has never needed this workaround; it exists solely to compensate for the emulator's
own differently-worded error text during local development and CI.

Consequently, the concurrency tests never need to (and do not) tolerate gRPC code 3 — the one
signal they may tolerate anywhere is a confirmed gRPC code 10 (`ABORTED`), production Firestore's
genuine retry-exhaustion status, and even that is only accepted where a losing side is expected to
race a winner.

## Lazy cleanup — no scheduled job

There is no scheduled/background cleanup function. Every `start`/`renew`/`end` call, inside its own
transaction, reads the allocator, drops every entry whose `leaseExpiresAt <= now`, and never counts
a dropped entry toward the limit — the *next* call for that user is always what performs the
pruning, and correctness never depends on anything running in the background. A session's own
`leaseExpiresAt` on the `liveViewSessions/{sessionId}` document itself is the source of truth for
whether it is logically active, independent of whether the document has been physically cleaned up.

## Fail-closed integrity

- A corrupt/unparseable allocator document denies `START`/`RENEW` outright
  (`ALLOCATOR_STATE_INVALID`) — never silently reset or repaired as a side effect of an allocation
  decision.
- An allocator entry that references a `(homeDeviceId, cameraDeviceId)` pair whose own
  `liveViewSessions/{sessionId}` document does not independently confirm `status === "ACTIVE"` and
  an unexpired lease denies the idempotent-START path (`ALLOCATOR_SESSION_MISMATCH`) rather than
  silently trusting the allocator's cached copy or creating a duplicate session.
- **Every successful `END` — including a repeated, idempotent one — attempts a full allocator
  cleanup, not a surgical removal of just the target `sessionId`.** When the allocator parses
  cleanly, it prunes **every** entry whose own `leaseExpiresAt <= now` (regardless of which session
  they belong to, not only the target), removes the target `sessionId` if still present, and writes
  the complete cleaned map back with a fresh `updatedAt`. See "Corrupt allocator handling" below for
  exactly what happens instead when the allocator does *not* parse cleanly.

## Corrupt allocator handling

**Design chosen: an explicit `integrityStatus: "HEALTHY" | "CORRUPT"` state machine on the
allocator document itself (option A)** — not automatic reconstruction from canonical session
documents (option B, out of scope for this stage; see "Future work" below).

**Why a blind reset is unsafe.** An earlier version of this design had `END` "repair" a corrupt
allocator by overwriting it with a clean, empty `activeSessions` map, reasoning that `END` only
ever removes a slot and therefore could never itself grant unauthorized access. That reasoning
missed a concrete bypass:

1. Sessions **A** and **B** are both canonically `ACTIVE` (real, valid `liveViewSessions` documents),
   both correctly present in the allocator's `activeSessions` map.
2. A third, malformed entry — or a corrupted **A** or **B** entry itself — is written into the SAME
   map (e.g. by a bug elsewhere, manual Firestore console edit, or a not-yet-understood race).
   `parseAllocatorState` fails the **entire** map on that one bad entry (never a partial parse), so
   the allocator is now "corrupt" as a whole, even though **A** and **B**'s own entries are
   individually fine.
3. `endLiveViewSession(A)` runs. Under the old design, `END` cannot parse the allocator, so it
   resets it to `{ activeSessions: {} }` as part of ending A.
4. **B is still canonically `ACTIVE`**, but its allocator entry is now gone. The allocator looks
   completely healthy and empty.
5. A subsequent `startLiveViewSession` for a *different* camera sees zero occupied slots and
   allocates a new session — even if the account's `maxConcurrentLiveSessions` was already fully
   consumed by session B alone. **Session-limit bypass.**

**How the explicit state machine prevents this.** `integrityStatus` makes "this document's
`activeSessions` can no longer be trusted, in either direction" an explicit, sticky, persisted
fact, completely decoupled from whatever `END` happens to be doing to one specific session:

- The FIRST time any operation's read of the allocator fails to parse it (schema mismatch,
  unparseable `activeSessions`, unknown `integrityStatus`, etc.), and that operation is `END` (the
  only writer allowed to touch this flag), it merges in exactly `{ integrityStatus: "CORRUPT",
  corruptAt: now, corruptionReason: "PARSE_FAILED", updatedAt: now }` — **`activeSessions` is
  deliberately omitted from this write and is never touched**, so whatever entries (A's, B's, the
  bad one) it currently holds are preserved byte-for-byte, not destroyed.
- `START` and `RENEW` never write this flag themselves — a corrupt/unreadable allocator simply
  denies them outright (`ALLOCATOR_STATE_INVALID`), exactly as for any other corruption, so an
  allocation decision is never made against state that can't be trusted.
- Once `integrityStatus === "CORRUPT"` is present, `parseAllocatorState` checks and short-circuits
  on it as the very **first** thing it does once there is a document to inspect at all —
  strictly before the unexpected-top-level-key check, before `schemaVersion`, before `updatedAt`,
  and before `activeSessions` or any other structural validation. This ordering is deliberate and
  load-bearing, not incidental: if any structural check ran first, a document that is already
  `CORRUPT` but *also* happens to have (for whatever reason — a bug, a manual edit) an invalid
  `schemaVersion` or an unexpected field on top of that would be misdiagnosed as a **freshly**
  discovered corruption instead of the *same*, already-known one — which would let `END` rewrite
  `corruptAt`/`corruptionReason` with a new timestamp, and (via `maybeMarkAllocatorCorrupt`'s own
  merge write, which always sets `schemaVersion` back to the current value) silently "repair" that
  stacked `schemaVersion` corruption as an unintended side effect, all while `activeSessions`
  itself still never gets safely reconstructed. Checking `integrityStatus === "CORRUPT"` first
  makes the flag genuinely sticky regardless of what else about the document is or becomes
  malformed — the flag is sticky and can never auto-heal just because the map happens to look
  structurally parseable again on a later read. `START`/`RENEW` keep denying; a repeat `END` sees
  `alreadyMarkedCorrupt: true` and performs **no write at all** to the allocator (not even
  `updatedAt`), so `corruptAt`/`corruptionReason` always reflect the *original* discovery, never a
  later repeat, and no stacked corruption is ever silently repaired.
- `END` itself never depends on the allocator being readable — its own identity/ownership
  verification (challenge signature, `session.ownerUid`/`session.homeDeviceId` match) is entirely
  independent of allocator state, so the target session is still transitioned to `ENDED` (or,
  idempotently, left `ENDED`) regardless of whether the allocator write above went down the
  healthy-cleanup or the mark-corrupt path.
- Re-running the walk-through above with this design: step 3 becomes "`END(A)` marks the allocator
  `CORRUPT`, touches nothing in `activeSessions`, and still ends session A." Step 5 becomes "a
  subsequent `startLiveViewSession` reads `integrityStatus: "CORRUPT"`, denies immediately
  (`ALLOCATOR_STATE_INVALID`), and allocates nothing." **No bypass is possible**: a corrupt
  allocator can never be observed as "zero active sessions" by any code path in this module.

**Future work (option B, not implemented in this pass).** Recovering a `CORRUPT` allocator back to
`HEALTHY` requires a *safe*, bounded, transactional reconstruction — e.g. an explicit, separately
audited admin operation that queries `liveViewSessions` for `ownerUid == uid && status == "ACTIVE"
&& leaseExpiresAt > now` (bounded, since a legitimate account can only ever have a small number of
concurrently-active sessions) and atomically rewrites `activeSessions` from that canonical set in
one transaction, only then clearing `integrityStatus` back to `"HEALTHY"`. This is **not** a
query-count used as the *normal* allocator mechanism (the map remains the source of truth for
every ordinary START/RENEW/END) — it is a one-time, explicit repair path, deliberately not
implemented as part of this change. Until it exists, a `CORRUPT` allocator remains blocked for
`START`/`RENEW` indefinitely; `END` remains available throughout.

## Threat model

- **In scope for this stage**: proving that a specific, currently-registered, operational HOME
  installation — cryptographically, via Keystore proof-of-possession, not merely "some Firebase
  Auth uid" — is requesting Live View access to a specific Camera it genuinely owns and has paired,
  within a short, renewable, server-enforced concurrency limit. Every identity/ownership/binding
  check that could otherwise become an oracle for another user's devices collapses to one generic
  `LIVE_VIEW_SESSION_DENIED` (`permission-denied`) in `index.ts`'s own error mapping — a caller can
  never use the response to learn whether a given `cameraDeviceId`/`sessionId` exists, who owns it,
  or which specific check failed. Only the caller's *own* entitlement limit
  (`LIVE_VIEW_SESSION_LIMIT_REACHED` on START, `LIVE_VIEW_ENTITLEMENT_DENIED` on RENEW — both
  `resource-exhausted`) and the caller's *own* device/challenge state (`CHALLENGE_EXPIRED`,
  `CHALLENGE_ALREADY_USED`,
  `DEVICE_SUSPENDED`/`DEVICE_SUSPENDED_PLAN`/`DEVICE_REVOKED` for a device already confirmed to be
  theirs) get a distinguishable reason.
- **`END` is deliberately reachable even for a since-suspended/revoked Home or Camera, or after a
  plan downgrade** — once identity and session ownership are confirmed, closing a session you
  already legitimately opened can never itself be the abuse this feature exists to prevent, and a
  user must always be able to free their own slot. `START`/`RENEW` do **not** get this leniency —
  they are exactly where a suspended/revoked/downgraded account is denied.
- **What this stage deliberately does NOT do** (future stages, not part of this one):
  - **Bind a session to an actual TURN credential.** `getTurnCredentials` is completely unchanged;
    obtaining TURN credentials and holding a valid Live View session are, today, two independent
    facts the client must separately satisfy. A future stage is expected to require an active
    session as a precondition for `getTurnCredentials` (or fold session issuance into it) — until
    then, a Live View session on its own does not yet gate coturn access, which is why this is
    explicitly framed as *stage 1*, not the complete defense.
  - Change the TURN credential format, TTL, REST secret, or coturn's own configuration/quotas.
  - Add server-side scheduled cleanup — see "Lazy cleanup" above.
  - Rate-limit `startLiveViewSession`/`renewLiveViewSession`/`endLiveViewSession` calls themselves
    (only the *concurrent session count* is bounded, not the call rate).
