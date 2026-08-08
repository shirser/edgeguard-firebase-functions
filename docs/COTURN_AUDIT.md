# coturn / VPS Relay Audit — verified server state

Read-only audit of `turn.edgeguard.cc`, the external VPS running coturn, performed via direct SSH
inspection. Supersedes an earlier pre-SSH-access audit that could only reason from the Firebase
Functions source and public DNS/WHOIS records — every fact below was read directly from the
running server, not inferred or guessed. `static-auth-secret` itself is never recorded in this
document or anywhere in this repo; only the fact that the directive is present is noted.

## VPS

| Field | Value |
|---|---|
| OS | Ubuntu 24.04.4 LTS |
| Public IPv4 | 51.83.240.144 |
| Public IPv6 | 2001:41d0:601:1100::84c3 |
| coturn version | 4.6.1 |

## systemd service

```
ExecStart=/usr/bin/turnserver -c /etc/turnserver.conf --pidfile=
```

- Runs as a dedicated `turnserver` user/group (not root).
- `InaccessibleDirectories=/home` — the service cannot read user home directories.
- `PrivateTmp=yes` — isolated `/tmp`.
- `Restart=on-failure`.

## Effective `/etc/turnserver.conf`

```
listening-port=3478
tls-listening-port=5349
listening-ip=51.83.240.144
relay-ip=51.83.240.144
min-port=49152
max-port=65535
realm=turn.edgeguard.cc
server-name=turn.edgeguard.cc
fingerprint
use-auth-secret
stale-nonce=600
no-tlsv1
no-tlsv1_1
no-dtls
no-loopback-peers
no-multicast-peers
no-cli
```

Plus a configured TLS certificate (path/contents not reproduced here). `use-auth-secret` mode is
confirmed active, matching the TURN REST API credential scheme `getTurnCredentials` (Firebase
Functions) already implements — `username = <expiresAt>:<uid>`, `credential =
Base64(HMAC-SHA1(TURN_REST_SECRET, username))`. The secret value itself was not retrieved and is
not stored here.

coturn currently listens on **IPv4 only** — the relay does not bind the VPS's public IPv6 address,
even though the host itself has one and IPv6 is routable.

### Present, and effective

- `no-loopback-peers` — blocks relaying toward 127.0.0.0/8.
- `no-multicast-peers` — blocks relaying toward multicast ranges.
- `no-cli` — the coturn CLI/admin interface is disabled outright, not just firewalled.
- `stale-nonce=600` — nonce rotation window (mostly moot under pure `use-auth-secret` mode, which
  has no persistent per-session nonce to rotate, but confirms the directive is set).
- `fingerprint` — STUN/TURN fingerprint attribute enabled.
- TLS: `no-tlsv1`/`no-tlsv1_1`/`no-dtls` — legacy TLS 1.0/1.1 and DTLS are explicitly disabled;
  only TLS 1.2+ over TCP (5349) is offered.

### Verified absent

- `user-quota` — no per-user allocation cap.
- `total-quota` — no server-wide allocation cap.
- `max-bps` / `bps-capacity` — no bandwidth ceiling, per-session or server-wide.
- `denied-peer-ip` — **no explicit RFC1918/link-local/private-range denylist.** `no-loopback-peers`
  and `no-multicast-peers` are present, but nothing blocks relaying toward the rest of RFC1918
  (10/8, 172.16/12, 192.168/16), link-local (169.254.0.0/16, including cloud metadata endpoints at
  169.254.169.254), or the IPv6 equivalents (ULA `fc00::/7`, link-local `fe80::/10`). This is the
  live SSRF gap.
- No session-aware TURN authorization of any kind — coturn's `use-auth-secret` validation is
  local-only (HMAC recompute + expiry check); it has no concept of a Firebase uid, Home, Camera,
  Live View session, or entitlement, and cannot be told to reject an otherwise-valid credential
  based on any of those.
- No per-user bandwidth control (follows from the missing `max-bps`/`user-quota`).
- No issuance rate limit at coturn itself — rate limiting, if it exists at all, would have to live
  in front of coturn (Firebase Function or a future VPS-side service), not in coturn's own config.

## UFW (host firewall)

Default policy: **deny incoming**.

| Port | Protocol | Scope |
|---|---|---|
| 22 | tcp | public |
| 80 | tcp | public |
| 3478 | tcp | public |
| 3478 | udp | public |
| 5349 | tcp | public |
| 49152:65535 | udp | public |

Equivalent IPv6 allow rules exist for the same ports. Since coturn itself only binds IPv4
(`listening-ip=51.83.240.144`), the IPv6 firewall openings are currently unused by the relay —
they don't correspond to a live IPv6 listener yet.

## Routing

- IPv4 default route via `51.83.240.1`.
- No private IPv4 routes present on the host — the VPS has no direct network path into an RFC1918
  range by routing alone (the SSRF risk above is about what coturn's *config* permits it to
  attempt, not about routes existing to internal EdgeGuard infrastructure specifically).
- IPv6 default route is configured.

## Security architecture — division of responsibility

**Firebase is the authorization/control plane**: identity (Firebase Auth), device registry,
ownership, Home↔Camera binding, entitlements, and Live View session/lease/allocator state all live
there, fully enforced before a TURN credential is ever issued.

**The VPS/coturn is the media relay plane**: once `getTurnCredentials` hands out a valid
`username`/`credential` pair, coturn evaluates it entirely on its own — a recomputed HMAC and an
expiry check on the FIRST authenticated request only (see "Credential TTL vs. allocation lifetime"
below for the source-verified detail: the expiry timestamp is not re-checked on `Refresh`).

**Key architectural conclusion, now confirmed against live server state AND coturn's own 4.6.1
source (not just code + documented coturn defaults):** Firebase can decide *whether* Live View is
authorized. It cannot decide what happens to the relay traffic *after* coturn accepts that
credential — coturn has no quota, no bandwidth cap, and no peer-network restriction beyond
loopback/multicast, and (see below) that exposure is NOT bounded by `TURN_CREDENTIAL_TTL_SECONDS`
once an allocation has been established and refreshed even once — only by how long the client
keeps its connection open and keeps refreshing.

## Credential TTL vs. allocation lifetime (source-verified against coturn 4.6.1)

**Correction (this section previously reached the wrong conclusion — see below for what changed).**
The original write-up below claimed the REST credential's embedded timestamp is re-checked on every
authenticated request (including `Refresh`), and that this bounds a client-held allocation to
"~10 minutes of leftover credential TTL plus one more ≤600s lifetime window." A closer reading of
the actual 4.6.1 control flow (not just the function names/doc comments) shows this is **wrong**:
the timestamp is checked at most **once per connection**, and an allocation that has been
`Refresh`ed even once can be kept alive **indefinitely**, with no dependency on the original
credential's `expiresAt` at all. Do not cite the old conclusion; the corrected findings below
supersede it.

Open question from the hardening plan: does ending a Live View session on the Firebase side tear
down a TURN allocation that a credential from that session already established, or does it only
block issuance of *new* credentials? This was resolved by reading coturn's actual 4.6.1 source
(tag `4.6.1` on github.com/coturn/coturn), not by SSH'ing into the VPS — the behavior is a property
of the coturn version running there, not of anything specific to this deployment's config.

**Finding 1 — the REST-API credential's embedded expiry timestamp is validated ONLY ONCE per TURN
session, not on every authenticated request.** `check_stun_auth()`
(`src/server/ns_turn_server.c:3304-3541`) only calls the `userkeycb` callback (`get_user_key()`,
where the timestamp check actually lives — `turn_time_before(ts, ctime)`,
`src/apps/relay/userdb.c:535-549`) when the connection's own session struct has **no cached key
yet**:

```c
/* Password */
if(!(ss->hmackey_set) && (ss->pwd[0] == 0)) {
    (server->userkeycb)(...);   /* -> get_user_key(): the ONLY place the timestamp is checked */
    ...
}
/* Check integrity */
if(stun_check_message_integrity_by_key_str(..., ss->hmackey, ss->pwd, ...) < 1) { ... }
```
(`src/server/ns_turn_server.c:3496-3520`)

`ss->hmackey_set` is set to `1` the moment the FIRST authenticated request on a connection succeeds
(`resume_processing_after_username_check`, `src/server/ns_turn_server.c:3283`) and is never cleared
again under `use-auth-secret`/non-OAuth mode — the only code path that resets it (`ss->hmackey_set =
0`, line 3449) is gated on `ss->oauth`, which is false for this deployment's REST-secret scheme.
`check_stun_auth()` is the exact same function used for `Allocate`, the standard `Refresh` path
(call site at `src/server/ns_turn_server.c:3748`), `CreatePermission`, and `ChannelBind` (all
confirmed call sites: lines 1681, 2489, 3748). So: the first successful request on a connection
authenticates via `get_user_key()` and caches the key; **every subsequent `Refresh` on that same
connection reuses the cached key for its `MESSAGE-INTEGRITY` check and never calls `get_user_key()`
again** — meaning the REST username's embedded timestamp is never re-examined past that first
request.

**Finding 2 — in REST-secret mode, a client cannot even rotate to a fresh credential mid-session.**
If a client tries to present a *different* STUN `USERNAME` on an already-authenticated, non-OAuth
connection, `check_stun_auth()` rejects it outright with `437`/`441`
(`src/server/ns_turn_server.c:3444-3452`) rather than re-validating the new username. A client is
therefore locked to whatever credential it first authenticated with for the life of that
connection — it can neither be forced to re-prove a fresh timestamp, nor could it voluntarily do so
even if it wanted to.

**Finding 3 — this is still a passive check with no active revocation (this part of the original
finding stands), but the practical consequence is stronger than originally stated.** coturn has no
mechanism by which Firebase (or anything else) can proactively tell it "this session just ended,
tear down this specific allocation now" — that part was correct. What was wrong is the assumption
that the *passive* timestamp check would eventually catch an expired credential on its own: per
Finding 1, it structurally cannot, past the first request on a connection, regardless of how much
time has passed or how many times the allocation has been refreshed since.

**Finding 4 — `max-allocate-lifetime` bounds each individual grant, not an allocation's cumulative
lifetime (corrects the original Finding 3's conclusion).** `stun_adjust_allocate_lifetime()`
(`src/client/ns_turn_msg.c:1253-1264`) caps the lifetime value returned by a *single*
`Allocate`/`Refresh` call against `max-allocate-lifetime` (or the compiled-in
`STUN_DEFAULT_MAX_ALLOCATE_LIFETIME = 3600`s default this VPS falls back to, since it does not set
the directive). It is not a ceiling on the allocation's total life: every successful `Refresh`
resets the allocation's expiry to an **absolute** `now + lifetime` —
`refresh_relay_connection()` (`src/server/ns_turn_server.c:4468-4494`) calls
`set_allocation_lifetime_ev(a, server->ctime + lifetime, ev, family)` backed by a freshly re-armed
`set_ioa_timer(server->e, lifetime, ...)` — never decremented from any ceiling anchored to the
original `Allocate`. The one field that could impose an additional, independent per-session ceiling
(`ss->max_session_time_auth`, `stun_adjust_allocate_lifetime`'s third argument) is populated only by
the **OAuth** branch of `get_user_key()` (`*max_session_time = to - ct`,
`src/apps/relay/userdb.c:513-514`); the REST-secret (`use_auth_secret_with_timestamp`) branch never
touches it, leaving it at its initialized `0` (`src/apps/relay/userdb.c:405-406`) for this
deployment's auth mode — which makes the `if(max_lifetime && ...)` guard in
`stun_adjust_allocate_lifetime` (`src/client/ns_turn_msg.c:1259`) permanently inert here. So: for
this deployment's auth mode, nothing bounds how many times an allocation can be refreshed, only how
big each individual refresh's grant can be (≤3600s).

**Combined consequence — this changes the "definition of done" conclusion, not just a footnote.** A
client that has ever successfully established an allocation on a given connection can keep that
allocation alive **indefinitely** — past its original credential's `expiresAt`, past any Live View
session ending, past any Firebase-side revocation — simply by sending a `Refresh` at least once
every ≤`max-allocate-lifetime` seconds (≤3600s here) on that same connection. coturn never
re-examines the credential's embedded timestamp after the first successful request on that
connection, and `max-allocate-lifetime` bounds only the size of each individual grant, not how many
times it can be granted. The exposure window is **not** "≈10 minutes of leftover credential TTL
plus one more ≤600s lifetime window" as the original version of this document stated — it is
bounded only by how long the client keeps its underlying connection to coturn open and how often it
chooses to `Refresh`, neither of which this project has any visibility into or control over once a
credential has been issued and used at least once.

**Consequence for the hardening plan — corrected.** The "definition of done" claim that a
VPS-issued grant makes a credential "unusable without a genuinely ACTIVE session" describes
*issuance* only, as previously noted — but the previously-stated mitigation ("shortening credential
TTL further... directly shrinks the window") is **wrong** for any allocation that has already been
`Refresh`ed at least once: shrinking `TURN_CREDENTIAL_TTL_SECONDS` shrinks the window during which a
credential can be used to establish a *new* allocation via `Allocate` — it has **no effect** on how
long an allocation already established (and refreshed even once) can keep being refreshed, since
that no longer depends on the credential's timestamp at all. Closing this gap requires the VPS Auth
API (or an equivalent) to periodically re-check still-open allocations against Firebase's own Live
View session state and administratively tear down (or refuse to further extend) stale ones — there
is no way to close it by tuning coturn's config or the credential TTL alone. Do not claim a short
credential TTL bounds the lifetime of an already-established allocation in any future revision of
this document or the hardening plan; treat this as a higher-priority follow-on item than the
original version of this section implied.

## Future direction

1. Harden coturn at the VPS level (quotas, bandwidth caps, `denied-peer-ip` for
   RFC1918/link-local/ULA, matching IPv6 relay config or an explicit decision to stay IPv4-only).
2. Add a small TURN Auth API beside coturn on the same VPS.
3. Have it verify a short-lived signed grant from Firebase (which itself verifies ID token
   identity **and** an ACTIVE Live View session) before issuing anything — the VPS should not read
   Firestore or hold Firebase Admin SDK credentials directly.
4. Issue short-lived, opaque TURN credentials (no raw uid in the username, TTL well under today's
   10 minutes) — see "Credential TTL vs. allocation lifetime" above: this shrinks the window during
   which a credential can be used to establish a *new* allocation, but (source-verified against
   coturn 4.6.1) has **no effect** on an allocation that has already been `Refresh`ed at least once
   — that allocation's lifetime no longer depends on the credential's timestamp at all once cached.
   Closing the post-session exposure window requires item 6's periodic re-check/teardown, not a
   shorter TTL.
5. Eventually keep `TURN_REST_SECRET` only on the VPS, removed from Firebase Secret Manager
   entirely, once the VPS is the sole issuer.
6. Add quotas, bandwidth limits, peer-network restrictions, metrics, and an emergency kill switch —
   for allocation lifetime specifically, this must include the VPS Auth API (or equivalent)
   periodically re-checking still-open allocations against Firebase's own Live View session state
   and administratively tearing down (or refusing to further extend) stale ones; see "Credential TTL
   vs. allocation lifetime" above for why this is the *only* mechanism that actually bounds a
   refreshed allocation's lifetime under this deployment's auth mode.
