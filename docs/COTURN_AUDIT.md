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
expiry check, nothing else.

**Key architectural conclusion, now confirmed against live server state (not just code +
documented coturn defaults):** Firebase can decide *whether* Live View is authorized. It cannot
decide what happens to the relay traffic *after* coturn accepts that credential — coturn has no
quota, no bandwidth cap, and no peer-network restriction beyond loopback/multicast for the
remaining 10 minutes (`TURN_CREDENTIAL_TTL_SECONDS`) that credential stays valid.

## Future direction

1. Harden coturn at the VPS level (quotas, bandwidth caps, `denied-peer-ip` for
   RFC1918/link-local/ULA, matching IPv6 relay config or an explicit decision to stay IPv4-only).
2. Add a small TURN Auth API beside coturn on the same VPS.
3. Have it verify Firebase ID token identity **and** an ACTIVE Live View session before issuing
   anything.
4. Issue short-lived, opaque TURN credentials (no raw uid in the username, TTL well under today's
   10 minutes).
5. Eventually keep `TURN_REST_SECRET` only on the VPS, removed from Firebase Secret Manager
   entirely, once the VPS is the sole issuer.
6. Add quotas, bandwidth limits, peer-network restrictions, metrics, and an emergency kill switch.
