# ODoH list service

`odoh-list-service.py` builds `odoh-feed.json`, a small JSON feed of ODoH
targets and relays that a client can fetch to rotate over without a release.

It fetches the DNSCrypt community's ODoH lists (`odoh-servers.md`,
`odoh-relays.md`) and their `.minisig` signatures, verifies the minisign
(Ed25519) signatures against the DNSCrypt public key in the source, decodes the
DNS stamps, attaches operator metadata, adds the Handshake-aware
`odoh.hns.one` target, and writes the feed. On any signature or parse failure
it exits non-zero and writes nothing, so the previous feed stays in place.

The feed itself is not signed. A client trusts it as far as it trusts the host
serving it.

- Requires Python 3 and `cryptography`.
- Writes one file, the feed.
- Tests: `python3 -m unittest test_odoh_list_service -v`. They run offline
  against `test-fixtures/`, unmodified copies of the DNSCrypt lists and their
  signatures.

`hardening-check.py` checks a live target without changing it: DNSSEC
validation (with a negative probe on deliberately broken zones), EDNS Client
Subnet, that the target does not also serve `/proxy`, and that no relay shares
the target's operator. Run it on the target host for the DNS checks, or with
`--skip-dns` from anywhere.

## Generate

```
python3 odoh-list-service.py --out /var/www/html/.well-known/odoh-feed.json
python3 odoh-list-service.py --offline test-fixtures --print   # offline
python3 odoh-list-service.py --check                           # verify only
```

## Host it

1. Copy the repository to the host (the unit assumes `/opt/hns-odoh`).
2. Install the timer, which refreshes the feed every 6 hours:
   ```
   cp deploy/hns-odoh-feed.service deploy/hns-odoh-feed.timer /etc/systemd/system/
   systemctl enable --now hns-odoh-feed.timer
   ```
   Adjust the `--out` path in the service to your web root. The unit runs as
   the web root's owner (`www-data`): with `DynamicUser=yes` each run gets a
   new uid and cannot replace the file the previous run wrote.
3. Add the `location` block from `deploy/nginx-odoh-feed.conf` to a server
   block, then `nginx -t && systemctl reload nginx`.

The hns.one instance is served at `https://hns.one/.well-known/odoh-feed.json`.

## Feed format

```jsonc
{
  "version": 1,
  "generated": "2026-08-18T...Z",
  "own": { "operator": "hns.one", "org": "hns.one" },
  "signature": {                       // provenance of the upstream lists
    "verified": true,
    "minisign_key": "RWQf6LRCGA9i5...",
    "servers_trusted_comment": "timestamp:...\tfile:odoh-servers.md",
    "relays_trusted_comment":  "timestamp:...\tfile:odoh-relays.md"
  },
  "targets": [
    { "name": "odoh-hns-one", "host": "odoh.hns.one", "path": "/dns-query",
      "dnssec": true, "no_logs": true, "no_filter": true,
      "handshake_aware": true, "operator": "hns.one", "org": "hns.one" },
    { "name": "...", "host": "adl01.dnscry.pt", "path": "/dns-query",
      "dnssec": true, "handshake_aware": false, "operator": "dnscry.pt", ... }
  ],
  "relays": [
    { "name": "odohrelay-numa", "host": "odoh-relay.numa.rs", "path": "/relay",
      "operator": "numa", "org": "numa.rs" }
  ],
  "pairs": [                           // precomputed, operator-distinct, DNSSEC-only
    { "target_host": "odoh.hns.one", "target_path": "/dns-query",
      "relay_host": "odoh-relay.numa.rs", "relay_path": "/relay",
      "handshake_aware": true,
      "target_operator": "hns.one", "relay_operator": "numa" }
  ]
}
```

## Rules a client must enforce

1. **Handshake names go only to `handshake_aware: true` targets.** Public
   ICANN ODoH targets return NXDOMAIN for Handshake names; `odoh.hns.one` is
   the only Handshake-aware target in the feed. ICANN names may use any target.
2. **Require `target.dnssec === true`.**
3. **Require `relay.operator !== target.operator`.** This is the no-collusion
   rule. Judge it on `operator`, not on host or `org`: the crypto.sx relay is
   hosted on `edgecompute.app` but has the same operator as the crypto.sx
   target, and the feed gives both `operator: "crypto.sx"`.
4. **Never pair `odoh.hns.one` with an hns.one relay.** Rule 3 covers this;
   hns.one runs no relay.
5. **Rotate** across the eligible pairs. `pairs` already applies rules 1 to 4;
   a client may use it directly or recompute from `targets` and `relays`.
6. **Say so when falling back** to plain DoH.

## Scope

The ICANN targets in the feed cannot resolve Handshake names. For
`odoh.hns.one`, the useful part of the feed is the current, signed relay set.
`odoh.hns.one` is not on the DNSCrypt list, which is why the service adds it;
if it is accepted, run with `--no-inject-own`.
