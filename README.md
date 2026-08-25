# hns-odoh — Oblivious DoH for Handshake

**The first Oblivious DoH (RFC 9230) deployment for the Handshake root zone.**
Live at `odoh.hns.one` since 2026-08-17.

## Why

Every Handshake user without a local node resolves names through someone
else's DoH server — and a DoH server learns **both** who you are (your IP)
and **what you look up** (every name you visit). For a naming system whose
whole point is censorship-resistance, that is a bad trade to take silently.

[Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230) splits the two:

```
you ──(HPKE-encrypted query)──▶ RELAY ──▶ TARGET (odoh.hns.one) ──▶ hsd recursive
        relay sees your IP,        target sees the query,
        not your query             not your IP
```

Unless the relay and the target collude, no single party can link you to
your lookups. That is why **the relay must be run by someone other than the
target's operator** — never pair an hns.one relay with the hns.one target.

## The public target

| | |
|---|---|
| Target | `https://odoh.hns.one/dns-query` |
| Config | `https://odoh.hns.one/.well-known/odohconfigs` |
| Health | `https://odoh.hns.one/health` |
| Suite | X25519-HKDF-SHA256 / HKDF-SHA256 / AES-128-GCM |
| Upstream | Handshake-aware `hsd` recursive resolver (SPV) on the same host |
| Logs | nginx `access_log off`; server telemetry stays local |

Use it from any RFC 9230 client through an independent relay, e.g. with
[dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy) or the client
in this repo. Known-working public relay today:
`https://odoh-relay.numa.rs/relay`. (`odoh-relay.edgecompute.app` relays
only to targets on the DNSCrypt public list — see roadmap.)

## Client (`client/`)

A dependency-light ES-module RFC 9230 client (`@hpke/core` +
`@hpke/dhkem-x25519`, WebCrypto for HKDF/AES-GCM). It is the same code the
[HNS.ONE Browser](https://hns.one) ships (2.28+, where oblivious resolution
is the default with automatic fallback to plain DoH).

```js
import { OdohTransport } from './odoh.js'
const t = new OdohTransport({
  target: 'odoh.hns.one',
  relays: ['https://odoh-relay.numa.rs/relay']
})
const { answer, via } = await t.query(dnsWireQuery) // Uint8Array in, out
```

```
cd client && npm install && npm run example
```

The example resolves `14898` (a Handshake TLD) directly and through each
public relay, printing latency and answers.

## Run your own target (`server/`, `deploy/`)

The target is Cloudflare's [odoh-server-go](https://github.com/cloudflare/odoh-server-go)
(MIT) plus one patch making the upstream nameservers env-configurable
(`ODOH_NAMESERVERS`) so it can forward to a **Handshake-aware** recursive
resolver — that is the entire trick that makes this a Handshake ODoH target.

```
cd server && ./build.sh            # needs Go ≥1.22; static linux/amd64 binary
scp hns-odoh root@host:/usr/local/bin/
# then: deploy/hns-odoh.env.example -> /etc/hns-odoh.env  (seed! keep it)
#       deploy/hns-odoh.service    -> /etc/systemd/system/
#       deploy/nginx-odoh.conf     -> your nginx, TLS via your certs
```

Point `ODOH_NAMESERVERS` at an hsd recursive (`hsd --rs-host 127.0.0.1
--rs-port 5350` or equivalent). Without a Handshake-aware upstream this is
just another ICANN ODoH target.

Run a **relay** instead (more valuable to the ecosystem the fewer exist):
the same binary serves `/proxy`; put it on a host and organization that has
nothing to do with any target its users query.

## Honest limits

- ODoH protects **who-asked-what** at the resolver. It is not a VPN: the
  page fetch that follows still comes from your IP (the browser's Tor/VPS
  anonymization modes cover that), and it is **not chain proof** — a
  malicious target can still lie about records. Chain-proof resolution
  (local SPV + DANE) remains the gold standard; ODoH is for the fallback
  window and for clients that cannot run a node.
- RFC 9230 is experimental; the public relay pool is currently tiny (two).
- Queries take one extra hop (~100–500 ms in practice).

## Roadmap

- [ ] Submit `odoh.hns.one` to the [DNSCrypt public ODoH server list](https://github.com/DNSCrypt/dnscrypt-resolvers)
      (unlocks the `crypto.sx` relay and every dnscrypt-proxy user).
- [ ] Second target region; independent Handshake relays.
- [ ] ODoH in the HNS.ONE Android browser.
- [ ] Oblivious resolution for ICANN names in the desktop browser — blocked
      on Chromium accepting only `https` DoH templates (a plain-http
      localhost ODoH bridge was probed and rejected); needs upstream ODoH
      support or a trusted local certificate. Until then ICANN lookups ride
      encrypted (non-oblivious) DoH to a pool that includes several public
      ODoH operators.

## License

MIT. `server/` builds on [cloudflare/odoh-server-go](https://github.com/cloudflare/odoh-server-go)
(MIT, © Cloudflare & Apple). The client also ships inside the AGPL-3.0
HNS.ONE Browser; this standalone copy is MIT so anything can embed it.
