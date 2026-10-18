# hns-odoh

An Oblivious DNS-over-HTTPS ([RFC 9230](https://www.rfc-editor.org/rfc/rfc9230))
target that resolves Handshake names, with a client, build and deployment files,
and a service that publishes a list of usable relays.

With ODoH, the client encrypts its query to the target and sends it through a
relay run by someone else. The relay sees the client's IP but not the query;
the target sees the query but not the IP. This only holds if the relay and the
target are run by different operators.

```
client --(HPKE-encrypted query)--> relay --> target (odoh.hns.one) --> resolver
```

## Public target

| | |
|---|---|
| Target | `https://odoh.hns.one/dns-query` |
| Config | `https://odoh.hns.one/.well-known/odohconfigs` |
| Health | `https://odoh.hns.one/health` |
| Suite | X25519-HKDF-SHA256 / HKDF-SHA256 / AES-128-GCM |
| Upstream | hsd for Handshake names, a validating resolver for ICANN names |

Use it through an independent relay with any RFC 9230 client, such as
[dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy) or the client in
this repository. DNSCrypt maintains a
[list of public ODoH relays](https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/odoh-relays.md).
hns.one runs no relay, and the target does not serve `/proxy`.

## Client (`client/`)

An ES-module RFC 9230 client using `@hpke/core` and `@hpke/dhkem-x25519`.
`odoh.js` is the same module the [Wildroot](https://wildroot.io) browser uses.

```js
import { OdohTransport } from './odoh.js'

const t = new OdohTransport({
  target: 'odoh.hns.one',
  relays: ['https://odoh-relay.numa.rs/relay']
})
const { answer, via } = await t.query(dnsWireQuery) // Uint8Array in and out
```

```sh
cd client
npm install
node --test odoh.test.js   # unit tests
npm run example            # resolves the Handshake TLD 14898 directly and through each relay
```

## Running a target (`server/`, `deploy/`)

The target is Cloudflare's [odoh-server-go](https://github.com/cloudflare/odoh-server-go)
with one patch that makes the upstream nameservers configurable
(`ODOH_NAMESERVERS`), so it can forward to a Handshake-aware resolver.

```sh
cd server && ./build.sh    # needs git and Go; builds server/hns-odoh for linux/amd64
```

Then copy `server/hns-odoh` to `/usr/local/bin/`, install
`deploy/hns-odoh.env.example` as `/etc/hns-odoh.env` (keep the seed: the key
pair is derived from it), `deploy/hns-odoh.service` as a systemd unit, and
`deploy/nginx-odoh.conf` in nginx with your certificates.

Point `ODOH_NAMESERVERS` at a resolver that answers Handshake names, such as
hsd's recursive resolver. hsd does not reject DNSSEC-bogus answers, so put a
validating resolver in front of it for ICANN names before advertising DNSSEC.
`list-service/hardening-check.py` tests this.

The same binary also serves a relay at `/proxy`. The sample nginx config
disables it, because a host that is both target and relay sees both halves.

## List service (`list-service/`)

Builds a JSON feed of ODoH targets and relays from DNSCrypt's signed lists,
verifying the minisign signatures and excluding target and relay pairs run by
the same operator. The hns.one feed is at
`https://hns.one/.well-known/odoh-feed.json`. See
[`list-service/DEPLOY.md`](list-service/DEPLOY.md).

## Limits

- ODoH hides who asked what from the resolver. It does not hide the client's
  IP from the sites it then connects to, and it is not a chain proof: a
  dishonest target can still return false records.
- RFC 9230 is an experimental RFC, and there are few public relays.
- Each query takes one extra hop.

## License

MIT. `server/` builds on [cloudflare/odoh-server-go](https://github.com/cloudflare/odoh-server-go)
(MIT).
