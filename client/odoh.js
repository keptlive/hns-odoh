// Oblivious DoH client (RFC 9230) — the privacy upgrade over plain DoH.
//
// Plain DoH tells the resolver BOTH who you are (your IP) and what you are
// browsing (the queried name). ODoH splits those: the query is HPKE-encrypted
// end-to-end to the TARGET (odoh.hns.one, fronting the same Handshake-aware
// hsd recursive as query.hns.one) and sent through an independent third-party
// RELAY. The relay sees your IP but only an encrypted blob; the target sees
// the query but only the relay's IP. Unless relay and target collude, no
// single party links you to your lookups. The relay list must therefore
// never contain a relay run by the target's operator (us).
//
// Crypto per RFC 9230 §6: HPKE (X25519-HKDF-SHA256 / HKDF-SHA256 /
// AES-128-GCM) via @hpke/core, plain HKDF for key-id and response keys via
// WebCrypto HMAC. The response is AEAD-sealed with keys derived from the
// HPKE exporter secret and a target-chosen response nonce, so it never
// rides the HPKE context directly.
//
// This file is transport only: DoHResolver drives it exactly like another
// endpoint and falls back to plain DoH whenever ODoH fails — resolution
// keeps working through relay outages, just with the weaker privacy story
// (and an honest log line saying so).

const ODOH_VERSION = 0x0001
const KEM_X25519 = 0x0020
const KDF_HKDF_SHA256 = 0x0001
const AEAD_AES128GCM = 0x0001
const MEDIA_TYPE = 'application/oblivious-dns-message'
const NH = 32 // SHA-256 output
const NK = 16 // AES-128-GCM key
const NN = 12 // AES-128-GCM nonce
/** How long a fetched target config is trusted before refetch. */
const CONFIG_TTL_MS = 60 * 60 * 1000

const te = new TextEncoder()

// --- byte helpers -----------------------------------------------------------

function u16 (n) {
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff])
}

function readU16 (buf, at) {
  return (buf[at] << 8) | buf[at + 1]
}

function concat (...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}

// --- HKDF (RFC 5869) over WebCrypto HMAC-SHA256 -----------------------------
// The RFC's Extract/Expand are the raw HKDF functions with literal ASCII
// labels — NOT the HPKE labeled variants. Zero-length salt means HashLen
// zeros (RFC 5869 §2.2; identical under HMAC key padding).

async function hmac (keyBytes, data) {
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    keyBytes.length ? keyBytes : new Uint8Array(NH),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  return new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', key, data))
}

async function hkdfExtract (salt, ikm) {
  return hmac(salt, ikm)
}

/** Single-block expand — every ODoH output (Nh/Nk/Nn) fits in one block. */
async function hkdfExpand (prk, infoStr, length) {
  const t1 = await hmac(prk, concat(te.encode(infoStr), new Uint8Array([1])))
  return t1.slice(0, length)
}

// --- config parsing (§5) ----------------------------------------------------

/**
 * Parse /.well-known/odohconfigs and return the first supported config:
 * { publicKey, contents } where contents is the serialized
 * ObliviousDoHConfigContents (needed verbatim for the key id). Throws when
 * nothing supported is present.
 * @param {Uint8Array} buf
 */
export function parseConfigs (buf) {
  if (buf.length < 2) throw new Error('odoh configs: truncated')
  const total = readU16(buf, 0)
  if (2 + total > buf.length) throw new Error('odoh configs: length overruns buffer')
  let at = 2
  const end = 2 + total
  while (at + 4 <= end) {
    const version = readU16(buf, at)
    const length = readU16(buf, at + 2)
    const contents = buf.slice(at + 4, at + 4 + length)
    at += 4 + length
    if (version !== ODOH_VERSION || contents.length !== length) continue
    if (contents.length < 8) continue
    const kem = readU16(contents, 0)
    const kdf = readU16(contents, 2)
    const aead = readU16(contents, 4)
    const pkLen = readU16(contents, 6)
    if (kem !== KEM_X25519 || kdf !== KDF_HKDF_SHA256 || aead !== AEAD_AES128GCM) continue
    if (contents.length !== 8 + pkLen) continue
    return { publicKey: contents.slice(8), contents }
  }
  throw new Error('odoh configs: no supported (X25519/HKDF-SHA256/AES-128-GCM) config')
}

/** key_id = Expand(Extract("", contents), "odoh key id", Nh) — §6.1. */
export async function computeKeyId (contents) {
  const prk = await hkdfExtract(new Uint8Array(0), contents)
  return hkdfExpand(prk, 'odoh key id', NH)
}

// --- plaintext framing (§6.1) ----------------------------------------------

/** ObliviousDoHMessagePlaintext with empty padding. */
export function encodePlaintext (dnsMessage) {
  return concat(u16(dnsMessage.length), dnsMessage, u16(0))
}

/** Parse and validate (padding MUST be all zeros — §7). */
export function decodePlaintext (buf) {
  if (buf.length < 4) throw new Error('odoh plaintext: truncated')
  const dnsLen = readU16(buf, 0)
  if (2 + dnsLen + 2 > buf.length) throw new Error('odoh plaintext: bad dns length')
  const dns = buf.slice(2, 2 + dnsLen)
  const padLen = readU16(buf, 2 + dnsLen)
  const padStart = 2 + dnsLen + 2
  if (padStart + padLen !== buf.length) throw new Error('odoh plaintext: bad padding length')
  for (let i = padStart; i < buf.length; i++) {
    if (buf[i] !== 0) throw new Error('odoh plaintext: nonzero padding')
  }
  return dns
}

// --- the transport ----------------------------------------------------------

export class OdohTransport {
  /**
   * Targets must all be HANDSHAKE-AWARE — every public ICANN ODoH target
   * (verified against 8, Cloudflare included, 2026-08-18) NXDOMAINs
   * Handshake names, so adding one here would 404 live hns sites, not back
   * them up. Today the list is exactly [odoh.hns.one]; the day a second
   * Handshake target exists (another region, a community deployment) it is
   * a config entry, not a release.
   * @param {object} opts
   * @param {{host: string, path?: string}[]} [opts.targets] tried in order
   * @param {string} [opts.target] legacy single-target form
   * @param {string} [opts.targetPath]
   * @param {string[]} opts.relays relay base URLs (query-string style)
   * @param {number} [opts.timeout]
   * @param {(url: string, init?: object) => Promise<Response>} [opts.fetchImpl]
   */
  constructor ({ targets, target, targetPath = '/dns-query', relays = [], timeout = 8000, fetchImpl } = {}) {
    this.targets = (Array.isArray(targets) && targets.length
      ? targets
      : [{ host: target, path: targetPath }])
      .filter((t) => t && t.host)
      .map((t) => ({ host: t.host, path: t.path || '/dns-query' }))
    this.relays = relays
    this.timeout = timeout
    this.fetchImpl = fetchImpl || ((...a) => globalThis.fetch(...a))
    /** per-target config cache: host -> {config, keyId, pkR, at} */
    this._cfgs = new Map()
    this._suitePromise = null
  }

  get label () {
    return `odoh ${this.targets.map((t) => t.host).join(',')}`
  }

  /** Lazy HPKE suite — @hpke/* stay unloaded until ODoH is actually used. */
  async _suite () {
    if (!this._suitePromise) {
      this._suitePromise = (async () => {
        const [{ CipherSuite, HkdfSha256, Aes128Gcm }, { DhkemX25519HkdfSha256 }] =
          await Promise.all([import('@hpke/core'), import('@hpke/dhkem-x25519')])
        return new CipherSuite({
          kem: new DhkemX25519HkdfSha256(),
          kdf: new HkdfSha256(),
          aead: new Aes128Gcm()
        })
      })()
    }
    return this._suitePromise
  }

  /** Fetch (or reuse) a target's config, DIRECTLY from the target: the
   * config is public and authenticated by the target's TLS; fetching it via
   * a relay would add nothing (the relay could not tamper without breaking
   * every query anyway — decryption just fails). */
  async _config (target, force = false) {
    const now = Date.now()
    const cached = this._cfgs.get(target.host)
    if (!force && cached && now - cached.at < CONFIG_TTL_MS) return cached
    const res = await this.fetchImpl(`https://${target.host}/.well-known/odohconfigs`, {
      signal: AbortSignal.timeout(this.timeout)
    })
    if (!res.ok) throw new Error(`odoh config fetch: ${res.status}`)
    const config = parseConfigs(new Uint8Array(await res.arrayBuffer()))
    const suite = await this._suite()
    const pkR = await suite.kem.deserializePublicKey(
      config.publicKey.buffer.slice(
        config.publicKey.byteOffset,
        config.publicKey.byteOffset + config.publicKey.byteLength
      )
    )
    const entry = { config, keyId: await computeKeyId(config.contents), pkR, at: now }
    this._cfgs.set(target.host, entry)
    return entry
  }

  /** Seal one DNS query for a target; returns the message and opener. */
  async _seal (dnsWire, target = this.targets[0]) {
    const { keyId, pkR } = await this._config(target)
    const suite = await this._suite()
    const qPlain = encodePlaintext(dnsWire)
    const ctx = await suite.createSenderContext({
      recipientPublicKey: pkR,
      info: te.encode('odoh query').buffer
    })
    const aad = concat(new Uint8Array([0x01]), u16(keyId.length), keyId)
    const ct = new Uint8Array(await ctx.seal(
      qPlain.buffer.slice(qPlain.byteOffset, qPlain.byteOffset + qPlain.byteLength),
      aad.buffer.slice(aad.byteOffset, aad.byteOffset + aad.byteLength)
    ))
    const enc = new Uint8Array(ctx.enc)
    const encrypted = concat(enc, ct)
    const message = concat(
      new Uint8Array([0x01]), u16(keyId.length), keyId, u16(encrypted.length), encrypted
    )
    const open = async (respBytes) => {
      // ObliviousDoHMessage: type 0x02, key_id = response nonce, ct
      if (respBytes.length < 5 || respBytes[0] !== 0x02) {
        throw new Error('odoh response: not a response message')
      }
      const nonceLen = readU16(respBytes, 1)
      const respNonce = respBytes.slice(3, 3 + nonceLen)
      const ctLen = readU16(respBytes, 3 + nonceLen)
      const respCt = respBytes.slice(5 + nonceLen, 5 + nonceLen + ctLen)
      if (respNonce.length !== nonceLen || respCt.length !== ctLen) {
        throw new Error('odoh response: truncated')
      }
      // §6.3: secret from the HPKE exporter; key/nonce via HKDF with the
      // query plaintext + response nonce as salt.
      const secret = new Uint8Array(await ctx.export(te.encode('odoh response').buffer, NK))
      const salt = concat(qPlain, u16(respNonce.length), respNonce)
      const prk = await hkdfExtract(salt, secret)
      const key = await hkdfExpand(prk, 'odoh key', NK)
      const nonce = await hkdfExpand(prk, 'odoh nonce', NN)
      const aad = concat(new Uint8Array([0x02]), u16(respNonce.length), respNonce)
      const aesKey = await globalThis.crypto.subtle.importKey(
        'raw', key, { name: 'AES-GCM' }, false, ['decrypt']
      )
      const plain = new Uint8Array(await globalThis.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
        aesKey,
        respCt
      ))
      return decodePlaintext(plain)
    }
    return { message, open }
  }

  _relayUrl (relay, target = this.targets[0]) {
    const sep = relay.includes('?') ? '&' : '?'
    return `${relay}${sep}targethost=${encodeURIComponent(target.host)}` +
      `&targetpath=${encodeURIComponent(target.path)}`
  }

  /**
   * Resolve one wire-format DNS query obliviously. Tries each relay in
   * order; a 401 from the target means our cached config went stale (key
   * rotation) — refetch once and retry. Throws when every relay fails.
   * @param {Uint8Array} dnsWire
   * @returns {Promise<{answer: Uint8Array, via: string}>}
   */
  async query (dnsWire) {
    let lastErr = null
    for (const target of this.targets) {
      let retriedConfig = false
      for (let i = 0; i < this.relays.length; i++) {
        const relay = this.relays[i]
        try {
          const { message, open } = await this._seal(dnsWire, target)
          const res = await this.fetchImpl(this._relayUrl(relay, target), {
            method: 'POST',
            headers: { 'content-type': MEDIA_TYPE, accept: MEDIA_TYPE },
            body: message,
            signal: AbortSignal.timeout(this.timeout)
          })
          if (res.status === 401 && !retriedConfig) {
            // Target rotated its key since we cached the config.
            retriedConfig = true
            await this._config(target, true)
            i-- // retry the same relay with the fresh config
            continue
          }
          if (!res.ok) throw new Error(`relay ${res.status}`)
          const answer = await open(new Uint8Array(await res.arrayBuffer()))
          return { answer, via: new URL(relay).host, target: target.host }
        } catch (err) {
          lastErr = err
        }
      }
    }
    throw lastErr || new Error('odoh: no relays configured')
  }
}
