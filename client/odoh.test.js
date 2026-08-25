import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  parseConfigs,
  computeKeyId,
  encodePlaintext,
  decodePlaintext,
  OdohTransport
} from './odoh.js'

function cfgBytes (kem = 0x0020, kdf = 0x0001, aead = 0x0001, pk = new Uint8Array(32).fill(7)) {
  const contents = new Uint8Array(8 + pk.length)
  const dv = new DataView(contents.buffer)
  dv.setUint16(0, kem); dv.setUint16(2, kdf); dv.setUint16(4, aead); dv.setUint16(6, pk.length)
  contents.set(pk, 8)
  const out = new Uint8Array(2 + 4 + contents.length)
  const odv = new DataView(out.buffer)
  odv.setUint16(0, 4 + contents.length) // total configs length
  odv.setUint16(2, 0x0001) // version
  odv.setUint16(4, contents.length)
  out.set(contents, 6)
  return { out, contents }
}

test('parseConfigs: accepts the supported suite and keeps contents verbatim', () => {
  const { out, contents } = cfgBytes()
  const parsed = parseConfigs(out)
  assert.deepEqual(parsed.contents, contents)
  assert.equal(parsed.publicKey.length, 32)
})

test('parseConfigs: skips unsupported versions/suites; rejects garbage', () => {
  const { out } = cfgBytes(0x0010) // P-256 — unsupported
  assert.throws(() => parseConfigs(out), /no supported/)
  assert.throws(() => parseConfigs(new Uint8Array([0])), /truncated/)
  const { out: good } = cfgBytes()
  // Prepend an unsupported-version config; the good one must still be found.
  const bad = new Uint8Array([0x00, 0x02, 0x00, 0x00]) // version 2, len 0
  const both = new Uint8Array(2 + bad.length + (good.length - 2))
  new DataView(both.buffer).setUint16(0, bad.length + (good.length - 2))
  both.set(bad, 2)
  both.set(good.slice(2), 2 + bad.length)
  assert.equal(parseConfigs(both).publicKey.length, 32)
})

test('computeKeyId is deterministic and 32 bytes (HKDF, "odoh key id")', async () => {
  const { contents } = cfgBytes()
  const a = await computeKeyId(contents)
  const b = await computeKeyId(contents)
  assert.equal(a.length, 32)
  assert.deepEqual(a, b)
  const { contents: other } = cfgBytes(0x0020, 0x0001, 0x0001, new Uint8Array(32).fill(9))
  assert.notDeepEqual(await computeKeyId(other), a)
})

test('plaintext framing round-trips; nonzero padding refused', () => {
  const dns = new Uint8Array([1, 2, 3, 4, 5])
  const framed = encodePlaintext(dns)
  assert.deepEqual(decodePlaintext(framed), dns)
  // dns_len=5, dns, pad_len=1, pad=0x41 — declared padding must be zeros
  const evil = new Uint8Array([0, 5, 1, 2, 3, 4, 5, 0, 1, 0x41])
  assert.throws(() => decodePlaintext(evil), /nonzero padding/)
  assert.throws(() => decodePlaintext(new Uint8Array([0, 9, 1, 2])), /bad dns length/)
  assert.throws(() => decodePlaintext(new Uint8Array([0, 9, 1])), /truncated/)
})

test('relay URL building appends target params to either URL shape', () => {
  const t = new OdohTransport({ target: 'odoh.hns.one', relays: [] })
  assert.equal(
    t._relayUrl('https://relay.example/'),
    'https://relay.example/?targethost=odoh.hns.one&targetpath=%2Fdns-query')
  assert.equal(
    t._relayUrl('https://relay.example/p?x=1'),
    'https://relay.example/p?x=1&targethost=odoh.hns.one&targetpath=%2Fdns-query')
})
