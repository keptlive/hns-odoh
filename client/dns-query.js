/*
 * Minimal DNS wire-format client: one query to one nameserver.
 *
 * The browser resolves Handshake hosts in two hops: the SPV node answers
 * "which nameservers own this TLD" with an Urkel proof, then we ask that
 * authoritative server directly for the host's records. Node's dns module
 * cannot ask a *specific* server for TLSA records, and pulling in a full
 * DNS library for three record types is not worth the surface area — so
 * the ~worth-auditing-in-one-sitting encoder/decoder lives here.
 *
 * TCP only, deliberately: our own research (resolve.py) found UDP:53
 * unreliable across home ISPs and half the public Handshake resolvers,
 * while TCP behaved. An authoritative server that cannot do DNS-over-TCP
 * is broken per RFC 7766 anyway.
 */

import net from 'node:net'

export const TYPES = {
  A: 1,
  NS: 2,
  CNAME: 5,
  AAAA: 28,
  TXT: 16,
  DS: 43,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  TLSA: 52
}

function encodeName (name) {
  const parts = name.replace(/\.$/, '').split('.')
  const chunks = []
  for (const part of parts) {
    const label = Buffer.from(part, 'ascii')
    if (label.length === 0 || label.length > 63) {
      throw new Error(`bad DNS label in ${name}`)
    }
    chunks.push(Buffer.from([label.length]), label)
  }
  chunks.push(Buffer.from([0]))
  return Buffer.concat(chunks)
}

export function buildQuery (name, type, id, { dnssec = false } = {}) {
  const header = Buffer.alloc(12)
  header.writeUInt16BE(id, 0)
  header.writeUInt16BE(0x0100, 2) // RD (ignored by authoritative, harmless)
  header.writeUInt16BE(1, 4) // QDCOUNT
  if (dnssec) header.writeUInt16BE(1, 10) // ARCOUNT = 1 (the OPT record)
  const q = encodeName(name)
  const tail = Buffer.alloc(4)
  tail.writeUInt16BE(type, 0)
  tail.writeUInt16BE(1, 2) // IN
  if (!dnssec) return Buffer.concat([header, q, tail])
  // EDNS0 OPT record with the DO (DNSSEC OK) bit set, so the server returns
  // RRSIG/DNSKEY/NSEC alongside the answer.
  const opt = Buffer.alloc(11)
  opt.writeUInt8(0, 0) // root name
  opt.writeUInt16BE(41, 1) // TYPE OPT
  opt.writeUInt16BE(4096, 3) // UDP payload size (advisory; we use TCP)
  opt.writeUInt8(0, 5) // extended rcode
  opt.writeUInt8(0, 6) // version
  opt.writeUInt16BE(0x8000, 7) // flags: DO bit
  opt.writeUInt16BE(0, 9) // rdlen
  return Buffer.concat([header, q, tail, opt])
}

function readName (buf, offset) {
  const labels = []
  let jumped = false
  let next = offset
  let guard = 0
  while (guard++ < 128) {
    const len = buf[offset]
    if (len === undefined) throw new Error('truncated name')
    if ((len & 0xc0) === 0xc0) {
      const ptr = buf.readUInt16BE(offset) & 0x3fff
      if (!jumped) next = offset + 2
      offset = ptr
      jumped = true
      continue
    }
    if (len === 0) {
      if (!jumped) next = offset + 1
      return { name: labels.join('.'), next }
    }
    labels.push(buf.toString('ascii', offset + 1, offset + 1 + len))
    offset += 1 + len
  }
  throw new Error('name compression loop')
}

export function parseAnswers (buf) {
  const id = buf.readUInt16BE(0)
  const flags = buf.readUInt16BE(2)
  const rcode = flags & 0x0f
  const truncated = (flags & 0x0200) !== 0 // TC bit
  const qdcount = buf.readUInt16BE(4)
  const ancount = buf.readUInt16BE(6)
  const nscount = buf.readUInt16BE(8)
  const arcount = buf.readUInt16BE(10)
  let offset = 12
  for (let i = 0; i < qdcount; i++) {
    offset = readName(buf, offset).next + 4
  }

  function parseRecord () {
    const { name, next } = readName(buf, offset)
    offset = next
    const type = buf.readUInt16BE(offset)
    const ttl = buf.readUInt32BE(offset + 4)
    const rdlength = buf.readUInt16BE(offset + 8)
    const rdataStart = offset + 10
    const rdata = buf.subarray(rdataStart, rdataStart + rdlength)
    offset += 10 + rdlength
    const rec = { name, type, ttl }
    if (type === TYPES.A && rdata.length === 4) {
      rec.address = Array.from(rdata).join('.')
      rec.rdataRaw = Buffer.from(rdata) // canonical: no embedded names
    } else if (type === TYPES.AAAA && rdata.length === 16) {
      const parts = []
      for (let j = 0; j < 16; j += 2) parts.push(rdata.readUInt16BE(j).toString(16))
      rec.address = parts.join(':')
      rec.rdataRaw = Buffer.from(rdata)
    } else if (type === TYPES.TXT) {
      let p = 0
      const strings = []
      while (p < rdata.length) {
        const l = rdata[p]
        strings.push(rdata.toString('utf8', p + 1, p + 1 + l))
        p += 1 + l
      }
      rec.txt = strings
      rec.rdataRaw = Buffer.from(rdata)
    } else if (type === TYPES.TLSA && rdata.length > 3) {
      rec.usage = rdata[0]
      rec.selector = rdata[1]
      rec.matchingType = rdata[2]
      rec.certificate = rdata.subarray(3).toString('hex')
      rec.rdataRaw = Buffer.from(rdata)
    } else if (type === TYPES.DNSKEY && rdata.length > 4) {
      rec.flags = rdata.readUInt16BE(0)
      rec.protocol = rdata[2]
      rec.algorithm = rdata[3]
      rec.rawPubKey = Buffer.from(rdata.subarray(4))
      rec.rdataRaw = Buffer.from(rdata)
    } else if (type === TYPES.DS && rdata.length > 4) {
      rec.keyTag = rdata.readUInt16BE(0)
      rec.algorithm = rdata[2]
      rec.digestType = rdata[3]
      rec.digest = rdata.subarray(4).toString('hex')
    } else if (type === TYPES.RRSIG && rdata.length > 18) {
      rec.typeCovered = rdata.readUInt16BE(0)
      rec.algorithm = rdata[2]
      rec.labels = rdata[3]
      rec.originalTtl = rdata.readUInt32BE(4)
      rec.expiration = rdata.readUInt32BE(8)
      rec.inception = rdata.readUInt32BE(12)
      rec.keyTag = rdata.readUInt16BE(16)
      // Signer name (uncompressed per RFC 4034) starts at rdata offset 18.
      const { name: signer, next } = readName(buf, rdataStart + 18)
      rec.signer = signer
      rec.signature = Buffer.from(buf.subarray(next, rdataStart + rdlength))
    } else if (type === TYPES.CNAME || type === TYPES.NS) {
      rec.target = readName(buf, rdataStart).name
    } else {
      rec.rdata = rdata.toString('hex')
    }
    return rec
  }

  // All three sections use the same record encoding. authority/additional
  // matter for root-server referrals: an hsd SPV node answers TLD queries
  // with the delegation (NS/DS) in AUTHORITY and glue A records in
  // ADDITIONAL — nothing in the answer section at all.
  const readSection = (count) => {
    const out = []
    for (let i = 0; i < count; i++) {
      const rec = parseRecord()
      if (rec.type !== 41) out.push(rec) // drop the EDNS OPT pseudo-record
    }
    return out
  }
  const answers = readSection(ancount)
  const authority = readSection(nscount)
  const additional = readSection(arcount)
  return { id, rcode, truncated, answers, authority, additional }
}

/**
 * Ask one server one question over TCP. Resolves to parsed answers;
 * rejects on transport failure, timeout, or a mismatched reply id.
 */
export function query (server, port, name, type, { timeout = 5000, dnssec = false } = {}) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 0xffff)
    const msg = buildQuery(name, type, id, { dnssec })
    const framed = Buffer.concat([Buffer.alloc(2), msg])
    framed.writeUInt16BE(msg.length, 0)

    const socket = net.connect({ host: server, port })
    const chunks = []
    let expected = null
    const timer = setTimeout(() => {
      socket.destroy()
      reject(new Error(`DNS timeout asking ${server} for ${name}`))
    }, timeout)

    socket.on('connect', () => socket.write(framed))
    socket.on('data', (chunk) => {
      chunks.push(chunk)
      const buf = Buffer.concat(chunks)
      if (expected === null && buf.length >= 2) expected = buf.readUInt16BE(0)
      if (expected !== null && buf.length >= expected + 2) {
        clearTimeout(timer)
        socket.destroy()
        try {
          const parsed = parseAnswers(buf.subarray(2, expected + 2))
          if (parsed.id !== id) throw new Error('DNS reply id mismatch')
          resolve(parsed)
        } catch (err) {
          reject(err)
        }
      }
    })
    socket.on('error', (err) => {
      clearTimeout(timer)
      reject(err)
    })
  })
}
