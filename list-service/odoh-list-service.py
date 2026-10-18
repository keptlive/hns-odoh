#!/usr/bin/env python3
"""
Signed ODoH resolver/relay list service -- the trust root under the browser's
oblivious resolution.

WHAT IT DOES
    The Wildroot browser resolves obliviously by pairing an ODoH *target* (who
    sees the query, not your IP) with a third-party *relay* (who sees your IP,
    not the query). For that pairing to be private the two must be run by
    DIFFERENT organizations -- otherwise one operator sees both halves and the
    whole scheme buys nothing. Hard-coding a target+relay list in the browser
    means the browser can never learn a new relay, drop a dead one, or notice
    that a target stopped validating DNSSEC without a full app release.

    This service turns the DNSCrypt community's signed, curated ODoH lists into
    a small JSON feed a client can fetch and rotate over on its own:

        DNSCrypt odoh-servers.md  (+ .minisig)   ICANN targets
        DNSCrypt odoh-relays.md   (+ .minisig)   relays
                          |
                 verify minisign signature  (refuse the list if it fails)
                          |
                 parse DNS stamps  ->  host, path, DNSSEC flag, no-logs...
                          |
                 attach operator identity  ->  org-distinctness metadata
                          |
                 inject our own Handshake-aware target (odoh.hns.one)
                          |
                          v
                    odoh-feed.json   <- what a client consumes

WHY VERIFY THE SIGNATURE (and refuse on failure)
    The lists are fetched over HTTPS from GitHub/CDNs, but TLS only proves you
    talked to that host -- not that the bytes are the DNSCrypt maintainers'.
    A compromised mirror (or us, the middle-man generating the feed) could add
    a hostile "relay" that is really run by a target operator, silently
    de-anonymizing every user. minisign (Ed25519) signs the list itself, so we
    verify against the maintainers' well-known public key and REFUSE to emit a
    feed from a list that does not verify. Fail closed: a stale good feed beats
    a fresh forged one.

WHY OPERATOR IDENTITY, NOT JUST HOSTNAME
    "Different organizations" is the whole security property, and registrable
    domain alone is not enough to check it. The crypto.sx relay is served from
    `odoh-relay.edgecompute.app` (Fastly) yet is operated by the same person
    who runs the `crypto.sx` *target*. Pairing those two would look
    domain-distinct while being operator-identical -- exactly the collusion the
    scheme forbids. So each endpoint carries a canonical `operator` id derived
    from a curated group map (below), and distinctness is judged on operator,
    not host. Our own target's operator is `hns.one`; because we run NO relay,
    the generic "relay.operator != target.operator" rule already forbids ever
    pairing our target with an hns.one relay (there is none) -- the no-collusion
    rule falls out for free.

HOW A CLIENT CONSUMES IT
    - Fetch odoh-feed.json (this file, hosted as a static hns.one asset).
    - For a Handshake name: pick a target with handshake_aware == true
      (today only odoh.hns.one; ICANN targets NXDOMAIN Handshake names).
    - For an ICANN name: any target is eligible.
    - Require target.dnssec == true; drop a target that stops validating.
    - Pick a relay whose operator != target.operator (org-distinctness).
    - Rotate across the eligible (target, relay) pairs; no app rebuild needed.
    - `feed.pairs` is a precomputed, org-distinct, DNSSEC-checked convenience
      list the browser MAY use directly instead of recomputing.

USAGE
    python3 odoh-list-service.py --out odoh-feed.json        # fetch + verify
    python3 odoh-list-service.py --offline test-fixtures --out odoh-feed.json
    python3 odoh-list-service.py --check                     # verify only, no write
    python3 odoh-list-service.py --print                     # feed to stdout

    Run it from cron / a systemd timer (see DEPLOY.md) to keep the feed fresh.
    Stdlib + `cryptography` (Ed25519) only. It writes exactly one file: the feed.
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import sys
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))

# The DNSCrypt resolvers-list minisign public key. This is the well-known key
# baked into dnscrypt-proxy itself and published in the list headers; it is the
# anchor of the whole trust chain, so it lives in the source, not a fetched
# file (a fetched key an attacker could swap proves nothing).
DNSCRYPT_MINISIGN_KEY = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"

# Source URLs, primary first. All three are the same signed content; if the
# primary is unreachable we try the next rather than emit a stale feed.
SERVERS_URLS = [
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-servers.md",
    "https://download.dnscrypt.info/resolvers-list/v3/odoh-servers.md",
    "https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/odoh-servers.md",
]
RELAYS_URLS = [
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-relays.md",
    "https://download.dnscrypt.info/resolvers-list/v3/odoh-relays.md",
    "https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/odoh-relays.md",
]

# Canonical operator groups: registrable domain -> operator id. The point is to
# collapse hosts that are DIFFERENT domains but the SAME operator, so
# org-distinctness is judged on who actually runs the box. Anything not listed
# defaults to its own registrable domain (see operator_of), which is the safe
# assumption for an unknown independent host.
OPERATOR_GROUPS = {
    "cloudflare-dns.com": "cloudflare",
    "dnscry.pt": "dnscry.pt",
    "crypto.sx": "crypto.sx",
    # crypto.sx runs this relay on Fastly's edge; same operator as the
    # crypto.sx TARGET, so it MUST collapse to the same id or the browser
    # could pair the two and think they were distinct. This single line is
    # the teeth of the no-collusion rule against the current public list.
    "edgecompute.app": "crypto.sx",
    "numa.rs": "numa",
    "snowstorm.love": "snowstorm",
    # tiar.app / tiarap.org are the same "Tiarap" operator across two domains.
    "tiar.app": "tiarap",
    "tiarap.org": "tiarap",
    "hns.one": "hns.one",
}

# Multi-label public suffixes we care about, so registrable-domain extraction
# does not mistake "co.uk" for a registrable domain. This is a deliberately
# tiny list (not the full PSL) covering the ccTLD shapes an ODoH operator is
# realistically on; extend it if a future list entry needs it. Everything else
# uses the last two labels.
MULTI_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.za", "com.br", "co.jp", "or.jp", "ne.jp",
}

# Our own Handshake-aware target, injected because odoh.hns.one is not yet on
# the DNSCrypt public list (roadmap item). It is the ONLY target that can
# resolve Handshake names -- every public ICANN target NXDOMAINs them -- so the
# handshake_aware flag is what routes Handshake lookups here and ICANN lookups
# anywhere.
#
# dnssec IS TRUE AGAIN, AND NOW IT IS ACTUALLY TRUE.
# It said True from the day this was written, on the strength of a check that
# could not fail: hardening-check.py probed a known-GOOD signed name and passed
# on `ad or has_rrsig`, both of which a non-validating resolver produces. The
# negative probe added 2026-08-20 shows the truth -- hsd's recursive returns
# NOERROR with records for `dnssec-failed.org` and
# `sigfail.verteiltesysteme.net`, because bns `recursive.js` drops the trust
# chain (`rc.chain = false`) on a failed signature check and answers anyway.
# It was DNSSEC-aware, not DNSSEC-enforcing.
#
# FIXED 2026-08-20 by putting a validating resolver in front: ICANN names now
# go to unbound (root anchor, val-permissive-mode off) and Handshake names to
# hsd, split by TLD on 127.0.0.1:5351. Bogus zones now SERVFAIL end to end,
# verified through the live ODoH service, and `hardening-check.py` passes its
# negative probes.
#
# This flag is consumed by distinct_pairs() and by anyone reading the feed, and
# DNSCrypt's rule is that a server caught claiming a policy it does not honour
# is removed permanently. So: set this to False the moment
# `python3 hardening-check.py --recursive 127.0.0.1:5351` stops passing its
# "rejects bogus DNSSEC" checks.
OWN_TARGET = {
    "name": "odoh-hns-one",
    "host": "odoh.hns.one",
    "path": "/dns-query",
    "dnssec": True,
    "no_logs": True,
    "no_filter": True,
    "handshake_aware": True,
    "operator": "hns.one",
    "org": "hns.one",
    "stamp": None,
    "info_url": "https://hns.one",
    "description": "HNS.ONE Handshake-aware ODoH target (hsd recursive upstream).",
    "injected": True,
}
OWN_OPERATOR = "hns.one"


# --- minisign verification (Ed25519) ---------------------------------------
# minisign format: a signature file is four lines --
#   untrusted comment: ...
#   base64( algo[2] || key_id[8] || ed25519_sig[64] )
#   trusted comment: <text>
#   base64( ed25519_sig over (sig || trusted_comment_text) )
# algo "Ed" signs the raw file; "ED" signs its BLAKE2b-512 prehash. The global
# signature binds the trusted comment (a timestamp here) to the signature so it
# cannot be swapped. We verify BOTH, and that the signing key id matches ours.

def load_minisign_pubkey(key_b64):
    """(algo, key_id, Ed25519PublicKey) from a minisign public key string."""
    raw = base64.b64decode(key_b64)
    if len(raw) != 42:
        raise ValueError("minisign public key: wrong length")
    return raw[:2], raw[2:10], Ed25519PublicKey.from_public_bytes(raw[10:42])


def verify_minisig(key_b64, data, sig_text):
    """Verify a minisign signature over `data`. Returns the trusted comment.

    Raises InvalidSignature/ValueError on ANY problem -- the caller treats that
    as "do not trust this list" and keeps the previous feed.
    """
    algo_pk, key_id_pk, pub = load_minisign_pubkey(key_b64)
    lines = sig_text.splitlines()
    if len(lines) < 4:
        raise ValueError("minisig: truncated (need 4 lines)")
    sig_blob = base64.b64decode(lines[1])
    if len(sig_blob) != 74:
        raise ValueError("minisig: bad signature blob length")
    algo, key_id, sig = sig_blob[:2], sig_blob[2:10], sig_blob[10:74]
    if key_id != key_id_pk:
        raise ValueError("minisig: key id does not match the trusted key")
    if not lines[2].startswith("trusted comment: "):
        raise ValueError("minisig: missing trusted comment")
    trusted_comment = lines[2][len("trusted comment: "):]
    global_sig = base64.b64decode(lines[3])

    if algo == b"ED":
        signed = hashlib.blake2b(data).digest()
    elif algo == b"Ed":
        signed = data
    else:
        raise ValueError(f"minisig: unknown algorithm {algo!r}")

    pub.verify(sig, signed)                                  # the file itself
    pub.verify(global_sig, sig + trusted_comment.encode())   # the trusted comment
    return trusted_comment


# --- DNS stamp decoding (dnscrypt.info/stamps-specifications) ---------------
# We only decode the two ODoH shapes:
#   0x05 ODoH target:  props[8 LE] || LP(hostname) || LP(path)
#   0x85 ODoH relay :  props[8 LE] || LP(addr) || VLP(hashes) || LP(host) || LP(path)
# LP = 1-byte length + bytes. VLP = a vector where each element's length byte's
# high bit (0x80) means "another element follows". props bit0=DNSSEC,
# bit1=no-logs, bit2=no-filter.

PROTO_ODOH_TARGET = 0x05
PROTO_ODOH_RELAY = 0x85


def _b64u_decode(s):
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class _Reader:
    def __init__(self, buf):
        self.buf, self.at = buf, 0

    def u8(self):
        v = self.buf[self.at]
        self.at += 1
        return v

    def lp(self):
        n = self.u8()
        v = self.buf[self.at:self.at + n]
        if len(v) != n:
            raise ValueError("stamp: length-prefixed field overruns")
        self.at += n
        return v

    def vlp(self):
        out = []
        while True:
            n = self.u8()
            more = n & 0x80
            n &= 0x7f
            out.append(self.buf[self.at:self.at + n])
            self.at += n
            if not more:
                return out


def decode_stamp(stamp):
    """Decode an ODoH target/relay sdns:// stamp to a dict, or raise."""
    if not stamp.startswith("sdns://"):
        raise ValueError("stamp: not an sdns:// URI")
    r = _Reader(_b64u_decode(stamp[len("sdns://"):]))
    proto = r.u8()
    props = int.from_bytes(r.buf[r.at:r.at + 8], "little")
    r.at += 8
    out = {
        "proto": proto,
        "dnssec": bool(props & 0x01),
        "no_logs": bool(props & 0x02),
        "no_filter": bool(props & 0x04),
    }
    if proto == PROTO_ODOH_TARGET:
        out["host"] = r.lp().decode()
        out["path"] = r.lp().decode()
    elif proto == PROTO_ODOH_RELAY:
        r.lp()      # addr (usually empty; resolved from hostname)
        r.vlp()     # cert hashes (usually empty for a relay)
        out["host"] = r.lp().decode()
        out["path"] = r.lp().decode()
    else:
        raise ValueError(f"stamp: not an ODoH stamp (proto 0x{proto:02x})")
    return out


# --- operator / org identity ------------------------------------------------

def registrable_domain(host):
    """Naive eTLD+1: last two labels, or three for a known multi-part suffix."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return host.lower()
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def operator_of(host):
    """Canonical operator id for a host (the org-distinctness key)."""
    dom = registrable_domain(host)
    return OPERATOR_GROUPS.get(dom, dom)


def same_org(a_host, b_host):
    """True if two hosts are run by the same operator (must NOT be paired)."""
    return operator_of(a_host) == operator_of(b_host)


# --- markdown list parsing --------------------------------------------------
# Each entry is:  "## name", then free-text description lines (one of which may
# be a https:// info URL), then a single "sdns://..." stamp line.

_INFO_URL_RE = re.compile(r"(https?://\S+)")


def parse_list(md_text):
    """Parse a DNSCrypt v3 .md list into [{name, description, info_url, stamp}]."""
    entries, name, desc, info, stamp = [], None, [], None, None

    def flush():
        if name and stamp:
            entries.append({
                "name": name,
                "description": " ".join(desc).strip(),
                "info_url": info,
                "stamp": stamp,
            })

    for line in md_text.splitlines():
        line = line.strip()
        if line.startswith("## "):
            flush()
            name, desc, info, stamp = line[3:].strip(), [], None, None
        elif line.startswith("sdns://"):
            stamp = line
        elif line and name:
            m = _INFO_URL_RE.search(line)
            if m and info is None and not line.startswith("sdns://"):
                info = m.group(1)
            # keep the human description, minus a bare URL-only line
            if not (m and line == m.group(1)):
                desc.append(line)
    flush()
    return entries


def build_endpoint(entry, is_relay):
    """A parsed entry + decoded stamp -> the feed record, or None to skip."""
    try:
        s = decode_stamp(entry["stamp"])
    except (ValueError, IndexError):
        return None
    if is_relay and s["proto"] != PROTO_ODOH_RELAY:
        return None
    if not is_relay and s["proto"] != PROTO_ODOH_TARGET:
        return None
    rec = {
        "name": entry["name"],
        "host": s["host"],
        "path": s["path"],
        "operator": operator_of(s["host"]),
        "org": registrable_domain(s["host"]),
        "info_url": entry["info_url"],
        "description": entry["description"],
        "stamp": entry["stamp"],
    }
    if not is_relay:
        rec["dnssec"] = s["dnssec"]
        rec["no_logs"] = s["no_logs"]
        rec["no_filter"] = s["no_filter"]
        # Every public ICANN ODoH target NXDOMAINs Handshake names (surveyed
        # 2026-08-18); only our injected target is Handshake-aware.
        rec["handshake_aware"] = False
    return rec


# --- feed assembly ----------------------------------------------------------

def build_feed(servers_md, servers_sig, relays_md, relays_sig,
               inject_own=True, key_b64=DNSCRYPT_MINISIGN_KEY):
    """Verify both lists, parse them, and assemble the feed dict.

    Raises if either signature fails -- there is no partial feed.
    """
    servers_tc = verify_minisig(key_b64, servers_md, servers_sig)
    relays_tc = verify_minisig(key_b64, relays_md, relays_sig)

    targets = [r for r in (build_endpoint(e, False)
                           for e in parse_list(servers_md.decode())) if r]
    relays = [r for r in (build_endpoint(e, True)
                          for e in parse_list(relays_md.decode())) if r]

    if inject_own:
        # De-dupe in case odoh.hns.one lands on the public list later.
        targets = [t for t in targets if t["host"] != OWN_TARGET["host"]]
        targets.insert(0, dict(OWN_TARGET))

    feed = {
        "version": 1,
        "generated": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0).isoformat(),
        "own": {"operator": OWN_OPERATOR, "org": "hns.one"},
        "signature": {
            "verified": True,
            "minisign_key": key_b64,
            "servers_trusted_comment": servers_tc,
            "relays_trusted_comment": relays_tc,
        },
        "source": {"servers": SERVERS_URLS[0], "relays": RELAYS_URLS[0]},
        "targets": targets,
        "relays": relays,
        "pairs": distinct_pairs(targets, relays),
    }
    return feed


def distinct_pairs(targets, relays, require_dnssec=True):
    """Precomputed org-distinct (target, relay) pairs the browser can use.

    Only DNSSEC-capable targets, only operator-distinct relays. Handshake-aware
    targets come first so a Handshake lookup finds a usable pair immediately.
    """
    pairs = []
    ordered = sorted(targets, key=lambda t: not t.get("handshake_aware"))
    for t in ordered:
        if require_dnssec and not t.get("dnssec"):
            continue
        for r in relays:
            if r["operator"] != t["operator"]:
                pairs.append({
                    "target_host": t["host"],
                    "target_path": t["path"],
                    "relay_host": r["host"],
                    "relay_path": r["path"],
                    "handshake_aware": t.get("handshake_aware", False),
                    "target_operator": t["operator"],
                    "relay_operator": r["operator"],
                })
    return pairs


# --- fetching ---------------------------------------------------------------

def _fetch(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": "hns.one-odoh-list"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_first(urls):
    """Fetch the first reachable mirror. Raises if all fail."""
    last = None
    for u in urls:
        try:
            return _fetch(u)
        except Exception as exc:            # noqa: BLE001 -- try the next mirror
            last = exc
            print(f"  .. {u} failed: {exc}", file=sys.stderr)
    raise RuntimeError(f"all mirrors failed; last error: {last}")


def load_sources(offline_dir=None):
    """Return (servers_md, servers_sig, relays_md, relays_sig) as bytes/str."""
    if offline_dir:
        def rd(name, binary):
            p = os.path.join(offline_dir, name)
            return open(p, "rb").read() if binary else open(p).read()
        return (rd("odoh-servers.md", True), rd("odoh-servers.md.minisig", False),
                rd("odoh-relays.md", True), rd("odoh-relays.md.minisig", False))
    return (fetch_first(SERVERS_URLS),
            fetch_first([u + ".minisig" for u in SERVERS_URLS]).decode(),
            fetch_first(RELAYS_URLS),
            fetch_first([u + ".minisig" for u in RELAYS_URLS]).decode())


def main():
    ap = argparse.ArgumentParser(description="Build the signed ODoH feed for the browser.")
    ap.add_argument("--out", help="write the feed JSON here (atomic replace)")
    ap.add_argument("--offline", metavar="DIR",
                    help="read the four list files from DIR instead of the network")
    ap.add_argument("--check", action="store_true",
                    help="verify signatures and parse, but write nothing")
    ap.add_argument("--print", action="store_true", dest="to_stdout",
                    help="print the feed JSON to stdout")
    ap.add_argument("--no-inject-own", action="store_true",
                    help="do not add odoh.hns.one to the target list")
    args = ap.parse_args()

    print("fetching DNSCrypt ODoH lists..." if not args.offline
          else f"reading lists from {args.offline}", file=sys.stderr)
    try:
        servers_md, servers_sig, relays_md, relays_sig = load_sources(args.offline)
    except Exception as exc:                # noqa: BLE001
        print(f"!! cannot load lists: {exc}", file=sys.stderr)
        return 2

    try:
        feed = build_feed(servers_md, servers_sig, relays_md, relays_sig,
                          inject_own=not args.no_inject_own)
    except (InvalidSignature, ValueError) as exc:
        # Fail closed: a signature/parse failure must never produce a feed.
        print(f"!! SIGNATURE/PARSE FAILURE, refusing to emit feed: {exc}",
              file=sys.stderr)
        return 3

    print(f"verified: {len(feed['targets'])} targets, {len(feed['relays'])} "
          f"relays, {len(feed['pairs'])} org-distinct pairs", file=sys.stderr)
    print(f"  servers: {feed['signature']['servers_trusted_comment']}", file=sys.stderr)
    print(f"  relays:  {feed['signature']['relays_trusted_comment']}", file=sys.stderr)

    blob = json.dumps(feed, indent=2, ensure_ascii=False) + "\n"
    if args.to_stdout:
        sys.stdout.write(blob)
    if args.check:
        return 0
    if args.out:
        tmp = args.out + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(blob)
        os.replace(tmp, args.out)           # atomic: readers never see a half file
        print(f"wrote {args.out} ({len(blob)} bytes)", file=sys.stderr)
    elif not args.to_stdout:
        print("(nothing written; pass --out FILE or --print)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
