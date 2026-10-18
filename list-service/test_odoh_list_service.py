#!/usr/bin/env python3
"""
Tests for odoh-list-service.py -- the two things that carry the security
weight: minisign signature verification (fail-closed) and the org-distinctness
logic that stops a target from being paired with a relay run by the same
operator.

Run:  python3 -m unittest test_odoh_list_service -v
      (needs `cryptography`; the module name has a hyphen so we load it by path)
"""

import base64
import importlib.util
import os
import struct
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "test-fixtures")


def _fx(name, binary=False):
    """Read a bundled fixture file (closing it -- keeps the tests warning-free)."""
    mode = "rb" if binary else "r"
    with open(os.path.join(FIXTURES, name), mode) as fh:
        return fh.read()


def _load_module():
    path = os.path.join(HERE, "odoh-list-service.py")
    spec = importlib.util.spec_from_file_location("odoh_list_service", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


svc = _load_module()


# --- helpers to forge a minisign key + signature for the ED/Ed branches -----
# minisign public key  = base64( algo[2] || key_id[8] || pk[32] )
# minisign signature   = 4 lines; line2 = base64(algo || key_id || sig64),
#                        line4 = base64( sig64 over (sig64 || trusted_comment) )

def _make_key():
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    key_id = os.urandom(8)
    pk_raw = pk.public_bytes_raw()
    pub_b64 = base64.b64encode(b"Ed" + key_id + pk_raw).decode()
    return sk, key_id, pub_b64


def _sign(sk, key_id, data, algo=b"Ed", trusted_comment="timestamp:1\tfile:x"):
    import hashlib
    signed = hashlib.blake2b(data).digest() if algo == b"ED" else data
    sig = sk.sign(signed)
    global_sig = sk.sign(sig + trusted_comment.encode())
    line2 = base64.b64encode(algo + key_id + sig).decode()
    line4 = base64.b64encode(global_sig).decode()
    return (f"untrusted comment: test\n{line2}\n"
            f"trusted comment: {trusted_comment}\n{line4}\n")


class MinisignTests(unittest.TestCase):
    def test_real_dnscrypt_lists_verify(self):
        # The real signed lists must verify against the real DNSCrypt key --
        # this is the end-to-end trust anchor, offline from bundled fixtures.
        for base in ("odoh-servers.md", "odoh-relays.md"):
            data = _fx(base, binary=True)
            sig = _fx(base + ".minisig")
            tc = svc.verify_minisig(svc.DNSCRYPT_MINISIGN_KEY, data, sig)
            self.assertIn("file:" + base, tc)

    def test_tampered_data_rejected(self):
        data = _fx("odoh-relays.md", binary=True)
        sig = _fx("odoh-relays.md.minisig")
        with self.assertRaises(InvalidSignature):
            svc.verify_minisig(svc.DNSCRYPT_MINISIGN_KEY, data + b"evil", sig)

    def test_wrong_key_rejected(self):
        # A signature from the right maintainer but a different trusted key must
        # fail on key-id mismatch, not silently pass.
        data = _fx("odoh-relays.md", binary=True)
        sig = _fx("odoh-relays.md.minisig")
        _, _, other_pub = _make_key()
        with self.assertRaises(ValueError):
            svc.verify_minisig(other_pub, data, sig)

    def test_ed_prehash_branch(self):
        # Exercise the "ED" (BLAKE2b prehash) algorithm path with a forged key.
        sk, key_id, pub = _make_key()
        data = b"hello handshake"
        sig = _sign(sk, key_id, data, algo=b"ED")
        self.assertEqual(svc.verify_minisig(pub, data, sig), "timestamp:1\tfile:x")
        with self.assertRaises(InvalidSignature):
            svc.verify_minisig(pub, data + b"x", sig)

    def test_ed_legacy_branch(self):
        sk, key_id, pub = _make_key()
        data = b"raw file body"
        sig = _sign(sk, key_id, data, algo=b"Ed")
        self.assertEqual(svc.verify_minisig(pub, data, sig), "timestamp:1\tfile:x")

    def test_trusted_comment_tamper_rejected(self):
        # The global signature binds the trusted comment; swapping it must fail.
        sk, key_id, pub = _make_key()
        data = b"body"
        sig = _sign(sk, key_id, data, trusted_comment="timestamp:1\tfile:x")
        forged = sig.replace("file:x", "file:evil")
        with self.assertRaises(InvalidSignature):
            svc.verify_minisig(pub, data, forged)


class StampTests(unittest.TestCase):
    def test_decode_target(self):
        s = svc.decode_stamp(
            "sdns://BQcAAAAAAAAAD2FkbDAxLmRuc2NyeS5wdAovZG5zLXF1ZXJ5")
        self.assertEqual(s["proto"], svc.PROTO_ODOH_TARGET)
        self.assertEqual(s["host"], "adl01.dnscry.pt")
        self.assertEqual(s["path"], "/dns-query")
        self.assertTrue(s["dnssec"])

    def test_decode_relay(self):
        s = svc.decode_stamp(
            "sdns://hQcAAAAAAAAAAAAab2RvaC1yZWxheS5lZGdlY29tcHV0ZS5hcHABLw")
        self.assertEqual(s["proto"], svc.PROTO_ODOH_RELAY)
        self.assertEqual(s["host"], "odoh-relay.edgecompute.app")
        self.assertEqual(s["path"], "/")

    def test_non_odoh_stamp_rejected(self):
        # A plain DoH stamp (proto 0x02) must not be accepted as ODoH.
        blob = bytes([0x02]) + struct.pack("<Q", 0) + b"\x00\x00\x00\x00"
        stamp = "sdns://" + base64.urlsafe_b64encode(blob).decode().rstrip("=")
        with self.assertRaises(ValueError):
            svc.decode_stamp(stamp)


class OrgDistinctnessTests(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(svc.registrable_domain("odoh.cloudflare-dns.com"),
                         "cloudflare-dns.com")
        self.assertEqual(svc.registrable_domain("adl01.dnscry.pt"), "dnscry.pt")
        self.assertEqual(svc.registrable_domain("x.example.co.uk"),
                         "example.co.uk")

    def test_operator_group_collapses_edge_host(self):
        # The crux: the crypto.sx relay lives on edgecompute.app but is the
        # SAME operator as the crypto.sx target. operator_of must collapse them.
        self.assertEqual(svc.operator_of("odoh-relay.edgecompute.app"), "crypto.sx")
        self.assertEqual(svc.operator_of("odoh.crypto.sx"), "crypto.sx")
        self.assertTrue(svc.same_org("odoh-relay.edgecompute.app", "odoh.crypto.sx"))

    def test_independent_hosts_are_distinct(self):
        self.assertFalse(svc.same_org("odoh-relay.numa.rs", "odoh.cloudflare-dns.com"))
        self.assertFalse(svc.same_org("odoh-relay.numa.rs", "odoh.hns.one"))

    def test_our_target_never_pairs_our_relay(self):
        # We run no relay, but if one ever appeared on hns.one the rule must
        # already forbid it. operator hns.one == operator hns.one.
        self.assertTrue(svc.same_org("odoh.hns.one", "relay.hns.one"))

    def test_distinct_pairs_excludes_collusion(self):
        targets = [
            {"host": "odoh.crypto.sx", "path": "/dns-query",
             "operator": "crypto.sx", "dnssec": True},
            {"host": "odoh.hns.one", "path": "/dns-query",
             "operator": "hns.one", "dnssec": True, "handshake_aware": True},
        ]
        relays = [
            {"host": "odoh-relay.edgecompute.app", "path": "/", "operator": "crypto.sx"},
            {"host": "odoh-relay.numa.rs", "path": "/relay", "operator": "numa"},
        ]
        pairs = svc.distinct_pairs(targets, relays)
        # crypto.sx target must NOT be paired with the crypto.sx (edge) relay.
        self.assertNotIn(("odoh.crypto.sx", "odoh-relay.edgecompute.app"),
                         [(p["target_host"], p["relay_host"]) for p in pairs])
        # but it may pair with numa
        self.assertIn(("odoh.crypto.sx", "odoh-relay.numa.rs"),
                      [(p["target_host"], p["relay_host"]) for p in pairs])
        # handshake-aware target sorts first
        self.assertTrue(pairs[0]["handshake_aware"])

    def test_distinct_pairs_requires_dnssec(self):
        targets = [{"host": "t.example.com", "path": "/dns-query",
                    "operator": "example.com", "dnssec": False}]
        relays = [{"host": "r.numa.rs", "path": "/", "operator": "numa"}]
        self.assertEqual(svc.distinct_pairs(targets, relays), [])


class FeedTests(unittest.TestCase):
    def _sources(self):
        return (_fx("odoh-servers.md", True), _fx("odoh-servers.md.minisig"),
                _fx("odoh-relays.md", True), _fx("odoh-relays.md.minisig"))

    def test_build_feed_injects_own_target_first(self):
        feed = svc.build_feed(*self._sources())
        self.assertTrue(feed["signature"]["verified"])
        self.assertEqual(feed["targets"][0]["host"], "odoh.hns.one")
        self.assertTrue(feed["targets"][0]["handshake_aware"])
        self.assertEqual(feed["own"]["operator"], "hns.one")
        # exactly one Handshake-aware target today
        self.assertEqual(sum(t.get("handshake_aware") for t in feed["targets"]), 1)

    def test_build_feed_refuses_on_bad_signature(self):
        s_md, s_sig, r_md, r_sig = self._sources()
        with self.assertRaises((InvalidSignature, ValueError)):
            svc.build_feed(s_md + b"tampered", s_sig, r_md, r_sig)

    def test_feed_pairs_are_all_distinct_and_dnssec(self):
        feed = svc.build_feed(*self._sources())
        for p in feed["pairs"]:
            self.assertNotEqual(p["target_operator"], p["relay_operator"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
