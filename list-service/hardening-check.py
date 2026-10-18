#!/usr/bin/env python3
"""
odoh.hns.one target hardening check -- verify, never mutate.

WHAT IT CHECKS (and why each matters for the oblivious-DoH threat model)
    1. DNSSEC VALIDATION -- and it is checked with a NEGATIVE probe, because a
       positive one cannot fail. This check used to query a known-good signed
       name (`cloudflare.com`) with DO=1 and pass if `ad or has_rrsig`. Both
       of those are produced by a resolver that does no validation at all:
       RRSIGs are just records it forwarded, and AD is whatever it chose to
       set. A non-validating resolver returns byte-identical answers for a
       VALID name, so the check could not fail for the condition it named --
       and it passed for months while `odoh.hns.one` happily returned answers
       for deliberately-broken zones, which we then published as
       `"dnssec": true` in the public feed.

       The only probe that separates validating from non-validating is a
       BOGUS name: `dnssec-failed.org` and `sigfail.verteiltesysteme.net` are
       signed with signatures that do not verify, and a validating resolver
       MUST answer SERVFAIL. Anything else -- NOERROR with records, however
       the AD bit is set -- means bogus data reaches the caller.

       History: hsd's own recursive is DNSSEC-AWARE, not DNSSEC-ENFORCING
       (bns `recursive.js` drops the chain on a failed signature and answers
       anyway, NOERROR/AD=0), so this check FAILED against it. FIXED
       2026-08-20 by putting a validating resolver in front: ICANN names go
       to unbound and Handshake names to hsd, split by TLD
       (127.0.0.1:5351, the default `--recursive` below). The check passes
       against that; it must be re-run whenever the split changes.

       odoh-server-go forwards the decrypted query VERBATIM to the upstream
       (confirmed against the source: it only rewrites the response id), so
       this is a property of the recursive behind the target, not of ODoH.
    2. EDNS Client Subnet (ECS) disabled. ECS leaks a chunk of the client's IP
       to authoritative servers -- in ODoH the "client" is the relay, but any
       ECS at all narrows the anonymity set and is pure downside for a privacy
       resolver. The target adds none (verbatim forward), so the check is: does
       the recursive honor / echo a client-supplied ECS option? A privacy
       recursive must ignore it (no ECS option, or scope prefix length 0).
    3. No-collusion relay pairing. The whole scheme collapses if the relay and
       target share an operator. We reuse the list-service operator map to
       assert every relay handed to the browser has operator != hns.one, and
       that the target host is NOT also answering as a relay.
    4. Target liveness + suite. /.well-known/odohconfigs parses and advertises
       X25519-HKDF-SHA256 / HKDF-SHA256 / AES-128-GCM (what odoh.js speaks).

WHAT IT DOES NOT DO
    It changes nothing and restarts nothing, so it is safe to run against a
    live target. The DNSSEC/ECS probes talk to the *recursive* directly
    (default 127.0.0.1:5351), so run this ON the target host for those two checks; the
    HTTPS/relay checks work from anywhere. Full end-to-end ODoH (through HPKE)
    is left to the repo's JS client (client/example.mjs); this tool verifies the
    DNS-layer properties that the verbatim-forwarding target passes through.

USAGE
    python3 hardening-check.py                      # all checks, defaults
    python3 hardening-check.py --recursive 127.0.0.1:5351 \
        --target odoh.hns.one \
        --relays odoh-relay.numa.rs,odoh-relay.edgecompute.app
    python3 hardening-check.py --skip-dns           # HTTPS/relay checks only
"""

import argparse
import importlib.util
import os
import socket
import struct
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

# A well-known DNSSEC-signed ICANN name to probe with DO=1. `cloudflare.com`
# is signed and stable; override with --signed-name for a Handshake test.
DEFAULT_SIGNED_NAME = "cloudflare.com"

# Deliberately-broken zones: signed, with signatures that do not verify. These
# are the ONLY probes here that can distinguish a validating resolver from one
# that merely carries DNSSEC records. Both are long-standing public test zones.
BOGUS_NAMES = ("dnssec-failed.org", "sigfail.verteiltesysteme.net")


def _load_list_service():
    """Borrow operator_of() from the list service so distinctness stays one
    source of truth (the module name has a hyphen, so load it by path)."""
    path = os.path.join(HERE, "odoh-list-service.py")
    spec = importlib.util.spec_from_file_location("odoh_list_service", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- minimal DNS wire (query build + response header/opt parse) -------------
# Just enough to set DO=1, attach an ECS option, read the AD flag, and find
# RRSIG / a returned ECS option. Stdlib only.

def _encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def build_query(name, qtype=1, do=True, ecs=None):
    """A DNS query with an OPT RR. ecs=(family, prefixlen, addr_bytes)."""
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 1)  # RD=1, 1 OPT
    question = _encode_name(name) + struct.pack(">HH", qtype, 1)  # IN
    rdata = b""
    if ecs is not None:
        family, prefixlen, addr = ecs
        # RFC 7871: option-code 8, family, source-prefix, scope-prefix(0), addr
        opt_data = struct.pack(">HBB", family, prefixlen, 0) + addr
        rdata = struct.pack(">HH", 8, len(opt_data)) + opt_data
    # OPT: name=root, type=41, class=UDP size 4096, TTL = ext-rcode|ver|flags
    do_flag = 0x8000 if do else 0
    ttl = struct.pack(">BBH", 0, 0, do_flag)
    opt = b"\x00" + struct.pack(">HH", 41, 4096) + ttl + \
        struct.pack(">H", len(rdata)) + rdata
    return header + question + opt


def _skip_name(buf, at):
    while True:
        n = buf[at]
        if n & 0xC0 == 0xC0:      # compression pointer ends the name
            return at + 2
        at += 1
        if n == 0:
            return at
        at += n


def parse_response(buf):
    """Return {ad, rcode, has_rrsig, ecs_scope} from a DNS response."""
    qd, an, ns, ar = struct.unpack(">HHHH", buf[4:12])
    flags2 = buf[3]
    info = {"ad": bool(flags2 & 0x20), "rcode": flags2 & 0x0F,
            "has_rrsig": False, "ecs_scope": None}
    at = 12
    for _ in range(qd):
        at = _skip_name(buf, at) + 4          # + qtype + qclass
    for section, count in (("an", an), ("ns", ns), ("ar", ar)):
        for _ in range(count):
            at = _skip_name(buf, at)
            rtype, rclass, _ttl, rdlen = struct.unpack(">HHIH", buf[at:at + 10])
            at += 10
            if rtype == 46:                    # RRSIG present -> signed answer
                info["has_rrsig"] = True
            if rtype == 41:                    # OPT: scan options for ECS (8)
                opt_end, oat = at + rdlen, at
                while oat + 4 <= opt_end:
                    ocode, olen = struct.unpack(">HH", buf[oat:oat + 4])
                    if ocode == 8 and olen >= 4:
                        # byte 3 of ECS data is the SCOPE prefix length
                        info["ecs_scope"] = buf[oat + 4 + 3]
                    oat += 4 + olen
            at += rdlen
    return info


def dns_query(server, name, qtype=1, do=True, ecs=None, timeout=5):
    host, _, port = server.partition(":")
    port = int(port or 53)
    wire = build_query(name, qtype, do, ecs)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(wire, (host, port))
        data, _ = sock.recvfrom(65535)
    finally:
        sock.close()
    if data[2] & 0x02:                         # TC set -> retry over TCP
        return _dns_query_tcp(host, port, wire, timeout)
    return parse_response(data)


def _dns_query_tcp(host, port, wire, timeout):
    with socket.create_connection((host, port), timeout) as s:
        s.sendall(struct.pack(">H", len(wire)) + wire)
        ln = struct.unpack(">H", _recv_n(s, 2))[0]
        return parse_response(_recv_n(s, ln))


def _recv_n(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("short DNS/TCP read")
        buf += chunk
    return buf


# --- HTTPS checks -----------------------------------------------------------

ODOH_VERSION = 0x0001
KEM_X25519, KDF_HKDF_SHA256, AEAD_AES128GCM = 0x0020, 0x0001, 0x0001


def check_odohconfigs(target, timeout=10):
    """Fetch and sanity-parse /.well-known/odohconfigs. Returns (ok, detail)."""
    url = f"https://{target}/.well-known/odohconfigs"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "hns.one-hardening"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            buf = resp.read()
    except Exception as exc:                   # noqa: BLE001
        return False, f"fetch failed: {exc}"
    if len(buf) < 2:
        return False, "config truncated"
    total = (buf[0] << 8) | buf[1]
    at, end = 2, 2 + total
    while at + 4 <= end:
        length = (buf[at + 2] << 8) | buf[at + 3]
        contents = buf[at + 4:at + 4 + length]
        at += 4 + length
        if len(contents) < 8:
            continue
        kem = (contents[0] << 8) | contents[1]
        kdf = (contents[2] << 8) | contents[3]
        aead = (contents[4] << 8) | contents[5]
        if (kem, kdf, aead) == (KEM_X25519, KDF_HKDF_SHA256, AEAD_AES128GCM):
            return True, "X25519-HKDF-SHA256/HKDF-SHA256/AES-128-GCM"
    return False, "no supported suite advertised"


def check_not_a_relay(target, timeout=8):
    """A target host must not also relay -- if one box is both, pairing it with
    itself de-anonymizes the user completely, so the relay endpoint should be
    physically absent (nginx 404) even though our feed never lists it.

    odoh-server-go serves the proxy (relay) at /proxy from the SAME binary as
    the target. A live relay handler rejects a paramless request with 400 (Bad
    Request); a disabled one returns 404. So: exposed unless /proxy is 404.

    THREE-STATE, and the third state is what this function got wrong:

        True   /proxy is provably 404 -- the relay endpoint is disabled.
        False  /proxy answered something else -- it is LIVE. Total
               de-anonymisation if the browser ever pairs the box with itself.
        None   the probe did not complete, so NOTHING WAS PROVEN.

    It used to `return True` on ANY exception -- a DNS failure, a TLS error, a
    timeout, a typo in --target -- with the comment "treat as not exposed".
    That is exactly backwards: an unreachable probe is the absence of evidence,
    not evidence of absence, and combined with the caller's `hard=False` it
    meant a live /proxy on the ODoH target could still print
    "RESULT: PASS -- all hard checks green"."""
    try:
        req = urllib.request.Request(f"https://{target}/proxy",
                                     headers={"User-Agent": "hns.one-hardening"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = resp.status
    except urllib.error.HTTPError as exc:
        code = exc.code
    except Exception as exc:                    # noqa: BLE001
        return None, (f"/proxy probe did not complete ({exc}) -- this run did "
                      f"NOT establish that {target} refuses to relay. Re-run "
                      f"from somewhere that can reach it.")
    if code == 404:
        return True, "/proxy returns 404 -- relay endpoint disabled"
    return False, (f"/proxy answered {code} -- the relay endpoint is LIVE on the "
                   f"target host; disable it (nginx: location = /proxy "
                   f"{{ return 404; }}) so the box cannot relay its own target")


# --- runner -----------------------------------------------------------------

class Report:
    """Collects check outcomes. `ok` is TRI-STATE:

        True   the check ran and passed
        False  the check ran and failed
        None   the check could not be performed -- UNKNOWN

    UNKNOWN counts as a failure for a hard check. A verifier that could not
    verify has not verified anything, and the whole reason this file exists is
    that `check_not_a_relay` used to convert "I could not tell" into PASS.
    """

    def __init__(self):
        self.fail = False

    def check(self, ok, name, detail, hard=True):
        if ok is True:
            mark = "PASS"
        elif ok is None:
            mark = "UNKNOWN" if hard else "WARN"
        else:
            mark = "FAIL" if hard else "WARN"
        print(f"  [{mark}] {name}: {detail}")
        if ok is not True and hard:
            self.fail = True


def main():
    ap = argparse.ArgumentParser(description="Verify odoh.hns.one hardening.")
    ap.add_argument("--recursive", default="127.0.0.1:5351",
                    help="recursive to probe for DNSSEC/ECS (run on the target host)")
    ap.add_argument("--target", default="odoh.hns.one")
    ap.add_argument("--relays", default="odoh-relay.numa.rs,odoh-relay.edgecompute.app",
                    help="comma-separated relay hosts the browser pairs with the target")
    ap.add_argument("--signed-name", default=DEFAULT_SIGNED_NAME)
    ap.add_argument("--skip-dns", action="store_true",
                    help="skip the recursive DNSSEC/ECS probes (runs from another host)")
    args = ap.parse_args()

    svc = _load_list_service()
    r = Report()

    print(f"== DNSSEC / ECS (recursive {args.recursive}) ==")
    if args.skip_dns:
        print("  (skipped)")
    else:
        # POSITIVE probe: a good signed name must still resolve, and should
        # carry AD. On its own this proves nothing about validation -- see the
        # module docstring -- so it is reported, not asserted on.
        try:
            signed = dns_query(args.recursive, args.signed_name, qtype=1, do=True)
            r.check(signed["rcode"] == 0, "signed name resolves",
                    f"{args.signed_name} DO=1 -> AD={signed['ad']} "
                    f"RRSIG={signed['has_rrsig']} rcode={signed['rcode']}"
                    + ("" if signed["ad"] else "  (AD not set: not validated)"))
        except Exception as exc:               # noqa: BLE001
            r.check(False, "signed name resolves", f"probe error: {exc}")

        # NEGATIVE probe: THE check. A validating resolver MUST refuse these.
        for bogus in BOGUS_NAMES:
            try:
                res = dns_query(args.recursive, bogus, qtype=1, do=True)
                servfail = res["rcode"] == 2
                r.check(servfail, f"rejects bogus DNSSEC ({bogus})",
                        "SERVFAIL as required" if servfail else
                        f"returned rcode={res['rcode']} AD={res['ad']} "
                        f"-- BOGUS DATA IS BEING SERVED; this resolver does not "
                        f"validate, so no 'dnssec' claim may be published for it")
            except Exception as exc:           # noqa: BLE001
                r.check(False, f"rejects bogus DNSSEC ({bogus})", f"probe error: {exc}")
        try:
            # Hand the recursive a bogus client subnet; a privacy recursive must
            # NOT honor it (no ECS echoed, or scope prefix length 0).
            ecs = (1, 24, bytes([203, 0, 113]))     # 203.0.113.0/24, IPv4
            resp = dns_query(args.recursive, args.signed_name, qtype=1,
                             do=True, ecs=ecs)
            scope = resp["ecs_scope"]
            ok = scope in (None, 0)
            r.check(ok, "ECS disabled",
                    "recursive ignored client subnet"
                    if ok else f"recursive echoed ECS scope /{scope} -- ECS is ON")
        except Exception as exc:               # noqa: BLE001
            r.check(False, "ECS disabled", f"probe error: {exc}")

    print(f"== Target {args.target} ==")
    ok, detail = check_odohconfigs(args.target)
    r.check(ok, "odohconfigs + suite", detail)
    ok, detail = check_not_a_relay(args.target)
    # HARD. A target that also relays is total de-anonymisation -- the single
    # worst outcome this file exists to prevent -- so it cannot be the one
    # check whose failure is a WARN. `hard=False` here was how a live /proxy
    # still produced "PASS -- all hard checks green".
    r.check(ok, "target is not a relay", detail)

    print("== No-collusion relay pairing ==")
    target_op = svc.operator_of(args.target)
    print(f"  target operator: {target_op}")
    relays = [x.strip() for x in args.relays.split(",") if x.strip()]
    # A loop over an empty list passes trivially. `--relays ""` used to iterate
    # zero times and report PASS, which says the pairing is safe when in fact
    # no pairing was examined at all.
    r.check(bool(relays), "relays to check",
            f"{len(relays)} relay(s) supplied"
            if relays else "NO RELAYS SUPPLIED -- the no-collusion property "
                           "was not checked against anything; this run proves "
                           "nothing about pairing")
    for relay in relays:
        rop = svc.operator_of(relay)
        # Self-pairing is the same catastrophe as a target that relays, and
        # comparing operators alone would miss `--relays odoh.hns.one` if the
        # operator map ever went quiet about one of them.
        same_host = relay.split(":")[0].lower() == args.target.split(":")[0].lower()
        r.check(rop != target_op and not same_host, f"relay {relay}",
                f"operator {rop} != target operator {target_op}"
                if rop != target_op and not same_host
                else (f"IS THE TARGET HOST -- pairing it with itself de-anonymizes "
                      f"every query" if same_host
                      else f"SAME operator as target ({rop}) -- COLLUSION, never pair"))

    print()
    print("RESULT:", "FAIL -- see above" if r.fail else "PASS -- all hard checks green")
    return 1 if r.fail else 0


if __name__ == "__main__":
    sys.exit(main())
