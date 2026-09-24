"""Latency benchmarks of the everyday operations.

    # emulator (from the repository root, emulator + pcscd running, e.g. via
    # the harness: see tests/README.md)
    PYTHONPATH=tests:tools/librefido python tests/bench/bench.py --fido-emulator

    # real device over PC/SC (Windows or Linux), on a profile you can wipe:
    python tests/bench/bench.py --reader "LibreKeys" --i-understand-this-modifies-the-card

It generates keys (PIV 9A/9C, OpenPGP signature key, an OATH credential) with
the DEFAULT PINs (123456 / 12345678, PIV management key 010203...08), so run
it only on a fresh or throw-away profile. Presence: PIV keys are generated
with touch policy NEVER and OpenPGP UIF stays off, so only the FIDO part
needs presence (auto on the emulator; on hardware it needs a press per
operation unless "my device is safe" is on for FIDO).

Prints a markdown table: operation, runs, median and p90 in milliseconds.
"""

import argparse
import statistics
import sys
import time

from smartcard.System import readers

AID_OPENPGP = bytes.fromhex("D27600012401")
AID_PIV = bytes.fromhex("A000000308")
AID_OATH = bytes.fromhex("A0000005272101")
AID_LFMGMT = b"\xF0LIBREFIDO"
PIV_MGMT_DEFAULT = bytes.fromhex("010203040506070801020304050607080102030405060708")


class Card:
    def __init__(self, reader_prefix):
        for r in readers():
            if str(r).startswith(reader_prefix):
                self.conn = r.createConnection()
                self.conn.connect()
                return
        sys.exit("no reader starting with %r (have: %s)" % (reader_prefix, ", ".join(map(str, readers()))))

    def send(self, cla, ins, p1, p2, data=b"", le=0, check=True):
        """Extended APDU if needed; follows 61xx."""
        if len(data) > 255:
            apdu = bytes([cla, ins, p1, p2, 0]) + len(data).to_bytes(2, "big") + data + b"\x00\x00"
        else:
            apdu = bytes([cla, ins, p1, p2]) + (bytes([len(data)]) + data if data else b"") + bytes([le])
        resp, sw1, sw2 = self.conn.transmit(list(apdu))
        out = bytes(resp)
        while sw1 == 0x61:
            resp, sw1, sw2 = self.conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
            out += bytes(resp)
        sw = (sw1 << 8) | sw2
        if check and sw != 0x9000:
            raise RuntimeError("%02X %02X: SW %04X" % (cla, ins, sw))
        return out

    def select(self, aid):
        return self.send(0x00, 0xA4, 0x04, 0x00, aid)


def tlv(tag, value):
    tag = tag.to_bytes(2, "big") if tag > 0xFF else bytes([tag])
    n = len(value)
    ln = bytes([n]) if n < 0x80 else (bytes([0x81, n]) if n < 0x100 else b"\x82" + n.to_bytes(2, "big"))
    return tag + ln + value


def measure(name, fn, runs, rows):
    fn()                                    # warm up (and fail early)
    t = []
    for _ in range(runs):
        s = time.perf_counter()
        fn()
        t.append((time.perf_counter() - s) * 1000)
    t.sort()
    rows.append((name, runs, statistics.median(t), t[min(len(t) - 1, int(len(t) * 0.9))]))
    print("  %-40s %7.1f ms" % (name, statistics.median(t)), file=sys.stderr)


def bench_mgmt(c, runs, rows):
    c.select(AID_LFMGMT)
    measure("management INFO", lambda: c.send(0x80, 0x01, 0, 0), runs, rows)


def bench_oath(c, runs, rows):
    c.select(AID_OATH)
    c.send(0x00, 0x01, 0, 0, tlv(0x71, b"bench") + tlv(0x73, b"\x21\x06" + b"\x55" * 20))
    challenge = tlv(0x74, (int(time.time()) // 30).to_bytes(8, "big"))
    measure("OATH CALCULATE (TOTP SHA-256)", lambda: c.send(0x00, 0xA2, 0, 1, tlv(0x71, b"bench") + challenge), runs, rows)
    measure("OATH CALCULATE ALL", lambda: c.send(0x00, 0xA4, 0, 1, challenge), runs, rows)
    c.send(0x00, 0x02, 0, 0, tlv(0x71, b"bench"))


def piv_auth(c):
    """Single-step 9B authentication is not assumed: mutual (witness) with AES-192/3DES."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    meta = c.send(0x00, 0xF7, 0x00, 0x9B, check=False)
    algo = 0x03
    if meta[:2] == b"\x01\x01":
        algo = meta[2]
    if algo == 0x03:
        cipher = algorithms.TripleDES(PIV_MGMT_DEFAULT)
    else:
        cipher = algorithms.AES(PIV_MGMT_DEFAULT)
    bs = cipher.block_size // 8
    r = c.send(0x00, 0x87, algo, 0x9B, tlv(0x7C, tlv(0x80, b"")))
    witness = r[4:4 + bs]
    dec = Cipher(cipher, modes.ECB()).decryptor().update(witness)
    challenge = b"\x5A" * bs
    c.send(0x00, 0x87, algo, 0x9B, tlv(0x7C, tlv(0x80, dec) + tlv(0x81, challenge)))


def bench_piv(c, runs, rows):
    c.select(AID_PIV)
    piv_auth(c)
    # 9C: P-256, PIN once, touch never; 9A: RSA-2048, touch never
    c.send(0x00, 0x47, 0x00, 0x9C, tlv(0xAC, tlv(0x80, b"\x11") + tlv(0xAA, b"\x01") + tlv(0xAB, b"\x01")))
    c.send(0x00, 0x20, 0x00, 0x80, b"123456\xff\xff")
    digest = b"\x33" * 32
    measure("PIV sign P-256 (9C)", lambda: c.send(0x00, 0x87, 0x11, 0x9C,
                                                 tlv(0x7C, tlv(0x82, b"") + tlv(0x81, digest))), runs, rows)
    t = time.perf_counter()
    c.send(0x00, 0x47, 0x00, 0x9A, tlv(0xAC, tlv(0x80, b"\x07") + tlv(0xAA, b"\x01") + tlv(0xAB, b"\x01")))
    rows.append(("PIV generate RSA-2048 (9A)", 1, (time.perf_counter() - t) * 1000, (time.perf_counter() - t) * 1000))
    block = b"\x00\x01" + b"\xff" * (256 - 3 - 51) + b"\x00" + b"\x30\x31" + b"\x00" * 49
    measure("PIV sign RSA-2048 (9A)", lambda: c.send(0x00, 0x87, 0x07, 0x9A,
                                                    tlv(0x7C, tlv(0x82, b"") + tlv(0x81, block))), max(3, runs // 5), rows)


def bench_openpgp(c, runs, rows):
    c.select(AID_OPENPGP)
    c.send(0x00, 0x20, 0x00, 0x83, b"12345678")
    # signature key: NIST P-256 (algorithm attributes C1), then generate
    c.send(0x00, 0xDA, 0x00, 0xC1, bytes.fromhex("132A8648CE3D030107"))
    t = time.perf_counter()
    c.send(0x00, 0x47, 0x80, 0x00, bytes.fromhex("B600"))
    rows.append(("OpenPGP generate P-256", 1, (time.perf_counter() - t) * 1000, (time.perf_counter() - t) * 1000))

    def sign():
        c.send(0x00, 0x20, 0x00, 0x81, b"123456")
        c.send(0x00, 0x2A, 0x9E, 0x9A, b"\x44" * 32)
    measure("OpenPGP VERIFY + sign P-256", sign, runs, rows)


def bench_fido_emulator(runs, rows):
    sys.path.insert(0, "tests")
    from harness import ctaphid
    from fido2.ctap2 import Ctap2
    ctaphid.install()
    dev = ctaphid.open_device()
    ctap = Ctap2(dev)
    rp, user = {"id": "bench.example", "name": "b"}, {"id": b"\x01", "name": "u"}
    params = [{"type": "public-key", "alg": -7}]
    cdh = b"\x00" * 32
    measure("FIDO makeCredential ES256", lambda: ctap.make_credential(cdh, rp, user, params), runs, rows)
    cred = ctap.make_credential(cdh, rp, user, params)
    cid = {"type": "public-key", "id": cred.auth_data.credential_data.credential_id}
    measure("FIDO getAssertion ES256", lambda: ctap.get_assertion(rp["id"], cdh, [cid]), runs, rows)
    measure("CTAPHID getInfo", lambda: ctap.get_info(), runs, rows)
    dev.close()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--reader", default="Virtual PCD", help="PC/SC reader name prefix")
    p.add_argument("--runs", type=int, default=20)
    p.add_argument("--fido-emulator", action="store_true", help="also FIDO over the emulator's CTAPHID socket")
    p.add_argument("--i-understand-this-modifies-the-card", dest="ok", action="store_true",
                   help="required for a real device: keys are generated with the default PINs")
    a = p.parse_args()
    if a.reader != "Virtual PCD" and not a.ok:
        sys.exit("refusing to touch a real device without --i-understand-this-modifies-the-card")
    rows = []
    c = Card(a.reader)
    for fn in (bench_mgmt, bench_oath, bench_piv, bench_openpgp):
        try:
            fn(c, a.runs, rows)
        except Exception as e:
            print("  %s failed: %s" % (fn.__name__, e), file=sys.stderr)
            rows.append((fn.__name__ + " (failed: %s)" % e, 0, float("nan"), float("nan")))
    if a.fido_emulator:
        bench_fido_emulator(a.runs, rows)
    print("| Operation | Runs | Median (ms) | p90 (ms) |")
    print("|---|---:|---:|---:|")
    for name, n, med, p90 in rows:
        print("| %s | %d | %.1f | %.1f |" % (name, n, med, p90))


if __name__ == "__main__":
    main()
