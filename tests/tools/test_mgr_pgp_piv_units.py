"""Pure helpers of the OpenPGP and PIV key managers (librefido.mgr_pgp,
librefido.mgr_piv), no device: OpenPGP public key packets and fingerprints
(an RFC 9580 test vector, and byte for byte against keys GnuPG makes when it
is installed), the PIN KDF, algorithm attributes; PIV PIN blocks,
management keys, subjects, the signature payloads and the assembly of
certificates and requests around a signature as the card gives it (checked
with cryptography, and OpenSSL when installed).

    PYTHONPATH=tools/librefido python -m pytest -q tests/tools/test_mgr_pgp_piv_units.py
"""

import base64
import datetime
import hashlib
import os
import shutil
import struct
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils, x25519

from librefido import mgr_pgp, mgr_piv, stdformats
from librefido.mgr_common import AuthRequired, ManagerError, NotSupported

RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
POINT = (serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


# ----------------------------------------------------------------------------
# OpenPGP
# ----------------------------------------------------------------------------

# RFC 9580, A.3: "Sample Version 4 Ed25519Legacy key" (public key packet).
RFC9580_V4_ED25519 = "xjMEU/NfCxYJKwYBBAHaRw8BAQdAPwmJlL3ZFu1AUxl5NOSofIBzOhKA1i+AEJkuQ+47JAY="
RFC9580_V4_FPR = "C959BDBAFA32A2F89A153B678CFDE12197965A9A"


def test_rfc9580_ed25519_packet_and_fingerprint():
    packet = base64.b64decode(RFC9580_V4_ED25519)
    body = packet[2:]
    created = struct.unpack(">I", body[1:5])[0]
    pub = body[-32:]
    attr = mgr_pgp.algorithm_attributes("ed25519", "sig")
    mine = mgr_pgp.public_key_packet(attr, {0x86: pub}, created)
    assert mine == body
    assert mgr_pgp.fingerprint(mine).hex().upper() == RFC9580_V4_FPR
    # the card may answer the key with its 0x40 prefix too
    assert mgr_pgp.public_key_packet(attr, {0x86: b"\x40" + pub}, created) == body


def card_fields(key):
    """Public key fields as the card answers them (GENERATE 7F49)."""
    if isinstance(key, rsa.RSAPublicKey):
        n = key.public_numbers()
        return {0x81: n.n.to_bytes((n.n.bit_length() + 7) // 8, "big"), 0x82: n.e.to_bytes(3, "big")}
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {0x86: key.public_bytes(*POINT)}
    return {0x86: key.public_bytes(*RAW)}


@pytest.mark.parametrize("algorithm,ref,make,kdf", [
    ("rsa2048", "sig", lambda: rsa.generate_private_key(65537, 2048), None),
    ("nistp256", "sig", lambda: ec.generate_private_key(ec.SECP256R1()), None),
    ("nistp256", "dec", lambda: ec.generate_private_key(ec.SECP256R1()), b"\x03\x01\x08\x07"),
    ("nistp384", "dec", lambda: ec.generate_private_key(ec.SECP384R1()), b"\x03\x01\x09\x09"),
    ("brainpoolP384r1", "dec", lambda: ec.generate_private_key(ec.BrainpoolP384R1()), b"\x03\x01\x09\x09"),
    ("nistp521", "dec", lambda: ec.generate_private_key(ec.SECP521R1()), b"\x03\x01\x0a\x09"),
    ("brainpoolP512r1", "dec", lambda: ec.generate_private_key(ec.BrainpoolP512R1()), b"\x03\x01\x0a\x09"),
    ("secp256k1", "aut", lambda: ec.generate_private_key(ec.SECP256K1()), None),
    ("ed25519", "aut", ed25519.Ed25519PrivateKey.generate, None),
    ("cv25519", "dec", x25519.X25519PrivateKey.generate, b"\x03\x01\x08\x07"),
])
def test_public_key_packets_parse_back(algorithm, ref, make, kdf):
    key = make().public_key()
    attr = mgr_pgp.algorithm_attributes(algorithm, ref)
    assert mgr_pgp.algorithm_name(attr) == algorithm
    fields = card_fields(key)
    body = mgr_pgp.public_key_packet(attr, fields, 1700000000)
    k = stdformats._PgpKey(6, body, None)
    assert k.unsupported is None and k.pub_len == len(body) and k.created == 1700000000
    assert k.fingerprint == hashlib.sha1(b"\x99" + struct.pack(">H", len(body)) + body).digest()
    assert mgr_pgp.fingerprint(body) == k.fingerprint
    if kdf is not None:
        assert body.endswith(kdf) and k.algo == 18
    # the public key object of the card's answer is the key
    obj = mgr_pgp.public_key_object(attr, fields)
    assert stdformats._spki(obj) == stdformats._spki(key)
    assert "BEGIN PUBLIC KEY" in mgr_pgp.public_key_pem(attr, fields)


def test_algorithm_attributes():
    assert mgr_pgp.algorithm_attributes("rsa2048", 1) == bytes.fromhex("010800002000")
    assert mgr_pgp.algorithm_attributes("rsa4096", "aut") == bytes.fromhex("011000002000")
    p256 = bytes.fromhex("2a8648ce3d030107")
    assert mgr_pgp.algorithm_attributes("nistp256", "sig") == b"\x13" + p256
    assert mgr_pgp.algorithm_attributes("nistp256", "dec") == b"\x12" + p256
    assert mgr_pgp.algorithm_attributes("ed25519", "aut")[0] == 0x16
    assert mgr_pgp.algorithm_attributes("cv25519", "dec")[0] == 0x12
    for bad in (("ed25519", "dec"), ("cv25519", "sig"), ("cv25519", "aut"), ("rsa1000", "sig"), ("x448", "dec"),
                ("rsa2048", "enc"), ("rsa2048", 4)):
        with pytest.raises(ManagerError):
            mgr_pgp.algorithm_attributes(*bad)
    # every offered algorithm fits at least one slot and reads back by name
    for name in mgr_pgp.ALGORITHMS:
        fitting = 0
        for ref in (1, 2, 3):
            try:
                attr = mgr_pgp.algorithm_attributes(name, ref)
            except ManagerError:
                continue
            fitting += 1
            assert mgr_pgp.algorithm_name(attr) == name
            assert mgr_pgp.algorithm_name(attr + b"\xff") == name       # import format flag
        assert fitting
    assert mgr_pgp.algorithm_name(bytes.fromhex("010400002000")) == "rsa1024"
    assert mgr_pgp.algorithm_name(b"\x12\x2b\x65\x6e") == "cv25519"        # RFC 8410 OID
    assert "curve" in mgr_pgp.algorithm_name(b"\x13\x01\x02\x03")


def test_offered_matches_curves_whatever_algorithm_id():
    # the card lists P-256 with the ECDSA id for the decryption slot too
    listed = [bytes.fromhex("010800002000"), b"\x13" + bytes.fromhex("2a8648ce3d030107")]
    assert mgr_pgp._offered(mgr_pgp.algorithm_attributes("nistp256", "dec"), listed)
    assert mgr_pgp._offered(mgr_pgp.algorithm_attributes("rsa2048", "dec"), listed)
    assert not mgr_pgp._offered(mgr_pgp.algorithm_attributes("rsa4096", "dec"), listed)
    assert not mgr_pgp._offered(mgr_pgp.algorithm_attributes("nistp384", "dec"), listed)


def test_s2k_iterated():
    salt, pin = bytes(range(8)), b"123456"
    unit = salt + pin
    for count in (1, 14, 15, 100, 65536 + 7, 200003):
        stream = (unit * (count // len(unit) + 1))[:max(count, len(unit))]
        assert mgr_pgp.s2k_iterated("sha256", salt, pin, count) == hashlib.sha256(stream).digest()
    assert mgr_pgp.s2k_iterated("sha512", salt, pin, 1000) == \
        hashlib.sha512((unit * 100)[:1000]).digest()


def kdf_do(salts=True, hash_id=0x08, count=100000):
    do = bytes([0x81, 1, 3, 0x82, 1, hash_id, 0x83, 4]) + count.to_bytes(4, "big") + bytes([0x84, 8]) + b"A" * 8
    if salts:
        do += bytes([0x85, 8]) + b"B" * 8 + bytes([0x86, 8]) + b"C" * 8
    return do


def test_kdf_pin():
    pin = b"12345678"
    for none in (b"", b"\x00", bytes.fromhex("810100"), bytes.fromhex("f90100"), bytes.fromhex("f903810100"),
                 b"garbage"):
        assert mgr_pgp.kdf_pin(none, pin, mgr_pgp.PW3) == pin
    do = kdf_do()
    assert mgr_pgp.kdf_pin(do, pin, mgr_pgp.PW1) == mgr_pgp.s2k_iterated("sha256", b"A" * 8, pin, 100000)
    tagged = bytes([0xF9, len(do)]) + do                    # as GET DATA F9 answers it
    assert mgr_pgp.kdf_pin(tagged, pin, mgr_pgp.PW1) == mgr_pgp.kdf_pin(do, pin, mgr_pgp.PW1)
    assert mgr_pgp.kdf_pin(do, pin, mgr_pgp.RC) == mgr_pgp.s2k_iterated("sha256", b"B" * 8, pin, 100000)
    assert mgr_pgp.kdf_pin(do, pin, mgr_pgp.PW3) == mgr_pgp.s2k_iterated("sha256", b"C" * 8, pin, 100000)
    # without their own salts, the Reset Code and PW3 use PW1's
    assert mgr_pgp.kdf_pin(kdf_do(False), pin, mgr_pgp.PW3) == mgr_pgp.s2k_iterated("sha256", b"A" * 8, pin, 100000)
    assert len(mgr_pgp.kdf_pin(kdf_do(hash_id=0x0A), pin, mgr_pgp.PW1)) == 64
    with pytest.raises(NotSupported):
        mgr_pgp.kdf_pin(kdf_do(hash_id=0x02), pin, mgr_pgp.PW1)


def test_pin_lengths():
    assert mgr_pgp._pin_bytes("123456", mgr_pgp.PW1, new=True) == b"123456"
    assert mgr_pgp._pin_bytes("密码", mgr_pgp.PW1) == "密码".encode("utf-8")
    with pytest.raises(ManagerError):
        mgr_pgp._pin_bytes("12345", mgr_pgp.PW1, new=True)
    with pytest.raises(ManagerError):
        mgr_pgp._pin_bytes("1234567", mgr_pgp.PW3, new=True)
    with pytest.raises(ManagerError):
        mgr_pgp._pin_bytes("x" * 128, mgr_pgp.PW1)
    with pytest.raises(AuthRequired):
        mgr_pgp._pin_bytes(None, mgr_pgp.PW3)


GPG = shutil.which("gpg")


@pytest.fixture
def gpg_home(tmp_path):
    if not GPG:
        pytest.skip("GnuPG not installed")
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    yield str(home)
    subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], capture_output=True)


def gpg(home, *args):
    r = subprocess.run([GPG, "--homedir", home, "--batch", "--no-tty", "--pinentry-mode", "loopback",
                        "--passphrase", "", *args], capture_output=True, timeout=300)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    return r.stdout


@pytest.mark.parametrize("primary,sub", [("rsa2048", "rsa2048"), ("nistp256", "nistp256"), ("nistp384", "nistp384"),
                                         ("nistp521", "nistp521"), ("ed25519", "cv25519"),
                                         ("brainpoolP256r1", "brainpoolP256r1"), ("brainpoolP384r1", "brainpoolP384r1"),
                                         ("brainpoolP512r1", "brainpoolP512r1"), ("secp256k1", "secp256k1")])
def test_packets_are_gnupgs(gpg_home, primary, sub):
    """The packet built from a card's answer (public key fields, the
    attributes of the slot, the generation time) is byte for byte the one
    GnuPG makes for the same key: RSA, ECDSA, EdDSA and ECDH with GnuPG's KDF
    parameters, so the fingerprints agree."""
    uid = "Packet Test <packet@librefido.example>"
    gpg(gpg_home, "--quick-gen-key", uid, primary, "sign,cert", "0")
    fpr = [ln.split(":")[9] for ln in gpg(gpg_home, "--with-colons", "--list-keys", uid).decode().splitlines()
           if ln.startswith("fpr:")][0]
    gpg(gpg_home, "--quick-add-key", fpr, sub, "encr", "0")
    exported = gpg(gpg_home, "--export", fpr)
    keys = [(tag, body) for tag, body in stdformats._pgp_packets(exported) if tag in (6, 14)]
    assert len(keys) == 2
    for (tag, body), (name, ref) in zip(keys, ((primary, "sig"), (sub, "dec"))):
        k = stdformats._PgpKey(tag, body, None)
        attr = mgr_pgp.algorithm_attributes(name, ref)
        if name.startswith("rsa"):
            fields = {0x81: k.pub["n"], 0x82: k.pub["e"]}
        else:
            q = k.pub["q"]
            fields = {0x86: q[1:] if name in ("ed25519", "cv25519") else q}     # the card has no 0x40 prefix
        mine = mgr_pgp.public_key_packet(attr, fields, k.created)
        assert mine == body[:k.pub_len], (name, mine.hex(), body.hex())
        assert mgr_pgp.fingerprint(mine) == k.fingerprint


# ----------------------------------------------------------------------------
# PIV
# ----------------------------------------------------------------------------

def test_pin_block():
    b = mgr_piv.pin_block("123456")
    assert isinstance(b, bytearray) and bytes(b) == b"123456\xff\xff"
    assert bytes(mgr_piv.pin_block("12345678", mgr_piv.PUK_REF, new=True)) == b"12345678"
    assert bytes(mgr_piv.pin_block("1")) == b"1" + b"\xff" * 7          # a wrong one still costs a retry
    for bad, new in (("12345", True), ("123456789", True), ("123456789", False), ("", False),
                     (b"1234\xff6", False), ("密码密码", True)):
        with pytest.raises(ManagerError):
            mgr_piv.pin_block(bad, new=new)
    with pytest.raises(AuthRequired):
        mgr_piv.pin_block(None)


def test_parse_management_key():
    k = mgr_piv.parse_management_key("01 02 03 04 05 06 07 08:0102030405060708-0102030405060708")
    assert bytes(k) == mgr_piv.DEFAULT_MGMT_KEY
    assert len(mgr_piv.parse_management_key(os.urandom(32).hex(), "aes256")) == 32
    assert len(mgr_piv.parse_management_key(os.urandom(16), 0x08)) == 16
    for bad, algo in (("zz" * 16, None), ("00" * 20, None), ("00" * 16, "aes192"), ("00" * 24, "aes128"),
                      ("00" * 16, "des"), (1234, None)):
        with pytest.raises(ManagerError):
            mgr_piv.parse_management_key(bad, algo)
    for algo, size in (("3des", 24), ("aes128", 16), ("aes192", 24), ("aes256", 32)):
        assert len(bytes.fromhex(mgr_piv.generate_management_key(algo))) == size


def test_parse_subject():
    assert mgr_piv.parse_subject("Alice").rfc4514_string() == "CN=Alice"
    name = mgr_piv.parse_subject("CN=Alice Example,O=Example Org,C=CN")
    assert name.rfc4514_string() == "CN=Alice Example,O=Example Org,C=CN"
    assert mgr_piv.parse_subject("CN=张三").rfc4514_string() == "CN=张三"
    for bad in ("", "   ", "CN=", "XX=1", "a" * 65):
        with pytest.raises(ManagerError):
            mgr_piv.parse_subject(bad)
    assert mgr_piv.slot_ref("9a") == 0x9A and mgr_piv.slot_ref(0x95) == 0x95 and mgr_piv.slot_ref("0x82") == 0x82
    for bad in ("9B", 0x96, "F9", "zz", None):
        with pytest.raises(ManagerError):
            mgr_piv.slot_ref(bad)
    assert mgr_piv.slot_name(0x9C) == "Digital Signature" and mgr_piv.slot_name(0x85) == "Retired key 4"


def card_signer(priv, algo):
    """What the card answers to GENERAL AUTHENTICATE 81 <payload>: the raw RSA
    operation, a DER ECDSA signature of the digest, an Ed25519 signature of
    the message."""
    def sign(payload):
        if algo in (0x06, 0x07, 0x05, 0x16):
            n = priv.private_numbers()
            k = priv.key_size // 8
            assert len(payload) == k and payload[:2] == b"\x00\x01"
            return pow(int.from_bytes(payload, "big"), n.d, n.public_numbers.n).to_bytes(k, "big")
        if algo in (0x11, 0x14):
            h = hashes.SHA256() if algo == 0x11 else hashes.SHA384()
            assert len(payload) == h.digest_size
            return priv.sign(payload, ec.ECDSA(utils.Prehashed(h)))
        return priv.sign(payload)
    return sign


KEYS = [(0x06, lambda: rsa.generate_private_key(65537, 1024)), (0x07, lambda: rsa.generate_private_key(65537, 2048)),
        (0x05, lambda: rsa.generate_private_key(65537, 3072)), (0x11, lambda: ec.generate_private_key(ec.SECP256R1())),
        (0x14, lambda: ec.generate_private_key(ec.SECP384R1())), (0xE0, ed25519.Ed25519PrivateKey.generate)]


def openssl(*args, data=None):
    r = subprocess.run(["openssl", *args], input=data, capture_output=True, timeout=60)
    return r.returncode, (r.stdout + r.stderr).decode(errors="replace")


@pytest.mark.parametrize("algo,make", KEYS, ids=[mgr_piv.ALGORITHM_NAMES[a] for a, _ in KEYS])
def test_certificate_and_request_assembly(algo, make, tmp_path):
    priv = make()
    pub = priv.public_key()
    sign = card_signer(priv, algo)
    now = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)

    tbs, sig_alg = mgr_piv.certificate_tbs(pub, algo, "CN=Card Key,O=LibreFido", 365, now=now, serial=12345)
    sig = sign(mgr_piv.signature_payload(algo, tbs))
    assert mgr_piv.verify_signature(pub, algo, tbs, sig)
    der = mgr_piv.assemble_signed(tbs, sig_alg, sig)
    cert = x509.load_der_x509_certificate(der)
    cert.verify_directly_issued_by(cert)            # self-signed, by the card key
    assert cert.subject.rfc4514_string() == "CN=Card Key,O=LibreFido" and cert.serial_number == 12345
    assert cert.not_valid_before_utc == now and cert.not_valid_after_utc == now + datetime.timedelta(days=365)
    assert stdformats._spki(cert.public_key()) == stdformats._spki(pub)
    info = mgr_piv.certificate_info(der, pub)
    assert info["matches_key"] is True and info["subject"] == "CN=Card Key,O=LibreFido" and info["serial"] == "3039"

    info, req_alg = mgr_piv.csr_info(pub, algo, "CN=Request")
    sig = sign(mgr_piv.signature_payload(algo, info))
    req = x509.load_der_x509_csr(mgr_piv.assemble_signed(info, req_alg, sig))
    assert req.is_signature_valid and req.subject.rfc4514_string() == "CN=Request"
    assert stdformats._spki(req.public_key()) == stdformats._spki(pub)

    # a signature that is not the key's does not pass
    bad = bytearray(sig)
    bad[-1] ^= 1
    assert not mgr_piv.verify_signature(pub, algo, info, bytes(bad))

    if shutil.which("openssl"):
        (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        rc, out = openssl("verify", "-CAfile", str(tmp_path / "c.pem"), str(tmp_path / "c.pem"))
        assert rc == 0 and ": OK" in out, out
        rc, out = openssl("x509", "-noout", "-subject", "-in", str(tmp_path / "c.pem"))
        assert rc == 0 and "Card Key" in out, out
        rc, out = openssl("req", "-verify", "-noout", "-inform", "DER",
                          data=req.public_bytes(serialization.Encoding.DER))
        assert rc == 0 and "verif" in out.lower() and "fail" not in out.lower(), out


def test_rsa_payload_is_pkcs1_v15():
    priv = rsa.generate_private_key(65537, 2048)
    payload = mgr_piv.signature_payload(0x07, b"message")
    raw = card_signer(priv, 0x07)(payload)
    assert raw == priv.sign(b"message", padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(NotSupported):
        mgr_piv.signature_payload(0xE1, b"x")          # X25519 cannot sign


def test_der_helpers():
    for n in (0, 1, 127, 128, 255, 256, 70000):
        enc = mgr_piv._der(0x04, b"x" * n)
        tag, start, end = mgr_piv._der_read(enc, 0)
        assert tag == 0x04 and end - start == n and end == len(enc)
    seq = mgr_piv._der(0x30, mgr_piv._der(0x02, b"\x01") + mgr_piv._der(0x04, b"ab"))
    assert mgr_piv.der_sequence_items(seq) == [b"\x02\x01\x01", b"\x04\x02ab"]
    for bad in (b"\x30\x05\x02\x01", b"\x04\x00", b"\x30\x85\x00\x00\x00\x00\x00", seq + b"\x00"):
        with pytest.raises(ValueError):
            mgr_piv.der_sequence_items(bad)
    info = mgr_piv.certificate_info(b"\x30\x03\x02\x01\x00")
    assert info["error"] and info["pem"] is None


def test_load_certificates():
    priv = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "x")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(priv.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(priv, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    der = cert.public_bytes(serialization.Encoding.DER)
    assert len(mgr_piv.load_certificates(pem + pem)) == 2
    assert mgr_piv.load_certificates(pem.decode())[0] == cert
    assert mgr_piv.load_certificates(der)[0] == cert
    for bad in (b"", b"-----BEGIN CERTIFICATE-----\nxx\n-----END CERTIFICATE-----\n", b"\x30\x00"):
        with pytest.raises(ManagerError):
            mgr_piv.load_certificates(bad)
