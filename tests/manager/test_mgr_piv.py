"""PIV key manager (librefido.mgr_piv) against the emulated device: status
with the key metadata, management key authentication (default 3DES, changed
AES / 3DES keys, touch), key generation for every algorithm the device
offers (the card then signs / decrypts / agrees, checked with the public key
the manager returned), self-signed certificates and requests signed by the
card (checked with cryptography and OpenSSL), attestation, certificate
import / export / deletion, moving and deleting keys, PIN / PUK / unblock
and the reset.

    bash ~/work/scripts/locked_tests.sh <build> -q -rfEs -p no:randomly tests/manager/test_mgr_piv.py
"""

import datetime
import os
import shutil
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from cryptography.x509.oid import NameOID

from harness.emulator import Emulator, Pcscd
from librefido import mgr_piv, stdformats
from librefido.mgmt import Management
from librefido.mgr_common import (AuthRequired, ManagerError, NotSupported, SecretBlocked, WrongSecret, applet,
                                  parse_tlvs, send, tlv)
from librefido.mgr_piv import PivManager

PIN, PUK = "123456", "12345678"
AID = mgr_piv.PIV_AID
POINT = (serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
OPENSSL = shutil.which("openssl")


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    p.start()
    yield p
    p.stop()


class Device:
    def __init__(self, workdir):
        self.emu = Emulator(workdir=workdir)
        self.emu.start()
        try:
            self.m = Management.open(timeout=15)
        except BaseException:
            self.emu.stop()
            raise
        self.piv = PivManager(self.m)

    def close(self):
        try:
            self.m.close()
            conn = self.m.card.conn         # the PC/SC context too, while pcscd runs
            while hasattr(conn, "component"):
                conn = conn.component
            getattr(conn, "release", lambda: None)()
        except Exception:
            pass
        finally:
            self.emu.stop()


@pytest.fixture
def dev(pcscd, tmp_path):
    """A new emulated device for each test (emulators share the ports: one
    at a time)."""
    d = Device(str(tmp_path / "dev"))
    yield d
    d.close()


def load_pem(pem):
    return serialization.load_pem_public_key(pem.encode())


def spki(key):
    return stdformats._spki(key)


def authenticate_raw(m, slot, algo, body, pin=PIN):
    """GENERAL AUTHENTICATE with a key (VERIFY PIN right before when pin)."""
    with applet(m, AID, "PIV"):
        if pin is not None:
            _, sw = send(m.card, 0x20, 0x00, 0x80, pin.encode() + b"\xff" * (8 - len(pin)))
            assert sw == 0x9000, "%04X" % sw
        resp, sw = send(m.card, 0x87, algo, slot, tlv(0x7C, body))
    assert sw == 0x9000, "GENERAL AUTHENTICATE %02X: %04X" % (slot, sw)
    return dict(parse_tlvs(dict(parse_tlvs(resp, "t"))[0x7C], "t"))[0x82]


def check_key_works(m, slot, name, pub, pin=PIN):
    """The card uses the key: signs (RSA, ECC, Ed25519), decrypts (RSA),
    agrees on a secret (ECC, X25519)."""
    algo = mgr_piv.ALGORITHMS[name]
    if name != "x25519":
        msg = os.urandom(64)
        sig = authenticate_raw(m, slot, algo, tlv(0x82) + tlv(0x81, mgr_piv.signature_payload(algo, msg)), pin)
        assert mgr_piv.verify_signature(pub, algo, msg, sig)
    if name.startswith("rsa"):
        secret = os.urandom(24)
        raw = authenticate_raw(m, slot, algo, tlv(0x82) + tlv(0x81, pub.encrypt(secret, padding.PKCS1v15())), pin)
        assert raw[:2] == b"\x00\x02" and raw[raw.index(b"\x00", 2) + 1:] == secret
    elif name == "x25519":
        eph = x25519.X25519PrivateKey.generate()
        shared = authenticate_raw(m, slot, algo, tlv(0x82) + tlv(0x85, eph.public_key().public_bytes_raw()), pin)
        assert shared == eph.exchange(pub)
    elif name.startswith("ecc"):
        eph = ec.generate_private_key(pub.curve)
        shared = authenticate_raw(m, slot, algo, tlv(0x82) + tlv(0x85, eph.public_key().public_bytes(*POINT)), pin)
        assert shared == eph.exchange(ec.ECDH(), pub)


def openssl(*args, data=None):
    r = subprocess.run(["openssl", *args], input=data, capture_output=True, timeout=60)
    return r.returncode, (r.stdout + r.stderr).decode(errors="replace")


def check_with_openssl(tmp_path, cert_pem=None, csr_pem=None):
    if not OPENSSL:
        return
    if cert_pem:
        p = tmp_path / "cert.pem"
        p.write_text(cert_pem)
        rc, out = openssl("verify", "-CAfile", str(p), str(p))
        assert rc == 0 and ": OK" in out, out
        rc, out = openssl("x509", "-noout", "-text", "-in", str(p))
        assert rc == 0, out
    if csr_pem:
        rc, out = openssl("req", "-verify", "-noout", data=csr_pem.encode())
        assert rc == 0 and "fail" not in out.lower(), out


def host_certificate(pub, cn="Host CA issued", ca=None):
    """A certificate for pub issued by a host CA key."""
    ca = ca or ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Host CA")]))
            .public_key(pub).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=30))
            .sign(ca, hashes.SHA256()))


# -- status and management key ---------------------------------------------------

def test_status_of_a_fresh_card(dev):
    st = dev.piv.status()
    assert st["version"] == "5.7.0" and isinstance(st["serial"], int)
    assert (st["pin_retries"], st["pin_attempts"], st["puk_retries"], st["puk_attempts"]) == (3, 3, 3, 3)
    assert st["pin_default"] is True and st["puk_default"] is True
    assert st["mgmt_key_algorithm"] == "3des" and st["mgmt_key_default"] is True and st["mgmt_key_touch"] is False
    assert st["algorithms"] == ["rsa1024", "rsa2048", "eccp256", "eccp384", "ed25519", "x25519"]
    assert dev.piv.supported_algorithms() == st["algorithms"]
    assert sorted(st["slots"]) == sorted(mgr_piv.SLOTS) and len(st["slots"]) == 24
    for slot, info in st["slots"].items():
        assert info["has_key"] is False and info["certificate"] is None and info["algorithm"] is None
    assert st["slots"][0x9C]["name"] == "Digital Signature" and st["slots"][0x95]["name"] == "Retired key 20"


@pytest.mark.parametrize("algorithm", ["aes128", "aes192", "aes256", "3des"])
def test_management_key(dev, algorithm):
    piv = dev.piv
    piv.authenticate()                                    # the default 3DES key
    assert piv.authenticated
    with pytest.raises(WrongSecret):
        piv.authenticate("00" * 24)
    new = mgr_piv.generate_management_key(algorithm)
    piv.set_management_key(new, algorithm)
    st = piv.status()
    assert st["mgmt_key_algorithm"] == algorithm and st["mgmt_key_default"] is False
    piv.generate(0x9A, "eccp256")                         # with the kept new key

    other = PivManager(dev.m)                             # knows no key: the default one is not there
    with pytest.raises(AuthRequired):
        other.generate(0x9A, "eccp256", replace=True)
    with pytest.raises(AuthRequired):
        other.authenticate()
    with pytest.raises(WrongSecret):
        other.authenticate(mgr_piv.DEFAULT_MGMT_KEY.hex() if algorithm in ("3des", "aes192") else "00" * 16)
    with pytest.raises(ManagerError):
        other.authenticate("00" * 32 if algorithm != "aes256" else "00" * 16)     # wrong size for the device's key
    other.authenticate(new.lower())
    other.delete_key(0x9A, with_certificate=True)
    other.forget()
    assert not other.authenticated
    with pytest.raises(AuthRequired):
        other.generate(0x9A, "eccp256")

    # a touch for every authentication (the emulator's button is pressed), then back to the default
    piv.set_management_key(new, algorithm, touch=True)
    assert piv.status()["mgmt_key_touch"] is True
    piv.set_management_key(mgr_piv.DEFAULT_MGMT_KEY, "3des")
    st = piv.status()
    assert st["mgmt_key_default"] is True and st["mgmt_key_touch"] is False and st["mgmt_key_algorithm"] == "3des"
    PivManager(dev.m).generate(0x9A, "eccp256")           # the default key again, nothing given


def test_a_kept_key_that_changed_is_forgotten(dev):
    a, b = PivManager(dev.m), PivManager(dev.m)
    a.authenticate()
    b.set_management_key("11" * 16, "aes128")
    with pytest.raises(WrongSecret):
        a.generate(0x9A, "eccp256")
    assert not a.authenticated


# -- keys ------------------------------------------------------------------------

GEN = [("rsa1024", 0x9A), ("rsa2048", 0x9C), ("eccp256", 0x9D), ("eccp384", 0x9E), ("ed25519", 0x82),
       ("x25519", 0x95), ("eccp256", 0x9C), ("ed25519", 0x9E)]


@pytest.mark.parametrize("name,slot", GEN, ids=["%s-%02X" % g for g in GEN])
def test_generate_sign_certify(dev, tmp_path, name, slot):
    piv, m = dev.piv, dev.m
    piv.generate(slot, "eccp256" if name != "eccp256" else "ed25519")      # something to replace
    with pytest.raises(ManagerError) as e:
        piv.generate(slot, name)
    assert e.value.sw == 0x6A89
    pem = piv.generate(slot, name, replace=True)
    pub = load_pem(pem)
    info = piv.status()["slots"][slot]
    assert info["has_key"] and info["algorithm"] == name and info["origin"] == "generated"
    assert info["public_key"] == pem
    assert info["pin_policy"] == {0x9C: "always", 0x9E: "never"}.get(slot, "once")
    assert info["touch_policy"] == "never"
    pin = None if slot == 0x9E else PIN
    check_key_works(m, slot, name, pub, pin)
    if name == "x25519":
        assert info["certificate"] is None            # the device makes none for a key that cannot sign
        with pytest.raises(NotSupported):
            piv.self_sign(slot, "CN=x", 30, PIN)
        with pytest.raises(NotSupported):
            piv.csr(slot, "CN=x", PIN)
    else:
        assert info["certificate"]["matches_key"] is True        # the device's own certificate
        with pytest.raises(ManagerError) as e:
            piv.self_sign(slot, "CN=Not replaced", 30, pin)
        assert e.value.sw == 0x6A89
        cert_pem = piv.self_sign(slot, "CN=Key Manager %02X,O=LibreFido" % slot, 90, pin, replace=True)
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        cert.verify_directly_issued_by(cert)                     # signed by the card, with the slot's key
        assert spki(cert.public_key()) == spki(pub)
        assert cert.subject.rfc4514_string() == "CN=Key Manager %02X,O=LibreFido" % slot
        assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days == 90
        assert piv.export_certificate(slot) == cert_pem
        st = piv.status()["slots"][slot]["certificate"]
        assert st["subject"] == cert.subject.rfc4514_string() and st["matches_key"] is True
        csr_pem = piv.csr(slot, "Plain Name", pin)
        req = x509.load_pem_x509_csr(csr_pem.encode())
        assert req.is_signature_valid and spki(req.public_key()) == spki(pub)
        assert req.subject.rfc4514_string() == "CN=Plain Name"
        check_with_openssl(tmp_path, cert_pem, csr_pem)
    # attestation by the device's F9 key
    att = x509.load_pem_x509_certificate(piv.attest(slot).encode())
    assert spki(att.public_key()) == spki(pub)
    with applet(m, AID, "PIV"):
        resp, sw = send(m.card, 0xCB, 0x3F, 0xFF, tlv(0x5C, bytes.fromhex("5FFF01")))
    assert sw == 0x9000
    f9 = x509.load_der_x509_certificate(dict(parse_tlvs(dict(parse_tlvs(resp, "t"))[0x53], "t"))[0x70])
    att.verify_directly_issued_by(f9)


def test_generate_checks(dev):
    piv = dev.piv
    with pytest.raises(NotSupported):
        piv.generate(0x9A, "rsa4096")                     # imported only on this device
    with pytest.raises(ManagerError):
        piv.generate(0x9B, "eccp256")
    with pytest.raises(ManagerError):
        piv.generate(0x9A, "eccp256", pin_policy="sometimes")
    piv.generate(0x9A, "eccp256", pin_policy="never", touch_policy="always")
    info = piv.status()["slots"][0x9A]
    assert info["pin_policy"] == "never" and info["touch_policy"] == "always"
    with pytest.raises(ManagerError) as e:
        piv.generate(0x9A, "eccp384")
    assert e.value.sw == 0x6A89
    assert piv.status()["slots"][0x9A]["algorithm"] == "eccp256"          # nothing changed
    # PIN never: the card signs without it, self_sign too
    check_key_works(dev.m, 0x9A, "eccp256", load_pem(info["public_key"]), pin=None)
    piv.self_sign(0x9A, "CN=No PIN", 1, None, replace=True)
    piv.self_sign(0x9A, "CN=No PIN", 1, "999999", replace=True)      # a PIN given is not even tried
    assert piv.status()["pin_retries"] == 3
    piv.generate(0x9D, "eccp256", pin_policy="always")
    with pytest.raises(AuthRequired):
        piv.self_sign(0x9D, "CN=needs the PIN", 1, None, replace=True)
    with pytest.raises(WrongSecret) as e:
        piv.self_sign(0x9D, "CN=wrong PIN", 1, "654321", replace=True)
    assert e.value.retries == 2
    subject = piv.status()["slots"][0x9D]["certificate"]["subject"]
    assert "Pico" in subject                                             # still the device's own
    piv.self_sign(0x9D, "CN=PIN always", 1, PIN, replace=True)           # VERIFY right before the signature
    assert piv.status()["pin_retries"] == 3
    for bad in (0, 36501, "30"):
        with pytest.raises(ManagerError):
            piv.self_sign(0x9D, "CN=x", bad, PIN, replace=True)
    with pytest.raises(ManagerError) as e:
        piv.self_sign(0x83, "CN=x", 1, PIN)
    assert e.value.sw == 0x6A88


def test_certificates(dev, tmp_path):
    piv = dev.piv
    pub = load_pem(piv.generate(0x9A, "eccp256"))
    cert = host_certificate(pub)
    pem = cert.public_bytes(serialization.Encoding.PEM)
    with pytest.raises(ManagerError) as e:
        piv.import_certificate(0x9A, pem)                  # the device's own is there
    assert e.value.sw == 0x6A89
    info = piv.import_certificate(0x9A, pem, replace=True)
    assert info["matches_key"] is True and info["subject"] == "CN=Host CA issued" and info["issuer"] == "CN=Host CA"
    assert piv.export_certificate(0x9A) == pem.decode()
    # the one for the key out of several; one for another key is refused unless verify=False
    other = host_certificate(ec.generate_private_key(ec.SECP256R1()).public_key(), "Other")
    other_pem = other.public_bytes(serialization.Encoding.PEM)
    info = piv.import_certificate(0x9A, other_pem + pem, replace=True)
    assert info["subject"] == "CN=Host CA issued"
    with pytest.raises(ManagerError):
        piv.import_certificate(0x9A, other_pem, replace=True)
    info = piv.import_certificate(0x9A, other.public_bytes(serialization.Encoding.DER), replace=True, verify=False)
    assert info["matches_key"] is False
    assert piv.status()["slots"][0x9A]["certificate"]["matches_key"] is False
    # a slot without key takes any certificate; delete, export errors
    piv.import_certificate(0x85, other_pem)
    st = piv.status()["slots"][0x85]
    assert st["has_key"] is False and st["certificate"]["subject"] == "CN=Other"
    piv.delete_certificate(0x85)
    assert piv.status()["slots"][0x85]["certificate"] is None
    for call in (lambda: piv.delete_certificate(0x85), lambda: piv.export_certificate(0x85)):
        with pytest.raises(ManagerError) as e:
            call()
        assert e.value.sw == 0x6A82
    with pytest.raises(ManagerError):
        piv.import_certificate(0x85, b"not a certificate")
    # a large RSA certificate (chained APDUs both ways)
    big = host_certificate(rsa.generate_private_key(65537, 4096).public_key(), "R" * 60,
                           ca=rsa.generate_private_key(65537, 4096))
    piv.import_certificate(0x86, big.public_bytes(serialization.Encoding.PEM))
    assert piv.export_certificate(0x86) == big.public_bytes(serialization.Encoding.PEM).decode()


def test_move_and_delete(dev):
    piv, m = dev.piv, dev.m
    pub = load_pem(piv.generate(0x9A, "ed25519"))
    subject = x509.load_pem_x509_certificate(piv.self_sign(0x9A, "CN=Moving", 10, PIN, replace=True).encode()).subject
    piv.move_key(0x9A, 0x82)
    st = piv.status()["slots"]
    assert not st[0x9A]["has_key"] and st[0x9A]["certificate"] is None
    assert st[0x82]["has_key"] and spki(load_pem(st[0x82]["public_key"])) == spki(pub)
    assert st[0x82]["certificate"]["subject"] == subject.rfc4514_string() and st[0x82]["origin"] == "generated"
    check_key_works(m, 0x82, "ed25519", pub)
    with pytest.raises(ManagerError) as e:
        piv.move_key(0x9A, 0x83)
    assert e.value.sw == 0x6A88                             # nothing in 9A now
    piv.generate(0x83, "eccp256")
    with pytest.raises(ManagerError) as e:
        piv.move_key(0x82, 0x83)
    assert e.value.sw == 0x6A89
    piv.move_key(0x82, 0x83, replace=True)
    st = piv.status()["slots"]
    assert st[0x83]["algorithm"] == "ed25519" and st[0x83]["certificate"]["subject"] == "CN=Moving"
    assert not st[0x82]["has_key"] and st[0x82]["certificate"] is None
    # without the certificate: it stays where it was
    piv.move_key(0x83, 0x84, with_certificate=False)
    st = piv.status()["slots"]
    assert st[0x84]["has_key"] and st[0x84]["certificate"] is None and st[0x83]["certificate"] is not None
    with pytest.raises(ManagerError):
        piv.move_key(0x84, 0x84)
    piv.delete_key(0x84)
    assert not piv.status()["slots"][0x84]["has_key"]
    with pytest.raises(ManagerError) as e:
        piv.delete_key(0x84)
    assert e.value.sw == 0x6A88
    piv.generate(0x84, "eccp256")
    piv.delete_key(0x84, with_certificate=True)
    assert piv.status()["slots"][0x84] == dict(piv.status()["slots"][0x85], name="Retired key 3",
                                               name_zh="历史密钥 3")


# -- PIN and PUK -----------------------------------------------------------------

def test_pin_puk_unblock(dev):
    piv, m = dev.piv, dev.m
    with pytest.raises(WrongSecret) as e:
        piv.change_pin("000000", "654321")
    assert e.value.retries == 2 and piv.status()["pin_retries"] == 2
    for bad in ("12345", "123456789", "密码密码"):          # (the last: 12 bytes of UTF-8)
        with pytest.raises(ManagerError):
            piv.change_pin(PIN, bad)                       # refused before the card
    with pytest.raises(ManagerError):
        piv.change_pin("123456789", "654321")              # cannot be right: not sent
    assert piv.status()["pin_retries"] == 2
    piv.change_pin(PIN, "密码12")                           # 8 bytes of UTF-8
    st = piv.status()
    assert st["pin_retries"] == 3 and st["pin_default"] is False
    for _ in range(3):
        with pytest.raises((WrongSecret, SecretBlocked)):
            piv.change_pin("000000", "654321")
    with pytest.raises(SecretBlocked):
        piv.change_pin("密码12", "654321")
    assert piv.status()["pin_retries"] == 0
    with pytest.raises(WrongSecret) as e:
        piv.unblock_pin("87654321", "111111")
    assert "PUK" in str(e.value) and piv.status()["puk_retries"] == 2
    piv.unblock_pin(PUK, "111111")
    assert piv.status()["pin_retries"] == 3
    pub = load_pem(piv.generate(0x9A, "eccp256"))
    check_key_works(m, 0x9A, "eccp256", pub, pin="111111")
    piv.change_puk(PUK, "puk-8888")
    st = piv.status()
    assert st["puk_default"] is False and st["puk_retries"] == 3
    with pytest.raises(WrongSecret):
        piv.change_puk(PUK, "puk-9999")
    piv.unblock_pin("puk-8888", "222222")
    check_key_works(m, 0x9A, "eccp256", pub, pin="222222")


def test_reset(dev):
    piv, m = dev.piv, dev.m
    piv.generate(0x9A, "eccp256")
    piv.generate(0x82, "ed25519")
    piv.set_management_key("22" * 32, "aes256")
    piv.change_pin(PIN, "654321")
    piv.change_puk(PUK, "87654321")
    piv.import_certificate(0x90, host_certificate(ec.generate_private_key(ec.SECP256R1()).public_key())
                           .public_bytes(serialization.Encoding.PEM))
    before = x509.load_pem_x509_certificate(piv.attest(0x9A).encode()).issuer
    piv.reset()
    assert not piv.authenticated
    st = piv.status()
    assert all(not s["has_key"] and s["certificate"] is None for s in st["slots"].values())
    assert st["pin_default"] and st["puk_default"] and st["mgmt_key_default"] and st["mgmt_key_algorithm"] == "3des"
    assert (st["pin_retries"], st["puk_retries"]) == (3, 3)
    pub = load_pem(piv.generate(0x9A, "eccp256"))          # the default management key again
    check_key_works(m, 0x9A, "eccp256", pub, pin=PIN)
    # the attestation key stays
    assert x509.load_pem_x509_certificate(piv.attest(0x9A).encode()).issuer == before
