"""PIV with standard tooling: OpenSC (opensc-tool, piv-tool, pkcs11-tool
with opensc-pkcs11.so), yubico-piv-tool and OpenSSL, against the emulator.

    source ~/work/testenv.sh
    PYTHONPATH=tests:tools/librefido python -m pytest tests/piv
"""

import os
import shutil
import subprocess

import pytest

from harness.emulator import Emulator, Pcscd
from librefido.pcsc import open_device

TOOLS = ("opensc-tool", "pkcs11-tool", "yubico-piv-tool", "openssl")
pytestmark = pytest.mark.skipif(any(shutil.which(t) is None for t in TOOLS),
                                reason="OpenSC / yubico-piv-tool / OpenSSL not installed")


def pkcs11_module():
    for d in (os.environ.get("TESTENV_LIBDIR", ""), "/usr/lib/x86_64-linux-gnu", "/usr/lib"):
        for p in (os.path.join(d, "opensc-pkcs11.so"), os.path.join(d, "pkcs11", "opensc-pkcs11.so")):
            if d and os.path.exists(p):
                return p
    pytest.skip("opensc-pkcs11.so not found")


def run(*args, check=True, stdin=None, env=None):
    # The card has a PIV and an OpenPGP application: pin OpenSC to its PIV
    # driver (opensc.conf card_drivers, or OPENSC_DRIVER), see docs/PIV.md.
    e = dict(os.environ, OPENSC_DRIVER="PIV-II")
    e.update(env or {})
    e = {k: v for k, v in e.items() if v is not None}     # None: not set (empty names no driver)
    args = list(args)
    if args[0] == "yubico-piv-tool":
        # it only looks at readers named like a YubiKey unless told otherwise
        args[1:1] = ["-r", os.environ.get("VPCD_READER_NAME", "Virtual PCD")]
    r = subprocess.run(args, capture_output=True, text=True, timeout=180, input=stdin, env=e)
    if check and r.returncode != 0:
        raise AssertionError("%s failed (%d):\n%s\n%s" % (" ".join(args), r.returncode, r.stdout, r.stderr))
    return r.stdout + r.stderr


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no PC/SC stack configured (see tests/README.md)")
    p.start()
    yield p
    p.stop()


@pytest.fixture
def card(pcscd, tmp_path):
    e = Emulator(workdir=str(tmp_path / "dev"))
    e.start()
    try:        # a failed setup must not leave the emulator holding the ports
        open_device(timeout=15).close()         # the card is in the reader
        yield tmp_path
    finally:
        e.stop()


def host_cert(pub_path, cn, out_path):
    """A certificate for the card's public key, made on the host:
    yubico-piv-tool 2.2 cannot selfsign with OpenSSL 3 ("Failed signing
    certificate" before it sends anything to the card). The card's own
    signatures are checked through PKCS#11 below."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    with open(pub_path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(pub)
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256()))
    with open(out_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def keygen_and_cert(w, slot, algo):
    pub, cert = str(w / ("pub%s.pem" % slot)), str(w / ("cert%s.pem" % slot))
    run("yubico-piv-tool", "-a", "generate", "-s", slot, "-A", algo, "-o", pub)
    host_cert(pub, "LibreFido PIV %s" % slot, cert)
    run("yubico-piv-tool", "-a", "import-certificate", "-s", slot, "-i", cert)
    return pub, cert


def test_opensc_sees_both_applications(card):
    # opensc-tool -n prints the name of the driver that took the card
    assert "Personal Identity Verification Card" in run("opensc-tool", "-n")
    # without a driver choice OpenSC tries its PIV driver before its OpenPGP
    # driver (with the malformed SELECT answer of earlier versions the PIV
    # driver gave up, and OpenSC fell back to OpenPGP)
    assert "Personal Identity Verification Card" in run("opensc-tool", "-n", env={"OPENSC_DRIVER": None})
    assert "OpenPGP" in run("opensc-tool", "-n", env={"OPENSC_DRIVER": "openpgp"})


def test_pkcs11_sign_and_decrypt(card):
    w = card
    mod = pkcs11_module()
    pub9a, cert9a = keygen_and_cert(w, "9a", "ECCP256")
    pub9d, _ = keygen_and_cert(w, "9d", "RSA2048")

    objects = run("pkcs11-tool", "--module", mod, "--list-objects")
    assert "LibreFido PIV 9a" in objects and "LibreFido PIV 9d" in objects, objects

    data = w / "data"
    data.write_bytes(b"signed and decrypted through PKCS#11")
    # ECDSA P-256 signature with the 9A key, verified by OpenSSL
    run("pkcs11-tool", "--module", mod, "--login", "--pin", "123456", "--sign", "--id", "01",
        "--mechanism", "ECDSA-SHA256", "--signature-format", "openssl", "-i", str(data), "-o", str(w / "sig"))
    run("openssl", "dgst", "-sha256", "-verify", pub9a, "-signature", str(w / "sig"), str(data))
    # the certificate read back from the card is the one written
    run("pkcs11-tool", "--module", mod, "--read-object", "--type", "cert", "--id", "01", "-o", str(w / "c.der"))
    assert run("openssl", "x509", "-inform", "DER", "-in", str(w / "c.der"), "-noout", "-subject").count("LibreFido PIV 9a")
    # RSA-2048 decryption with the 9D key
    run("openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", pub9d, "-in", str(data), "-out", str(w / "enc"))
    run("pkcs11-tool", "--module", mod, "--login", "--pin", "123456", "--decrypt", "--id", "03",
        "--mechanism", "RSA-PKCS", "-i", str(w / "enc"), "-o", str(w / "dec"))
    assert (w / "dec").read_bytes() == data.read_bytes()


def test_pin_puk_management_key_and_reset(card):
    w = card
    run("yubico-piv-tool", "-a", "change-pin", "-P", "123456", "-N", "654321")
    out = run("yubico-piv-tool", "-a", "verify-pin", "-P", "123456", check=False)
    assert "Pin verification failed" in out or "wrong" in out.lower(), out
    run("yubico-piv-tool", "-a", "verify-pin", "-P", "654321")
    # PUK resets the PIN
    run("yubico-piv-tool", "-a", "unblock-pin", "-P", "12345678", "-N", "111111")
    run("yubico-piv-tool", "-a", "verify-pin", "-P", "111111")
    # a new management key replaces the default (3DES: yubico-piv-tool 2.2
    # knows no AES management keys)
    newkey = "00112233445566778899aabbccddeeff0011223344556677"
    run("yubico-piv-tool", "-a", "set-mgm-key", "-n", newkey)
    out = run("yubico-piv-tool", "-a", "generate", "-s", "9c", "-A", "ECCP256", "-o", str(w / "x.pem"), check=False)
    assert "Failed" in out or "failed" in out, out                 # the default key no longer works
    run("yubico-piv-tool", "-k" + newkey, "-a", "generate", "-s", "9c", "-A", "ECCP256",
        "-o", str(w / "x.pem"))
    # block PIN and PUK, then RESET restores all defaults
    for _ in range(3):
        run("yubico-piv-tool", "-a", "verify-pin", "-P", "000000", check=False)
    for _ in range(3):
        run("yubico-piv-tool", "-a", "change-puk", "-P", "00000000", "-N", "11111111", check=False)
    run("yubico-piv-tool", "-a", "reset")
    run("yubico-piv-tool", "-a", "verify-pin", "-P", "123456")
    run("yubico-piv-tool", "-a", "generate", "-s", "9a", "-A", "ECCP256", "-o", str(w / "y.pem"))


def test_retired_slots_and_key_deletion(card):
    w = card
    mod = pkcs11_module()
    for slot in ("82", "93", "95"):                                  # 93: stored apart from OpenPGP's 0x93
        keygen_and_cert(w, slot, "ECCP256")
    # OpenSC shows retired keys as far as the key history object counts
    # certificates on the card (SP 800-73-4 part 1, 3.3.2): all 20 slots
    history = w / "history.bin"
    history.write_bytes(bytes.fromhex("C10114 C20100 FE00"))
    run("yubico-piv-tool", "-a", "write-object", "--id=%d" % 0x5FC10C, "-f", "binary", "-i", str(history))
    objects = run("pkcs11-tool", "--module", mod, "--list-objects")
    for slot in ("82", "93", "95"):
        assert "LibreFido PIV %s" % slot in objects, objects
    run("yubico-piv-tool", "-a", "delete-certificate", "-s", "82")
    assert delete_key(0x82) == 0x6A88                               # no metadata: no key
    status = run("yubico-piv-tool", "-a", "status")
    assert "Slot 82" not in status or "LibreFido PIV 82" not in status, status


def delete_key(slot):
    """MOVE KEY to FF with the default management key (yubico-piv-tool 2.2
    has no delete-key); returns the status of GET METADATA afterwards."""
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    from harness.card import Card
    tdes = Cipher(TripleDES(bytes.fromhex("010203040506070801020304050607080102030405060708")), modes.ECB())
    card = Card()
    try:
        card.select(bytes.fromhex("A000000308"))
        resp, _ = card.transmit(0x00, 0x87, 0x03, 0x9B, bytes.fromhex("7C028000"), le=0)
        d = tdes.decryptor()
        witness = d.update(resp[4:12]) + d.finalize()
        card.transmit(0x00, 0x87, 0x03, 0x9B, bytes.fromhex("7C148008") + witness + bytes.fromhex("8108") + os.urandom(8),
                      le=0)
        card.transmit(0x00, 0xF6, 0xFF, slot)
        return card.transmit(0x00, 0xF7, 0x00, slot, le=0, check=False)[1]
    finally:
        card.close()
