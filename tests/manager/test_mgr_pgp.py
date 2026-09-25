"""OpenPGP key manager (librefido.mgr_pgp) against the emulated device:
status, key generation for every algorithm the card offers in every slot
that takes it (the card then signs, decrypts and authenticates, checked with
the public key the manager returned), the fingerprint (the one GnuPG
computes when it makes a key from the card key, and what `gpg --card-status`
shows), PINs, Reset Code, touch policies, cardholder name, key deletion, the
PIN KDF and the reset.

    bash ~/work/scripts/locked_tests.sh <build> -q -rfEs -p no:randomly tests/manager/test_mgr_pgp.py
"""

import hashlib
import os
import shutil
import subprocess
import tempfile
import threading
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils, x25519

from harness.emulator import Emulator, Pcscd
from librefido import mgr_pgp
from librefido.mgmt import Management
from librefido.mgr_common import ManagerError, SecretBlocked, WrongSecret, applet, send, tlv
from librefido.mgr_pgp import OpenPgpManager

USER_PIN, ADMIN_PIN = "123456", "12345678"
AID = mgr_pgp.OPENPGP_AID
SHA256_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
POINT = (serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    p.start()
    yield p
    p.stop()


class Device:
    """An emulated device with its Management; reopen() after programs such
    as GnuPG used the card."""

    def __init__(self, workdir):
        self.emu = Emulator(workdir=workdir)
        self.emu.start()
        try:
            self.m = Management.open(timeout=15)
        except BaseException:
            self.emu.stop()
            raise
        self.pgp = OpenPgpManager(self.m)

    def close(self):
        try:
            self.m.close()
            # the PC/SC context too, while pcscd still runs (pyscard would
            # release it when the object goes, maybe after pcscd stopped)
            conn = self.m.card.conn
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


# -- the card used directly (what GnuPG does with the keys) ---------------------

def apdu(m, ins, p1, p2, data=b""):
    with applet(m, AID, "OpenPGP"):
        return send(m.card, ins, p1, p2, data)


def pin_then(m, pw, pin, ins, p1, p2, data):
    """VERIFY pw, then one command, in one selection of the application."""
    with applet(m, AID, "OpenPGP"):
        _, sw = send(m.card, 0x20, 0x00, pw, pin.encode())
        assert sw == 0x9000, "VERIFY %02X: %04X" % (pw, sw)
        return send(m.card, ins, p1, p2, data)


def _hash_for(curve):
    bits = {"nistp384": 384, "brainpoolP384r1": 384, "nistp521": 512, "brainpoolP512r1": 512}.get(curve, 256)
    return {256: hashes.SHA256(), 384: hashes.SHA384(), 512: hashes.SHA512()}[bits]


def check_signature(m, ref, algorithm, pub):
    """The card signs (PSO:CDS for sig, INTERNAL AUTHENTICATE for aut) and
    the signature verifies with the public key."""
    msg = os.urandom(40)
    if algorithm.startswith("rsa"):
        data = SHA256_INFO + hashlib.sha256(msg).digest()
    elif algorithm == "ed25519":
        data = msg
    else:
        h = hashes.Hash(_hash_for(algorithm))
        h.update(msg)
        data = h.finalize()
    if ref == 1:
        sig, sw = pin_then(m, 0x81, USER_PIN, 0x2A, 0x9E, 0x9A, data)
    else:
        sig, sw = pin_then(m, 0x82, USER_PIN, 0x88, 0x00, 0x00, data)
    assert sw == 0x9000, "signature %s: %04X" % (algorithm, sw)
    if algorithm.startswith("rsa"):
        pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
    elif algorithm == "ed25519":
        pub.verify(sig, msg)
    else:
        n = len(sig) // 2
        der = utils.encode_dss_signature(int.from_bytes(sig[:n], "big"), int.from_bytes(sig[n:], "big"))
        pub.verify(der, data, ec.ECDSA(utils.Prehashed(_hash_for(algorithm))))


def check_decipher(m, algorithm, pub):
    """The card decrypts (RSA) or agrees on a secret (ECDH) with the key."""
    if algorithm.startswith("rsa"):
        secret = os.urandom(32)
        out, sw = pin_then(m, 0x82, USER_PIN, 0x2A, 0x80, 0x86, b"\x00" + pub.encrypt(secret, padding.PKCS1v15()))
        assert sw == 0x9000 and out == secret, "%04X" % sw
        return
    if algorithm == "cv25519":
        eph = x25519.X25519PrivateKey.generate()
        point = eph.public_key().public_bytes_raw()
        want = eph.exchange(pub)
    else:
        eph = ec.generate_private_key(pub.curve)
        point = eph.public_key().public_bytes(*POINT)
        want = eph.exchange(ec.ECDH(), pub)
    out, sw = pin_then(m, 0x82, USER_PIN, 0x2A, 0x80, 0x86, tlv(0xA6, tlv(0x7F49, tlv(0x86, point))))
    assert sw == 0x9000 and out == want, "%s: %04X" % (algorithm, sw)


def load_pem(pem):
    return serialization.load_pem_public_key(pem.encode())


# -- status ------------------------------------------------------------------------

def test_status_of_a_fresh_card(dev):
    st = dev.pgp.status()
    assert st["version"] == "3.4"
    assert len(st["serial"]) == 8 and int(st["serial"], 16) >= 0
    assert st["pin_retries"] == (3, 0, 3)        # no Reset Code until one is set
    assert st["name"] == "" and st["url"] == "" and st["signature_counter"] == 0 and st["kdf"] is False
    for name in ("sig", "dec", "aut"):
        k = st["keys"][name]
        assert k["present"] is False and k["fingerprint"] is None and k["created"] is None
        assert k["algorithm"] == "rsa2048" and k["uif"] == 0 and k["uif_name"] == "off"
    for ref in (1, 3):
        assert dev.pgp.public_key(ref) is None


def expected_offers(ref):
    names = ["rsa2048", "rsa3072", "rsa4096", "nistp256", "nistp384", "nistp521", "brainpoolP256r1",
             "brainpoolP384r1", "brainpoolP512r1", "secp256k1"]
    names += ["cv25519"] if ref == 2 else ["ed25519"]
    return sorted(names)


def test_supported_algorithms(dev):
    for ref in (1, 2, 3):
        assert sorted(dev.pgp.supported_algorithms(ref)) == expected_offers(ref)


# -- keys --------------------------------------------------------------------------

COMBOS = [(a, r) for a in mgr_pgp.ALGORITHMS for r in ("sig", "dec", "aut")
          if not (a == "ed25519" and r == "dec") and not (a == "cv25519" and r != "dec")]


@pytest.mark.parametrize("algorithm,slot", COMBOS, ids=["%s-%s" % c for c in COMBOS])
def test_generate_and_use(dev, algorithm, slot):
    pgp, m = dev.pgp, dev.m
    ref = mgr_pgp.KEY_REFS[slot]
    created = int(time.time()) - 1000
    t0 = time.time()
    r = pgp.generate(slot, algorithm, ADMIN_PIN, created=created)
    took = time.time() - t0
    assert r["key_ref"] == slot and r["algorithm"] == algorithm and r["created"] == created
    pub = load_pem(r["public_key"])
    assert pgp.public_key(slot) == r["public_key"]

    # what the card holds: attributes, fingerprint, generation time
    st = pgp.status()["keys"][slot]
    assert st["present"] is True and st["algorithm"] == algorithm, st
    assert st["fingerprint"] == r["fingerprint"] and st["created"] == created
    attr = mgr_pgp.algorithm_attributes(algorithm, ref)
    resp, sw = apdu(m, 0x47, 0x81, 0x00, bytes([{1: 0xB6, 2: 0xB8, 3: 0xA4}[ref], 0]))
    assert sw == 0x9000
    packet = mgr_pgp.public_key_packet(attr, mgr_pgp.parse_public_key(resp), created)
    assert mgr_pgp.fingerprint(packet).hex().upper() == r["fingerprint"]

    if slot == "dec":
        check_decipher(m, algorithm, pub)
    else:
        check_signature(m, ref, algorithm, pub)
    print("%s in %s: generated in %.1f s" % (algorithm, slot, took))


def test_generate_refuses_to_replace_and_checks_the_admin_pin(dev):
    pgp = dev.pgp
    first = pgp.generate("sig", "nistp256", ADMIN_PIN)
    with pytest.raises(ManagerError) as e:
        pgp.generate("sig", "ed25519", ADMIN_PIN)
    assert e.value.sw == 0x6A89 and e.value.zh
    with pytest.raises(WrongSecret) as e:
        pgp.generate("aut", "ed25519", "87654321")
    assert e.value.retries == 2 and "Admin PIN" in str(e.value)
    st = pgp.status()
    assert st["keys"]["sig"]["fingerprint"] == first["fingerprint"]       # nothing changed
    assert st["keys"]["aut"]["present"] is False and st["pin_retries"] == (3, 0, 2)
    pgp.generate("aut", "ed25519", ADMIN_PIN)                             # a right PIN resets the counter
    assert pgp.status()["pin_retries"] == (3, 0, 3)
    with pytest.raises(ManagerError):
        pgp.generate("dec", "ed25519", ADMIN_PIN)                          # never reaches the card


def test_delete_key(dev):
    pgp = dev.pgp
    pgp.generate("dec", "cv25519", ADMIN_PIN)
    pgp.set_uif("dec", "on", ADMIN_PIN)
    with pytest.raises(WrongSecret):
        pgp.delete_key("dec", "00000000")
    assert pgp.status()["keys"]["dec"]["present"] is True
    pgp.delete_key("dec", ADMIN_PIN)
    k = pgp.status()["keys"]["dec"]
    assert k["present"] is False and k["fingerprint"] is None and k["created"] is None
    assert k["algorithm"] == "cv25519" and k["uif_name"] == "on"          # the slot keeps its settings
    assert pgp.public_key("dec") is None
    with pytest.raises(ManagerError) as e:
        pgp.delete_key("dec", ADMIN_PIN)
    assert e.value.sw == 0x6A88
    # an RSA 2048 slot (the attributes the change goes through otherwise)
    pgp.generate("aut", "rsa2048", ADMIN_PIN)
    pgp.delete_key("aut", ADMIN_PIN)
    assert pgp.status()["keys"]["aut"]["present"] is False and pgp.status()["keys"]["aut"]["algorithm"] == "rsa2048"


# -- PINs --------------------------------------------------------------------------

def test_pins_reset_code_and_unblock(dev):
    pgp, m = dev.pgp, dev.m
    with pytest.raises(WrongSecret) as e:
        pgp.change_pin("654321", "111111")
    assert e.value.retries == 2
    with pytest.raises(ManagerError):
        pgp.change_pin(USER_PIN, "12345")                   # too short: refused before the card
    assert pgp.status()["pin_retries"][0] == 2
    pgp.change_pin(USER_PIN, "pin-新的")                    # UTF-8
    _, sw = apdu(m, 0x20, 0x00, 0x81, "pin-新的".encode())
    assert sw == 0x9000
    pgp.change_admin_pin(ADMIN_PIN, "admin-pin-2")
    with pytest.raises(ManagerError):
        pgp.change_admin_pin("admin-pin-2", "1234567")      # PW3 has at least 8
    # the Reset Code
    with pytest.raises(WrongSecret):
        pgp.set_reset_code(ADMIN_PIN, "reset-code")
    pgp.set_reset_code("admin-pin-2", "reset-code")
    assert pgp.status()["pin_retries"] == (3, 3, 3)
    for _ in range(3):
        with pytest.raises((WrongSecret, SecretBlocked)):
            pgp.change_pin("wrong-pin", "whatever")
    assert pgp.status()["pin_retries"][0] == 0
    with pytest.raises(SecretBlocked) as e:
        pgp.change_pin("pin-新的", "whatever")
    assert "Reset Code" in str(e.value)
    with pytest.raises(WrongSecret):
        pgp.unblock_pin("new-pin-1", reset_code="wrong-code")
    pgp.unblock_pin("new-pin-1", reset_code="reset-code")
    assert pgp.status()["pin_retries"] == (3, 3, 3)
    _, sw = apdu(m, 0x20, 0x00, 0x82, b"new-pin-1")
    assert sw == 0x9000
    # with the Admin PIN, and removing the Reset Code
    pgp.unblock_pin("new-pin-2", admin_pin="admin-pin-2")
    _, sw = apdu(m, 0x20, 0x00, 0x81, b"new-pin-2")
    assert sw == 0x9000
    pgp.set_reset_code("admin-pin-2", None)
    assert pgp.status()["pin_retries"] == (3, 0, 3)
    with pytest.raises(SecretBlocked):
        pgp.unblock_pin("new-pin-3", reset_code="reset-code")
    with pytest.raises(ManagerError):
        pgp.unblock_pin("new-pin-3")                        # neither
    with pytest.raises(ManagerError):
        pgp.unblock_pin("new-pin-3", admin_pin="admin-pin-2", reset_code="reset-code")


def test_pin_change_keeps_the_keys(dev):
    pgp, m = dev.pgp, dev.m
    r = pgp.generate("sig", "ed25519", ADMIN_PIN)
    pgp.change_pin(USER_PIN, "654321")
    pgp.change_admin_pin(ADMIN_PIN, "87654321")
    msg = b"still signs"
    sig, sw = pin_then(m, 0x81, "654321", 0x2A, 0x9E, 0x9A, msg)
    assert sw == 0x9000
    load_pem(r["public_key"]).verify(sig, msg)


# -- settings ------------------------------------------------------------------------

def test_touch_policy(dev):
    pgp, m = dev.pgp, dev.m
    r = pgp.generate("sig", "nistp256", ADMIN_PIN)
    pgp.set_uif("sig", "on", ADMIN_PIN)
    pgp.set_uif(3, 3, ADMIN_PIN)
    st = pgp.status()["keys"]
    assert st["sig"]["uif_name"] == "on" and st["aut"]["uif_name"] == "cached" and st["dec"]["uif"] == 0
    check_signature(m, 1, "nistp256", load_pem(r["public_key"]))      # the emulator's button is pressed for it
    with pytest.raises(ManagerError):
        pgp.set_uif("sig", "fixed", ADMIN_PIN)                         # permanent: must be confirmed
    with pytest.raises(ManagerError):
        pgp.set_uif("sig", "sometimes", ADMIN_PIN)
    pgp.set_uif("sig", "fixed", ADMIN_PIN, permanent=True)
    assert pgp.status()["keys"]["sig"]["uif_name"] == "fixed"
    with pytest.raises(ManagerError) as e:
        pgp.set_uif("sig", "off", ADMIN_PIN)
    assert "fixed" in str(e.value)
    pgp.set_uif("sig", "fixed", ADMIN_PIN, permanent=True)             # the same value is fine
    pgp.reset(admin_pin=ADMIN_PIN)
    assert pgp.status()["keys"]["sig"]["uif_name"] == "off"


def test_cardholder_and_url(dev):
    pgp = dev.pgp
    pgp.set_cardholder("Mustermann<<Erika", ADMIN_PIN)
    pgp.set_url("https://keys.example/erika.asc", ADMIN_PIN)
    st = pgp.status()
    assert st["name"] == "Mustermann<<Erika" and st["url"] == "https://keys.example/erika.asc"
    for bad in ("Müller<<Hans", "x" * 40, "a\nb"):
        with pytest.raises(ManagerError):
            pgp.set_cardholder(bad, ADMIN_PIN)
    with pytest.raises(WrongSecret):
        pgp.set_cardholder("Other", "wrongpin")
    assert pgp.status()["name"] == "Mustermann<<Erika"
    pgp.set_cardholder("", ADMIN_PIN)
    assert pgp.status()["name"] == ""


# -- reset -----------------------------------------------------------------------------

def test_reset_without_the_admin_pin(dev):
    pgp = dev.pgp
    pgp.generate("sig", "rsa2048", ADMIN_PIN)
    pgp.generate("dec", "cv25519", ADMIN_PIN)
    pgp.change_pin(USER_PIN, "654321")
    pgp.change_admin_pin(ADMIN_PIN, "forgotten-admin")
    pgp.set_reset_code("forgotten-admin", "reset-code")
    pgp.set_cardholder("Name<<Some", "forgotten-admin")
    pgp.reset()
    st = pgp.status()
    assert all(k["present"] is False and k["fingerprint"] is None for k in st["keys"].values())
    assert st["pin_retries"] == (3, 0, 3) and st["name"] == ""
    assert st["keys"]["dec"]["algorithm"] == "rsa2048"
    pgp.change_pin(USER_PIN, "654321")                     # the default PINs again
    pgp.change_admin_pin(ADMIN_PIN, "87654321")


def test_reset_with_the_admin_pin_keeps_other_applications(dev):
    pgp, m = dev.pgp, dev.m
    pgp.generate("aut", "ed25519", ADMIN_PIN)
    with pytest.raises(WrongSecret):
        pgp.reset(admin_pin="00000000")
    assert pgp.status()["keys"]["aut"]["present"] is True
    # PIV's PIN is not the OpenPGP one: it stays as it was
    with applet(m, bytes.fromhex("A000000308"), "PIV"):
        _, sw = send(m.card, 0x24, 0x00, 0x80, b"123456\xff\xff" + b"999999\xff\xff")
        assert sw == 0x9000
    pgp.reset(admin_pin=ADMIN_PIN)
    assert pgp.status()["keys"]["aut"]["present"] is False
    with applet(m, bytes.fromhex("A000000308"), "PIV"):
        _, sw = send(m.card, 0x20, 0x00, 0x80, b"999999\xff\xff")
        assert sw == 0x9000


# -- PIN KDF ---------------------------------------------------------------------------

def test_pin_kdf(dev):
    """With a KDF-DO asking for KDF_ITERSALTED_S2K (as `gpg --card-edit
    kdf-setup` writes it) the PINs are the S2K hashes: set up here by hand
    (the card only stores the DO), then the manager's operations use it."""
    pgp, m = dev.pgp, dev.m
    salts = {0x84: os.urandom(8), 0x85: os.urandom(8), 0x86: os.urandom(8)}
    do = bytes.fromhex("810103820108830400010000") + b"".join(bytes([t, 8]) + s for t, s in salts.items())
    pw1 = mgr_pgp.s2k_iterated("sha256", salts[0x84], USER_PIN.encode(), 0x10000)
    pw3 = mgr_pgp.s2k_iterated("sha256", salts[0x86], ADMIN_PIN.encode(), 0x10000)
    with applet(m, AID, "OpenPGP"):
        card = m.card
        assert send(card, 0x20, 0x00, 0x83, ADMIN_PIN.encode())[1] == 0x9000
        assert send(card, 0xDA, 0x00, 0xF9, do)[1] == 0x9000
        assert send(card, 0x24, 0x00, 0x81, USER_PIN.encode() + pw1)[1] == 0x9000
        assert send(card, 0x24, 0x00, 0x83, ADMIN_PIN.encode() + pw3)[1] == 0x9000
    assert pgp.status()["kdf"] is True
    r = pgp.generate("sig", "ed25519", ADMIN_PIN)          # PW3 through the KDF
    pgp.change_pin(USER_PIN, "654321")
    pgp.set_reset_code(ADMIN_PIN, "reset-code")
    pgp.unblock_pin("111111", reset_code="reset-code")
    new = mgr_pgp.s2k_iterated("sha256", salts[0x84], b"111111", 0x10000)
    with applet(m, AID, "OpenPGP"):
        assert send(m.card, 0x20, 0x00, 0x81, new)[1] == 0x9000
        sig, sw = send(m.card, 0x2A, 0x9E, 0x9A, b"kdf")
    assert sw == 0x9000
    load_pem(r["public_key"]).verify(sig, b"kdf")
    with pytest.raises(WrongSecret):
        pgp.change_admin_pin("12345679", "87654321")
    pgp.reset()                                              # blocks the (hashed) Admin PIN, then resets
    assert pgp.status()["kdf"] is False
    pgp.change_pin(USER_PIN, "654321")                      # plain default PINs again


# -- GnuPG ---------------------------------------------------------------------------

GPG_OK = shutil.which("gpg") and os.environ.get("SCDAEMON_PROGRAM")


def gpg(*args, check=True, stdin=None):
    r = subprocess.run(["gpg", "--batch", "--no-tty", "--pinentry-mode", "loopback", *args],
                       input=stdin, capture_output=True, timeout=300)
    if check and r.returncode != 0:
        raise AssertionError("gpg %s failed:\n%s" % (" ".join(args), r.stderr.decode(errors="replace")))
    return r


def gpg_drive(args, answers, commands=(), pin=USER_PIN, timeout=300):
    """gpg with its questions answered through --command-fd (by status
    keyword; lists are used up in order), keyedit prompts from commands, and
    every passphrase with pin (the card's PIN for signing)."""
    err = tempfile.TemporaryFile()
    p = subprocess.Popen(["gpg", "--no-tty", "--pinentry-mode", "loopback", "--command-fd", "0", "--status-fd", "1",
                          *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err, text=True)
    timer = threading.Timer(timeout, p.kill)
    timer.start()
    answers = {k: (list(v) if isinstance(v, list) else v) for k, v in answers.items()}
    commands, transcript, unknown = list(commands), [], 0
    try:
        for line in p.stdout:
            transcript.append(line.rstrip())
            if not line.startswith("[GNUPG:] GET_"):
                continue
            kw = line.split()[2]
            if kw == "keyedit.prompt":
                reply = commands.pop(0) if commands else "quit"
            elif kw == "passphrase.enter":
                reply = pin
            else:
                reply = answers.get(kw)
                if isinstance(reply, list):
                    reply = reply.pop(0) if reply else None
                if reply is None:
                    unknown += 1
                    if unknown > 5:
                        p.kill()
                        break
                    reply = ""
            p.stdin.write(reply + "\n")
            p.stdin.flush()
        p.stdin.close()
        p.wait(60)
    finally:
        timer.cancel()
    err.seek(0)
    return p.returncode, "\n".join(transcript) + "\n" + err.read().decode(errors="replace")


@pytest.fixture
def gnupg(dev):
    if not GPG_OK:
        pytest.skip("GnuPG test home not configured (source testenv.sh)")
    subprocess.run(["bash", "-c", "source ~/work/testenv.sh >/dev/null && GPG_TEST_PCSC_SHARED=1 gpg_test_reset"],
                   check=True, capture_output=True)
    yield dev
    subprocess.run(["gpgconf", "--kill", "all"], check=False)


def fpr_lines(uid):
    out = gpg("--with-colons", "--list-keys", uid).stdout.decode()
    return [ln.split(":")[9] for ln in out.splitlines() if ln.startswith("fpr:")]


def card_status_fprs(text):
    out = {}
    for label, name in (("Signature key", "sig"), ("Encryption key", "dec"), ("Authentication key", "aut")):
        line = next(ln for ln in text.splitlines() if ln.startswith(label))
        out[name] = line.split(":", 1)[1].replace(" ", "").strip()
    return out


CARD_COMBOS = [("rsa2048", "rsa2048", "rsa2048"), ("ed25519", "cv25519", "ed25519"),
               ("nistp256", "nistp256", "nistp256"), ("nistp384", "nistp384", "nistp384"),
               ("nistp521", "nistp521", "brainpoolP256r1")]


@pytest.mark.parametrize("sig,dec,aut", CARD_COMBOS, ids=["-".join(c) for c in CARD_COMBOS])
def test_gnupg_agrees(gnupg, sig, dec, aut):
    """Keys generated by the manager: `gpg --card-status` shows their
    fingerprints and attributes; GnuPG makes an OpenPGP key from the card keys
    ("Existing key from card", at their generation time) with the very same
    fingerprints, then signs and decrypts with the card."""
    d = gnupg
    created = int(time.time()) - 86400
    want = {name: d.pgp.generate(name, alg, ADMIN_PIN, created=created)["fingerprint"]
            for name, alg in (("sig", sig), ("dec", dec), ("aut", aut))}
    d.pgp.set_cardholder("Tester<<Manager", ADMIN_PIN)
    status = gpg("--card-status").stdout.decode()
    assert card_status_fprs(status) == want, status
    assert "Key attributes ...: %s %s %s" % (sig, dec, aut) in status, status
    assert "Name of cardholder: Manager Tester" in status, status

    uid = "Manager Test <mgr-%s@librefido.example>" % sig
    faked = ["--faked-system-time", "%d!" % created]
    rc, log = gpg_drive(["--expert", *faked, "--full-generate-key"],
                        {"keygen.algo": "14", "keygen.cardkey": "1", "keygen.flags": "Q", "keygen.valid": "0",
                         "keygen.valid.okay": "y", "keygen.name": "Manager Test",
                         "keygen.email": "mgr-%s@librefido.example" % sig, "keygen.comment": "",
                         "keygen.userid.cmd": "O"})
    assert rc == 0 and "KEY_CREATED" in log, log
    assert fpr_lines(uid) == [want["sig"]], log
    for index, name in (("2", "dec"), ("3", "aut")):
        rc, log = gpg_drive(["--expert", *faked, "--edit-key", want["sig"]],
                            {"keygen.algo": "14", "keygen.cardkey": index, "keygen.flags": "Q", "keygen.valid": "0",
                             "keygen.valid.okay": "y", "keyedit.save.okay": "y"}, commands=["addkey", "save"])
        assert rc == 0, log
    assert fpr_lines(uid) == [want["sig"], want["dec"], want["aut"]]

    # every self-signature and binding signature the card made is good
    checks = gpg("--with-colons", "--check-signatures", want["sig"]).stdout.decode()
    sigs = [ln.split(":")[1] for ln in checks.splitlines() if ln.startswith("sig:")]
    assert len(sigs) == 3 and all(s == "!" for s in sigs), checks

    # the exact keys ("!"): GnuPG gives a subkey made from a card key the
    # sign capability by default, and would otherwise sign with the newest
    w = tempfile.mkdtemp()
    msg = os.path.join(w, "msg.txt")
    with open(msg, "w") as f:
        f.write("signed and decrypted with keys the LibreFido key manager made\n")
    gpg("--passphrase", USER_PIN, "--output", msg + ".sig", "--detach-sign", "--local-user", want["sig"] + "!", msg)
    verified = gpg("--verify", msg + ".sig", msg).stderr.decode()
    assert "Good signature" in verified and want["sig"] in verified.replace(" ", ""), verified
    gpg("--trust-model", "always", "--recipient", want["dec"] + "!", "--output", msg + ".gpg", "--encrypt", msg)
    assert gpg("--passphrase", USER_PIN, "--decrypt", msg + ".gpg").stdout == open(msg, "rb").read()
    shutil.rmtree(w)
    # the self-signature, two bindings, the message (and GnuPG's revocation
    # certificate made at key creation)
    assert d.pgp.status()["signature_counter"] >= 4


def gnupg_version():
    out = subprocess.run(["gpg", "--version"], capture_output=True, text=True).stdout
    return tuple(int(x) for x in out.split()[2].split(".")[:3])


AUT_COMBOS = [("nistp256", "nistp256", "nistp256"), ("rsa2048", "rsa2048", "rsa2048"),
              ("ed25519", "cv25519", "ed25519")]


@pytest.mark.parametrize("sig,dec,aut", AUT_COMBOS, ids=[c[2] for c in AUT_COMBOS])
def test_gnupg_signs_with_the_authentication_key(gnupg, sig, dec, aut):
    """A signing subkey GnuPG made from the card's authentication key (scdaemon
    signs with INTERNAL AUTHENTICATE): the signature is good, except for
    Ed25519 with GnuPG before 2.5.8. Its scdaemon puts the SHA-2 DigestInfo in
    front of the hash and strips 19 bytes of it for ECDSA but only 15 for
    EdDSA (GnuPG bug 7589, fixed by GnuPG commit eb7d5d4d85): the card signs
    the data field as given, as EdDSA does (OpenPGP card 3.4, 7.2.13), the 4
    bytes left over included (docs/COMPATIBILITY.md; the exact bytes are
    checked in tests/openpgp/test_openpgp_25519.py). The same key then
    authenticates for SSH through gpg-agent (ssh-keygen -Y sign / verify)."""
    d = gnupg
    created = int(time.time()) - 86400
    want = {name: d.pgp.generate(name, alg, ADMIN_PIN, created=created)["fingerprint"]
            for name, alg in (("sig", sig), ("dec", dec), ("aut", aut))}
    email = "aut-%s@librefido.example" % aut
    faked = ["--faked-system-time", "%d!" % created]
    # the answers are used up: a question asked again ends gpg instead of looping
    rc, log = gpg_drive(["--expert", *faked, "--full-generate-key"],
                        {"keygen.algo": ["14"], "keygen.cardkey": ["1"], "keygen.flags": ["Q"],
                         "keygen.valid": ["0"], "keygen.valid.okay": ["y"], "keygen.name": ["Aut Test"],
                         "keygen.email": [email], "keygen.comment": [""], "keygen.userid.cmd": ["O"]})
    assert rc == 0 and "KEY_CREATED" in log, log
    rc, log = gpg_drive(["--expert", *faked, "--edit-key", want["sig"]],
                        {"keygen.algo": ["14"], "keygen.cardkey": ["3"], "keygen.flags": ["Q"], "keygen.valid": ["0"],
                         "keygen.valid.okay": ["y"], "keyedit.save.okay": ["y"]}, commands=["addkey", "save"])
    assert rc == 0, log
    assert fpr_lines(email) == [want["sig"], want["aut"]]
    w = tempfile.mkdtemp()
    try:
        # (a reload does not take enable-ssh-support: the agent starts again)
        agent_log = os.path.join(os.environ["GNUPGHOME"], "gpg-agent.log")
        with open(os.path.join(os.environ["GNUPGHOME"], "gpg-agent.conf"), "a") as f:
            f.write("enable-ssh-support\nlog-file %s\nverbose\n" % agent_log)
        subprocess.run(["gpgconf", "--kill", "gpg-agent"], check=True)
        msg = os.path.join(w, "msg.txt")
        with open(msg, "wb") as f:
            f.write(os.urandom(100))
        # OpenPGP first: it verifies PW1 through the loopback pinentry, which
        # the SSH request then needs no more
        gpg("--passphrase", USER_PIN, "--output", msg + ".gpg-sig", "--detach-sign", "--local-user",
            want["aut"] + "!", msg)
        verified = gpg("--verify", msg + ".gpg-sig", msg, check=False).stderr.decode()
        if aut == "ed25519" and gnupg_version() < (2, 5, 8):
            assert "BAD signature" in verified, verified
        else:
            assert "Good signature" in verified and "BAD signature" not in verified, verified
        ssh_pub = gpg("--export-ssh-key", want["aut"] + "!").stdout.decode().strip()
        with open(os.path.join(w, "id.pub"), "w") as f:
            f.write(ssh_pub + "\n")
        with open(os.path.join(w, "allowed"), "w") as f:
            f.write("tester " + ssh_pub + "\n")
        env = dict(os.environ, SSH_AUTH_SOCK=subprocess.run(["gpgconf", "--list-dirs", "agent-ssh-socket"],
                                                            capture_output=True, text=True).stdout.strip())
        r = subprocess.run(["ssh-keygen", "-Y", "sign", "-f", os.path.join(w, "id.pub"), "-n", "file", msg],
                           env=env, capture_output=True, timeout=120)
        if r.returncode != 0:
            with open(agent_log, errors="replace") as f:
                raise AssertionError("%s\ngpg-agent:\n%s" % (r.stderr.decode(errors="replace"), f.read()[-3000:]))
        with open(msg, "rb") as f:
            r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", os.path.join(w, "allowed"), "-I", "tester",
                                "-n", "file", "-s", msg + ".sig"], stdin=f, capture_output=True, timeout=60)
        assert r.returncode == 0 and b"Good" in r.stdout, r.stdout + r.stderr
    finally:
        shutil.rmtree(w)
