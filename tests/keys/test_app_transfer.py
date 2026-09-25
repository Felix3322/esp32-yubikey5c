"""Single-key transfer of OATH accounts, OTP slots, OpenPGP keys and PIV keys
between two emulated devices (docs/KEY_TRANSFER.md).

Each key is made on device A, exported with the host library (keyio, which
drives KEY_LIST / KEY_EXPORT of the management applet), passed through a
.lfkey file, added to device B through keyio or the command line, and then
used on B: the result is checked against what A produced or the public key
A gave out. A and B have their own flash and chip ID and share the ports, so
only one of them runs at a time.

    bash ~/work/scripts/locked_tests.sh <build> -q -rfEs -p no:randomly tests/keys
"""

import datetime
import hashlib
import hmac
import os
import shutil
import subprocess
import tempfile
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from fido2 import cbor
from smartcard.Exceptions import CardConnectionException

from harness.card import Card, YkConnection
from harness.emulator import Button
from librefido import cli, keyio, stdformats
from librefido.keyfile import SingleKey, read_key_file, write_key_file
from librefido.keyio import KeyTransferError
from librefido.mgmt import INS_KEY_EXPORT, Management

from test_profiles_backup import emulators, pcscd  # noqa: F401  (fixtures)
from test_mgmt_security import sw_of

yoath = pytest.importorskip("yubikit.oath")
yotp = pytest.importorskip("yubikit.yubiotp")
ypiv = pytest.importorskip("yubikit.piv")

FILE_PW = "transfer file passphrase"
OPENPGP_AID = bytes.fromhex("D27600012401")
PW1, PW3 = b"123456", b"12345678"
PIV_PIN = "123456"
# Manual button with the typed text in the emulator log (the OTP slots type)
KEYBOARD = {"LF_EMU_UP": "manual", "LF_EMU_UP_TIMEOUT_MS": "1500", "LF_EMU_KEYBOARD_LOG": "1"}
RFC4226_SECRET = b"12345678901234567890"
RFC4226_CODES = [755224, 287082, 359152, 969429, 338314]


# -- devices -----------------------------------------------------------------------

def close(card):
    """Disconnects and releases the PC/SC context now: left to the garbage
    collector, the release may come after the module's pcscd has stopped."""
    card.close()
    try:
        card.conn.release()
    except Exception:
        pass


def wait_card(timeout=15):
    """Until the reader shows the emulator just started: a connection made
    while pcscd still has the previous card fails its first command."""
    deadline = time.time() + timeout
    while True:
        card = None
        try:
            card = Card()
            card.raw(bytes([0x00, 0xA4, 0x04, 0x00, len(OPENPGP_AID)]) + OPENPGP_AID)
            return
        except CardConnectionException:
            if time.time() > deadline:
                raise
            time.sleep(0.2)
        finally:
            if card is not None:
                close(card)


def power(devices, e, **env):
    """e alone runs (the devices share the ports), started with env."""
    for d in devices.made:
        d.stop()
    e.start(**env)
    wait_card()


class Session:
    """A card connection, closed before anything else talks to the device (a
    connection left to the garbage collector resets the card later)."""

    def __enter__(self):
        self.card = Card()
        return self.card

    def __exit__(self, *a):
        close(self.card)


class Mgmt:
    def __enter__(self):
        self.m = Management.open(timeout=15)
        return self.m

    def __exit__(self, *a):
        self.m.close()


def through_file(tmp_path, key, name):
    """The key written to an encrypted .lfkey file and read back."""
    path = str(tmp_path / ("%s-%s.lfkey" % (key.app, name)))
    write_key_file(path, key, FILE_PW, scrypt_log_n=10)
    info, again = read_key_file(path, FILE_PW, require_encryption=True)
    assert info["encrypted"] and again.app == key.app and again.record == key.record
    return again


def run_cli(capsys, *argv):
    cli.main(["--wait", "15"] + list(argv))
    return capsys.readouterr()


def hotp(secret, counter, digits, alg="sha1"):
    mac = hmac.new(secret, counter.to_bytes(8, "big"), alg).digest()
    o = mac[-1] & 0x0F
    return str((int.from_bytes(mac[o:o + 4], "big") & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


# -- OATH --------------------------------------------------------------------------

T = 1_900_000_000
OATH_HASHES = {yoath.HASH_ALGORITHM.SHA1: "sha1", yoath.HASH_ALGORITHM.SHA256: "sha256",
               yoath.HASH_ALGORITHM.SHA512: "sha512"}


def oath_accounts():
    """(credential data, touch required) of the accounts made on A."""
    CD, TOTP, HOTP, H = yoath.CredentialData, yoath.OATH_TYPE.TOTP, yoath.OATH_TYPE.HOTP, yoath.HASH_ALGORITHM
    return [(CD("alice", TOTP, H.SHA1, os.urandom(20), digits=6, issuer="Sha1"), False),
            (CD("bob", TOTP, H.SHA256, os.urandom(32), digits=8, period=60, issuer="Sha256"), False),
            (CD("carol", TOTP, H.SHA512, os.urandom(64), digits=8, period=60, issuer="Sha512"), False),
            (CD("dave", HOTP, H.SHA1, os.urandom(20), digits=6, counter=5, issuer="Hotp"), False),
            (CD("erin", TOTP, H.SHA256, os.urandom(32), digits=6, issuer="Touch"), True)]


def expected_code(data, counter=None):
    """The code of an account at T (TOTP) or at counter (HOTP), host side."""
    moving = counter if data.oath_type == yoath.OATH_TYPE.HOTP else T // data.period
    return hotp(data.secret, moving, data.digits, OATH_HASHES[data.hash_algorithm])


def oath_codes(s):
    """{credential ID: code} of every account of an OATH session (TOTP at
    T; HOTP at the next counter value, which the calculation uses up)."""
    return {c.id: s.calculate_code(c, T).value for c in s.list_credentials()}


def test_oath_accounts(pcscd, emulators, tmp_path, capsys):
    a, b, c = emulators("a"), emulators("b"), emulators("c")
    accounts = oath_accounts()
    power(emulators, a)
    with Session() as card:
        s = yoath.OathSession(YkConnection(card))
        creds = {}
        for data, touch in accounts:
            cred = s.put_credential(data, touch_required=touch)
            creds[cred.id] = (cred, data, touch)
        codes_a = {}
        for cid, (cred, data, _) in creds.items():
            if data.oath_type == yoath.OATH_TYPE.HOTP:
                assert s.calculate_code(cred).value == expected_code(data, 5)
                assert s.calculate_code(cred).value == expected_code(data, 6)
            else:
                codes_a[cid] = s.calculate_code(cred, T).value      # the touch account: the emulator presses
                assert codes_a[cid] == expected_code(data)
    assert b"60/Sha256:bob" in creds and b"Touch:erin" in creds

    with Mgmt() as m:
        entries, exportable = m.list_keys("oath")
        assert exportable
        listed = {e[1]: e for e in entries}
        assert set(listed) == set(creds)
        for cid, (cred, data, touch) in creds.items():
            kind = 0x10 if data.oath_type == yoath.OATH_TYPE.HOTP else 0x20
            assert listed[cid] == {1: cid, 2: kind | int(data.hash_algorithm), 3: data.digits, 4: touch}
        keys = {cid: through_file(tmp_path, keyio.export_single(m, "oath", cid), cid.hex()) for cid in creds}
    for cid, (cred, data, touch) in creds.items():
        r = keys[cid].record
        assert r[4] == data.secret and bool(r.get(6)) is touch
        assert r.get(5) == (7 if data.oath_type == yoath.OATH_TYPE.HOTP else None)
    # the otpauth:// form of each account, as the command line writes it
    links = {}
    for cid in creds:
        out = run_cli(capsys, "key", "export", "oath:hex:" + cid.hex(), "-o", "-", "--format", "otpauth",
                      "--plaintext", "--yes-plaintext").out.strip()
        [rec] = stdformats.parse_otpauth(out)
        assert {k: rec.get(k) for k in (1, 2, 3, 4, 5)} == {k: keys[cid].record.get(k) for k in (1, 2, 3, 4, 5)}
        links[cid] = out

    # B has an OATH password: the import needs it, the accounts keep their codes
    power(emulators, b)
    with Session() as card:
        s = yoath.OathSession(YkConnection(card))
        s.set_key(s.derive_key("oath pw"))
    with Mgmt() as m:
        first = keys[next(iter(keys))]
        with pytest.raises(KeyTransferError, match="protected by a password"):
            keyio.import_single(m, first)
        with pytest.raises(KeyTransferError, match="wrong OATH password"):
            keyio.import_single(m, first, oath_password="not it")
        for key in keys.values():
            assert keyio.import_single(m, key, oath_password="oath pw").endswith("added")
        with pytest.raises(KeyTransferError, match="already on the device"):
            keyio.import_single(m, first, oath_password="oath pw")
        touch_b = {e[1]: e[4] for e in m.list_keys("oath")[0]}
    assert touch_b == {cid: touch for cid, (_, _, touch) in creds.items()}
    b.restart()
    wait_card()
    with Session() as card:
        s = yoath.OathSession(YkConnection(card))
        assert s.locked
        s.validate(s.derive_key("oath pw"))
        codes_b = oath_codes(s)
    for cid, (cred, data, _) in creds.items():
        if data.oath_type == yoath.OATH_TYPE.HOTP:
            assert codes_b[cid] == expected_code(data, 7)       # the counter goes on
        else:
            assert codes_b[cid] == codes_a[cid]

    # C: the same accounts from their otpauth:// links, through the command line
    power(emulators, c)
    for cid, link in links.items():
        assert "added" in run_cli(capsys, "key", "import", link).out
    with Session() as card:
        codes_c = oath_codes(yoath.OathSession(YkConnection(card)))
    for cid, (cred, data, _) in creds.items():
        assert codes_c[cid] == (expected_code(data, 7) if data.oath_type == yoath.OATH_TYPE.HOTP else codes_a[cid])


# -- OTP ---------------------------------------------------------------------------

MODHEX = "cbdefghijklnrtuv"
# "Transfer2026" as keyboard scan codes (0x80: shift)
STATIC = bytes([0x97, 0x15, 0x04, 0x11, 0x16, 0x09, 0x08, 0x15, 0x1F, 0x27, 0x1F, 0x23])


def typed(e, presses=1, timeout=6.0):
    """What the device types after presses of its button while idle (1 press:
    slot 1, 2 presses: slot 2), from the emulator log."""
    off = os.path.getsize(e.log_path)
    button = Button()
    try:
        for _ in range(presses):
            button.press(0.1)
            time.sleep(0.2)
    finally:
        button.close()
    deadline = time.time() + timeout

    def lines():
        with open(e.log_path, errors="replace") as f:
            f.seek(off)
            return [ln.split("[otp] keyboard: ", 1)[1] for ln in f.read().splitlines() if "[otp] keyboard: " in ln]
    while not lines() and time.time() < deadline:
        time.sleep(0.1)
    time.sleep(0.3)
    return lines()


def crc16(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x8408 if crc & 1 else 0)
    return crc


def yubico_otp(text, aes_key):
    """Public ID, private ID and counters of a typed Yubico OTP, decrypted
    with the slot's AES key (its CRC checked)."""
    raw = bytes(MODHEX.index(text[i]) << 4 | MODHEX.index(text[i + 1]) for i in range(0, len(text), 2))
    d = Cipher(algorithms.AES(aes_key), modes.ECB()).decryptor()
    tok = d.update(raw[-16:]) + d.finalize()
    assert crc16(tok) == 0xF0B8, "the OTP does not decrypt with this AES key"
    return {"public": raw[:-16], "uid": tok[:6], "counter": int.from_bytes(tok[6:8], "little"), "session": tok[11]}


def test_otp_slots(pcscd, emulators, tmp_path):
    a, b = emulators("a"), emulators("b")
    public, private, aes = bytes.fromhex("ccbbddeeffcc"), os.urandom(6), os.urandom(16)
    key20, chal = os.urandom(20), os.urandom(32)
    SLOT = yotp.SLOT

    # A: HOTP in slot 1, Yubico OTP with an access code in slot 2, both used
    power(emulators, a, **KEYBOARD)
    with Session() as card:
        s = yotp.YubiOtpSession(YkConnection(card))
        s.put_configuration(SLOT.ONE, yotp.HotpSlotConfiguration(RFC4226_SECRET).append_cr(False))
        s.put_configuration(SLOT.TWO, yotp.YubiOtpSlotConfiguration(public, private, aes).append_cr(False),
                            acc_code=b"secret")
    time.sleep(1.2)
    assert typed(a) == [str(RFC4226_CODES[0])]
    assert typed(a) == [str(RFC4226_CODES[1])]
    tok_a = [yubico_otp(typed(a, presses=2)[0], aes) for _ in range(3)]
    assert tok_a[0]["public"] == public and tok_a[0]["uid"] == private
    power(emulators, a)
    with Mgmt() as m:
        assert m.list_keys("otp")[0] == [{1: b"\x01", 2: "hotp", 3: False}, {1: b"\x02", 2: "yubico-otp", 3: True}]
        k_hotp = through_file(tmp_path, keyio.export_single(m, "otp", b"\x01"), "hotp")
        k_yubico = through_file(tmp_path, keyio.export_single(m, "otp", b"\x02"), "yubico")
    assert k_yubico.record[4] == "yubico-otp" and len(k_yubico.record[2]) == 52

    # A again: a static password in slot 1, HMAC challenge-response in slot 2
    with Session() as card:
        s = yotp.YubiOtpSession(YkConnection(card))
        s.put_configuration(SLOT.ONE, yotp.StaticPasswordSlotConfiguration(STATIC).append_cr(False))
        s.put_configuration(SLOT.TWO, yotp.HmacSha1SlotConfiguration(key20), acc_code=b"hmac!!",
                            cur_acc_code=b"secret")
        resp_a = s.calculate_hmac_sha1(SLOT.TWO, chal)
    assert resp_a == hmac.new(key20, chal, "sha1").digest()
    with Mgmt() as m:
        assert m.list_keys("otp")[0] == [{1: b"\x01", 2: "static", 3: False}, {1: b"\x02", 2: "chal-hmac", 3: True}]
        k_static = through_file(tmp_path, keyio.export_single(m, "otp", b"\x01"), "static")
        k_hmac = through_file(tmp_path, keyio.export_single(m, "otp", b"\x02"), "hmac")
    power(emulators, a, **KEYBOARD)
    time.sleep(1.2)
    static_a = typed(a)
    # the whole 38-byte field is typed; scan code 0 is "no key" to the host
    assert static_a == ["".join("<%02x>" % c for c in STATIC.ljust(38, b"\0"))]

    # B: HOTP and Yubico OTP into empty slots; they go on where A stopped
    power(emulators, b)
    with Mgmt() as m:
        assert "slot 1 written" in keyio.import_single(m, k_hotp)
        assert "slot 2 written" in keyio.import_single(m, k_yubico)
    power(emulators, b, **KEYBOARD)
    time.sleep(1.2)
    assert typed(b) == [str(RFC4226_CODES[2])]
    tok_b = yubico_otp(typed(b, presses=2)[0], aes)
    assert tok_b["public"] == public and tok_b["uid"] == private
    assert tok_b["counter"] > tok_a[-1]["counter"]

    # B: the configured slots are replaced only on request, slot 2 only with
    # its access code (the one the Yubico OTP configuration brought)
    power(emulators, b)
    with Mgmt() as m:
        with pytest.raises(KeyTransferError, match="replace it explicitly"):
            keyio.import_single(m, k_static)
        assert "slot 1 written" in keyio.import_single(m, k_static, replace=True)
        with pytest.raises(KeyTransferError, match="replace it explicitly"):
            keyio.import_single(m, k_hmac, otp_access_code=b"secret".hex())
        with pytest.raises(KeyTransferError, match="access code"):
            keyio.import_single(m, k_hmac, replace=True)
        with pytest.raises(KeyTransferError) as err:
            keyio.import_single(m, k_hmac, replace=True, otp_access_code=b"wrong!".hex())
        assert err.value.sw == 0x6982
        assert m.list_keys("otp")[0][1] == {1: b"\x02", 2: "yubico-otp", 3: True}     # unchanged
        assert "slot 2 written" in keyio.import_single(m, k_hmac, replace=True, otp_access_code=b"secret".hex())
        assert m.list_keys("otp")[0] == [{1: b"\x01", 2: "static", 3: False}, {1: b"\x02", 2: "chal-hmac", 3: True}]
    with Session() as card:
        s = yotp.YubiOtpSession(YkConnection(card))
        assert s.calculate_hmac_sha1(SLOT.TWO, chal) == resp_a
    with Mgmt() as m:
        # slot 2 now has the imported configuration's access code
        with pytest.raises(KeyTransferError) as err:
            keyio.import_single(m, k_hotp, replace=True, target=2, otp_access_code=b"secret".hex())
        assert err.value.sw == 0x6982
    power(emulators, b, **KEYBOARD)
    time.sleep(1.2)
    assert typed(b) == static_a


# -- OpenPGP -----------------------------------------------------------------------

CRT = {1: b"\xB6\x00", 2: b"\xB8\x00", 3: b"\xA4\x00"}
P256_OID = bytes.fromhex("2A8648CE3D030107")
ATTR = {"rsa2048": bytes.fromhex("010800002000"), "p256-ecdsa": b"\x13" + P256_OID, "p256-ecdh": b"\x12" + P256_OID,
        "ed25519": bytes.fromhex("162B06010401DA470F01"), "cv25519": bytes.fromhex("122B060104019755010501")}
SHA256_DI = bytes.fromhex("3031300d060960864801650304020105000420")


def pgp(card, ins, p1, p2, data=b""):
    out, sw = card.transmit(0x00, ins, p1, p2, data, le=0, check=False)
    assert sw == 0x9000, "%02X %02X%02X: %04X" % (ins, p1, p2, sw)
    return out


def pgp_public(card, ref):
    """{tag: value} of the public key of a slot (7F49: 81 n, 82 e / 86 point)."""
    [(tag, body)] = keyio._tlvs(pgp(card, 0x47, 0x81, 0x00, CRT[ref]), "public key")
    assert tag == 0x7F49
    return dict(keyio._tlvs(body, "public key"))


def pw3_retries(card):
    return pgp(card, 0xCA, 0x00, 0xC4)[6]


def pgp_check_sign(card, kind, pub, ins):
    """Signature of the card (PSO:CDS or INTERNAL AUTHENTICATE) checked
    with the public key A gave out."""
    msg = os.urandom(40)
    pgp(card, 0x20, 0x00, 0x81 if ins == 0x2A else 0x82, PW1)
    p1p2 = (0x9E, 0x9A) if ins == 0x2A else (0x00, 0x00)
    if kind == "rsa2048":
        sig = pgp(card, ins, *p1p2, SHA256_DI + hashlib.sha256(msg).digest())
        rsa.RSAPublicNumbers(int.from_bytes(pub[0x82], "big"), int.from_bytes(pub[0x81], "big")).public_key() \
            .verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
    elif kind == "p256-ecdsa":
        digest = hashlib.sha256(msg).digest()
        sig = pgp(card, ins, *p1p2, digest)
        der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub[0x86]) \
            .verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    else:
        sig = pgp(card, ins, *p1p2, msg)
        ed25519.Ed25519PublicKey.from_public_bytes(pub[0x86]).verify(sig, msg)


def pgp_check_decipher(card, kind, pub):
    """ECDH of the card with an ephemeral key: the secret the host shares
    with the public key A gave out."""
    pgp(card, 0x20, 0x00, 0x82, PW1)
    if kind == "p256-ecdh":
        eph = ec.generate_private_key(ec.SECP256R1())
        point = eph.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        want = eph.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub[0x86]))
    else:
        eph = x25519.X25519PrivateKey.generate()
        point = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        want = eph.exchange(x25519.X25519PublicKey.from_public_bytes(pub[0x86]))
    shared = pgp(card, 0x2A, 0x80, 0x86, keyio._tlv(0xA6, keyio._tlv(0x7F49, keyio._tlv(0x86, point))))
    # the card answers the x coordinate, or the whole point (04 || x || y)
    assert shared == want or (len(shared) == 65 and shared[1:33] == want)


@pytest.mark.parametrize("layout", [("rsa2048", "p256-ecdh", "p256-ecdsa"), ("ed25519", "cv25519", "ed25519")],
                         ids=["rsa2048-p256", "25519"])
def test_openpgp_keys(pcscd, emulators, tmp_path, layout):
    a, b = emulators("a"), emulators("b")
    fps = {ref: os.urandom(20) for ref in (1, 2, 3)}
    times = {ref: 1_700_000_000 + 1000 * ref for ref in (1, 2, 3)}
    power(emulators, a)
    with Session() as card:
        card.select(OPENPGP_AID)
        pgp(card, 0x20, 0x00, 0x83, PW3)
        pubs = {}
        for ref, kind in zip((1, 2, 3), layout):
            pgp(card, 0xDA, 0x00, 0xC0 + ref, ATTR[kind])
            pgp(card, 0x47, 0x80, 0x00, CRT[ref])
            pgp(card, 0xDA, 0x00, 0xC6 + ref, fps[ref])
            pgp(card, 0xDA, 0x00, 0xCD + ref, times[ref].to_bytes(4, "big"))
        for ref in (1, 2, 3):
            pubs[ref] = pgp_public(card, ref)

    with Mgmt() as m:
        entries, exportable = m.list_keys("openpgp")
        assert exportable
        assert entries == [{1: bytes([ref]), 2: ATTR[kind], 3: fps[ref], 4: times[ref]}
                           for ref, kind in zip((1, 2, 3), layout)]
        # the Admin PIN: missing (6982, nothing counted), wrong (a retry used)
        with pytest.raises(KeyTransferError, match="Admin PIN"):
            keyio.export_single(m, "openpgp", b"\x01")
        assert sw_of(lambda: m._cmd(INS_KEY_EXPORT, data=cbor.encode({1: 3, 2: b"\x01"}))) == 0x6982
        with keyio._applet(m, OPENPGP_AID, "OpenPGP"):
            assert pw3_retries(m.card) == 3
        with pytest.raises(KeyTransferError) as err:
            keyio.export_single(m, "openpgp", b"\x01", secret="87654321")
        assert err.value.sw == 0x63C2
        with keyio._applet(m, OPENPGP_AID, "OpenPGP"):
            assert pw3_retries(m.card) == 2
        keys = {ref: through_file(tmp_path, keyio.export_single(m, "openpgp", bytes([ref]), secret=PW3.decode()),
                                  str(ref)) for ref in (1, 2, 3)}
        with keyio._applet(m, OPENPGP_AID, "OpenPGP"):
            assert pw3_retries(m.card) == 3
    for ref, key in keys.items():
        assert (key.record[1], key.record[2], key.record[4], key.record[5]) == (ref, ATTR[layout[ref - 1]], fps[ref],
                                                                                times[ref])

    power(emulators, b)
    with Mgmt() as m:
        with pytest.raises(KeyTransferError, match="Admin PIN"):
            keyio.import_single(m, keys[1])
        for key in keys.values():
            assert "added in the" in keyio.import_single(m, key, pgp_admin_pin=PW3.decode())
        with pytest.raises(KeyTransferError, match="replace it explicitly"):
            keyio.import_single(m, keys[1], pgp_admin_pin=PW3.decode())
    b.restart()
    wait_card()
    with Session() as card:
        card.select(OPENPGP_AID)
        assert pgp(card, 0xCA, 0x00, 0xC5) == fps[1] + fps[2] + fps[3]
        assert pgp(card, 0xCA, 0x00, 0xCD) == b"".join(times[ref].to_bytes(4, "big") for ref in (1, 2, 3))
        for ref, kind in zip((1, 2, 3), layout):
            assert pgp(card, 0xCA, 0x00, 0xC0 + ref) == ATTR[kind]
            assert pgp_public(card, ref) == pubs[ref]
        pgp_check_sign(card, layout[0], pubs[1], 0x2A)
        pgp_check_decipher(card, layout[1], pubs[2])
        pgp_check_sign(card, layout[2], pubs[3], 0x88)


def gpg_run(argv, env=None, stdin=None):
    r = subprocess.run(["gpg", "--batch", "--no-tty", "--pinentry-mode", "loopback", *argv], input=stdin, env=env,
                       capture_output=True, timeout=300)
    assert r.returncode == 0, "gpg %s failed:\n%s" % (" ".join(argv), r.stderr.decode(errors="replace"))
    return r


@pytest.mark.skipif(not shutil.which("gpg") or not os.environ.get("SCDAEMON_PROGRAM"),
                    reason="GnuPG test home not configured (source testenv.sh)")
def test_openpgp_key_file_from_gnupg(pcscd, emulators, tmp_path, capsys):
    """A secret key exported by GnuPG (protected by its passphrase) added to
    the card with the command line: GnuPG then finds it on the card and signs
    with it."""
    home = tempfile.mkdtemp(prefix="lfgpg", dir="/tmp")
    env = dict(os.environ, GNUPGHOME=home)
    try:
        uid = "Transfer Test <transfer@librefido.example>"
        gpg_run(["--passphrase", FILE_PW, "--quick-gen-key", uid, "ed25519", "sign,cert", "0"], env)
        fpr = [f.split(":")[9] for f in gpg_run(["--with-colons", "--list-keys", uid], env).stdout.decode()
               .splitlines() if f.startswith("fpr:")][0]
        gpg_run(["--passphrase", FILE_PW, "--quick-add-key", fpr, "cv25519", "encr", "0"], env)
        secret = gpg_run(["--passphrase", FILE_PW, "--armor", "--export-secret-keys", fpr], env).stdout
        public = gpg_run(["--armor", "--export", fpr], env).stdout
    finally:
        subprocess.run(["gpgconf", "--kill", "all"], env=env, check=False)
        shutil.rmtree(home, ignore_errors=True)
    asc, pw, admin = tmp_path / "key.asc", tmp_path / "pw", tmp_path / "admin"
    asc.write_bytes(secret)
    pw.write_text(FILE_PW + "\n", encoding="utf-8")
    admin.write_text(PW3.decode() + "\n", encoding="utf-8")
    with pytest.raises(stdformats.FormatError):
        stdformats.parse_openpgp_secret(secret, "not the passphrase")

    b = emulators("b")
    power(emulators, b)
    out = run_cli(capsys, "key", "import", str(asc), "--passphrase-file", str(pw), "--slot", "sig",
                  "--admin-pin-file", str(admin)).out
    assert "added in the signature slot" in out
    try:
        subprocess.run(["bash", "-c", "source ~/work/testenv.sh >/dev/null && GPG_TEST_PCSC_SHARED=1 gpg_test_reset"],
                       check=True, capture_output=True)
        gpg_run(["--import"], stdin=public)
        status = gpg_run(["--with-colons", "--card-status"]).stdout.decode()
        card_fprs = next(line for line in status.splitlines() if line.startswith("fpr:")).split(":")
        assert card_fprs[1].upper() == fpr.upper(), status
        human = gpg_run(["--card-status"]).stdout.decode()
        spaced = " ".join(fpr[i:i + 4] for i in range(0, 40, 4))
        assert spaced[:24] in human.replace("  ", " "), human
        msg = tmp_path / "msg.txt"
        msg.write_text("signed with a key GnuPG exported, on the card\n")
        gpg_run(["--passphrase", PW1.decode(), "--local-user", fpr + "!", "--output", str(tmp_path / "msg.sig"),
                 "--detach-sign", str(msg)])
        assert b"Good signature" in gpg_run(["--verify", str(tmp_path / "msg.sig"), str(msg)]).stderr
        stubs = gpg_run(["--with-colons", "--list-secret-keys", fpr]).stdout.decode()
        assert any(line.split(":")[14].startswith("D2760001240") for line in stubs.splitlines()
                   if line.startswith("sec:")), stubs
    finally:
        subprocess.run(["gpgconf", "--kill", "all"], check=False)


# -- PIV ---------------------------------------------------------------------------

SLOT, KT, PIN, TOUCH = ypiv.SLOT, ypiv.KEY_TYPE, ypiv.PIN_POLICY, ypiv.TOUCH_POLICY
# (slot, key type, PIN policy, touch policy) of the keys made on A
PIV_KEYS = [(SLOT.AUTHENTICATION, KT.RSA2048, PIN.ONCE, TOUCH.NEVER),
            (SLOT.SIGNATURE, KT.ECCP256, PIN.ALWAYS, TOUCH.ALWAYS),
            (SLOT.KEY_MANAGEMENT, KT.X25519, PIN.ONCE, TOUCH.CACHED),
            (SLOT.CARD_AUTH, KT.ECCP384, PIN.NEVER, TOUCH.NEVER),
            (SLOT.RETIRED1, KT.ED25519, PIN.NEVER, TOUCH.ALWAYS)]
SPKI = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
NOW = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)


def certificate(public_key, cn):
    """A certificate for public_key, signed by a host CA (X25519 cannot sign
    its own)."""
    ca = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(public_key)
            .serial_number(x509.random_serial_number()).not_valid_before(NOW)
            .not_valid_after(NOW + datetime.timedelta(days=30)).sign(ca, hashes.SHA256()))


def piv_check(s, slot, kt, pub):
    """A private key operation of slot checked with pub (the public key of
    the key A made or the host imported)."""
    msg = os.urandom(64)
    s.verify_pin(PIV_PIN)
    if kt in (KT.RSA2048, KT.RSA1024):
        pub.verify(s.sign(slot, kt, msg, hashes.SHA256(), padding.PKCS1v15()), msg, padding.PKCS1v15(),
                   hashes.SHA256())
    elif kt in (KT.ECCP256, KT.ECCP384):
        h = hashes.SHA256() if kt == KT.ECCP256 else hashes.SHA384()
        pub.verify(s.sign(slot, kt, msg, h), msg, ec.ECDSA(h))
    elif kt == KT.ED25519:
        pub.verify(s.sign(slot, kt, msg, None), msg)
    else:
        eph = x25519.X25519PrivateKey.generate()
        assert s.calculate_secret(slot, eph.public_key()) == eph.exchange(pub)


def test_piv_keys(pcscd, emulators, tmp_path, capsys):
    a, b = emulators("a"), emulators("b")
    power(emulators, a)
    with Session() as card:
        s = ypiv.PivSession(YkConnection(card))
        s.authenticate(ypiv.DEFAULT_MANAGEMENT_KEY)
        made = {}
        for slot, kt, pin, touch in PIV_KEYS:
            pub = s.generate_key(slot, kt, pin, touch)
            cert = certificate(pub, "piv-%02x" % slot)
            s.put_certificate(slot, cert)
            made[slot] = (kt, pub, cert, s.get_slot_metadata(slot))
    with Mgmt() as m:
        entries, exportable = m.list_keys("piv")
        assert exportable
        assert {e[1][0]: (e[3], e[4]) for e in entries} == {slot: (int(pin), int(touch))
                                                           for slot, kt, pin, touch in PIV_KEYS}
        keys = {slot: through_file(tmp_path, keyio.export_single(m, "piv", bytes([slot])), "%02x" % slot)
                for slot in made}
    for slot, (kt, pub, cert, md) in made.items():
        r = keys[slot].record
        assert r[8] == cert.public_bytes(serialization.Encoding.DER)
        assert (r[4], r[5]) == (int(md.pin_policy), int(md.touch_policy))
        assert stdformats.piv_private_key(r).public_key().public_bytes(*SPKI) == pub.public_bytes(*SPKI)

    # B: 9A, 9C, 9D with the default management key, the rest with an AES one
    aes = os.urandom(32)
    firsts = [SLOT.AUTHENTICATION, SLOT.SIGNATURE, SLOT.KEY_MANAGEMENT]
    power(emulators, b)
    with Mgmt() as m:
        for slot in firsts:
            assert "added in slot %02X" % slot in keyio.import_single(m, keys[slot])
        with pytest.raises(KeyTransferError, match="replace it explicitly"):
            keyio.import_single(m, keys[SLOT.SIGNATURE])
    with Session() as card:
        s = ypiv.PivSession(YkConnection(card))
        s.authenticate(ypiv.DEFAULT_MANAGEMENT_KEY)
        s.set_management_key(ypiv.MANAGEMENT_KEY_TYPE.AES256, aes)
    # the P-384 key once more, from the PEM file written of its record
    pem = stdformats.piv_record_to_pem(keys[SLOT.CARD_AUTH].record, FILE_PW)
    assert b"ENCRYPTED PRIVATE KEY" in pem
    [(pem_record, pem_cert)] = stdformats.load_piv_key(pem, FILE_PW)
    assert pem_cert == keys[SLOT.CARD_AUTH].record[8]
    pem_key = SingleKey("piv", pem_record)
    with Mgmt() as m:
        with pytest.raises(KeyTransferError, match="not the default one"):
            keyio.import_single(m, keys[SLOT.CARD_AUTH])
        with pytest.raises(KeyTransferError, match="wrong PIV management key"):
            keyio.import_single(m, keys[SLOT.CARD_AUTH], piv_mgmt_key=os.urandom(32))
        for slot in made:
            if slot not in firsts:
                assert "added in slot %02X" % slot in keyio.import_single(m, keys[slot], piv_mgmt_key=aes.hex())
        assert "added in slot 83" in keyio.import_single(m, pem_key, piv_mgmt_key=aes, piv_slot=0x83)
    # a PKCS#12 file of the host, through the command line
    host_key = rsa.generate_private_key(65537, 2048)
    host_cert = certificate(host_key.public_key(), "p12")
    p12, pw = tmp_path / "key.p12", tmp_path / "pw"
    p12.write_bytes(pkcs12.serialize_key_and_certificates(b"p12", host_key, host_cert, None,
                                                          serialization.BestAvailableEncryption(b"p12 pw")))
    pw.write_text("p12 pw\n", encoding="utf-8")
    out = run_cli(capsys, "key", "import", str(p12), "--passphrase-file", str(pw), "--slot", "84",
                  "--mgmt-key", aes.hex()).out
    assert "added in slot 84" in out and "with certificate" in out

    b.restart()
    wait_card()
    with Session() as card:
        s = ypiv.PivSession(YkConnection(card))
        for slot, (kt, pub, cert, md) in made.items():
            got = s.get_slot_metadata(slot)
            assert (got.pin_policy, got.touch_policy) == (md.pin_policy, md.touch_policy)
            assert got.public_key.public_bytes(*SPKI) == pub.public_bytes(*SPKI)
            assert s.get_certificate(slot) == cert
            piv_check(s, slot, kt, pub)
        kt, pub = made[SLOT.CARD_AUTH][:2]
        assert s.get_slot_metadata(SLOT.RETIRED2).public_key.public_bytes(*SPKI) == pub.public_bytes(*SPKI)
        piv_check(s, SLOT.RETIRED2, kt, pub)
        assert s.get_certificate(SLOT.RETIRED3) == host_cert
        piv_check(s, SLOT.RETIRED3, KT.RSA2048, host_key.public_key())
        s.authenticate(aes)                             # B keeps its own management key


# -- .lfkey files through the command line -------------------------------------------

def test_key_files_cli(pcscd, emulators, tmp_path, capsys):
    a, b = emulators("a"), emulators("b")
    secret = os.urandom(20)
    pw, wrong = tmp_path / "pw", tmp_path / "wrong"
    pw.write_text(FILE_PW + "\n", encoding="utf-8")
    wrong.write_text("not the passphrase\n", encoding="utf-8")
    enc, plain = str(tmp_path / "oath.lfkey"), str(tmp_path / "piv.lfkey")
    power(emulators, a)
    with Session() as card:
        s = yoath.OathSession(YkConnection(card))
        cred = s.put_credential(yoath.CredentialData("cli", yoath.OATH_TYPE.TOTP, yoath.HASH_ALGORITHM.SHA1, secret,
                                                     issuer="Files"))
        s = ypiv.PivSession(YkConnection(card))
        s.authenticate(ypiv.DEFAULT_MANAGEMENT_KEY)
        pub = s.generate_key(SLOT.SIGNATURE, KT.ECCP256, PIN.ONCE, TOUCH.NEVER)
    out = run_cli(capsys, "key", "export", "oath:hex:" + cred.id.hex(), "-o", enc, "--passphrase-file", str(pw)).out
    assert "encrypted" in out
    out = run_cli(capsys, "key", "export", "piv:hex:9c", "-o", plain, "--plaintext", "--yes-plaintext").out
    assert "NOT encrypted" in out
    info, key = read_key_file(enc, FILE_PW, require_encryption=True)
    assert info["encrypted"] and key.record[4] == secret
    info, key = read_key_file(plain)
    assert not info["encrypted"] and key.app == "piv" and key.record[1] == 0x9C

    power(emulators, b)
    with pytest.raises(SystemExit):
        run_cli(capsys, "key", "import", enc, "--passphrase-file", str(wrong))
    assert "added" in run_cli(capsys, "key", "import", enc, "--passphrase-file", str(pw)).out
    with pytest.raises(SystemExit, match="NOT encrypted"):
        run_cli(capsys, "key", "import", plain)
    assert "added in slot 9C" in run_cli(capsys, "key", "import", plain, "--allow-unencrypted").out
    with Session() as card:
        s = yoath.OathSession(YkConnection(card))
        [c] = s.list_credentials()
        assert c.id == cred.id and s.calculate_code(c, T).value == hotp(secret, T // 30, 6)
        s = ypiv.PivSession(YkConnection(card))
        piv_check(s, SLOT.SIGNATURE, KT.ECCP256, pub)
