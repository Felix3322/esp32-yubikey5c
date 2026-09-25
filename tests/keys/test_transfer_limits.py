"""Single-key transfer at its limits (docs/KEY_TRANSFER.md), on emulated
devices: the sign counter a FIDO record may bring, and the OpenPGP Admin PIN
of a card whose KDF-DO asks for a PIN KDF (`gpg --card-edit` kdf-setup).

    bash ~/work/scripts/locked_tests.sh <build> -q -rfEs -p no:randomly tests/keys
"""

import os

from cryptography.hazmat.primitives.asymmetric import ed25519

from librefido import keyio, mgr_pgp

from test_app_transfer import ATTR, CRT, OPENPGP_AID, PW1, PW3, Mgmt, Session, pgp, pgp_public, power, pw3_retries
from test_mgmt_security import sw_of
from test_profiles_backup import ctap2, device, emulators, make_rk, pcscd  # noqa: F401  (fixtures)

COUNTER_MAX = 0x7FFFFFFF        # lf_keyio_fido.c FIDO_IMPORT_COUNTER_MAX


def test_fido_import_sign_counter_limit(pcscd, emulators):
    """The device counter is raised to the record's and never lowered, not
    even by authenticatorReset: a record near 2^32 is refused (nothing
    stored, the counter untouched), the highest accepted one leaves the
    device signing on."""
    a, b = emulators("a"), emulators("b")
    m = device(a)
    try:
        make_rk(b"user-1")
        [entry], _ = m.list_keys("fido", no_pin=True)
        rec = m.export_key("fido", entry[1], no_pin=True)
    finally:
        m.close()
    a.stop()

    m = device(b)
    try:
        for counter in (0xFFFFFFFE, COUNTER_MAX + 1):
            assert sw_of(lambda: m.import_key("fido", {**rec, 14: counter}, no_pin=True)) == 0x6A80
        assert m.list_keys("fido", no_pin=True)[0] == []
        first = make_rk(b"user-0", rp="other.example").auth_data.counter
        assert first < 16
        assert m.import_key("fido", {**rec, 14: COUNTER_MAX}, no_pin=True) == rec[2]
    finally:
        m.close()
    dev, c = ctap2()
    try:
        got = c.get_assertion("example.com", os.urandom(32))
        assert got.credential["id"] == rec[2] and got.auth_data.counter == COUNTER_MAX + 1
    finally:
        dev.close()
    assert make_rk(b"user-2", rp="third.example").auth_data.counter == COUNTER_MAX + 2


def kdf_setup(card):
    """A KDF-DO asking for KDF_ITERSALTED_S2K (SHA-256, 65536 bytes), as
    kdf-setup writes it, and PW1 / PW3 changed to their S2K hashes (the card
    only stores the DO; GnuPG sends the hashes). Returns the hashed PW1."""
    salts = {0x84: os.urandom(8), 0x85: os.urandom(8), 0x86: os.urandom(8)}
    do = bytes.fromhex("810103820108830400010000") + b"".join(bytes([t, 8]) + s for t, s in salts.items())
    pw1 = mgr_pgp.s2k_iterated("sha256", salts[0x84], PW1, 0x10000)
    pw3 = mgr_pgp.s2k_iterated("sha256", salts[0x86], PW3, 0x10000)
    pgp(card, 0x20, 0x00, 0x83, PW3)
    pgp(card, 0xDA, 0x00, 0xF9, do)
    pgp(card, 0x24, 0x00, 0x81, PW1 + pw1)
    pgp(card, 0x24, 0x00, 0x83, PW3 + pw3)
    return pw1


def test_openpgp_admin_pin_through_the_card_kdf(pcscd, emulators):
    """With a PIN KDF on the card the Admin PIN typed by the user goes to
    KEY_EXPORT and VERIFY as its S2K hash: the export and the import work,
    and no PW3 retry is used up."""
    a, b = emulators("a"), emulators("b")
    fp, created = os.urandom(20), 1_700_000_000
    power(emulators, a)
    with Session() as card:
        card.select(OPENPGP_AID)
        pgp(card, 0x20, 0x00, 0x83, PW3)
        pgp(card, 0xDA, 0x00, 0xC1, ATTR["ed25519"])
        pgp(card, 0x47, 0x80, 0x00, CRT[1])
        pgp(card, 0xDA, 0x00, 0xC7, fp)
        pgp(card, 0xDA, 0x00, 0xCE, created.to_bytes(4, "big"))
        pub = pgp_public(card, 1)
        kdf_setup(card)
    with Mgmt() as m:
        key = keyio.export_single(m, "openpgp", b"\x01", secret=PW3.decode())
        with keyio._applet(m, OPENPGP_AID, "OpenPGP"):
            assert pw3_retries(m.card) == 3
    assert (key.record[1], key.record[2], key.record[4], key.record[5]) == (1, ATTR["ed25519"], fp, created)

    power(emulators, b)
    with Session() as card:
        card.select(OPENPGP_AID)
        pw1 = kdf_setup(card)
    with Mgmt() as m:
        assert "added in the signature slot" in keyio.import_single(m, key, pgp_admin_pin=PW3.decode())
        with keyio._applet(m, OPENPGP_AID, "OpenPGP"):
            assert pw3_retries(m.card) == 3
    with Session() as card:
        card.select(OPENPGP_AID)
        assert pgp_public(card, 1) == pub
        msg = os.urandom(40)
        pgp(card, 0x20, 0x00, 0x81, pw1)
        ed25519.Ed25519PublicKey.from_public_bytes(pub[0x86]).verify(pgp(card, 0x2A, 0x9E, 0x9A, msg), msg)
