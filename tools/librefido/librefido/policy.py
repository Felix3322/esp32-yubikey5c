"""Per-profile policies: secure profiles, automatic presence per application
("my device is safe"), and the chip protection level (docs/SECURITY_MODES.md).
"""

# Applications with their own presence policy, in the order of the mask bits
# of PROFILE_SET key 4 and INFO profile key 7 (lf_app_t).
APPS = ("fido", "oath", "otp", "openpgp", "piv")
APP_LABELS = {
    "fido": "FIDO2 / U2F",
    "oath": "OATH (TOTP/HOTP)",
    "otp": "OTP challenge-response",
    "openpgp": "OpenPGP",
    "piv": "PIV",
}

# Profile flags (lf_sys.h)
F_NO_EXPORT = 0x01
F_SECURE = 0x02

LEVELS = {
    0: "keys readable from a flash dump (root key not bound to the chip)",
    1: "root key bound to the chip; readable by firmware of your own (no Secure Boot, JTAG or download mode locked)",
    2: "chip bound, JTAG and download mode locked; readable by unsigned firmware (no Secure Boot)",
    3: "Secure Boot, flash encryption, anti-rollback, JTAG and download mode locked: only physical attacks remain",
}


# AAGUID presets for the profile editor (Management.set_aaguid()). The first
# two are the firmware's own compiled-in defaults (pico-fido/src/fido/cbor.c);
# selecting one of them is the same as clearing the override. The rest are
# convenience identifiers: LibreFido's own team/enterprise AAGUIDs, plus
# well-known vendor AAGUIDs from the FIDO Alliance MDS (via Microsoft Entra,
# 2026-10). "custom" is not a preset: it means "the AAGUID entered by hand".
AAGUID_PRESETS = [
    # -- LibreFido's own --
    ("standard", "LibreFido 2 (standard build default)", "08c228d97ea02bc8d08e0d22a6d13f7d"),
    ("hardened", "LibreFido 2 (HARDENED build default)", "6c86ea00e57627564e8a6234f544e3fd"),
    ("enterprise", "LibreFido 2 enterprise (example)", "474c666c4b91b6a6aebf71ece93603e8"),
    ("team", "LibreFido 2 team (example)", "98eb403921c3cf5564cd70bc9ca3340b"),
    # -- YubiKey 5 Series --
    ("yk5", "YubiKey 5 Series (5.2/5.4)", "ee882879721c49139775 3dfcce97072a".replace(" ", "")),
    ("yk5-new", "YubiKey 5 Series (5.7+)", "19083c3d8383 4b18bc038f1c9ab2fd1b".replace(" ", "")),
    ("yk5-nfc", "YubiKey 5 NFC (5.2/5.4)", "2fc0579f811347eab116bb5a8db9202a"),
    ("yk5-nfc-new", "YubiKey 5 NFC (5.7+)", "a25342c03cdc44148e46f4807fca511c"),
    ("yk5ci", "YubiKey 5Ci (Lightning, 5.2/5.4)", "c5ef55ffad9a4b9fb580adebafe026d0"),
    ("yk5-fips", "YubiKey 5 FIPS Series", "73bb0cd4e50249b89c6fb59445bf720b"),
    ("yk5-nfc-fips", "YubiKey 5 NFC FIPS", "c1f9a0bc1dd2404ab27f8e29047a43fd"),
    # -- Security Key by Yubico --
    ("sk-nfc", "Security Key NFC by Yubico", "a4e9fc6d4cbe47588bba37598bb5bbaa"),
    ("sk-nfc-ee", "Security Key NFC by Yubico - Enterprise", "0bb43545fd2c418587ddfeb0b2916ace"),
    # -- YubiKey Bio --
    ("yk-bio-fido", "YubiKey Bio FIDO Edition", "d8522d9f575b486688a9ba99fa02f35b"),
    ("yk-bio-mp", "YubiKey Bio Multi-protocol Edition", "34744913 4f574e6ea527e9ec3c4b94e6".replace(" ", "")),
]


def parse_aaguid(text):
    """16 bytes from an AAGUID as people write it: the UUID form
    (524de2de-982f-49b4-a769-2b5e3b73ad79), with or without braces, or 32
    plain hex digits; spaces are ignored. Raises ValueError otherwise."""
    s = "".join(text.split()).strip("{}").replace("-", "")
    if len(s) != 32:
        raise ValueError("an AAGUID is 16 bytes: 32 hex digits, e.g. 524de2de-982f-49b4-a769-2b5e3b73ad79")
    return bytes.fromhex(s)             # ValueError for a non-hex digit


def format_aaguid(value):
    """UUID form (8-4-4-4-12, lower case) of 16 bytes or 32 hex digits."""
    h = value.hex() if isinstance(value, (bytes, bytearray)) else value.replace("-", "").lower()
    return "%s-%s-%s-%s-%s" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:32])


def auto_mask(**apps):
    """Presence mask from keyword flags, e.g. fido=True (the others off)."""
    unknown = set(apps) - set(APPS)
    if unknown:
        raise ValueError("unknown applications: %s" % ", ".join(sorted(unknown)))
    return sum(1 << i for i, a in enumerate(APPS) if apps.get(a))


def apps_of(mask):
    """Applications with automatic presence in a presence mask."""
    return [a for i, a in enumerate(APPS) if mask & (1 << i)]


def protection_level(security):
    """Chip protection level 0..3 from Management.info()['security']."""
    s = security
    if not s.get("root_key", "").endswith("bound to HMAC eFuse key"):
        return 0
    if not (s.get("jtag_disabled") and s.get("download_restricted")):
        return 1
    if not (s.get("secure_boot") and s.get("flash_encryption_release") and s.get("anti_rollback")):
        return 2
    return 3
