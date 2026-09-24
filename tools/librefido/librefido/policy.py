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
