"""ESP32-S3 security provisioning: what is set, what a target profile needs,
and the two irreversible steps this tool performs itself, which lead to
protection level 2 (policy.LEVELS): binding the root key to the chip with an
HMAC eFuse key generated on the device, and locking debugging (JTAG disabled,
secure download mode).

Rules (docs/PROVISIONING.md), the same for both steps:
- nothing is written unless --apply is given; the default prints the plan;
- --apply asks for a typed confirmation naming the device (BURN <chip serial>);
- non-secret metadata is saved before anything is changed;
- the device asks for a touch;
- the state is checked before (inconsistent state: refuse) and after.
Secure Boot, flash encryption and anti-rollback are not burned by this
tool: they belong to the bootloader configuration and have brick-risk
boundaries that need a human in the loop. The plan lists them in a safe
order with the exact consequences.
"""

import datetime
import json
import os

from .pcsc import ApduError

# Ordered steps towards a HARDENED device. "hmac" and "lock_debug" are
# automated (level 2); the rest are guided manual steps (level 3).
STEPS = [
    {
        "id": "hmac",
        "title": "Bind the root key to this chip (HMAC eFuse key)",
        "done": lambda s: s["hmac_key"] and s["root_key"].endswith("bound to HMAC eFuse key"),
        "automated": True,
        "command": "librefido provision bind-root-key",
        "irreversible": "uses eFuse BLOCK_KEY5 for good (purpose HMAC_UP, read and write protected)",
        "effect": "a copy of the flash no longer reveals the keys on another chip; backups still work "
                  "(the backup carries the root key, re-wrapped by the target chip)",
        "brick_risk": "none: the firmware keeps booting; only the key block is consumed",
    },
    {
        "id": "lock_debug",
        "title": "Lock debugging: disable JTAG (pad and USB) and enable secure download mode",
        "done": lambda s: s["jtag_disabled"] and s["download_restricted"],
        "automated": True,
        "command": "librefido provision lock-debug",
        "irreversible": "burns DIS_PAD_JTAG, DIS_USB_JTAG and ENABLE_SECURITY_DOWNLOAD",
        "effect": "no hardware debugging; the ROM loader keeps flashing firmware (esptool write_flash, "
                  "with --no-stub), so recovery flashing still works, but it can no longer read the flash "
                  "or run code in RAM: a flash dump over USB is no longer possible",
        "brick_risk": "none: the firmware keeps booting and esptool can still write it",
    },
    {
        "id": "secure_boot",
        "title": "Secure Boot V2 (signed bootloader and application)",
        "done": lambda s: s["secure_boot"],
        "automated": False,
        "irreversible": "burns the signing key digest and SECURE_BOOT_EN; only images signed with that "
                        "key boot afterwards",
        "effect": "firmware updates and recovery flashing need images signed with your key",
        "brick_risk": "HIGH: losing the signing key means no firmware can ever be installed again; a "
                      "bootloader signed with the wrong key does not boot",
    },
    {
        "id": "flash_encryption",
        "title": "Flash encryption (release mode)",
        "done": lambda s: s["flash_encryption"] and s["flash_encryption_release"],
        "automated": False,
        "irreversible": "burns the XTS-AES key and SPI_BOOT_CRYPT_CNT; release mode also disables "
                        "plaintext flashing in download mode",
        "effect": "the flash content is encrypted with a key that never leaves the chip",
        "brick_risk": "HIGH: after release mode only OTA updates (or encrypted flashing with the key, "
                      "which release mode forbids) can change the firmware; a failed OTA with no "
                      "working slot cannot be recovered over USB",
    },
    {
        "id": "anti_rollback",
        "title": "Anti-rollback (secure version eFuse)",
        "done": lambda s: s["anti_rollback"],
        "automated": False,
        "irreversible": "SECURE_VERSION bits are burned as versions are confirmed",
        "effect": "older firmware with known issues can no longer be installed",
        "brick_risk": "medium: an image with a lower secure version never boots again",
    },
]


class ProvisionError(Exception):
    pass


ROOT_PLAIN = "flash (not bound to the chip)"
ROOT_BOUND = "flash, bound to HMAC eFuse key"


def state(info, keystore=None):
    """Security state from Management.info(), and keystore (whether the
    active profile's key store is unlocked, Management.keystore_unlocked();
    None: unknown). held: the chip has its HMAC key and Secure Boot, and the
    firmware keeps the active profile's key store locked until the binding
    is confirmed with that profile active, because its root key is
    - stored in plain (a profile created before the binding, or one written
      by someone who could write the flash): "held_plain", or
    - missing (a profile without root key: legacy derivations from the
      serial, migrated from a store without eFuse key or restored from a
      backup without its root key): "held_none". INFO reports such a profile
      as "none" whether it is held or already recorded, hence the key store
      probe.
    none_recorded: a profile without root key that runs on a chip with the
    HMAC key (recorded by the binding, or a chip without Secure Boot)."""
    s = dict(info["security"])
    s["boot_status"] = info["boot_status"]
    s["build_profile"] = info["build_profile"]
    s["platform"] = info.get("firmware_slot", {}).get("platform", "unknown")
    profiles = info.get("profiles") or []
    active = info.get("active")
    s["secure_profile"] = bool(active is not None and active < len(profiles) and profiles[active].get("secure"))
    s["keystore"] = keystore
    s["root_none"] = s["root_key"].startswith("none")
    s["held_plain"] = bool(s["hmac_key"] and s["secure_boot"] and s["root_key"] == ROOT_PLAIN)
    s["held_none"] = bool(s["hmac_key"] and s["secure_boot"] and s["root_none"] and keystore is False)
    s["held"] = s["held_plain"] or s["held_none"]
    s["none_recorded"] = bool(s["hmac_key"] and s["root_none"] and keystore is True)
    return s


HELD_TEXT = ("The chip already has its HMAC key, but the root key of the active profile is stored in plain: "
             "the profile was created before the binding, or someone who could write the flash put it there. "
             "The device keeps its key store locked until you bind this root key too. Bind it only if you "
             "created this profile yourself; the eFuse is not burned again.")

HELD_NONE_TEXT = ("The active profile has no root key: its keys are derived from the device serial (a profile "
                  "migrated from a store without eFuse key, or restored from a backup without its root key). On "
                  "this chip (HMAC key and Secure Boot) such a profile stays locked until you confirm it: the "
                  "binding records on the chip that this profile has no root key, and it unlocks at the next "
                  "start. Its keys stay what they are (derived from the serial: a flash dump reveals them, "
                  "protection level 0 for this profile; to change that, back it up, wipe it and set it up "
                  "again). Confirm only if you created this profile yourself; the eFuse is not burned again.")


def held_text(s):
    return HELD_NONE_TEXT if s["held_none"] else HELD_TEXT


def plan(info, keystore=None):
    """Steps with their state for this device (in order: the automated ones
    lead to protection level 2, the manual ones to level 3). A profile
    without root key recorded on the chip counts as bound: the binding can
    do no more for it."""
    s = state(info, keystore)
    steps = [dict(step, is_done=bool(step["done"](s))) for step in STEPS]
    if s["none_recorded"]:
        steps[0]["is_done"] = True
    return steps


def check_consistent(info, keystore=None, binding=True):
    """Refuses a device whose state does not allow a safe provisioning step
    (binding: the root key binding, which also needs a root key or a
    profile without one to record; otherwise locking debugging)."""
    s = state(info, keystore)
    if s["platform"] != "esp32s3" and s["platform"] != "emulation":
        raise ProvisionError("provisioning is for ESP32-S3 devices (this is %s)" % s["platform"])
    if s["boot_status"] != "ok":
        raise ProvisionError("the device booted in safe mode (%s): fix the storage first" % s["boot_status"])
    bound = s["root_key"].endswith("bound to HMAC eFuse key")
    if s["hmac_key"] and s["root_none"] and keystore is False and not s["held_none"]:
        raise ProvisionError("the active profile has no root key and its key store is locked on this chip; "
                             "wipe the profile or restore a backup that has its root key")
    if s["held"] and s["secure_profile"]:
        raise ProvisionError("the root key of this secure profile is %s: a secure profile's root is bound from the "
                             "start, so it was removed or replaced; wipe the profile"
                             % ("missing" if s["held_none"] else "in plain"))
    if s["held_none"] and s["build_profile"] == "hardened":
        raise ProvisionError("the active profile has no root key and is locked: a HARDENED build never uses a "
                             "profile without root key; wipe it or restore a backup that has its root key")
    if s["hmac_key"] and not bound and not s["held"] and not (s["root_none"] and keystore is not False):
        raise ProvisionError("an HMAC eFuse key exists but the root key is not bound to it (%s); "
                             "restart the device and check again before anything else" % s["root_key"])
    if binding and s["root_none"] and not s["hmac_key"] and not s["secure_profile"]:
        # (a secure profile without the chip key makes its root key once the chip has it)
        raise ProvisionError("the active profile has no root key (its keys are derived from the device serial), "
                             "so binding protects nothing for it: switch to another profile to bind the chip")
    return s


def save_metadata(info, directory="."):
    """Non-secret device metadata, written before any change."""
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    path = os.path.join(directory, "librefido-provision-%s-%s.json" % (info["chip_serial"], stamp))
    keep = {k: info[k] for k in ("firmware", "chip_serial", "serial", "build_profile", "boot_status",
                                 "security", "firmware_slot") if k in info}
    keep["profiles"] = [{k: p[k] for k in ("index", "used", "name", "uuid")} for p in info.get("profiles", [])]
    with open(path, "w") as f:
        json.dump(keep, f, indent=2)
    return path


def _keystore(mgmt, info):
    """Key store state of the active profile when it matters: a profile
    without root key on a chip with the HMAC key (INFO cannot tell held from
    recorded there)."""
    sec = info["security"]
    if sec["hmac_key"] and sec["root_key"].startswith("none") and hasattr(mgmt, "keystore_unlocked"):
        return mgmt.keystore_unlocked()
    return None


def bind_root_key(mgmt, confirm, directory=".", out=print):
    """The HMAC step: check, save metadata, confirm, burn (on the device,
    after a touch), verify. confirm(expected) must return the typed text.
    For a held profile (see state: a root key in plain, or none) the same
    confirmation and touch bind it to the key already in the chip (a
    profile without root key: the chip records that it has none); the key
    store unlocks at the next start."""
    info = mgmt.info()
    keystore = _keystore(mgmt, info)
    s = check_consistent(info, keystore)
    if s["hmac_key"] and not s["held"]:
        if s["root_none"] and keystore is None:
            raise ProvisionError("the active profile has no root key, and the device does not say whether it is "
                                 "held (its FIDO application does not answer); nothing changed")
        out("already done: %s" % ("this profile has no root key, and that is recorded on the chip"
                                  if s["root_none"] else "the root key is bound to this chip"))
        return info
    if s["held"]:
        out(held_text(s))
    meta = save_metadata(info, directory)
    out("device metadata saved to %s" % meta)
    expected = "BURN %s" % info["chip_serial"]
    if confirm(expected) != expected:
        raise ProvisionError("not confirmed, nothing changed")
    try:
        mgmt.provision_hmac()
    except ApduError as e:
        if s["held"] and e.sw == 0x6F00:
            raise ProvisionError("the device refuses to bind this profile. If you bound it already since the key "
                                 "last started, restart the key and check `librefido info`. Otherwise it was bound "
                                 "to the chip before, so its root record can only have been removed or replaced: "
                                 "wipe the profile or restore a backup")
        raise
    after = mgmt.info()
    s2 = state(after)
    if s["root_none"] and s["secure_profile"] and not s["hmac_key"]:
        if not s2["hmac_key"]:
            raise ProvisionError("the eFuse key was written but the device does not report it; do not continue, "
                                 "see docs/PROVISIONING.md")
        out("the chip has its HMAC key now; this secure profile makes its root key, bound to it, at the next "
            "start. Restart the key and check that `librefido info` shows key_store: unlocked.")
        return after
    if s["held_none"]:
        # (INFO keeps reporting "none"; the key store unlocks at the next start)
        out("recorded: this profile has no root key. Restart the key (unplug it and plug it in again): its key "
            "store unlocks at the next start. Then check that `librefido info` shows key_store: unlocked.")
        return after
    if not (s2["hmac_key"] and s2["root_key"].endswith("bound to HMAC eFuse key")):
        raise ProvisionError("%s but the device does not report the binding (%s); do not continue, see "
                             "docs/PROVISIONING.md" % ("the root key was sent for binding" if s["held"] else
                                                       "the eFuse key was written", s2["root_key"]))
    if s["held"]:
        out("the root key is bound now. Restart the key (unplug it and plug it in again): its key store "
            "unlocks at the next start. Then check that `librefido info` shows the root key as '%s' and "
            "key_store: unlocked." % ROOT_BOUND)
    return after


LOCK_TEXT = ("Locking debugging burns the JTAG disable and secure download mode eFuses (irreversible). "
             "Firmware can still be flashed with esptool (write_flash, --no-stub), so recovery keeps "
             "working, but the ROM loader no longer reads the flash or runs code in RAM. Neither this "
             "step nor binding the root key can brick the board.")


def lock_debug(mgmt, confirm, directory=".", out=print):
    """The lock-debug step, with the rules of bind_root_key: check (the same
    inconsistent states are refused), save metadata, typed confirmation,
    burn (on the device, after a touch), verify (INFO: jtag_disabled and
    download_restricted). A half-locked chip is completed."""
    info = mgmt.info()
    s = check_consistent(info, _keystore(mgmt, info), binding=False)
    if s["jtag_disabled"] and s["download_restricted"]:
        out("already done: JTAG is disabled and download mode is secure")
        return info
    out(LOCK_TEXT)
    meta = save_metadata(info, directory)
    out("device metadata saved to %s" % meta)
    expected = "BURN %s" % info["chip_serial"]
    if confirm(expected) != expected:
        raise ProvisionError("not confirmed, nothing changed")
    try:
        mgmt.lock_debug()
    except ApduError as e:
        if e.sw == 0x6A81:
            raise ProvisionError("this device cannot lock debugging (not supported by its chip or firmware)")
        if e.sw == 0x6A88:
            raise ProvisionError("the device reports debugging as locked already, but INFO did not: "
                                 "restart it and check again")
        if e.sw == 0x6F00:
            raise ProvisionError("burning the eFuses failed; do not continue, restart the device and check "
                                 "its state, see docs/PROVISIONING.md")
        raise
    after = mgmt.info()
    s2 = state(after)
    if not (s2["jtag_disabled"] and s2["download_restricted"]):
        raise ProvisionError("the eFuses were written but the device does not report JTAG disabled and "
                             "secure download mode (JTAG disabled: %s, download restricted: %s); do not "
                             "continue, see docs/PROVISIONING.md" % (s2["jtag_disabled"], s2["download_restricted"]))
    return after
