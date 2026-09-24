"""ESP32-S3 security provisioning: what is set, what a target profile needs,
and the one irreversible step this tool performs itself (binding the root key
to the chip with an HMAC eFuse key generated on the device).

Rules (docs/PROVISIONING.md):
- nothing is written unless --apply is given; the default prints the plan;
- --apply asks for a typed confirmation naming the device;
- non-secret metadata is saved before anything is changed;
- the state is checked before (inconsistent state: refuse) and after;
- Secure Boot, flash encryption, JTAG and download-mode eFuses are not
  burned by this tool: they belong to the bootloader configuration and have
  brick-risk boundaries that need a human in the loop. The plan lists them
  in a safe order with the exact consequences.
"""

import datetime
import json
import os

# Ordered steps towards a HARDENED device. Only "hmac" is automated.
STEPS = [
    {
        "id": "hmac",
        "title": "Bind the root key to this chip (HMAC eFuse key)",
        "done": lambda s: s["hmac_key"] and s["root_key"].endswith("bound to HMAC eFuse key"),
        "automated": True,
        "irreversible": "uses eFuse BLOCK_KEY5 for good (purpose HMAC_UP, read and write protected)",
        "effect": "a copy of the flash no longer reveals the keys on another chip; backups still work "
                  "(the backup carries the root key, re-wrapped by the target chip)",
        "brick_risk": "none: the firmware keeps booting; only the key block is consumed",
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
        "id": "jtag",
        "title": "Disable JTAG (pad and USB)",
        "done": lambda s: s["jtag_disabled"],
        "automated": False,
        "irreversible": "DIS_PAD_JTAG, DIS_USB_JTAG",
        "effect": "no hardware debugging",
        "brick_risk": "low: USB serial and download mode keep working",
    },
    {
        "id": "download",
        "title": "Secure download mode",
        "done": lambda s: s["download_restricted"],
        "automated": False,
        "irreversible": "ENABLE_SECURITY_DOWNLOAD",
        "effect": "the ROM loader only accepts flash writes and basic commands: no flash reads, "
                  "no RAM loading",
        "brick_risk": "medium: esptool must run with --no-stub; reading or backing up the flash over USB "
                      "is no longer possible",
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


def state(info):
    """Security state from Management.info()."""
    s = dict(info["security"])
    s["boot_status"] = info["boot_status"]
    s["build_profile"] = info["build_profile"]
    s["platform"] = info.get("firmware_slot", {}).get("platform", "unknown")
    return s


def plan(info):
    """Steps with their state for this device."""
    s = state(info)
    return [dict(step, is_done=bool(step["done"](s))) for step in STEPS]


def check_consistent(info):
    """Refuses a device whose state does not allow a safe provisioning step."""
    s = state(info)
    if s["platform"] != "esp32s3" and s["platform"] != "emulation":
        raise ProvisionError("provisioning is for ESP32-S3 devices (this is %s)" % s["platform"])
    if s["boot_status"] != "ok":
        raise ProvisionError("the device booted in safe mode (%s): fix the storage first" % s["boot_status"])
    if s["hmac_key"] and not s["root_key"].endswith("bound to HMAC eFuse key"):
        raise ProvisionError("an HMAC eFuse key exists but the root key is not bound to it (%s); "
                             "restart the device and check again before anything else" % s["root_key"])
    if s["root_key"].startswith("none"):
        raise ProvisionError("the profile has no root key yet")
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


def bind_root_key(mgmt, confirm, directory=".", out=print):
    """The HMAC step: check, save metadata, confirm, burn (on the device,
    after a touch), verify. confirm(expected) must return the typed text."""
    info = mgmt.info()
    s = check_consistent(info)
    if s["hmac_key"]:
        out("already done: the root key is bound to this chip")
        return info
    meta = save_metadata(info, directory)
    out("device metadata saved to %s" % meta)
    expected = "BURN %s" % info["chip_serial"]
    if confirm(expected) != expected:
        raise ProvisionError("not confirmed, nothing changed")
    mgmt.provision_hmac()
    after = mgmt.info()
    s2 = state(after)
    if not (s2["hmac_key"] and s2["root_key"].endswith("bound to HMAC eFuse key")):
        raise ProvisionError("the eFuse key was written but the device does not report the binding "
                             "(%s); do not continue, see docs/PROVISIONING.md" % s2["root_key"])
    return after
