"""Client of the LibreFido management applet (pico-keys-sdk/src/fs/lf_mgmt.c)."""

import hashlib
import struct
import time

from fido2 import cbor

from . import firmware
from .pcsc import ApduError, MGMT_AID, open_device

CLA = 0x80
INS_INFO, INS_HEALTH = 0x01, 0x02
INS_PROFILE_SELECT, INS_PROFILE_SET, INS_PROFILE_WIPE, INS_PROFILE_DELETE, INS_BUTTON_SLOTS = \
    0x10, 0x11, 0x12, 0x13, 0x14
INS_EXPORT_BEGIN, INS_EXPORT_READ, INS_EXPORT_END = 0x20, 0x21, 0x22
INS_IMPORT_BEGIN, INS_IMPORT_WRITE, INS_IMPORT_END = 0x28, 0x29, 0x2A
INS_FACTORY_RESET, INS_REBOOT = 0x30, 0x3F
INS_FW_BEGIN, INS_FW_WRITE, INS_FW_END, INS_FW_CONFIRM, INS_FW_ROLLBACK = 0x40, 0x41, 0x42, 0x43, 0x44
INS_PROVISION_HMAC = 0x50

PROFILE_F_NO_EXPORT = 0x01
BOOT_STATUS = ["ok", "partition table too old", "system area unreadable",
               "legacy store not migrated", "active profile not mountable"]
RESULTS = ["none", "migrated", "imported", "import failed", "wiped", "deleted", "operation failed",
           "backup restore test passed", "backup restore test FAILED", "created"]
PENDING = ["none", "import", "wipe", "delete", "restore test"]
DRK_SOURCES = ["none (legacy)", "legacy eFuse", "flash (not bound to the chip)", "flash, bound to HMAC eFuse key"]

HEALTH_KEYS = ["generation", "sectors_checked", "sectors_written", "repaired_from_copy", "corrected_ecc",
               "ecc_bytes_corrected", "uncorrectable", "metadata_repaired", "served_from_copy_b",
               "journal_replayed", "journal_corrupt", "commit_failures", "max_erase_count",
               "total_erase_count", "lifetime_repairs", "lifetime_uncorrectable", "fs_used_bytes",
               "fs_total_bytes", "fs_files", "system_area_bad_copies"]


class Management:
    """Management session. Operations that need a touch return only after the
    user touched the key (or raise ApduError 6985 after the timeout)."""

    def __init__(self, card):
        self.card = card

    @classmethod
    def open(cls, reader=None, timeout=0.0):
        return cls(open_device(reader, timeout))

    def close(self):
        self.card.close()

    def reconnect(self, timeout=20.0):
        """After an operation that reboots the device: waits for the restarted
        instance (another boot ID), not the one about to go down."""
        reader, old = self.card.reader, self.card.boot_id
        self.card.close()
        time.sleep(0.3)
        self.card = open_device(reader, timeout, not_boot_id=old)

    def _cmd(self, ins, p1=0, p2=0, data=b"", what=""):
        resp, _ = self.card.transmit(CLA, ins, p1, p2, data, le=0, what=what)
        return resp

    # -- information ---------------------------------------------------------
    def info(self):
        m = cbor.decode(self._cmd(INS_INFO, what="info"))
        out = {
            "firmware": m[1],
            "protocol": m[2],
            "chip_serial": m[3].hex().upper(),
            "serial": m[4].hex().upper(),
            "boot_status": BOOT_STATUS[m[5]] if m[5] < len(BOOT_STATUS) else str(m[5]),
            "boot_message": m[6],
            "build_profile": m[7],
            "security": {
                "secure_boot": m[8][1], "flash_encryption": m[8][2], "flash_encryption_release": m[8][3],
                "jtag_disabled": m[8][4], "download_restricted": m[8][5], "anti_rollback": m[8][6],
                "hmac_key": m[8][7],
                "root_key": DRK_SOURCES[m[8][8]] if m[8][8] < len(DRK_SOURCES) else str(m[8][8]),
            },
        }
        if 16 in m:
            fw = m[16]
            out["firmware_slot"] = {
                "version": "%d.%d.%d" % tuple(fw[1]),
                "platform": firmware.PLATFORMS.get(fw[2], str(fw[2])),
                "board": fw[3],
                "slot": "factory" if fw[4] == firmware.SLOT_FACTORY else fw[4],
                "unconfirmed": fw[5],
                "rollback_possible": fw[6],
            }
        if 9 in m:
            out.update({
                "active": m[9],
                "button_slots": m[10],
                "last_result": RESULTS[m[11]] if m[11] < len(RESULTS) else str(m[11]),
                "pending": PENDING[m[12]] if m[12] < len(PENDING) else str(m[12]),
                "migrated": m[13],
                "export_allowed": m[14],
                "profiles": [{
                    "index": p[1], "used": p[2], "name": p[3], "color": p[4].hex(),
                    "uuid": p[5].hex(), "no_export": bool(p[6] & PROFILE_F_NO_EXPORT),
                } for p in m[15]],
            })
        return out

    def health(self, scrub=False):
        m = cbor.decode(self._cmd(INS_HEALTH, 1 if scrub else 0, what="health"))
        return {k: m[i + 1] for i, k in enumerate(HEALTH_KEYS)}

    # -- profiles ------------------------------------------------------------
    def select_profile(self, idx):
        """Makes profile idx active; the device reboots (an empty slot gets a
        new profile)."""
        self._cmd(INS_PROFILE_SELECT, idx, what="select profile")

    def set_profile(self, idx, name=None, color=None, no_export=None):
        m = {}
        if name is not None:
            m[1] = name
        if color is not None:
            m[2] = bytes.fromhex(color) if isinstance(color, str) else bytes(color)
        if no_export is not None:
            m[3] = PROFILE_F_NO_EXPORT if no_export else 0
        self._cmd(INS_PROFILE_SET, idx, data=cbor.encode(m), what="set profile")

    def wipe_profile(self, idx):
        """Empties (or creates) profile idx; touch required if it exists."""
        self._cmd(INS_PROFILE_WIPE, idx, what="wipe profile")

    def delete_profile(self, idx):
        self._cmd(INS_PROFILE_DELETE, idx, what="delete profile")

    def set_button_slots(self, n):
        self._cmd(INS_BUTTON_SLOTS, n, what="button slots")

    # -- backups -------------------------------------------------------------
    def export_profile(self, pin=None, progress=None):
        """Returns the profile stream of the active profile (touch, and the FIDO
        PIN when the profile has one)."""
        m = cbor.decode(self._cmd(INS_EXPORT_BEGIN, data=(pin or "").encode("utf-8"), what="export"))
        length, digest = m[1], m[2]
        out = bytearray()
        try:
            while len(out) < length:
                chunk = self._cmd(INS_EXPORT_READ, data=struct.pack(">I", len(out)), what="export read")
                if not chunk:
                    raise ApduError(0x6F00, "export read returned no data")
                out += chunk
                if progress:
                    progress(len(out), length)
        finally:
            self._cmd(INS_EXPORT_END, what="export end")
        if hashlib.sha256(out).digest() != digest:
            raise ApduError(0x6F00, "export transfer corrupted")
        return bytes(out)

    def _upload(self, stream, target, p2, progress=None):
        self._cmd(INS_IMPORT_BEGIN, target, p2, what="import")
        off, chunk = 0, 1024
        while off < len(stream):
            part = stream[off:off + chunk]
            self._cmd(INS_IMPORT_WRITE, data=struct.pack(">I", off) + part, what="import write")
            off += len(part)
            if progress:
                progress(off, len(stream))
        m = cbor.decode(self._cmd(INS_IMPORT_END, what="import end"))
        return {"files": m[1], "counters": m[2], "root_key": m[3], "length": m[4], "uuid": m[5].hex(),
                "serial": m[6].hex().upper(), "name": m[7], "firmware": "%d.%d.%d" % tuple(m[8]),
                "min_firmware": "%d.%d.%d" % tuple(m[9]), "flags": m[10], "sha256": m[11].hex()}

    def check_backup(self, stream, progress=None):
        """Device-side dry run: the firmware validates the stream completely
        (structure, digests, version, capacity) and imports nothing."""
        return self._upload(stream, 0, 1, progress)

    def restore_test(self, stream, progress=None, timeout=30.0):
        """Full restore of the backup into scratch space at the next boot,
        read back record by record and erased again; no profile changes.
        Returns the check result and whether the restore test passed."""
        res = self._upload(stream, 0, 3, progress)
        self.reconnect(timeout)
        return res, self.info()["last_result"] == RESULTS[7]

    def import_profile(self, stream, target, progress=None, timeout=30.0):
        """Replaces profile slot target with the backup (touch if the slot is
        in use); the device reboots, rebuilds and verifies it."""
        res = self._upload(stream, target, 0, progress)
        self.reconnect(timeout)
        info = self.info()
        if info["last_result"] != RESULTS[2]:
            raise ApduError(0x6F00, "import failed on the device: %s" % info["last_result"])
        return res

    # -- firmware ------------------------------------------------------------
    def update_firmware(self, image, pin=None, allow_downgrade=False, progress=None, confirm=True,
                        timeout=30.0):
        """Installs image in the other slot (touch, and the FIDO PIN when the
        active profile has one) and restarts into it. With confirm, the new
        firmware is kept once it answers with the expected version; otherwise
        the next reset of the device goes back to the current one."""
        desc = firmware.parse(image)
        params = {1: len(image), 2: hashlib.sha256(image).digest()}
        if pin:
            params[3] = pin.encode("utf-8")
        self._cmd(INS_FW_BEGIN, 0, 1 if allow_downgrade else 0, data=cbor.encode(params), what="firmware update")
        off, chunk = 0, 1024
        while off < len(image):
            part = image[off:off + chunk]
            self._cmd(INS_FW_WRITE, data=struct.pack(">I", off) + part, what="firmware write")
            off += len(part)
            if progress:
                progress(off, len(image))
        m = cbor.decode(self._cmd(INS_FW_END, what="firmware check"))
        installed = "%d.%d.%d" % tuple(m[1])
        self.reconnect(timeout)
        now = self.info()
        if now["firmware"] != installed:
            raise ApduError(0x6F00, "the device runs %s after the update, expected %s (rolled back?)"
                            % (now["firmware"], installed))
        if confirm:
            self.confirm_firmware()
        return {"installed": installed, "descriptor": desc, "confirmed": confirm}

    def confirm_firmware(self):
        """Keeps the running firmware (no rollback at the next reset)."""
        self._cmd(INS_FW_CONFIRM, what="confirm firmware")

    def rollback_firmware(self, timeout=30.0):
        """Goes back to the previous firmware (touch); the device restarts."""
        self._cmd(INS_FW_ROLLBACK, what="firmware rollback")
        self.reconnect(timeout)
        return self.info()["firmware"]

    def provision_hmac(self):
        """Irreversible: burns an HMAC key generated on the device into an
        eFuse key block and binds the root key to it (touch). Use
        librefido.provision.bind_root_key(), which checks and verifies."""
        self._cmd(INS_PROVISION_HMAC, 0xA5, 0x01, what="bind root key to the chip")

    def factory_reset(self, legacy=False):
        self._cmd(INS_FACTORY_RESET, 0x5A, 1 if legacy else 0, what="factory reset")

    def reboot(self, bootloader=False):
        self._cmd(INS_REBOOT, 1 if bootloader else 0, what="reboot")


__all__ = ["Management", "ApduError", "MGMT_AID"]
