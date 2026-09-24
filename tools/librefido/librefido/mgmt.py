"""Client of the LibreFido management applet (pico-keys-sdk/src/fs/lf_mgmt.c)."""

import hashlib
import struct
import time

from fido2 import cbor
from smartcard.Exceptions import CardConnectionException

from . import firmware, policy
from .pcsc import ApduError, MGMT_AID, open_device

CLA = 0x80
INS_INFO, INS_HEALTH = 0x01, 0x02
INS_PROFILE_SELECT, INS_PROFILE_SET, INS_PROFILE_WIPE, INS_PROFILE_DELETE, INS_BUTTON_SLOTS = \
    0x10, 0x11, 0x12, 0x13, 0x14
INS_PROFILE_CREATE_SECURE, INS_BOARD_SET, INS_PROFILE_AAGUID_SET = 0x15, 0x16, 0x17
INS_EXPORT_BEGIN, INS_EXPORT_READ, INS_EXPORT_END = 0x20, 0x21, 0x22
INS_IMPORT_BEGIN, INS_IMPORT_WRITE, INS_IMPORT_END = 0x28, 0x29, 0x2A
INS_FACTORY_RESET, INS_REBOOT = 0x30, 0x3F
INS_FW_BEGIN, INS_FW_WRITE, INS_FW_END, INS_FW_CONFIRM, INS_FW_ROLLBACK = 0x40, 0x41, 0x42, 0x43, 0x44
INS_PROVISION_HMAC = INS_PROVISION = 0x50
PROVISION_BIND, PROVISION_LOCK_DEBUG = 0x01, 0x02     # P2 of PROVISION (P1 0xA5)

# The FIDO application on the same PC/SC interface (CTAP over ISO 7816).
FIDO_AID = bytes.fromhex("A0000006472F0001")
CTAP_MSG, CTAP_GET_INFO = 0x10, 0x04
CTAP_NOT_ALLOWED = 0x30             # CTAP2_ERR_NOT_ALLOWED

PROFILE_F_NO_EXPORT = 0x01
PROFILE_NAME_MAX = 23       # bytes of UTF-8 (lf_sys.h: char name[24], NUL terminated)
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


class PinRequired(ApduError):
    """The operation needs the FIDO PIN of the active profile. kind says why:
    "missing" (the profile has one and none was given), "unknown" (the device
    cannot tell whether it has one), "device" (none was given and the device
    asks for it), "invalid" (the given one cannot be right: 4 to 63 bytes),
    "unavailable" (the device cannot check a PIN now). Apart from the last,
    nothing reached the PIN check: a missing or impossible PIN would use up
    one of its retries on firmware before protocol 2. ask: entering a PIN
    (or, for "unknown", stating that there is none) and trying again helps."""

    def __init__(self, message, kind):
        super().__init__(0x6982, message=message)
        self.kind = kind
        self.ask = kind in ("missing", "unknown", "device")


class FirmwareNotStarted(ApduError):
    """After an update the device runs the previous firmware (it went back)."""


def clip_name(name):
    """name shortened to what a profile slot holds (PROFILE_NAME_MAX bytes of
    UTF-8), never inside a character."""
    raw = name.split("\0", 1)[0].encode("utf-8")[:PROFILE_NAME_MAX]
    return raw.decode("utf-8", "ignore")


def display_name(s):
    """A name from the device or a backup file, safe to show: control and
    format characters (terminal escapes, bidi overrides, line breaks) become
    visible escapes. Rich text is the caller's matter (plain text in Qt)."""
    return "".join(c if c.isprintable() else ("\\x%02x" % ord(c) if ord(c) < 0x100 else "\\u%04x" % ord(c))
                   for c in (s or ""))


def _load(d, pos, depth):
    if depth > 16:
        raise ValueError("nested too deeply")
    fb = d[pos]
    mt, ai = fb >> 5, fb & 0x1F
    pos += 1
    if ai < 24:
        arg = ai
    elif ai < 28:
        n = 1 << (ai - 24)
        if pos + n > len(d):
            raise ValueError("truncated")
        arg = int.from_bytes(d[pos:pos + n], "big")
        pos += n
    else:
        raise ValueError("indefinite length or reserved item")
    if mt == 0:
        return arg, pos
    if mt == 1:
        return -1 - arg, pos
    if mt in (2, 3):
        if pos + arg > len(d):
            raise ValueError("truncated")
        v = d[pos:pos + arg]
        return (v if mt == 2 else v.decode("utf-8", "replace")), pos + arg
    if mt == 4:
        items = []
        for _ in range(arg):
            v, pos = _load(d, pos, depth + 1)
            items.append(v)
        return items, pos
    if mt == 5:
        m = {}
        for _ in range(arg):
            k, pos = _load(d, pos, depth + 1)
            v, pos = _load(d, pos, depth + 1)
            m[k] = v
        return m, pos
    if mt == 7 and ai in (20, 21, 22):
        return (False, True, None)[ai - 20], pos
    raise ValueError("unsupported item %02X" % fb)


def decode(data):
    """CBOR answer of the device. Like fido2.cbor.decode, except that text
    that is not valid UTF-8 (a profile name that older firmware cut inside a
    character) gets replacement characters instead of failing, so one bad
    name cannot lock the tools out. Raises ValueError."""
    data = bytes(data)
    try:
        value, pos = _load(data, 0, 0)
    except (IndexError, TypeError) as e:
        raise ValueError("malformed CBOR (%s)" % e)
    if pos != len(data):
        raise ValueError("extra data after the CBOR value")
    return value


class Management:
    """Management session. Operations that need a touch return only after the
    user touched the key (or raise ApduError 6985 after the timeout).
    Every command, and every multi-APDU operation as a whole, runs in a PC/SC
    transaction that selects the management applet first: no other PC/SC
    program can send APDUs to the device in between (see
    pcsc.Card.transaction for what it does not cover)."""

    def __init__(self, card):
        self.card = card
        self._no_pin_seen = False       # getInfo reported no PIN for the running operation

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

    def _cmd(self, ins, p1=0, p2=0, data=b"", what="", lock=True):
        # Alone, the command gets its own transaction and SELECT: another
        # program may have selected another application of the device (right
        # after a restart, for example). Inside an operation's transaction
        # this nests and costs nothing. lock=False (a display refresh that
        # must not wait for another program's transaction) sends it as is.
        if not lock and not getattr(self.card, "_locked", 0):
            resp, _ = self.card.transmit(CLA, ins, p1, p2, data, le=0, what=what)
            return resp
        with self.card.transaction(MGMT_AID):
            resp, _ = self.card.transmit(CLA, ins, p1, p2, data, le=0, what=what)
        return resp

    @staticmethod
    def _map(resp, what):
        """A CBOR map answered by the device."""
        try:
            m = decode(resp)
        except ValueError as e:
            raise ApduError(0x6F00, message="%s: malformed answer from the device (%s)" % (what, e))
        if not isinstance(m, dict):
            raise ApduError(0x6F00, message="%s: malformed answer from the device" % what)
        return m

    def _answer(self, ins, p1=0, p2=0, data=b"", what="", lock=True):
        """Command answered with a CBOR map."""
        return self._map(self._cmd(ins, p1, p2, data, what, lock), what)

    def _end_transfer(self, ins=INS_INFO, what="info"):
        """Ends a transfer that failed or was interrupted, inside its
        transaction: any management command makes the device drop the
        session and the staged data (which holds keys in the clear). The
        device may be busy with a request on another interface (a FIDO
        request waiting for a touch), so this retries for a moment; if the
        command still cannot be delivered, or is itself interrupted, the
        transaction ends with a card reset, which drops the session too."""
        delivered = False
        try:
            deadline = time.monotonic() + 1.0
            while True:
                try:
                    self._cmd(ins, what=what)
                    delivered = True
                    return
                except ApduError:
                    delivered = True        # answered: the session is over
                    return
                except CardConnectionException:
                    if time.monotonic() >= deadline:
                        return
                    time.sleep(0.2)
        finally:
            if not delivered:
                self.card.mark_reset()

    # -- information ---------------------------------------------------------
    def info(self, lock=True):
        """Device, security and profile state. lock=False: without a PC/SC
        transaction, for a display that must not wait while another program
        holds one (it may then fail instead)."""
        m = self._answer(INS_INFO, what="info", lock=lock)
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
        if 9 in m[8]:   # firmware 2.0.1+: key store state of the mounted profile
            out["security"]["keystore_unlocked"] = bool(m[8][9])
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
                    # protocol 3: automatic presence per application, secure profile
                    "auto_presence": policy.apps_of(p.get(7, 0)),
                    "secure": bool(p.get(8, False)),
                    # firmware 2.1.0+: AAGUID of the mounted profile only (its own
                    # file, unreadable for a slot that is not mounted -- reported
                    # as an empty byte string there, same as on older firmware
                    # that has no key 9 at all): the 32-hex-digit value actually
                    # in force (the build default when the profile never set its
                    # own), or None when it cannot be read.
                    "aaguid": (p[9].hex() or None) if 9 in p else None,
                } for p in m[15]],
            })
        if 17 in m:
            out["board"] = {"led_brightness": m[17].get(1)}
        if 18 in m:
            out["free_changes"] = m[18]     # changes without a touch left (names, colours, board, ...)
        return out

    def health(self, scrub=False):
        m = self._answer(INS_HEALTH, 1 if scrub else 0, what="health")
        return {k: m[i + 1] for i, k in enumerate(HEALTH_KEYS)}

    def fido_pin_set(self):
        """Whether the active profile has a FIDO PIN, from CTAP getInfo
        ("clientPin") of the FIDO application on the same interface: True,
        False, or None when that application does not answer. While the key
        store is locked (a chip not provisioned for a HARDENED build, a root
        key waiting to be bound) getInfo reports no PIN although the
        management applet asks for one on firmware before protocol 3:
        operations then raise PinRequired "device", and the caller asks for
        the PIN and tries again."""
        r = self._ctap(bytes([CTAP_GET_INFO]))
        if r is None or r[1] != 0x9000 or not r[0] or r[0][0] != 0:
            return None
        try:
            options = decode(r[0][1:]).get(4, {})
            return bool(options.get("clientPin", False))
        except (ValueError, AttributeError):
            return None

    def keystore_unlocked(self):
        """Whether the key store of the active profile is unlocked (its
        applications have their keys). A locked store (a held root key, a
        profile without root key on a Secure Boot chip before the binding, a
        HARDENED build on an incomplete chip) answers every CTAP command but
        getInfo with NOT_ALLOWED: probed with ClientPIN getPinRetries, which
        changes nothing. True, False, or None when the FIDO application does
        not answer. Firmware that reports the state in INFO (security key 9)
        is not probed."""
        try:
            known = self.info().get("security", {}).get("keystore_unlocked")
        except Exception:
            known = None
        if known is not None:
            return known
        r = self._ctap(bytes([0x06]) + cbor.encode({1: 1, 2: 1}))
        if r is None:
            return None
        resp, sw = r
        if sw == 0x6400 | CTAP_NOT_ALLOWED or (sw == 0x9000 and resp[:1] == bytes([CTAP_NOT_ALLOWED])):
            return False
        return True if sw == 0x9000 or (sw >> 8) == 0x64 else None

    def _ctap(self, msg):
        """One CTAP command through the FIDO application on this interface
        (NFCCTAP_MSG): (answer, status word), or None when it does not
        answer. The management applet is selected again afterwards."""
        with self.card.transaction():
            try:
                try:
                    self.card.select(FIDO_AID)
                    return self.card.transmit(CLA, CTAP_MSG, 0, 0, msg, le=0, check=False, what="FIDO")
                except (ApduError, CardConnectionException):
                    return None
            finally:
                # Without the management applet selected again, the next
                # commands would reach the FIDO application.
                try:
                    self.card.select(MGMT_AID)
                except (ApduError, CardConnectionException):
                    raise RuntimeError("the device is busy with another request (a FIDO request waiting "
                                       "for a touch?); try again")

    @staticmethod
    def _pin_bytes(pin, what):
        b = pin.encode("utf-8")
        if not 4 <= len(b) <= 63:
            raise PinRequired("%s: a FIDO PIN has 4 to 63 bytes, this one cannot be right (it was not sent)"
                              % what, "invalid")
        return b

    def _pin_or_none(self, pin, no_pin, what):
        """PIN bytes to send, or b"" after making sure the active profile does
        not need one: an empty PIN is never sent on a guess, since each
        attempt on a profile with a PIN costs one of its retries (on firmware
        before protocol 2). no_pin is the user's statement that the profile
        has none, used only when the device cannot tell."""
        self._no_pin_seen = False
        if pin:
            return self._pin_bytes(pin, what)
        has_pin = self.fido_pin_set()
        self._no_pin_seen = has_pin is False
        if has_pin:
            raise PinRequired("%s: the active profile has a FIDO PIN; enter it and try again" % what, "missing")
        if has_pin is None and not no_pin:
            raise PinRequired("%s: cannot tell whether the active profile has a FIDO PIN (its FIDO "
                              "application does not answer); enter the PIN, or state that it has none, and "
                              "try again" % what, "unknown")
        return b""

    def _pin_cmd(self, ins, p1=0, p2=0, data=b"", sent_pin=False, what=""):
        """Command that the device may refuse with 6982: the FIDO PIN is
        missing, or the root key of the active profile is not in use (a held
        root key, see provision.state), so that neither the PIN can be
        checked nor a complete backup made. From protocol 3 on getInfo knows
        the PIN whatever the state, so a refusal without a PIN of a profile
        without one is the root key."""
        no_pin_seen, self._no_pin_seen = self._no_pin_seen, False      # (set by _pin_or_none just before)
        try:
            return self._cmd(ins, p1, p2, data, what)
        except ApduError as e:
            if e.sw != 0x6982:
                raise
            if sent_pin or ((getattr(self.card, "protocol", None) or 0) >= 3 and no_pin_seen):
                raise PinRequired("%s: the device cannot check the FIDO PIN of the active profile or back it up "
                                  "now: its root key is not in use (held until bound: see `librefido provision "
                                  "plan`), or it has none and a PIN" % what, "unavailable")
            raise PinRequired("%s: the device asks for the FIDO PIN of the active profile; enter it and try "
                              "again" % what, "device")

    def _pin_needed(self, info, since_protocol=1):
        """Whether the device checks the FIDO PIN for a command: only with its
        key storage open, and only from the given protocol version on."""
        return info["boot_status"] == BOOT_STATUS[0] and info.get("protocol", 1) >= since_protocol

    # -- profiles ------------------------------------------------------------
    def select_profile(self, idx):
        """Makes profile idx active (the device may ask for a touch); the
        device reboots (an empty slot gets a new profile)."""
        self._cmd(INS_PROFILE_SELECT, idx, what="select profile")

    def set_profile(self, idx, name=None, color=None, no_export=None):
        """name is shortened to PROFILE_NAME_MAX bytes (clip_name)."""
        m = {}
        if name is not None:
            m[1] = clip_name(name)
        if color is not None:
            m[2] = bytes.fromhex(color) if isinstance(color, str) else bytes(color)
        if no_export is not None:
            m[3] = PROFILE_F_NO_EXPORT if no_export else 0
        self._cmd(INS_PROFILE_SET, idx, data=cbor.encode(m), what="set profile")

    def set_presence(self, idx, **apps):
        """Automatic presence of profile idx per application (policy.APPS,
        e.g. fido=True, piv=False; the others keep their setting): a presence
        request of that application is then confirmed without a press.
        Switching one on needs a touch and is refused (6986) for a secure
        profile and in HARDENED builds; switching off needs none."""
        unknown = set(apps) - set(policy.APPS)
        if unknown:
            raise ValueError("unknown applications: %s" % ", ".join(sorted(unknown)))
        with self.card.transaction(MGMT_AID):          # read, change, write as one
            profiles = self.info().get("profiles")
            if profiles is None:
                raise ApduError(0x6A86, "automatic presence")
            current = set(profiles[idx]["auto_presence"])
            for name, on in apps.items():
                (current.add if on else current.discard)(name)
            mask = policy.auto_mask(**{a: True for a in current})
            self._cmd(INS_PROFILE_SET, idx, data=cbor.encode({4: mask}), what="automatic presence")

    def create_secure_profile(self, idx):
        """A new, empty secure profile in slot idx, replacing what it holds
        (touch): its keys never leave it, it is never imported into, every
        presence needs a press. Needs the root key bound to the chip first
        (6982), refused in HARDENED builds (6986). The device restarts."""
        self._cmd(INS_PROFILE_CREATE_SECURE, idx, what="create secure profile")

    def set_led_brightness(self, value):
        """LED brightness 0..255 (device wide, applied at once; a touch once
        the free changes are used up)."""
        self._cmd(INS_BOARD_SET, data=cbor.encode({1: value}), what="LED brightness")

    def set_aaguid(self, aaguid=None):
        """AAGUID the mounted profile reports in getInfo and attestation from
        now on: 16 raw bytes, a 32-hex-digit string, or None to go back to
        the firmware's own default. Never a real vendor's AAGUID (this tool
        does not check for one; that is a policy decision for whoever calls
        it -- see docs/COMPATIBILITY.md). Always a touch. Refused (6d00)
        on firmware without the command."""
        m = {}
        if aaguid is not None:
            raw = policy.parse_aaguid(aaguid) if isinstance(aaguid, str) else bytes(aaguid)
            if len(raw) != 16:
                raise ValueError("an AAGUID is 16 bytes (32 hex digits)")
            m[1] = raw
        self._cmd(INS_PROFILE_AAGUID_SET, data=cbor.encode(m), what="AAGUID")

    def wipe_profile(self, idx):
        """Empties profile idx, or creates one in an empty slot (touch); the
        device restarts."""
        self._cmd(INS_PROFILE_WIPE, idx, what="wipe profile")

    def delete_profile(self, idx):
        self._cmd(INS_PROFILE_DELETE, idx, what="delete profile")

    def set_button_slots(self, n):
        self._cmd(INS_BUTTON_SLOTS, n, what="button slots")

    # -- backups -------------------------------------------------------------
    def export_profile(self, pin=None, progress=None, no_pin=False):
        """Returns the profile stream of the active profile (touch, and the FIDO
        PIN when the profile has one; without pin, PinRequired is raised
        before anything is sent if it has one, see _pin_or_none)."""
        with self.card.transaction(MGMT_AID):
            data = self._pin_or_none(pin, no_pin, "export")
            out = bytearray()
            try:
                # From here on the device may hold a session (it may have
                # taken the touch even when the answer never arrives here).
                m = self._map(self._pin_cmd(INS_EXPORT_BEGIN, data=data, sent_pin=bool(data), what="export"),
                              "export")
                # Protocol 2: every read carries the export ID of this session.
                length, digest, export_id = m[1], m[2], m.get(3, b"")
                while len(out) < length:
                    chunk = self._cmd(INS_EXPORT_READ, data=struct.pack(">I", len(out)) + export_id,
                                      what="export read")
                    if not chunk:
                        raise ApduError(0x6F00, "export read returned no data")
                    out += chunk
                    if progress:
                        progress(len(out), length)
                self._cmd(INS_EXPORT_END, what="export end")
            except BaseException:
                self._end_transfer(INS_EXPORT_END, "export end")    # the device erases the stream
                raise
        if hashlib.sha256(out).digest() != digest:
            raise ApduError(0x6F00, "export transfer corrupted")
        return bytes(out)

    def _session_id(self, resp, what):
        """Transfer ID answered by IMPORT_BEGIN / FW_BEGIN from protocol 3 on
        ({1: ID}; nothing before): every later command of the transfer
        carries it."""
        return self._map(resp, what).get(1, b"") if resp else b""

    def _upload(self, stream, target, p2, progress=None, pin=None, no_pin=False):
        with self.card.transaction(MGMT_AID):
            data = b""
            if p2 == 0 and (pin or self._import_needs_pin(target)):
                data = self._pin_or_none(pin, no_pin, "import")
            try:
                # A touched IMPORT_BEGIN opens a session: whatever happens
                # from here on, it is ended.
                sid = self._session_id(self._pin_cmd(INS_IMPORT_BEGIN, target, p2, data=data, sent_pin=bool(data),
                                                     what="import"), "import")
                off, chunk = 0, 1024
                while off < len(stream):
                    part = stream[off:off + chunk]
                    self._cmd(INS_IMPORT_WRITE, data=struct.pack(">I", off) + sid + part, what="import write")
                    off += len(part)
                    if progress:
                        progress(off, len(stream))
                m = self._answer(INS_IMPORT_END, data=sid, what="import end")
            except BaseException:
                self._end_transfer()
                raise
        return {"files": m[1], "counters": m[2], "root_key": m[3], "length": m[4], "uuid": m[5].hex(),
                "serial": m[6].hex().upper(), "name": m[7], "firmware": "%d.%d.%d" % tuple(m[8]),
                "min_firmware": "%d.%d.%d" % tuple(m[9]), "flags": m[10], "sha256": m[11].hex()}

    def _import_needs_pin(self, target):
        """From protocol 3 on an import into the active slot replaces the
        running authenticator: the device asks for its FIDO PIN, like for an
        update."""
        info = self.info()
        return self._pin_needed(info, 3) and target == info.get("active")

    def check_backup(self, stream, progress=None):
        """Device-side dry run: the firmware validates the stream completely
        (structure, digests, version, capacity) and imports nothing."""
        return self._upload(stream, 0, 1, progress)

    def restore_test(self, stream, progress=None, timeout=30.0):
        """Full restore of the backup into scratch space at the next boot,
        read back record by record and erased again; no profile changes (a
        touch from protocol 2 on). Returns the check result and whether the
        restore test passed."""
        res = self._upload(stream, 0, 3, progress)
        self.reconnect(timeout)
        return res, self.info()["last_result"] == RESULTS[7]     # (info() selects the applet itself)

    def import_profile(self, stream, target, progress=None, timeout=30.0, pin=None, no_pin=False):
        """Replaces profile slot target with the backup (touch; before
        protocol 2 only when the slot is in use; from protocol 3 on also the
        FIDO PIN when the target is the active profile and it has one, see
        _pin_or_none); the device reboots, rebuilds and verifies it."""
        res = self._upload(stream, target, 0, progress, pin=pin, no_pin=no_pin)
        self.reconnect(timeout)
        info = self.info()
        if info["last_result"] != RESULTS[2]:
            raise ApduError(0x6F00, message="import failed on the device: %s" % info["last_result"])
        return res

    # -- firmware ------------------------------------------------------------
    def update_firmware(self, image, pin=None, allow_downgrade=False, progress=None, confirm=True,
                        timeout=30.0, no_pin=False):
        """Installs image in the other slot (touch, and the FIDO PIN when the
        active profile has one, see _pin_or_none) and restarts into it. The
        update counts as done only when the device then runs the new image:
        another slot than before, not yet confirmed, and the version, build
        profile, platform and board the device reported for the image. With
        confirm the new firmware is then kept, unless it locks the key store
        of the active profile that was open before (then "warning" says so
        and it stays unconfirmed); otherwise the next reset of the device
        goes back to the current one. Raises ApduError when the device went
        back to the previous firmware."""
        desc = firmware.parse(image)
        params = {1: len(image), 2: hashlib.sha256(image).digest()}
        with self.card.transaction(MGMT_AID):
            before = self.info()
            old_slot = (before.get("firmware_slot") or {}).get("slot")
            if before.get("protocol", 1) >= 3 and (before.get("firmware_slot") or {}).get("unconfirmed"):
                # The upload would overwrite the image a reset goes back to.
                raise ApduError(0x6985, message="firmware update: the running firmware is not confirmed yet; "
                                                "keep it first (`librefido firmware confirm`, GUI: Keep this "
                                                "firmware) or restart the key to go back")
            if pin or self._pin_needed(before):
                data = self._pin_or_none(pin, no_pin, "firmware update")
                if data:
                    params[3] = data
            unlocked_before = self.keystore_unlocked() if before["boot_status"] == BOOT_STATUS[0] else None
            try:
                sid = self._session_id(self._pin_cmd(INS_FW_BEGIN, 0, 1 if allow_downgrade else 0,
                                                     data=cbor.encode(params), sent_pin=3 in params,
                                                     what="firmware update"), "firmware update")
                off, chunk = 0, 1024
                while off < len(image):
                    part = image[off:off + chunk]
                    self._cmd(INS_FW_WRITE, data=struct.pack(">I", off) + sid + part, what="firmware write")
                    off += len(part)
                    if progress:
                        progress(off, len(image))
                m = self._answer(INS_FW_END, data=sid, what="firmware check")
            except BaseException:
                self._end_transfer()
                raise
        want = {
            "version": "%d.%d.%d" % tuple(m[1]),
            "platform": firmware.PLATFORMS.get(m[2], str(m[2])),
            "build_profile": firmware.BUILD_PROFILES.get(m[3], str(m[3])),
            "board": m.get(4),
        }
        self.reconnect(timeout)
        try:
            # One transaction for the checks and the confirmation: no other
            # program can select another application of the restarted device
            # in between (FW_CONFIRM needs no touch).
            with self.card.transaction(MGMT_AID):
                now = self.info()
                fw = now.get("firmware_slot") or {}
                started = now["firmware"] == want["version"] and now["build_profile"] == want["build_profile"]
                if fw:
                    started = started and fw["platform"] == want["platform"] and \
                        (want["board"] is None or fw["board"] == want["board"])
                if old_slot is not None:
                    started = started and fw.get("slot") != old_slot and fw.get("unconfirmed") is True
                if not started:
                    raise FirmwareNotStarted(0x6F00, message=(
                        "the new firmware did not start, the device went back to the previous one: it runs %s "
                        "(%s build) in slot %s, expected %s (%s build) in another slot than %s"
                        % (now["firmware"], now["build_profile"], fw.get("slot", "?"), want["version"],
                           want["build_profile"], old_slot if old_slot is not None else "?")))
                warning = None
                if confirm and unlocked_before and self.keystore_unlocked() is False:
                    # The new firmware locks the active profile (for example a
                    # profile without root key on a Secure Boot chip): it is
                    # not kept, so a reset still goes back while the old one
                    # can open the storage.
                    confirm = False
                    warning = ("the new firmware keeps the key store of the active profile locked (see "
                               "`librefido provision plan`), so it was NOT confirmed: restart the key to go back "
                               "to the previous firmware, or unlock the profile first and then keep the new one "
                               "with `librefido firmware confirm`")
                if confirm:
                    self.confirm_firmware()
                    if (self.info().get("firmware_slot") or {}).get("unconfirmed"):
                        raise ApduError(0x6F00, message="the device did not keep the new firmware "
                                                        "(still unconfirmed)")
        except FirmwareNotStarted:
            raise
        except (ApduError, CardConnectionException) as e:
            raise ApduError(getattr(e, "sw", 0x6F00), message=(
                "%s -- the new firmware %s was installed, but it could not be checked%s: it may still be "
                "unconfirmed, so that the next reset goes back to the previous one. Check with `librefido "
                "firmware info` and keep it with `librefido firmware confirm` (GUI: Keep this firmware) "
                "before unplugging the key." % (e, want["version"], " and confirmed" if confirm else "")))
        return {"installed": want["version"], "descriptor": desc, "confirmed": confirm, "slot": fw.get("slot"),
                "warning": warning}

    def confirm_firmware(self):
        """Keeps the running firmware (no rollback at the next reset)."""
        self._cmd(INS_FW_CONFIRM, what="confirm firmware")

    def rollback_firmware(self, timeout=30.0, pin=None, no_pin=False):
        """Goes back to the previous firmware (touch, and from protocol 2 on
        the FIDO PIN like an update); the device restarts."""
        with self.card.transaction(MGMT_AID):
            data = b""
            if pin or self._pin_needed(self.info(), 2):
                data = self._pin_or_none(pin, no_pin, "firmware rollback")
            self._pin_cmd(INS_FW_ROLLBACK, data=data, sent_pin=bool(data), what="firmware rollback")
        self.reconnect(timeout)
        return self.info()["firmware"]      # (info() selects the applet itself)

    def provision_hmac(self):
        """Irreversible: burns an HMAC key generated on the device into an
        eFuse key block and binds the root key to it (touch). Use
        librefido.provision.bind_root_key(), which checks and verifies."""
        self._cmd(INS_PROVISION, 0xA5, PROVISION_BIND, what="bind root key to the chip")

    def lock_debug(self):
        """Irreversible: burns the JTAG disable and secure download mode
        eFuses (touch). Use librefido.provision.lock_debug(), which checks
        and verifies. 6A88: already locked, 6A81: not supported here."""
        self._cmd(INS_PROVISION, 0xA5, PROVISION_LOCK_DEBUG, what="lock debugging")

    def factory_reset(self, legacy=False):
        self._cmd(INS_FACTORY_RESET, 0x5A, 1 if legacy else 0, what="factory reset")

    def reboot(self, bootloader=False, pin=None, no_pin=False):
        """Restarts the device (from protocol 2 on after a touch); bootloader:
        into the ESP32 ROM loader, which from protocol 2 on also asks for the
        FIDO PIN like a firmware update."""
        with self.card.transaction(MGMT_AID):
            data = b""
            if bootloader and (pin or self._pin_needed(self.info(), 2)):
                data = self._pin_or_none(pin, no_pin, "reboot into the ROM loader")
            self._pin_cmd(INS_REBOOT, 1 if bootloader else 0, data=data, sent_pin=bool(data), what="reboot")


__all__ = ["Management", "ApduError", "PinRequired", "FirmwareNotStarted", "MGMT_AID", "clip_name",
           "display_name"]
