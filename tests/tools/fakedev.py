"""A simulated LibreFido device behind a stand-in for librefido.pcsc.Card,
following the management protocol of pico-keys-sdk/src/fs/lf_mgmt.c closely
enough for the host logic: sessions, the FIDO PIN check (a missing PIN costs
a retry, as in the firmware), firmware slots and reboots."""

import hashlib
import struct
from contextlib import contextmanager

from fido2 import cbor
from smartcard.Exceptions import CardConnectionException

from librefido import firmware, mgmt
from librefido.pcsc import MGMT_AID, ApduError

EXPORT, IMPORT, FW = "export", "import", "fw"
PROFILE_IDS = {v: k for k, v in firmware.BUILD_PROFILES.items()}


def image(version=(2, 0, 0), profile=1, platform=0x7F, size=3000):
    """Bytes with a firmware descriptor, as firmware.parse() expects."""
    desc = struct.pack(firmware.DESC_FMT, firmware.MAGIC, firmware.MAGIC_INV, 1, platform, profile,
                       bytes(version), 1, 1, 1, 1, b"emulation", bytes(4))
    return bytes(100) + desc + bytes(size)


class FakeDevice:
    def __init__(self, pin=None, fido=True, stream=b"", version=(2, 0, 0), profile="standard", protocol=2):
        self.protocol = protocol        # 2: export ID, PIN for rollback, no retry used for an empty PIN
        self.export_id = b""
        self.pin = pin                  # FIDO PIN of the active profile (None: none set)
        self.retries = 8
        self.fido = fido                # the FIDO application answers
        self.stream = stream            # what an export returns
        self.version = version
        self.profile = profile
        self.slot = firmware.SLOT_FACTORY
        self.pending = False
        self.boot_status = 0
        self.names = ["Profile 1", "", "", ""]
        self.used = [True, False, False, False]
        self.raw_name = None            # bytes stored as the name of profile 1 (maybe cut UTF-8)
        self.last_result = 0
        self.boot = 1
        self.log = []                   # ("SELECT", aid) or (ins, p1, p2, data, locked)
        self.sess = None
        self.upload = b""
        self.staged = None              # what the next boot applies
        self.rollback_on_boot = False   # the new firmware fails: back to the old slot
        self.fail_write_at = None       # IMPORT_WRITE offset answered with 6A84
        self.store_locked = False       # key store locked: getInfo reports no PIN, the applet asks for it
        self.firmware_text = None       # INFO key 1 as the device reports it (default: the version)
        self.interrupt_after = None     # INS after whose (processed) answer the host gets KeyboardInterrupt
        self.busy_from = None           # INS from which on every APDU fails like a busy device
        self.intruder_select = False    # another client selects another application after each restart
        self.fail_confirm = False       # FW_CONFIRM answers 6F00
        self.busy = False
        # protocol 3: policies, board settings, provisioning
        self.presence = [0, 0, 0, 0]    # automatic presence mask per profile
        self.secure = [False] * 4
        self.no_export = [False] * 4
        self.led = 255
        self.free_changes = 16
        self.hmac_key = False
        self.drk_source = 2             # flash (not bound to the chip)
        self.jtag = self.download = False
        self.hardened = False
        self.secure_boot = False
        self.unlock_at_boot = False     # a held profile was bound: its key store opens at the next start
        self.refuse_bind = False        # the held root can only have been removed or planted

    # -- boot ------------------------------------------------------------------
    def reboot(self):
        self.boot += 1
        self.sess = None
        if self.unlock_at_boot:
            self.store_locked = self.unlock_at_boot = False
        kind, arg = self.staged or (None, None)
        self.staged = None
        if kind == FW and not self.rollback_on_boot:
            self.slot = 0 if self.slot != 0 else 1
            self.pending = True
            self.version, self.profile = arg
        elif kind == FW:
            self.pending = False        # the old image, valid
        elif kind == IMPORT:
            self.last_result = 2

    # -- commands --------------------------------------------------------------
    def _info(self):
        fw = {1: bytes(self.version), 2: 0x7F, 3: "emulation", 4: self.slot, 5: self.pending, 6: False}
        name0 = "Q" * len(self.raw_name) if self.raw_name is not None else self.names[0]
        profiles = [{1: i, 2: self.used[i], 3: name0 if i == 0 else self.names[i], 4: b"\x00\xc0\x00",
                     5: bytes([i]) * 16, 6: (1 if self.no_export[i] else 0) | (2 if self.secure[i] else 0)}
                    for i in range(4)]
        if self.protocol >= 3:
            for i, p in enumerate(profiles):
                p.update({7: self.presence[i], 8: self.secure[i]})
        sec = {1: self.secure_boot, 2: False, 3: False, 4: self.jtag, 5: self.download, 6: False, 7: self.hmac_key,
               8: self.drk_source}
        m = {1: self.firmware_text or "%d.%d.%d" % self.version, 2: self.protocol, 3: bytes(8), 4: bytes(8),
             5: self.boot_status, 6: "ok" if self.boot_status == 0 else "safe mode",
             7: "hardened" if self.hardened else self.profile, 8: sec, 16: fw}
        if self.boot_status in (0, 3, 4):           # sys_usable(): the profiles are reported
            m.update({9: 0, 10: 2, 11: self.last_result, 12: 0, 13: False, 14: True, 15: profiles})
            if self.protocol >= 3:
                m.update({17: {1: self.led}, 18: self.free_changes})
        enc = cbor.encode(m)
        if self.raw_name is not None:
            enc = enc.replace(b"Q" * len(self.raw_name), self.raw_name)
        return enc

    def _pin_check(self, pin):
        if self.pin is None:
            return None
        if self.protocol >= 2 and not 4 <= len(pin) <= 63:
            return 0x6982                               # cannot be right: no retry used
        self.retries -= 1                               # before the comparison, like the firmware
        if pin != self.pin.encode():
            return 0x63C0 | self.retries
        self.retries = 8
        return None

    def _open_session(self):
        """Protocol 3: IMPORT_BEGIN / FW_BEGIN answer {1: session ID}."""
        if self.protocol < 3:
            return b""
        self.session_id = bytes(range(0x40, 0x48))
        return cbor.encode({1: self.session_id})

    def _session_data(self, data, at, whole=False):
        """data without the protocol-3 session ID at offset at (or data that
        is only the ID); a wrong one ends the transfer (6982)."""
        if self.protocol < 3:
            return data, None
        sid = data[at:at + 8]
        if sid != self.session_id or (whole and len(data) != 8):
            self.sess = None
            return b"", 0x6982
        return data[:at] + data[at + 8:], None

    def handle(self, app, ins, p1, p2, data):
        if app == mgmt.FIDO_AID:
            if ins == mgmt.CTAP_MSG and data == bytes([mgmt.CTAP_GET_INFO]):
                client_pin = self.pin is not None and not (self.store_locked and self.protocol < 3)
                return b"\x00" + cbor.encode({1: ["FIDO_2_0"], 4: {"rk": True, "clientPin": client_pin}}), 0x9000
            if self.store_locked:
                return b"", 0x6430                      # every other command: NOT_ALLOWED
            if ins == mgmt.CTAP_MSG and data[:1] == b"\x06":
                return b"\x00" + cbor.encode({3: self.retries}), 0x9000
            return b"", 0x6D00
        if app != MGMT_AID:
            return b"", 0x6D00
        if self.sess and not (ins in (0x21, 0x22) and self.sess == EXPORT or ins in (0x29, 0x2A) and
                              self.sess == IMPORT or ins in (0x41, 0x42) and self.sess == FW):
            self.sess = None
        if ins == mgmt.INS_INFO:
            return self._info(), 0x9000
        if ins == mgmt.INS_PROFILE_SET:
            m = cbor.decode(data)
            if 4 in m:
                if m[4] & ~0x1F:
                    return b"", 0x6A80
                if m[4] & ~self.presence[p1] and (self.secure[p1] or self.hardened):
                    return b"", 0x6986
                self.presence[p1] = m[4]
            if 3 in m:
                if not m[3] & 1 and self.secure[p1]:
                    return b"", 0x6986
                self.no_export[p1] = bool(m[3] & 1)
            return b"", 0x9000
        if ins == mgmt.INS_PROFILE_CREATE_SECURE:
            if self.hardened:
                return b"", 0x6986
            if not self.hmac_key:
                return b"", 0x6982
            self.used[p1], self.secure[p1], self.no_export[p1], self.presence[p1] = True, True, True, 0
            return b"", 0x9000
        if ins == mgmt.INS_BOARD_SET:
            v = cbor.decode(data).get(1)
            if v is not None and not 0 <= v <= 255:
                return b"", 0x6A80
            if v is not None and v != self.led:
                self.led = v
                self.free_changes = max(0, self.free_changes - 1)
            return b"", 0x9000
        if ins == mgmt.INS_PROVISION:
            if p1 != 0xA5:
                return b"", 0x6A86
            if p2 == mgmt.PROVISION_BIND:
                if self.store_locked:                   # a held profile: bound, opens at the next start
                    if self.refuse_bind:
                        return b"", 0x6F00
                    self.unlock_at_boot = True
                    if self.drk_source == 2:
                        self.drk_source = 3
                    return b"", 0x9000
                self.hmac_key = True
                if self.drk_source == 2:
                    self.drk_source = 3
                return b"", 0x9000
            if p2 == mgmt.PROVISION_LOCK_DEBUG:
                if self.jtag and self.download:
                    return b"", 0x6A88
                self.jtag = self.download = True
                return b"", 0x9000
            return b"", 0x6A86
        if ins in (mgmt.INS_PROFILE_WIPE, mgmt.INS_PROFILE_DELETE, mgmt.INS_PROFILE_SELECT):
            return b"", 0x9000
        if ins == mgmt.INS_EXPORT_BEGIN:
            sw = self._pin_check(data)
            if sw:
                return b"", sw
            self.sess = EXPORT
            m = {1: len(self.stream), 2: hashlib.sha256(self.stream).digest()}
            if self.protocol >= 2:
                self.export_id = bytes(range(8, 16))
                m[3] = self.export_id
            return cbor.encode(m), 0x9000
        if ins == mgmt.INS_EXPORT_READ:
            if self.sess != EXPORT:
                return b"", 0x6985
            if len(data) != 4 + len(self.export_id):
                return b"", 0x6700
            if data[4:] != self.export_id:
                self.sess = None
                return b"", 0x6982
            off = struct.unpack(">I", data[:4])[0]
            return self.stream[off:off + 256], 0x9000
        if ins == mgmt.INS_EXPORT_END:
            self.sess = None
            return b"", 0x9000
        if ins == mgmt.INS_IMPORT_BEGIN:
            if self.protocol >= 3 and p2 == 0 and p1 == 0 and self.boot_status == 0:
                sw = self._pin_check(data)              # into the active profile: like an update
                if sw:
                    return b"", sw
            self.sess, self.upload, self.import_mode = IMPORT, b"", p2
            return self._open_session(), 0x9000
        if ins == mgmt.INS_IMPORT_WRITE:
            if self.sess != IMPORT:
                return b"", 0x6985
            data, sw = self._session_data(data, 4)
            if sw:
                return b"", sw
            off = struct.unpack(">I", data[:4])[0]
            if off != len(self.upload):
                return b"", 0x6A80
            if self.fail_write_at is not None and off >= self.fail_write_at:
                self.sess = None
                return b"", 0x6A84
            self.upload += data[4:]
            return b"", 0x9000
        if ins == mgmt.INS_IMPORT_END:
            if self.sess != IMPORT:
                return b"", 0x6985
            _, sw = self._session_data(data, 0, whole=True)
            if sw:
                return b"", sw
            self.sess = None
            if self.import_mode == 0:
                self.staged = (IMPORT, self.upload)
            return cbor.encode({1: 2, 2: 1, 3: True, 4: len(self.upload), 5: bytes(16), 6: bytes(8), 7: "Work",
                                8: bytes([2, 0, 0]), 9: bytes([2, 0, 0]), 10: 0,
                                11: hashlib.sha256(self.upload).digest()}), 0x9000
        if ins == mgmt.INS_FW_BEGIN:
            if self.protocol >= 3 and self.pending:
                return b"", 0x6985
            params = cbor.decode(data)
            if self.boot_status == 0:
                sw = self._pin_check(params.get(3, b""))
                if sw:
                    return b"", sw
            self.sess, self.upload, self.fw_params = FW, b"", params
            return self._open_session(), 0x9000
        if ins == mgmt.INS_FW_WRITE:
            if self.sess != FW:
                return b"", 0x6985
            data, sw = self._session_data(data, 4)
            if sw:
                return b"", sw
            self.upload += data[4:]
            return b"", 0x9000
        if ins == mgmt.INS_FW_END:
            if self.sess != FW:
                return b"", 0x6985
            _, sw = self._session_data(data, 0, whole=True)
            if sw:
                return b"", sw
            self.sess = None
            d = firmware.parse(self.upload)
            self.staged = (FW, (d["version_tuple"], d["build_profile"]))
            return cbor.encode({1: bytes(d["version_tuple"]), 2: d["platform_id"],
                                3: PROFILE_IDS[d["build_profile"]], 4: d["board"]}), 0x9000
        if ins == mgmt.INS_FW_CONFIRM:
            if self.fail_confirm:
                return b"", 0x6F00
            self.pending = False
            return b"", 0x9000
        if ins == mgmt.INS_FW_ROLLBACK:
            if self.protocol >= 2 and self.boot_status == 0:
                sw = self._pin_check(data)
                if sw:
                    return b"", sw
            self.staged = (FW, ((2, 0, 0), "standard"))
            return b"", 0x9000
        if ins == mgmt.INS_REBOOT:
            if p1 == 1 and self.protocol >= 2 and self.boot_status == 0:
                sw = self._pin_check(data)
                if sw:
                    return b"", sw
            return b"", 0x9000
        return b"", 0x6D00


class FakeCard:
    """What Management needs of librefido.pcsc.Card."""

    def __init__(self, dev):
        self.dev = dev
        self.reader = "Fake Reader 00 00"
        self.boot_id = struct.pack(">I", dev.boot)
        self.protocol = dev.protocol
        self.app = None
        self.locked = 0
        self.closed = False
        self._reset = False

    def mark_reset(self):
        self._reset = True

    @contextmanager
    def transaction(self, aid=None):
        self.locked += 1
        try:
            if aid is not None and self.locked == 1:
                self.select(aid)
            yield self
        finally:
            self.locked -= 1
            if self.locked == 0:
                self.dev.log.append(("END", "reset" if self._reset else "leave"))
                if self._reset:
                    self.dev.sess = None        # a card reset unloads the applet: end_session()
                self._reset = False

    def select(self, aid):
        self.dev.log.append(("SELECT", bytes(aid)))
        if self.dev.busy_from is not None and self.dev.busy:
            raise CardConnectionException("slot busy")
        if bytes(aid) == mgmt.FIDO_AID and not self.dev.fido:
            raise ApduError(0x6A82, "select")
        self.app = bytes(aid)
        return b"LF\x01\x00" + self.boot_id, 0x9000

    def transmit(self, cla, ins, p1, p2, data=b"", le=0, check=True, what=""):
        data = bytes(data)
        self.dev.log.append((ins, p1, p2, data, self.locked))
        if self.dev.busy_from is not None and (self.dev.busy or ins == self.dev.busy_from):
            self.dev.busy = True
            raise CardConnectionException("slot busy")
        resp, sw = self.dev.handle(self.app, ins, p1, p2, data)
        if ins == self.dev.interrupt_after:
            self.dev.interrupt_after = None
            raise KeyboardInterrupt                 # Ctrl-C noticed once the touch wait returned
        if check and sw != 0x9000:
            raise ApduError(sw, what)
        return resp, sw

    def close(self):
        self.closed = True


def management(dev, monkeypatch):
    """Management on dev; reconnect() reboots the simulated device."""
    def open_device(reader=None, timeout=0.0, not_boot_id=None):
        dev.reboot()
        c = FakeCard(dev)
        c.select(MGMT_AID)
        if dev.intruder_select:
            c.app = b"\xA0\x00\x00\x03\x08"     # another program selected PIV right after
        return c
    monkeypatch.setattr(mgmt, "open_device", open_device)
    monkeypatch.setattr(mgmt.time, "sleep", lambda s: None)
    card = FakeCard(dev)
    card.select(MGMT_AID)
    dev.log.clear()
    return mgmt.Management(card)


def commands(dev, ins=None):
    """Logged commands (not SELECTs or transaction ends), optionally only one INS."""
    return [e for e in dev.log if e[0] not in ("SELECT", "END") and (ins is None or e[0] == ins)]
