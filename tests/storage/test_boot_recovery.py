"""Recovery of the resilient store from power cuts and worn-out flash at the
places the resilience tests do not reach: the first system area commit,
boot-time operations (import, delete), the journal log, metadata copies,
records at the sector size, and commands that touch more sectors than the
write cache holds.

Faults are injected by the emulator (lf_region.c): LF_FAULT_CTL names a
control file that the next boot (also the re-exec of a reboot) reads and
removes: "tear <region> <n>" cuts the power at the n-th erase/write of that
region, "fail <region> [<sector> <count>]" makes its erases and writes fail
the way worn-out flash does.

    python -m pytest tests/storage/test_boot_recovery.py

Tests that use the management applet or PIV need the PC/SC stack of
tests/README.md (like tests/profiles).
"""

import os
import shutil
import struct
import subprocess
import time
import zlib

import pytest

from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2

from harness import ctaphid
from harness import emulator as harness_emulator
from harness.emulator import Emulator, Pcscd
from test_store_resilience import last_mount

# Emulator flash layout (lf_region.c) and store layout (lf_store.c).
SECTOR = 4096
EMU_SYS = 0x800000
EMU_STAGE = 0x810000
EMU_STORE0 = 0x890000
EMU_STORE_SIZE = 0x180000
S_LOG, S_POOL, S_A, S_META_A, S_META_B, S_END = 2, 3, 35, 291, 313, 343
META_SECTORS = 22
REG_SYS, REG_STAGE, REG_STORE0 = 1, 2, 3
JREC_SIZE = 256
# 64-bit emulator: next, prev (8 bytes each), fid and length before the payload
MAX_RECORD_PAYLOAD = SECTOR - 20


# -- helpers -----------------------------------------------------------------

def read_at(path, off, n):
    with open(path, "rb") as f:
        f.seek(off)
        return f.read(n)


def write_at(path, off, data):
    with open(path, "r+b") as f:
        f.seek(off)
        f.write(data)


def region_off(region, sector=0):
    return EMU_STORE0 + region * EMU_STORE_SIZE + sector * SECTOR


def log_text(e):
    with open(e.log_path, errors="replace") as f:
        return f.read()


def boot_log(e):
    with open(e.log_path, errors="replace") as f:
        f.seek(e.log_start)
        return f.read()


def wait_log(e, text, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if text in boot_log(e):
            return True
        time.sleep(0.05)
    return False


def fault_emulator(workdir, **kw):
    """An emulator that reads the fault control file of its work directory."""
    ctl = os.path.join(str(workdir), "fault.ctl")
    env = dict(kw.pop("env", {}))
    env["LF_FAULT_CTL"] = ctl
    e = Emulator(workdir=str(workdir), env=env, **kw)
    e.fault_ctl = ctl
    return e


def arm(e, spec):
    """Fault for the next boot of e (the file is consumed by that boot)."""
    with open(e.fault_ctl, "w") as f:
        f.write(spec)


def boot_until_exit(e, timeout=60.0):
    """Boots e and waits for it to end by itself (simulated power loss)."""
    session = harness_emulator._session["emu"]
    if session is not None and session is not e and session.proc is not None:
        session.stop()                  # same ports
    env = dict(os.environ)
    env.update(e.extra_env)
    env["PICO_FLASH_FILE"] = e.flash_path
    env["PICO_EFUSE_FILE"] = e.efuse_path
    env["LF_EMU_VPCD_PORT"] = str(harness_emulator.VPCD_PORT)
    env["LF_EMU_UP_PORT"] = str(harness_emulator.UP_PORT)
    with open(e.log_path, "a") as log:
        p = subprocess.Popen([e.binary], cwd=e.workdir, env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            return p.wait(timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            return None


def wait_exit(e, timeout=60.0):
    """The emulator process (re-executed by a reboot) ends by itself."""
    try:
        rc = e.proc.wait(timeout)
    except subprocess.TimeoutExpired:
        return None
    e.proc = None
    e._log.close()
    return rc


def ctap2():
    dev = ctaphid.open_device()
    return dev, Ctap2(dev)


def make_rk(user_id, rp="example.com"):
    dev, c = ctap2()
    try:
        return c.make_credential(os.urandom(32), {"id": rp, "name": rp},
                                 {"id": user_id, "name": "u", "displayName": "U"},
                                 [{"type": "public-key", "alg": -7}], options={"rk": True})
    finally:
        dev.close()


def user_ids(rp="example.com"):
    dev, c = ctap2()
    try:
        try:
            first = c.get_assertion(rp, os.urandom(32))
        except CtapError as err:
            if err.code == CtapError.ERR.NO_CREDENTIALS:
                return set()
            raise
        found = {first.user["id"]}
        for _ in range((first.number_of_credentials or 1) - 1):
            found.add(c.get_next_assertion().user["id"])
        return found
    finally:
        dev.close()


def crc32c(data):
    """The firmware's crc32c() (crypto_utils.c) is the zlib CRC-32."""
    return zlib.crc32(data) & 0xFFFFFFFF


@pytest.fixture
def emu(tmp_path):
    ctaphid.install()
    e = fault_emulator(tmp_path / "dev")
    yield e
    e.stop()


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    p.start()
    ctaphid.install()
    yield p
    p.stop()


def management(timeout=15):
    from librefido.mgmt import Management
    return Management.open(timeout=timeout)


def wait_reboot(m):
    m.reconnect(timeout=30)
    time.sleep(0.3)


class Piv:
    """PIV data objects over short, chained APDUs (yubikit refuses commands
    longer than a YubiKey takes). Authenticated with the default management
    key."""

    def __init__(self):
        from harness.card import Card, YkConnection
        from yubikit.piv import DEFAULT_MANAGEMENT_KEY, PivSession
        self.card = Card()
        PivSession(YkConnection(self.card)).authenticate(DEFAULT_MANAGEMENT_KEY)

    @staticmethod
    def _len(n):
        return bytes([n]) if n < 0x80 else (b"\x81" + bytes([n]) if n < 0x100 else b"\x82" + n.to_bytes(2, "big"))

    def put(self, oid, data):
        tag = b"\x5c\x03" + oid.to_bytes(3, "big")
        self.card.transmit(0x00, 0xDB, 0x3F, 0xFF, tag + b"\x53" + self._len(len(data)) + data)

    def get(self, oid):
        resp, _ = self.card.transmit(0x00, 0xCB, 0x3F, 0xFF, b"\x5c\x03" + oid.to_bytes(3, "big"), le=0)
        assert resp[0] == 0x53
        n, off = resp[1], 2
        if n == 0x81:
            n, off = resp[2], 3
        elif n == 0x82:
            n, off = int.from_bytes(resp[2:4], "big"), 4
        return resp[off:off + n]

    def close(self):
        self.card.close()


# -- system area ---------------------------------------------------------------

@pytest.mark.parametrize("op", [0, 1, 2, 4], ids=["erase-copy0", "write-copy0", "mark-copy0", "write-copy1"])
def test_torn_first_system_commit_is_still_a_first_boot(emu, op):
    """A cut in the very first system area commit (per copy: erase, image,
    completion mark) leaves no acknowledged generation, or a complete first
    copy: the next boot never stays in safe mode."""
    arm(emu, "tear %d %d" % (REG_SYS, op))
    assert boot_until_exit(emu) == 99
    emu.start()
    assert wait_log(emu, "profile 1 mounted"), boot_log(emu)
    assert "SAFE MODE" not in boot_log(emu)
    make_rk(b"alice")
    emu.restart()
    assert user_ids() == {b"alice"}


def test_flash_encryption_without_encrypted_partitions_is_refused(emu):
    """Flash encryption on, key storage partitions without the "encrypted"
    flag: the map would decrypt plain data into garbage. Safe mode, and
    nothing is written."""
    emu.start()
    make_rk(b"alice")
    emu.stop()
    before = read_at(emu.flash_path, 0, os.path.getsize(emu.flash_path))
    emu.start(LF_EMU_FE_UNFLAGGED=1)
    assert wait_log(emu, "SAFE MODE"), boot_log(emu)
    assert "'encrypted' flag" in boot_log(emu)
    emu.stop()
    assert read_at(emu.flash_path, 0, len(before)) == before
    emu.start()
    assert user_ids() == {b"alice"}


def test_damaged_system_area_is_never_taken_for_a_blank_one(emu):
    """Every complete copy damaged beyond repair: safe mode, and no store is
    formatted again (the profiles are still there)."""
    emu.start()
    make_rk(b"alice")
    emu.stop()
    store_before = read_at(emu.flash_path, EMU_STORE0, 64 * SECTOR)
    for slot in range(16):
        head = read_at(emu.flash_path, EMU_SYS + slot * SECTOR, 4)
        if head == b"LFSY":
            write_at(emu.flash_path, EMU_SYS + slot * SECTOR + 16, os.urandom(300))
    emu.start()
    assert wait_log(emu, "SAFE MODE"), boot_log(emu)
    emu.stop()
    assert read_at(emu.flash_path, EMU_STORE0, 64 * SECTOR) == store_before


# -- journal and metadata --------------------------------------------------------

def test_stale_commit_left_by_a_torn_log_erase_is_not_replayed(emu):
    """A cut while the full journal log is erased can leave an old COMMIT
    readable with its APPLIED record gone: replaying it would roll newer
    transactions back."""
    emu.start()
    for i in range(6):
        make_rk(b"early%d" % i)
    emu.stop()
    log = read_at(emu.flash_path, region_off(0, S_LOG), SECTOR)
    commits = [log[i:i + JREC_SIZE] for i in range(0, SECTOR, JREC_SIZE)
               if log[i:i + 4] == b"LFJ3" and log[i + 4] == 1]
    assert commits
    old = commits[-1]
    # its journal images, so that it could really be replayed
    slots = [struct.unpack_from("<H", old, 16 + 12 * i + 4)[0] for i in range(old[5])]
    pool = {s: read_at(emu.flash_path, region_off(0, S_POOL + s), SECTOR) for s in slots}

    emu.start()
    make_rk(b"late")
    emu.stop()
    write_at(emu.flash_path, region_off(0, S_LOG), old + b"\xff" * (SECTOR - JREC_SIZE))
    for s, img in pool.items():
        write_at(emu.flash_path, region_off(0, S_POOL + s), img)

    emu.start()
    m = last_mount(emu)
    assert m["journal"] == "clean" and m["unrecoverable"] == 0
    assert "replayed transaction" not in boot_log(emu)
    assert user_ids() == {b"early%d" % i for i in range(6)} | {b"late"}
    emu.restart()
    assert user_ids() == {b"early%d" % i for i in range(6)} | {b"late"}


def test_worn_metadata_copy_does_not_fail_commits(emu):
    """Metadata copy A cannot be written any more: copy B carries every
    transaction, commands succeed and PIN retries count exactly."""
    emu.start()
    make_rk(b"alice")
    dev, c = ctap2()
    try:
        ClientPin(c).set_pin("12345678")
    finally:
        dev.close()
    emu.stop()

    arm(emu, "fail %d %d %d" % (REG_STORE0, S_META_A, META_SECTORS))
    emu.start()
    dev, c = ctap2()
    try:
        pin = ClientPin(c)
        for expect in (7, 6):
            with pytest.raises(CtapError) as err:
                pin.get_pin_token("00000000")
            assert err.value.code == CtapError.ERR.PIN_INVALID
            assert pin.get_pin_retries()[0] == expect
        pin.get_pin_token("12345678")
        assert pin.get_pin_retries()[0] == 8
        with pytest.raises(CtapError) as err:
            pin.get_pin_token("00000000")
        assert pin.get_pin_retries()[0] == 7
    finally:
        dev.close()
    assert "commit failed" not in boot_log(emu)

    emu.restart()                       # the fault was for one boot only
    m = last_mount(emu)
    assert m["meta"] >= 1 and m["unrecoverable"] == 0      # copy A caught up
    assert user_ids() == {b"alice"}
    dev, c = ctap2()
    try:
        assert ClientPin(c).get_pin_retries()[0] == 7     # the last attempt was kept
    finally:
        dev.close()
    emu.restart()
    assert last_mount(emu)["meta"] == 0


# -- boot-time operations (management applet) -------------------------------------

@pytest.fixture
def mgmt_device(tmp_path, pcscd):
    """Profile 1 (region 0) with alice, profile 2 (region 1) with bob."""
    e = fault_emulator(tmp_path / "dev")
    e.start()
    m = management()
    make_rk(b"alice")
    m.select_profile(1)
    wait_reboot(m)
    make_rk(b"bob")
    m.select_profile(0)
    wait_reboot(m)
    yield e, m
    try:
        m.close()
    except Exception:
        pass
    e.stop()


def region_formatted(e, region):
    return read_at(e.flash_path, region_off(region), 4) == b"LFST"


def region_erased(e, region):
    data = read_at(e.flash_path, region_off(region), S_END * SECTOR)
    return data == b"\xff" * len(data)


def test_interrupted_erase_of_a_deleted_profile_is_finished(mgmt_device):
    """The erase of a deleted profile's region is cut off: the next boot
    finishes it (the header goes last, so the region is still recognised)."""
    e, m = mgmt_device
    assert region_formatted(e, 1)
    arm(e, "tear %d 40" % (REG_STORE0 + 1))
    m.delete_profile(1)
    assert wait_exit(e) == 99
    m.close()
    e.start()
    m = management()
    try:
        info = m.info()
        assert info["boot_status"] == "ok" and not info["profiles"][1]["used"]
        assert info["last_result"] == "deleted"
    finally:
        m.close()
    assert region_erased(e, 1)
    assert user_ids() == {b"alice"}


def sys_generation(e):
    gens = [int.from_bytes(read_at(e.flash_path, EMU_SYS + s * SECTOR + 8, 8), "little")
            for s in range(16) if read_at(e.flash_path, EMU_SYS + s * SECTOR, 4) == b"LFSY"]
    return max(gens)


def wait_safe_mode(e, since, timeout=30.0):
    deadline = time.time() + timeout
    while "SAFE MODE" not in read_at(e.log_path, since, 1 << 20).decode(errors="replace"):
        assert time.time() < deadline, "no safe mode"
        time.sleep(0.1)


def test_import_survives_a_failing_system_area(mgmt_device):
    """The import is built, but the system area cannot record the switch:
    safe mode, and no region is erased (the old profile stays what the flash
    record says it is). The next boot settles the operation; profile 2 is
    still bob's."""
    e, m = mgmt_device
    stream = m.export_profile()                 # profile 1, alice
    # generation +1: the import request, +2: the attempt record of the boot
    # that applies it, +3: the switch; only the slot of the last one fails
    slot = (sys_generation(e) + 3) % 8
    arm(e, "fail %d %d 2" % (REG_SYS, 2 * slot))
    start = os.path.getsize(e.log_path)
    m._upload(stream, 1, 0)                     # replace profile 2; the device reboots
    m.close()
    wait_safe_mode(e, start)
    e.stop()
    assert "cannot record operation" in read_at(e.log_path, start, 1 << 20).decode(errors="replace")
    assert region_formatted(e, 0) and region_formatted(e, 1)
    e.start()                                   # the fault was for that boot only
    m = management()
    try:
        info = m.info()
        # the staged stream (keys in the clear) was erased in safe mode, so
        # the retried import fails; the old profile is untouched
        assert info["boot_status"] == "ok" and info["last_result"] in ("import failed", "imported")
        imported = info["last_result"] == "imported"
        m.select_profile(1)
        wait_reboot(m)
        assert user_ids() == ({b"alice"} if imported else {b"bob"})
        m.select_profile(0)
        wait_reboot(m)
        assert user_ids() == {b"alice"}
    finally:
        m.close()


def test_import_that_never_completes_is_given_up(mgmt_device):
    """Every boot that starts a pending import records the attempt first: an
    import that dies each time (here a power cut, in real life a crash on a
    hostile stream) is abandoned after three boots instead of looping."""
    e, m = mgmt_device
    stream = m.export_profile()
    arm(e, "tear %d 0" % (REG_STORE0 + 2))      # dies formatting the new region
    m._upload(stream, 1, 0)
    assert wait_exit(e) == 99
    m.close()
    for _ in range(2):
        arm(e, "tear %d 0" % (REG_STORE0 + 2))
        assert boot_until_exit(e) == 99
    e.start()
    m = management()
    try:
        info = m.info()
        assert info["boot_status"] == "ok" and info["last_result"] == "import failed"
        assert "abandoned after 3 attempts" in boot_log(e)
        m.select_profile(1)
        wait_reboot(m)
        assert user_ids() == {b"bob"}
    finally:
        m.close()


@pytest.mark.parametrize("change", ["target", "purpose"])
def test_import_uses_only_the_stream_staged_for_it(mgmt_device, change):
    """Between the import request and the boot that applies it, the staged
    stream is replaced (another slot, or an export): the import is refused
    and the profile stays as it was."""
    e, m = mgmt_device
    stream = m.export_profile()
    arm(e, "tear %d 0" % (REG_STORE0 + 2))      # the boot dies formatting the new region
    m._upload(stream, 1, 0)
    assert wait_exit(e) == 99
    m.close()
    hdr = bytearray(read_at(e.flash_path, EMU_STAGE, 48))
    assert hdr[:4] == b"LFSG" and hdr[6] == 2 and hdr[7] == 1   # import stream for profile 2
    if change == "target":
        hdr[7] = 2
    else:
        hdr[6] = 1                              # an export
    assert int.from_bytes(hdr[44:48], "little") == crc32c(bytes(read_at(e.flash_path, EMU_STAGE, 44)))
    hdr[44:48] = crc32c(bytes(hdr[:44])).to_bytes(4, "little")
    write_at(e.flash_path, EMU_STAGE, bytes(hdr))
    e.start()
    m = management()
    try:
        info = m.info()
        assert info["boot_status"] == "ok" and info["last_result"] == "import failed"
        assert "is not the requested one" in boot_log(e)
        m.select_profile(1)
        wait_reboot(m)
        assert user_ids() == {b"bob"}
    finally:
        m.close()
    # the refused stream (keys in the clear) did not stay behind
    assert read_at(e.flash_path, EMU_STAGE, 4) != b"LFSG"


# -- root key (security.c) ----------------------------------------------------------

@pytest.fixture
def emulators(tmp_path):
    """Emulators made by a test, stopped whatever happens."""
    made = []

    def make(**kw):
        e = fault_emulator(tmp_path / ("dev%d" % len(made)), **kw)
        made.append(e)
        return e
    yield make
    for e in made:
        e.stop()


def test_plain_root_key_is_not_bound_behind_the_users_back(pcscd, emulators):
    """Once the chip has the HMAC key and Secure Boot, a root key found in
    plain (a profile created before the binding, or one planted by someone
    who wrote the flash) is not bound silently: the key store stays locked
    until the binding command is repeated with that profile active."""
    e = emulators(env={"LF_EMU_CHIP_SECURE": "1"})
    e.start()
    m = management()
    try:
        make_rk(b"alice")
        m.select_profile(1)
        wait_reboot(m)
        make_rk(b"bob")
        m.select_profile(0)
        wait_reboot(m)
        m.provision_hmac()
        assert m.info()["security"]["root_key"] == "flash, bound to HMAC eFuse key"
        m.select_profile(1)
        wait_reboot(m)
        sec = m.info()["security"]
        assert sec["hmac_key"] and sec["root_key"] == "flash (not bound to the chip)"
        with pytest.raises(Exception):
            make_rk(b"mallory")                 # key store locked
        m.provision_hmac()                      # the explicit binding (touch)
        assert m.info()["security"]["root_key"] == "flash, bound to HMAC eFuse key"
    finally:
        m.close()
    e.restart()
    assert user_ids() == {b"bob"}


def test_wrapped_root_key_without_its_chip_key_locks_the_store(pcscd, emulators):
    """A root key wrapped with the HMAC key of a chip that does not have it
    (lost eFuse file here, a moved flash chip in real life) is never taken
    for a missing one: no other root key is used or created."""
    e = emulators()
    e.start()
    m = management()
    try:
        make_rk(b"alice")
        m.provision_hmac()
    finally:
        m.close()
    e.stop()
    with open(e.efuse_path, "rb") as f:
        key = f.read()
    record = read_at(e.flash_path, EMU_STORE0, EMU_STORE_SIZE)
    os.unlink(e.efuse_path)
    e.start()
    with pytest.raises(CtapError):
        user_ids()                              # locked, not an empty authenticator
    e.stop()
    assert read_at(e.flash_path, EMU_STORE0, EMU_STORE_SIZE) == record
    with open(e.efuse_path, "wb") as f:
        f.write(key)
    e.start()
    assert user_ids() == {b"alice"}


# -- file system records ----------------------------------------------------------

@pytest.fixture
def card_device(tmp_path, pcscd):
    pytest.importorskip("yubikit.piv")
    e = fault_emulator(tmp_path / "dev")
    e.start()
    management().close()                        # the card is in the reader
    yield e
    e.stop()


def test_objects_larger_than_a_record_are_refused(card_device):
    """A record never crosses a sector: objects that would need one are
    refused cleanly and the file system keeps working."""
    from harness.card import ApduError
    from yubikit.piv import OBJECT_ID
    e = card_device
    make_rk(b"alice")
    piv = Piv()
    try:
        fits = os.urandom(MAX_RECORD_PAYLOAD)
        piv.put(OBJECT_ID.RETIRED1, fits)
        # up to what one command carries (4096 bytes with the object tags)
        for n in (MAX_RECORD_PAYLOAD + 1, MAX_RECORD_PAYLOAD + 4, MAX_RECORD_PAYLOAD + 11):
            with pytest.raises(ApduError) as err:
                piv.put(OBJECT_ID.RETIRED2, os.urandom(n))
            assert err.value.sw == 0x6581, n
        piv.put(OBJECT_ID.RETIRED3, b"small")
        assert piv.get(OBJECT_ID.RETIRED1) == fits
    finally:
        piv.close()
    make_rk(b"bob")
    e.restart()
    assert user_ids() == {b"alice", b"bob"}
    piv = Piv()
    try:
        assert piv.get(OBJECT_ID.RETIRED1) == fits
        assert piv.get(OBJECT_ID.RETIRED3) == b"small"
    finally:
        piv.close()


def fido_reset():
    dev, c = ctap2()
    try:
        c.reset()
    finally:
        dev.close()


def test_power_cut_in_a_reset_spanning_many_sectors(card_device, tmp_path):
    """authenticatorReset deletes FIDO records spread over more sectors than
    the write cache holds, next to PIV objects. A cut at any point leaves a
    consistent list: the PIV objects survive, can be rewritten (which relinks
    their neighbours) and the reset can be done again."""
    from yubikit.piv import OBJECT_ID
    e = card_device
    objects = [OBJECT_ID.RETIRED1 + i for i in range(10)]
    content = {}
    piv = Piv()
    try:
        for i, oid in enumerate(objects):
            make_rk(b"a%d" % i)
            make_rk(b"b%d" % i)
            content[oid] = os.urandom(3700)
            piv.put(oid, content[oid])
    finally:
        piv.close()
    e.stop()
    base = str(tmp_path / "base")
    shutil.copytree(e.workdir, base, ignore=shutil.ignore_patterns("emulator.log", "fault.ctl"))

    def check(expect):
        management().close()                    # the restarted card is in the reader
        piv = Piv()
        try:
            for oid in objects:
                assert piv.get(oid) == expect[oid], hex(oid)
        finally:
            piv.close()

    batches_seen = False
    completed = False
    step = int(os.environ.get("LF_TEST_RESET_STEP", "7"))
    for n in range(0, 2000, step):
        wd = tmp_path / ("n%04d" % n)
        shutil.copytree(base, wd)
        d = fault_emulator(wd)
        try:
            d.start(LF_FAULT_OPS=n)
            done = False
            try:
                fido_reset()
                done = True
            except Exception:
                pass
            died = d.proc.poll() is not None or wait_exit(d, 1.0) is not None
            batches_seen |= "cache full" in log_text(d)
            d.stop()
            if done and not died:
                completed = True
                break
            d.start()
            m = last_mount(d)
            assert m["unrecoverable"] == 0 and m["journal"] != "corrupt", (n, m)
            check(content)
            # rewrite every object larger: each one moves, which relinks its
            # neighbours in the list
            new = {oid: os.urandom(3708 + 8 * i) for i, oid in enumerate(objects)}
            piv = Piv()
            try:
                for oid in objects:
                    piv.put(oid, new[oid])
            finally:
                piv.close()
            fido_reset()
            make_rk(b"after")
            d.restart()
            check(new)
            assert user_ids() == {b"after"}
        finally:
            d.stop()
            shutil.rmtree(str(wd), ignore_errors=True)
    assert completed
    assert batches_seen, "the reset fitted in one batch: the test does not cover split commits"
