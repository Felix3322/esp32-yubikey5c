"""Helpers for the tests of stores written by earlier firmware: records are
planted through a profile backup (export, edit, import into the same
emulator), and the emulator can run a new firmware image unconfirmed (a
reset would roll it back), when records of earlier firmware must not be
rewritten yet.
"""

import hashlib
import re
import struct
import threading

from harness.emulator import Button, Emulator
from librefido import backup, firmware
from librefido.mgmt import Management

REC_FILE, REC_END = backup.REC_FILE, backup.REC_END


def hash_multi(data):
    """pico-keys-sdk hash_multi() of the emulator (no chip serial mixed in)."""
    h = hashlib.sha256()
    iters, n = 256, len(data)
    while iters > n:
        h.update(data)
        iters -= n
    if iters > 0:
        h.update(data[:iters])
    return h.digest()


def double_hash_pin(pin):
    o1 = bytearray(hash_multi(pin))
    for i in range(len(o1)):
        o1[i] ^= pin[i % len(pin)]
    return hash_multi(bytes(o1))


def meta_file(entries):
    """EF_META (0xE010) with the given {key reference: record} entries, as
    meta_add() lays them out."""
    out = b""
    for fid, data in entries.items():
        out += bytes([fid & 0x1F, 2 + len(data)]) + struct.pack(">H", fid) + data
    return out


def files_of(stream):
    header, records = backup.parse_stream(stream)
    return {struct.unpack_from("<H", v)[0]: v[2:] for t, v in records if t == REC_FILE}


def edit_stream(stream, replace):
    """The stream with files replaced ({fid: bytes}) or added."""
    header, records = backup.parse_stream(stream)
    out, seen = [], set()
    for t, v in records:
        if t == REC_END:
            continue
        if t == REC_FILE:
            fid = struct.unpack_from("<H", v)[0]
            if fid in replace:
                seen.add(fid)
                v = struct.pack("<H", fid) + replace[fid]
        out.append((t, v))
    for fid, data in replace.items():
        if fid not in seen:
            out.append((REC_FILE, struct.pack("<H", fid) + data))
    body = b"".join(bytes([t]) + struct.pack("<H", len(v)) + v for t, v in out)
    return body + bytes([REC_END]) + struct.pack("<H", 32) + hashlib.sha256(body).digest()


def touching(fn):
    """Runs fn while the button of a manual-presence emulator is pressed
    every 0.3 s."""
    done = threading.Event()

    def press():
        b = Button()
        while not done.wait(0.3):
            b.press(0.05)
        b.close()
    t = threading.Thread(target=press)
    t.start()
    try:
        return fn()
    finally:
        done.set()
        t.join()


def management():
    return Management.open(timeout=15)


def with_management(fn):
    """fn(Management) on a session of its own. A management session kept
    open while other connections of the tests come and go (they power the
    card down when they close) leaves the reader refusing new connections,
    so it is never kept open across them."""
    m = management()
    try:
        return fn(m)
    finally:
        m.close()


def plant(replace):
    """Exports the active profile, replaces files and imports it back (the
    device reboots and rebuilds its store)."""
    def run(m):
        stream = m.export_profile()
        m.import_profile(edit_stream(stream, replace), target=0)
    with_management(run)


def run_unconfirmed(e, version=(2, 1, 0)):
    """Installs the emulator's own image as version 2.1.0 (or version)
    without confirming it: the device runs firmware a reset would roll
    back."""
    with open(e.binary, "rb") as f:
        img = firmware.set_version(f.read(), version)

    def run(m):
        m.update_firmware(img, confirm=False)
        fw = m.info()["firmware_slot"]
        assert fw["unconfirmed"], fw
    with_management(run)


def confirm():
    with_management(lambda m: m.confirm_firmware())


def scanned_len(e, fid):
    """Length of file fid at the last store scan in the emulator log (the
    size of the record as stored: sealed records are longer)."""
    with open(e.log_path, errors="replace") as f:
        found = re.findall(r"scan fid %x, len (\d+)" % fid, f.read())
    return int(found[-1]) if found else None


def emulator(tmp_path, name="dev", **env):
    return Emulator(workdir=str(tmp_path / name), env=env or None)
