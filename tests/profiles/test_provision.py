"""Security provisioning on the emulator (its eFuses are a file): the plan,
the refusals, and binding the root key to the chip, after which credentials
and clones still work.

    PYTHONPATH=tests:tools/librefido:tests/profiles python -m pytest tests/profiles/test_provision.py
"""

import json
import os

import pytest

from librefido import provision
from test_profiles_backup import device, emulators, make_rk, pcscd, user_ids, wait_reboot  # noqa: F401


def test_plan_and_binding(pcscd, emulators, tmp_path):
    e = emulators()
    m = device(e)
    make_rk(b"alice")
    info = m.info()
    steps = {s["id"]: s for s in provision.plan(info)}
    assert not steps["hmac"]["is_done"] and steps["hmac"]["automated"]
    # the tool burns only what leads to level 2 (it cannot brick the board)
    assert [k for k, s in steps.items() if s["automated"]] == ["hmac", "lock_debug"]
    assert all(s["brick_risk"].startswith("none") for s in steps.values() if s["automated"])
    assert info["security"]["root_key"] == "flash (not bound to the chip)"

    # a wrong confirmation changes nothing
    with pytest.raises(provision.ProvisionError):
        provision.bind_root_key(m, lambda expected: "yes", directory=str(tmp_path))
    assert not m.info()["security"]["hmac_key"]
    assert not os.path.exists(e.efuse_path) or os.path.getsize(e.efuse_path) == 0

    after = provision.bind_root_key(m, lambda expected: expected, directory=str(tmp_path))
    assert after["security"]["hmac_key"]
    assert after["security"]["root_key"] == "flash, bound to HMAC eFuse key"
    saved = [p for p in os.listdir(tmp_path) if p.startswith("librefido-provision-")]
    assert len(saved) == 2                              # before each attempt
    with open(tmp_path / saved[0]) as f:
        meta = json.load(f)
    assert meta["chip_serial"] == info["chip_serial"] and "security" in meta

    # the re-wrapped root key opens the same credentials after a power cycle
    e.restart()
    wait_reboot(m)
    assert m.info()["security"]["root_key"] == "flash, bound to HMAC eFuse key"
    assert user_ids() == {b"alice"}
    # done once
    assert provision.bind_root_key(m, lambda expected: pytest.fail("asked again"),
                                   directory=str(tmp_path))["security"]["hmac_key"]
    m.close()


def test_profile_without_root_key_is_recorded_by_the_tool(pcscd, emulators, tmp_path):
    """A profile without root key (legacy derivations; here restored from a
    backup without its root record) on a chip with the HMAC key and Secure
    Boot is held by the firmware: INFO says "none" and the key store is
    locked. bind-root-key recognises it and records it on the chip (same
    confirmation and touch); after a restart the profile is usable."""
    import hashlib
    a = emulators("a")
    m = device(a)
    make_rk(b"alice")
    stream = m.export_profile()
    m.close()
    a.stop()
    recs, off = [], 0
    while off < len(stream):
        n = int.from_bytes(stream[off + 1:off + 3], "little")
        recs.append((stream[off], stream[off + 3:off + 3 + n]))
        off += 3 + n
    body = b"".join(bytes([t]) + len(v).to_bytes(2, "little") + v for t, v in recs if t not in (0x02, 0x7F))
    rootless = body + b"\x7f" + (32).to_bytes(2, "little") + hashlib.sha256(body).digest()

    b = emulators("b")
    m = device(b)
    m.import_profile(rootless, 1)
    m.close()
    b.stop()
    with open(b.efuse_path, "wb") as f:
        f.write(os.urandom(32))                     # the chip has its HMAC key ...
    b.extra_env["LF_EMU_CHIP_SECURE"] = "1"         # ... and Secure Boot
    m = device(b)
    m.select_profile(1)
    wait_reboot(m)
    info = m.info()
    assert info["active"] == 1 and info["security"]["root_key"].startswith("none")
    assert m.keystore_unlocked() is False
    s = provision.check_consistent(info, False)
    assert s["held_none"]
    with pytest.raises(Exception):
        m.export_profile()                          # a held profile is not exported
    said = []
    with pytest.raises(provision.ProvisionError):
        provision.bind_root_key(m, lambda expected: "no", directory=str(tmp_path), out=said.append)
    assert provision.HELD_NONE_TEXT in said
    provision.bind_root_key(m, lambda expected: expected, directory=str(tmp_path), out=said.append)
    assert any("Restart the key" in x for x in said)
    b.restart()
    wait_reboot(m)
    # unlocked (its records came from a profile with a root key, so their
    # content does not open here: this checks the key store state only)
    assert m.info()["active"] == 1 and m.keystore_unlocked() is True
    said.clear()
    provision.bind_root_key(m, lambda expected: pytest.fail("asked"), directory=str(tmp_path), out=said.append)
    assert "recorded on the chip" in said[-1]
    provision.lock_debug(m, lambda expected: pytest.fail("asked"), directory=str(tmp_path), out=said.append)
    assert "already done" in said[-1]               # (not refused as inconsistent any more)
    assert len(m.export_profile()) > 0              # and it can be backed up
    m.close()


def test_lock_debug_reaches_level_2(pcscd, emulators, tmp_path):
    """Locking debugging (JTAG, secure download mode) follows the rules of the
    binding: confirmation, metadata first, touch, verified afterwards; with
    the root key bound that is protection level 2, kept after a restart."""
    from librefido import policy
    from librefido.pcsc import ApduError
    e = emulators()
    m = device(e)
    make_rk(b"alice")
    provision.bind_root_key(m, lambda expected: expected, directory=str(tmp_path))
    assert policy.protection_level(m.info()["security"]) == 1
    with pytest.raises(provision.ProvisionError):
        provision.lock_debug(m, lambda expected: "yes", directory=str(tmp_path))
    assert not m.info()["security"]["jtag_disabled"]
    after = provision.lock_debug(m, lambda expected: expected, directory=str(tmp_path))
    assert after["security"]["jtag_disabled"] and after["security"]["download_restricted"]
    assert policy.protection_level(after["security"]) == 2
    with pytest.raises(ApduError) as err:
        m.lock_debug()
    assert err.value.sw == 0x6A88                       # already locked
    e.restart()
    wait_reboot(m)
    assert policy.protection_level(m.info()["security"]) == 2
    assert user_ids() == {b"alice"}
    m.close()


def test_pin_of_a_held_root_key_is_never_spent(pcscd, emulators, tmp_path):
    """A profile whose root key waits to be bound (plain root, HMAC key and
    Secure Boot present) keeps it unloaded: its PIN verifier cannot be
    checked, so the management PIN check refuses (6982) before any retry is
    used, even with the right PIN."""
    import hashlib
    from fido2 import cbor
    from librefido.mgmt import INS_EXPORT_BEGIN, INS_FW_BEGIN, INS_IMPORT_BEGIN
    from librefido.pcsc import ApduError
    from test_profiles_backup import ctap2, pin_retries, set_pin
    e = emulators(env={"LF_EMU_CHIP_SECURE": "1"})
    m = device(e)
    m.select_profile(1)
    wait_reboot(m)
    set_pin("123456")                                   # profile 2 has a PIN, its root is plain
    m.select_profile(0)
    wait_reboot(m)
    provision.bind_root_key(m, lambda expected: expected, directory=str(tmp_path))
    m.select_profile(1)                                 # its root key is held, not bound
    wait_reboot(m)
    dev, c = ctap2()
    try:
        assert c.info.options.get("clientPin") is True  # known although the key store is locked
    finally:
        dev.close()
    with open(e.binary, "rb") as f:
        img = f.read()
    fw_params = cbor.encode({1: len(img), 2: hashlib.sha256(img).digest(), 3: b"123456"})
    for ins, p1, data in ((INS_FW_BEGIN, 0, fw_params), (INS_EXPORT_BEGIN, 0, b"123456"),
                          (INS_IMPORT_BEGIN, 1, b"123456")):
        for _ in range(3):
            with pytest.raises(ApduError) as err:
                m._cmd(ins, p1, data=data)
            assert err.value.sw == 0x6982, hex(ins)
    m.provision_hmac()                                  # binds the held root key
    e.restart()
    m.reconnect()
    assert m.info()["security"]["root_key"] == "flash, bound to HMAC eFuse key"
    assert pin_retries() == 8                           # not a single retry was used
    m.close()


def test_no_backup_without_its_root_key(pcscd, emulators, tmp_path):
    """A profile whose root key is held (not in use) is not exported: the
    backup would lack the root key and every key sealed with it."""
    from librefido.mgmt import INS_EXPORT_BEGIN
    from librefido.pcsc import ApduError
    e = emulators(env={"LF_EMU_CHIP_SECURE": "1"})
    m = device(e)
    m.select_profile(1)                                 # no PIN on this one
    wait_reboot(m)
    m.select_profile(0)
    wait_reboot(m)
    provision.bind_root_key(m, lambda expected: expected, directory=str(tmp_path))
    m.select_profile(1)
    wait_reboot(m)
    with pytest.raises(ApduError) as err:
        m._cmd(INS_EXPORT_BEGIN)
    assert err.value.sw == 0x6982
    m.provision_hmac()
    e.restart()
    m.reconnect()
    assert len(m.export_profile()) > 0
    m.close()


def test_bound_profile_clones_to_another_chip(pcscd, emulators, tmp_path):
    a = emulators("a")
    m = device(a)
    make_rk(b"alice")
    provision.bind_root_key(m, lambda expected: expected, directory=str(tmp_path))
    stream = m.export_profile()
    m.close()
    a.stop()

    b = emulators("b")
    m = device(b)
    m.import_profile(stream, 1)
    m.select_profile(1)
    wait_reboot(m)
    assert user_ids() == {b"alice"}
    m.close()
