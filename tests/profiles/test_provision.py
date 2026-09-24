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
    assert not any(s["automated"] for k, s in steps.items() if k != "hmac")   # never burned by the tool
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
