"""4 MB flash layout on the host emulator: only two store regions exist
(LF_EMU_STORE_REGIONS=2), with LF_EMU_BIN_4MB an emulator built with
-DLF_STORE_LOGICAL_SECTORS=64 like the 4 MB firmware. One profile plus the
spare region: the device must boot and work, wipes and imports must still
work, and a second profile must be refused instead of eating the spare."""

import os

import pytest

from harness.emulator import Emulator, Pcscd
from harness import ctaphid
from librefido.mgmt import Management
from librefido.pcsc import ApduError

from test_profiles_backup import make_rk, user_ids, wait_reboot

SW_FILE_FULL = 0x6A84


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    p.start()
    ctaphid.install()
    yield p
    p.stop()


@pytest.fixture
def small(tmp_path):
    e = Emulator(binary=os.environ.get("LF_EMU_BIN_4MB"), workdir=str(tmp_path / "dev"),
                 env={"LF_EMU_STORE_REGIONS": "2"})
    e.start()
    m = Management.open(timeout=15)
    yield e, m
    m.close()
    e.stop()


def test_boots_with_one_profile_and_works(pcscd, small):
    _, m = small
    info = m.info()
    assert info["boot_status"] == "ok"
    assert info["profiles"][0]["used"] and not any(p["used"] for p in info["profiles"][1:])
    make_rk(b"alice")
    assert user_ids() == {b"alice"}


def test_second_profile_is_refused(pcscd, small):
    _, m = small
    for attempt in (lambda: m.select_profile(1), lambda: m.wipe_profile(1)):
        with pytest.raises(ApduError) as ei:
            attempt()
        assert ei.value.sw == SW_FILE_FULL
    info = m.info()
    assert info["boot_status"] == "ok" and info["active"] == 0
    assert not any(p["used"] for p in info["profiles"][1:])


def test_import_into_a_new_slot_is_refused(pcscd, small):
    _, m = small
    make_rk(b"alice")
    stream = m.export_profile()
    with pytest.raises(ApduError) as ei:
        m.import_profile(stream, target=1)
    assert ei.value.sw == SW_FILE_FULL
    assert m.info()["boot_status"] == "ok"
    assert user_ids() == {b"alice"}


def test_wipe_and_import_use_the_spare(pcscd, small):
    _, m = small
    make_rk(b"alice")
    stream = m.export_profile()

    m.wipe_profile(0)
    wait_reboot(m)
    info = m.info()
    assert info["boot_status"] == "ok" and info["last_result"] == "wiped"
    assert user_ids() == set()

    m.import_profile(stream, target=0)
    info = m.info()
    assert info["boot_status"] == "ok"
    assert user_ids() == {b"alice"}

    # and again: the old region became the spare
    m.wipe_profile(0)
    wait_reboot(m)
    assert m.info()["boot_status"] == "ok" and user_ids() == set()
