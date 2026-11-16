"""The device-wide USB VID/PID board setting (management applet BOARD_SET /
INFO key 17), on the host emulator. See tests/profiles/test_profiles_backup.py
for the fixtures."""

import pytest

from harness.emulator import Emulator, Pcscd
from harness import ctaphid
from librefido.mgmt import Management
from librefido.pcsc import ApduError


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no user-mode pcscd configured (see tests/README.md)")
    p.start()
    ctaphid.install()
    yield p
    p.stop()


def device(e):
    e.start()
    return Management.open(timeout=15)


def test_usb_vidpid_is_default_then_custom_then_reset(pcscd, tmp_path):
    e = Emulator(workdir=str(tmp_path / "dev"))
    try:
        m = device(e)
        board = m.info()["board"]
        assert board["usb_custom"] is False and "vid" not in board

        m.set_usb_vidpid(0x1209, 0x2440)
        board = m.info()["board"]
        assert board["usb_custom"] is True and board["vid"] == 0x1209 and board["pid"] == 0x2440

        # A custom identity survives a restart (it is stored device-wide).
        m.reboot()
        m.reconnect(timeout=20)
        board = m.info()["board"]
        assert board["vid"] == 0x1209 and board["pid"] == 0x2440

        m.reset_usb_vidpid()
        board = m.info()["board"]
        assert board["usb_custom"] is False and "vid" not in board
    finally:
        e.stop()


def test_led_gpio_is_stored_and_refuses_bad_pins(pcscd, tmp_path):
    e = Emulator(workdir=str(tmp_path / "dev"))
    try:
        m = device(e)
        assert "led_gpio" not in m.info()["board"]      # the emulator build has no LED pin
        m.set_led_gpio(21)
        assert m.info()["board"]["led_gpio"] == 21
        m.reboot()
        m.reconnect(timeout=20)
        assert m.info()["board"]["led_gpio"] == 21
        with pytest.raises(ApduError) as err:
            m.set_led_gpio(64)                          # not a pin of this board
        assert err.value.sw == 0x6A80
        assert m.info()["board"]["led_gpio"] == 21
    finally:
        e.stop()


def test_usb_vidpid_accepts_any_vid_and_refuses_bad_values(pcscd, tmp_path):
    e = Emulator(workdir=str(tmp_path / "dev"))
    try:
        m = device(e)
        m.set_usb_vidpid(0x1050, 0x0407)
        board = m.info()["board"]
        assert board["usb_custom"] is True and board["vid"] == 0x1050 and board["pid"] == 0x0407
        m.reset_usb_vidpid()
        with pytest.raises(ValueError):             # VID 0 is not an identity
            m.set_usb_vidpid(0, 0x1234)
    finally:
        e.stop()
