"""librefido.mgmt against a simulated device: PIN handling, transactions,
firmware update verification, profile names."""

import pytest
from fido2 import cbor
from smartcard.Exceptions import CardConnectionException

import fakedev as F
from librefido import mgmt
from librefido.mgmt import PinRequired, clip_name
from librefido.pcsc import ApduError, MGMT_AID

STREAM = bytes(range(256)) * 3


# -- FIDO PIN ------------------------------------------------------------------

def test_pin_state_comes_from_the_fido_application(monkeypatch):
    for pin, fido, want in (("1234", True, True), (None, True, False), ("1234", False, None)):
        dev = F.FakeDevice(pin=pin, fido=fido)
        m = F.management(dev, monkeypatch)
        assert m.fido_pin_set() is want
        assert m.card.app == MGMT_AID and m.card.locked == 0       # management selected again


def test_export_never_guesses_an_empty_pin(monkeypatch):
    dev = F.FakeDevice(pin="1234", stream=STREAM)
    m = F.management(dev, monkeypatch)
    for kw in ({}, {"pin": ""}, {"pin": None}, {"no_pin": True}):
        with pytest.raises(PinRequired) as e:
            m.export_profile(**kw)
        assert e.value.sw == 0x6982 and "has a FIDO PIN" in str(e.value)
    with pytest.raises(PinRequired, match="4 to 63"):
        m.export_profile(pin="123")                     # can never be right: not sent either
    assert not F.commands(dev, mgmt.INS_EXPORT_BEGIN) and dev.retries == 8
    assert m.export_profile(pin="1234") == STREAM
    assert F.commands(dev, mgmt.INS_EXPORT_BEGIN)[0][3] == b"1234"


def test_export_without_pin(monkeypatch):
    dev = F.FakeDevice(stream=STREAM)
    m = F.management(dev, monkeypatch)
    assert m.export_profile() == STREAM
    assert F.commands(dev, mgmt.INS_EXPORT_BEGIN)[0][3] == b""
    assert F.commands(dev)[-1][0] == mgmt.INS_EXPORT_END


def test_export_when_the_device_cannot_tell(monkeypatch):
    dev = F.FakeDevice(fido=False, stream=STREAM)
    m = F.management(dev, monkeypatch)
    with pytest.raises(PinRequired, match="cannot tell"):
        m.export_profile()
    assert not F.commands(dev, mgmt.INS_EXPORT_BEGIN)
    assert m.export_profile(no_pin=True) == STREAM      # the user stated there is none


@pytest.mark.parametrize("protocol", [1, 2])
def test_export_on_both_protocols(monkeypatch, protocol):
    dev = F.FakeDevice(stream=STREAM, protocol=protocol)
    m = F.management(dev, monkeypatch)
    assert m.export_profile() == STREAM
    reads = F.commands(dev, mgmt.INS_EXPORT_READ)
    assert all(len(r[3]) == (12 if protocol == 2 else 4) for r in reads)     # protocol 2: offset + export ID


def test_protocol_3_transfer_ids(monkeypatch):
    """Protocol 3: IMPORT_BEGIN and FW_BEGIN answer a session ID that every
    following command of the transfer carries."""
    dev = F.FakeDevice(stream=STREAM, protocol=3)
    m = F.management(dev, monkeypatch)
    assert m.export_profile() == STREAM
    m.check_backup(bytes(3000))
    writes = F.commands(dev, mgmt.INS_IMPORT_WRITE)
    assert all(w[3][4:12] == dev.session_id for w in writes)
    assert F.commands(dev, mgmt.INS_IMPORT_END)[-1][3] == dev.session_id
    r = m.update_firmware(F.image((2, 0, 1)))
    assert r["confirmed"] and F.commands(dev, mgmt.INS_FW_END)[-1][3] == dev.session_id
    m.import_profile(bytes(100), 1)
    assert dev.last_result == 2


def test_protocol_3_import_into_the_active_profile_takes_the_pin(monkeypatch):
    dev = F.FakeDevice(pin="1234", protocol=3)
    m = F.management(dev, monkeypatch)
    with pytest.raises(PinRequired):
        m.import_profile(bytes(100), 0)
    assert not F.commands(dev, mgmt.INS_IMPORT_BEGIN) and dev.retries == 8
    m.import_profile(bytes(100), 0, pin="1234")
    assert F.commands(dev, mgmt.INS_IMPORT_BEGIN)[-1][3] == b"1234"
    m.import_profile(bytes(100), 2)                     # another slot: a touch only
    assert F.commands(dev, mgmt.INS_IMPORT_BEGIN)[-1][3] == b""


def test_protocol_3_update_over_an_unconfirmed_firmware(monkeypatch):
    dev = F.FakeDevice(protocol=3)
    m = F.management(dev, monkeypatch)
    m.update_firmware(F.image((2, 0, 1)), confirm=False)
    with pytest.raises(ApduError, match="not confirmed yet"):
        m.update_firmware(F.image((2, 0, 2)))
    assert len(F.commands(dev, mgmt.INS_FW_BEGIN)) == 1


def test_protocol_3_info_and_policies(monkeypatch):
    dev = F.FakeDevice(protocol=3)
    m = F.management(dev, monkeypatch)
    info = m.info()
    assert info["profiles"][0]["auto_presence"] == [] and info["profiles"][0]["secure"] is False
    assert info["board"] == {"led_brightness": 255} and info["free_changes"] == 16
    m.set_presence(0, fido=True, piv=True)
    assert dev.presence[0] == 0b10001
    m.set_presence(0, piv=False, oath=True)             # the others keep their setting
    assert m.info()["profiles"][0]["auto_presence"] == ["fido", "oath"]
    with pytest.raises(ValueError):
        m.set_presence(0, ssh=True)
    m.set_led_brightness(40)
    assert m.info()["board"]["led_brightness"] == 40
    with pytest.raises(ApduError) as e:
        m.set_led_brightness(300)
    assert e.value.sw == 0x6A80
    with pytest.raises(ApduError) as e:
        m.create_secure_profile(1)                      # the root key is not bound yet
    assert e.value.sw == 0x6982
    m.provision_hmac()
    m.create_secure_profile(1)
    p = m.info()["profiles"][1]
    assert p["used"] and p["secure"] and p["no_export"]
    with pytest.raises(ApduError) as e:
        m.set_presence(1, fido=True)
    assert e.value.sw == 0x6986
    m.lock_debug()
    sec = m.info()["security"]
    assert sec["jtag_disabled"] and sec["download_restricted"]
    with pytest.raises(ApduError) as e:
        m.lock_debug()
    assert e.value.sw == 0x6A88


def test_older_firmware_reports_no_policies(monkeypatch):
    m = F.management(F.FakeDevice(protocol=2), monkeypatch)
    info = m.info()
    assert info["profiles"][0]["auto_presence"] == [] and "board" not in info and "free_changes" not in info


def test_held_root_key_refusal_is_not_a_pin_request(monkeypatch):
    """Protocol 3: getInfo knows the PIN, so a 6982 without a PIN on a profile
    without one is the root key (held), not a PIN request."""
    dev = F.FakeDevice(protocol=3)
    m = F.management(dev, monkeypatch)
    monkeypatch.setattr(dev, "handle", lambda app, ins, p1, p2, data, real=dev.handle:
                        (b"", 0x6982) if ins == mgmt.INS_EXPORT_BEGIN else real(app, ins, p1, p2, data))
    with pytest.raises(PinRequired) as e:
        m.export_profile()
    assert e.value.kind == "unavailable" and not e.value.ask and "provision plan" in str(e.value)


def test_device_asking_for_the_pin_is_pin_required(monkeypatch):
    dev = F.FakeDevice(pin="1234", fido=False, stream=STREAM)
    m = F.management(dev, monkeypatch)
    with pytest.raises(PinRequired, match="asks for the FIDO PIN"):
        m.export_profile(no_pin=True)                   # the user was wrong: the device says so
    assert dev.retries == 8


def test_rollback_and_rom_loader_take_the_pin(monkeypatch):
    dev = F.FakeDevice(pin="1234")
    m = F.management(dev, monkeypatch)
    with pytest.raises(PinRequired):
        m.rollback_firmware()
    with pytest.raises(PinRequired):
        m.reboot(bootloader=True)
    assert not F.commands(dev, mgmt.INS_FW_ROLLBACK) and not F.commands(dev, mgmt.INS_REBOOT)
    m.reboot(bootloader=True, pin="1234")
    assert F.commands(dev, mgmt.INS_REBOOT)[-1][3] == b"1234"
    m.reboot()                                          # a plain restart takes no PIN
    assert F.commands(dev, mgmt.INS_REBOOT)[-1][3] == b""
    m.rollback_firmware(pin="1234")
    assert F.commands(dev, mgmt.INS_FW_ROLLBACK)[-1][3] == b"1234" and dev.retries == 8


def test_rollback_on_protocol_1_takes_no_pin(monkeypatch):
    dev = F.FakeDevice(pin="1234", protocol=1)
    m = F.management(dev, monkeypatch)
    m.rollback_firmware()
    assert F.commands(dev, mgmt.INS_FW_ROLLBACK)[-1][3] == b"" and dev.retries == 8


def test_locked_key_store_asks_for_the_pin(monkeypatch):
    """getInfo reports no PIN while the key store is locked, the management
    applet asks for it: PinRequired "device", nothing spent."""
    dev = F.FakeDevice(pin="1234", stream=STREAM)
    dev.store_locked = True
    m = F.management(dev, monkeypatch)
    with pytest.raises(PinRequired) as e:
        m.export_profile()
    assert e.value.kind == "device" and e.value.ask and "enter it and try again" in str(e.value)
    assert dev.retries == 8
    assert m.export_profile(pin="1234") == STREAM


@pytest.mark.parametrize("ins, cleanup", [(mgmt.INS_EXPORT_BEGIN, mgmt.INS_EXPORT_END),
                                          (mgmt.INS_IMPORT_BEGIN, mgmt.INS_INFO),
                                          (mgmt.INS_FW_BEGIN, mgmt.INS_INFO)])
def test_interrupt_right_after_begin_ends_the_session(monkeypatch, ins, cleanup):
    """Ctrl-C during the touch wait is raised once BEGIN returned: the device
    already opened the session, which must not stay open."""
    dev = F.FakeDevice(stream=STREAM)
    dev.interrupt_after = ins
    m = F.management(dev, monkeypatch)
    with pytest.raises(KeyboardInterrupt):
        if ins == mgmt.INS_EXPORT_BEGIN:
            m.export_profile()
        elif ins == mgmt.INS_IMPORT_BEGIN:
            m.import_profile(bytes(3000), 1)
        else:
            m.update_firmware(F.image((2, 0, 1)))
    assert F.commands(dev)[-1][0] == cleanup and F.commands(dev)[-1][-1] >= 1     # still in the transaction
    assert dev.sess is None and dev.log[-1] == ("END", "leave")


def test_busy_device_gets_a_card_reset(monkeypatch):
    """The device answers nothing (busy with a FIDO request on another
    interface): after a short retry the transaction ends with a card reset,
    which ends the session."""
    dev = F.FakeDevice(stream=STREAM * 4)
    dev.busy_from = mgmt.INS_EXPORT_READ
    m = F.management(dev, monkeypatch)
    clock = iter(range(0, 1000))
    monkeypatch.setattr(mgmt.time, "monotonic", lambda: next(clock) * 0.3)
    with pytest.raises(CardConnectionException):
        m.export_profile()
    assert dev.log[-1] == ("END", "reset") and dev.sess is None
    assert len(F.commands(dev, mgmt.INS_EXPORT_END)) >= 2         # retried before resetting


def test_busy_device_during_the_pin_check(monkeypatch):
    dev = F.FakeDevice()
    m = F.management(dev, monkeypatch)
    dev.busy_from, dev.busy = -1, True
    with pytest.raises(RuntimeError, match="busy"):
        m.fido_pin_set()


def test_commands_after_a_restart_select_the_applet_again(monkeypatch):
    """Another program selects another application of the restarted device:
    the checks and the confirmation still reach the management applet."""
    dev = F.FakeDevice()
    dev.intruder_select = True
    m = F.management(dev, monkeypatch)
    r = m.update_firmware(F.image((2, 0, 1)))
    assert r["confirmed"] and not dev.pending
    after = dev.log[[i for i, e in enumerate(dev.log) if e[0] == mgmt.INS_FW_END][-1] + 1:]
    confirm = [i for i, e in enumerate(after) if e[0] == mgmt.INS_FW_CONFIRM][0]
    assert ("SELECT", MGMT_AID) in after[:confirm] and after[confirm][-1] >= 1
    # the same for an import and a single command
    dev.log.clear()
    m.import_profile(bytes(100), 1)
    m.card.app = b"other"
    assert m.info()["firmware"] == "2.0.1"


def test_failed_confirmation_says_what_to_do(monkeypatch):
    dev = F.FakeDevice()
    dev.fail_confirm = True
    m = F.management(dev, monkeypatch)
    with pytest.raises(ApduError, match="librefido firmware confirm"):
        m.update_firmware(F.image((2, 0, 1)))


def test_display_name():
    assert mgmt.display_name("Work") == "Work"
    assert mgmt.display_name("\x1b[2Kx‮\n") == "\\x1b[2Kx\\u202e\\x0a"
    assert mgmt.display_name(None) == ""


def test_transfers_hold_one_transaction(monkeypatch):
    dev = F.FakeDevice(stream=STREAM)
    m = F.management(dev, monkeypatch)
    m.export_profile()
    assert dev.log[0] == ("SELECT", MGMT_AID)           # selected again once the card is locked
    assert all(e[-1] >= 1 for e in F.commands(dev))
    dev.log.clear()
    m.check_backup(STREAM)
    assert dev.log[0] == ("SELECT", MGMT_AID)
    assert [e[0] for e in F.commands(dev)] == [mgmt.INS_IMPORT_BEGIN] + [mgmt.INS_IMPORT_WRITE] * 1 + \
        [mgmt.INS_IMPORT_END]
    assert all(e[-1] >= 1 for e in F.commands(dev))


def test_failed_upload_ends_the_session(monkeypatch):
    dev = F.FakeDevice()
    dev.fail_write_at = 1024
    m = F.management(dev, monkeypatch)
    with pytest.raises(ApduError):
        m.check_backup(bytes(4000))
    assert F.commands(dev)[-1][0] == mgmt.INS_INFO and F.commands(dev)[-1][-1] >= 1
    assert not F.commands(dev, mgmt.INS_IMPORT_END)


# -- firmware update -----------------------------------------------------------

def test_update_is_confirmed_once_the_new_image_runs(monkeypatch):
    dev = F.FakeDevice()
    m = F.management(dev, monkeypatch)
    r = m.update_firmware(F.image((2, 0, 0)))           # same version: allowed by the device
    assert r["installed"] == "2.0.0" and r["confirmed"] and r["slot"] == 0
    assert F.commands(dev, mgmt.INS_FW_CONFIRM) and not dev.pending
    assert all(e[-1] >= 1 for e in F.commands(dev) if e[0] in (0x40, 0x41, 0x42))
    assert 3 not in cbor.decode(F.commands(dev, mgmt.INS_FW_BEGIN)[0][3])     # no PIN sent


def test_rolled_back_update_is_reported(monkeypatch):
    dev = F.FakeDevice()
    dev.rollback_on_boot = True
    m = F.management(dev, monkeypatch)
    with pytest.raises(ApduError, match="did not start"):
        m.update_firmware(F.image((2, 0, 0), profile=2))    # HARDENED 2.0.0 over STANDARD 2.0.0
    assert not F.commands(dev, mgmt.INS_FW_CONFIRM)


def test_other_build_profile_is_not_the_installed_image(monkeypatch):
    dev = F.FakeDevice()
    m = F.management(dev, monkeypatch)
    real = dev.reboot

    def reboot():                                       # boots another slot, but not the hardened build
        real()
        dev.profile = "standard"
    dev.reboot = reboot
    with pytest.raises(ApduError, match="hardened"):
        m.update_firmware(F.image((2, 0, 0), profile=2))
    assert not F.commands(dev, mgmt.INS_FW_CONFIRM)


def test_unconfirmed_update(monkeypatch):
    dev = F.FakeDevice()
    m = F.management(dev, monkeypatch)
    r = m.update_firmware(F.image((2, 1, 0)), confirm=False)
    assert not r["confirmed"] and dev.pending and not F.commands(dev, mgmt.INS_FW_CONFIRM)


def test_update_asks_for_the_pin(monkeypatch):
    dev = F.FakeDevice(pin="123456")
    m = F.management(dev, monkeypatch)
    with pytest.raises(PinRequired):
        m.update_firmware(F.image((2, 0, 1)))
    assert not F.commands(dev, mgmt.INS_FW_BEGIN) and dev.retries == 8
    m.update_firmware(F.image((2, 0, 1)), pin="123456")
    assert cbor.decode(F.commands(dev, mgmt.INS_FW_BEGIN)[0][3])[3] == b"123456"


def test_update_in_safe_mode_needs_no_pin(monkeypatch):
    dev = F.FakeDevice(pin="123456")
    dev.boot_status = 4                                 # active profile not mountable
    m = F.management(dev, monkeypatch)
    m.update_firmware(F.image((2, 0, 1)), confirm=False)
    assert not [e for e in dev.log if e == ("SELECT", mgmt.FIDO_AID)]


# -- profile names -------------------------------------------------------------

def test_clip_name():
    assert clip_name("我的工作安全密钥") == "我的工作安全密"     # 24 bytes -> 21, never inside a character
    assert clip_name("a" * 30) == "a" * 23
    assert clip_name("ab\0cd") == "ab"
    assert len(clip_name("é" * 20).encode()) == 22


def test_set_profile_clips_the_name(monkeypatch):
    dev = F.FakeDevice()
    m = F.management(dev, monkeypatch)
    m.set_profile(0, name="我的工作安全密钥")
    assert cbor.decode(F.commands(dev, mgmt.INS_PROFILE_SET)[0][3]) == {1: "我的工作安全密"}


def test_a_cut_name_does_not_lock_the_tools_out(monkeypatch):
    dev = F.FakeDevice()
    dev.raw_name = "我的工作安全密钥".encode()[:23]      # as older firmware stored it
    m = F.management(dev, monkeypatch)
    name = m.info()["profiles"][0]["name"]
    assert name.startswith("我的工作安全密") and name.endswith("�")


def test_decoder():
    assert mgmt.decode(b"\xa1\x01\x86\xf5\xf4\xf6\x24\x41x\x61y") == {1: [True, False, None, -5, b"x", "y"]}
    big = {1: 2 ** 40, 2: "t" * 300, 3: bytes(70000), 4: [{5: -2 ** 33}]}
    assert mgmt.decode(cbor.encode(big)) == big
    for bad in (b"", b"\xa1\x01", b"\x62a", b"\x01\x02", b"\x81" * 40 + b"\x00", b"\x9f"):
        with pytest.raises(ValueError):
            mgmt.decode(bad)


def test_malformed_answer_is_an_apdu_error(monkeypatch):
    dev = F.FakeDevice()
    m = F.management(dev, monkeypatch)
    monkeypatch.setattr(dev, "_info", lambda: b"\xa1\x01")
    with pytest.raises(ApduError, match="malformed"):
        m.info()
