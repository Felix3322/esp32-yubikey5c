"""
authenticatorConfig: parameters of every subcommand are parsed (no endless
loop before authentication), setMinPINLength bounds, what is not
implemented is refused.
"""

import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Config, Ctap2

from lf_fido_helpers import CONFIG_PIN_POLICY, ctap2, fresh, token

ACFG = ClientPin.PERMISSION.AUTHENTICATOR_CFG


def config(device):
    t, p = token(device, ACFG)
    return Config(ctap2(device), p, t)


@pytest.mark.parametrize("sub", [0x01, 0x02, 0x04, 0x7F])
def test_params_of_any_subcommand_are_skipped(device, sub):
    """{1: sub, 2: {1: 0}} used to spin forever for subcommands other than
    0x03 and 0xFF (the device stayed busy until unplugged)."""
    with pytest.raises(CtapError) as e:
        ctap2(device).send_cbor(Ctap2.CMD.CONFIG, {1: sub, 2: {1: 0, "x": [1, 2]}})
    assert e.value.code == CtapError.ERR.PUAT_REQUIRED
    ctap2(device).get_info()


def test_unknown_params_of_known_subcommands(device):
    fresh(device)
    cfg = config(device)
    cfg._call(Config.CMD.SET_MIN_PIN_LENGTH, {1: 8, 9: b"unknown"})
    assert ctap2(device).get_info().min_pin_length == 8
    ctap2(device).get_info()


@pytest.mark.parametrize("length", [64, 255, 260])
def test_min_pin_length_upper_bound(device, length):
    """Stored in one byte and no PIN exceeds 63 bytes: 260 used to be stored
    as 4 (lowering the minimum), 64..255 locked every PIN out."""
    fresh(device)
    config(device).set_min_pin_length(8)
    with pytest.raises(CtapError) as e:
        config(device).set_min_pin_length(length)
    assert e.value.code == CtapError.ERR.PIN_POLICY_VIOLATION
    assert ctap2(device).get_info().min_pin_length == 8


def test_min_pin_length_63(device):
    fresh(device)
    config(device).set_min_pin_length(63)
    info = ctap2(device).get_info()
    assert info.min_pin_length == 63
    assert info.force_pin_change is True


def test_always_uv_not_supported(device, info):
    assert "alwaysUv" not in info.options
    fresh(device)
    with pytest.raises(CtapError) as e:
        config(device).toggle_always_uv()
    assert e.value.code == CtapError.ERR.UNSUPPORTED_OPTION


def test_pin_policy_command_removed(device):
    """It set pinComplexityPolicy = true in getInfo without enforcing anything."""
    fresh(device)
    with pytest.raises(CtapError) as e:
        config(device)._call(0xFF, {1: CONFIG_PIN_POLICY, 2: b"https://example.com/policy"})
    assert e.value.code == CtapError.ERR.INVALID_SUBCOMMAND
    info = ctap2(device).get_info()
    assert info.pin_complexity_policy is None
    assert info.pin_complexity_policy_url is None
