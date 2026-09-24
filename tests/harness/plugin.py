"""pytest plugin: starts pcscd + the emulator for the whole session.

Usage (from the repository root, see tests/README.md):
    PYTHONPATH=tests:pico-fido/tests pytest -p harness.plugin tests/...
It also runs the upstream pico-fido suites unchanged: their Device.reboot()
(power cycle) is mapped to an emulator restart.
"""

import sys
import time

import pytest

from . import ctaphid
from .emulator import Emulator, Pcscd

_pcscd = None
_emu = None


def emulator_instance():
    return _emu


def pytest_configure(config):
    global _pcscd, _emu
    ctaphid.install()
    _pcscd = Pcscd()
    _pcscd.start()
    _emu = Emulator()
    _emu.start()
    time.sleep(0.5 if _pcscd.available else 0)


def pytest_unconfigure(config):
    if _emu:
        _emu.cleanup()
    if _pcscd:
        _pcscd.stop()


def _power_cycle_reboot(self):
    _emu.restart()
    time.sleep(0.3)
    # Re-open the transports the upstream Device object holds.
    self._Device__set_client(self._Device__origin, self._Device__user_interaction, self._Device__uv)
    self._Device__set_server(rp=self._Device__rp, attestation=self._Device__attestation)


def pytest_collection_modifyitems(session, config, items):
    mod = sys.modules.get("conftest")
    dev = getattr(mod, "Device", None) if mod else None
    if dev is not None:
        dev.reboot = _power_cycle_reboot


@pytest.fixture(scope="session")
def emulator():
    return _emu


@pytest.fixture
def card():
    from .card import Card
    c = Card()
    yield c
    c.close()


@pytest.fixture
def ctap_device():
    d = ctaphid.open_device()
    yield d
    d.close()
