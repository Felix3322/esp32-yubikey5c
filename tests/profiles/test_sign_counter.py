"""FIDO signature counter: durable before it is signed, strictly increasing,
kept in the counter log instead of rewriting a file for every signature.

    PYTHONPATH=tests:tools/librefido:tests/profiles python -m pytest tests/profiles/test_sign_counter.py
"""

import os

from test_profiles_backup import ctap2, device, emulators, make_rk, pcscd  # noqa: F401


def assertion_counter(rp="example.com"):
    dev, c = ctap2()
    try:
        return c.get_assertion(rp, os.urandom(32)).auth_data.counter
    finally:
        dev.close()


def test_counter_increases_and_survives_restarts(pcscd, emulators):
    e = emulators()
    m = device(e)
    reg = make_rk(b"alice")
    assert reg.auth_data.counter >= 1                   # 0 would mean "no counter"
    seen = [reg.auth_data.counter]
    for _ in range(3):
        seen.append(assertion_counter())
    e.restart()                                         # power cycle
    m.reconnect()
    seen.append(assertion_counter())
    e.stop(hard=True)                                   # power cut right after a signature
    e.start()
    m.reconnect()
    seen.append(assertion_counter())
    assert all(b > a for a, b in zip(seen, seen[1:])), seen
    m.close()


def test_signatures_do_not_rewrite_the_file_system(pcscd, emulators):
    e = emulators()
    m = device(e)
    make_rk(b"alice")
    before = m.health()["generation"]
    for _ in range(10):
        assertion_counter()
    # counter increments go to the counter log, not through FS transactions
    assert m.health()["generation"] == before
    m.close()
