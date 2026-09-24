"""GnuPG end to end on the emulated OpenPGP card: key generation on the card
(gpg --card-edit), signing, encryption/decryption, PIN change; the same
with Curve 25519 keys (GnuPG's default: ed25519 and cv25519), generated on
the card and moved to it (keytocard).

    source ~/work/testenv.sh
    PYTHONPATH=tests:tools/librefido python -m pytest tests/openpgp/test_gnupg_flow.py
"""

import os
import re
import shutil
import subprocess
import time

import pytest

from harness.emulator import Emulator, Pcscd
from librefido.pcsc import open_device

ADMIN_PIN, USER_PIN = "12345678", "123456"
pytestmark = pytest.mark.skipif(not shutil.which("gpg") or not os.environ.get("SCDAEMON_PROGRAM"),
                                reason="GnuPG test home not configured (source testenv.sh)")


@pytest.fixture(scope="module")
def pcscd():
    p = Pcscd()
    if not p.available:
        pytest.skip("no PC/SC stack configured (see tests/README.md)")
    p.start()
    yield p
    p.stop()


@pytest.fixture
def gnupg(pcscd, tmp_path):
    e = Emulator(workdir=str(tmp_path / "dev"))
    e.start()
    try:        # a failed setup must not leave the emulator holding the ports
        open_device(timeout=15).close()
        subprocess.run(["bash", "-c", "source ~/work/testenv.sh >/dev/null && GPG_TEST_PCSC_SHARED=1 gpg_test_reset"],
                       check=True, capture_output=True)
        yield tmp_path
    finally:
        subprocess.run(["gpgconf", "--kill", "all"], check=False)
        e.stop()


def gpg(*args, stdin=None, check=True):
    r = subprocess.run(["gpg", "--batch", "--no-tty", "--pinentry-mode", "loopback", *args],
                       input=stdin, capture_output=True, timeout=300)
    if check and r.returncode != 0:
        raise AssertionError("gpg %s failed:\n%s" % (" ".join(args), r.stderr.decode(errors="replace")))
    return r


PIN_PROMPT = re.compile(r"asking for PIN '([^']*)'")


def scd_pin_prompts():
    """PIN prompts scdaemon has made so far (its log, verbose)."""
    try:
        with open(os.path.join(os.environ["GNUPGHOME"], "scdaemon.log"), errors="replace") as f:
            return PIN_PROMPT.findall(f.read())
    except OSError:
        return []


def pin_for(prompt, pins):
    """The PIN scdaemon asks for: its prompt starts with |flags| (A admin PIN,
    N new PIN)."""
    flags = prompt.split("|")[1] if prompt.startswith("|") else ""
    if "N" in flags:
        return pins["new_admin" if "A" in flags else "new"]
    return pins["admin" if "A" in flags else "user"]


def card_edit(commands, answers, pins, args=("--card-edit",)):
    """Drives `gpg --card-edit` (or `gpg --edit-key KEY`, args) through its
    status protocol: commands are typed at the card (key) prompt, answers
    keyed by prompt keyword. A PIN is answered after the prompt scdaemon made
    for it: GnuPG asks again for the admin or user PIN whenever it switches
    between the OpenPGP and PIV applications of the card, so their order is
    not fixed. A prompt that scdaemon did not make itself is the agent's
    repeat of the last one."""
    p = subprocess.Popen(["gpg", "--no-tty", "--pinentry-mode", "loopback", "--command-fd", "0",
                          "--status-fd", "1", *args],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    commands = list(commands)
    transcript = []
    seen, last = len(scd_pin_prompts()), None
    for line in p.stdout:
        transcript.append(line.rstrip())
        if not line.startswith("[GNUPG:] GET_"):
            continue
        kw = line.split()[2]
        if kw in ("cardedit.prompt", "keyedit.prompt"):
            reply = commands.pop(0) if commands else "quit"
        elif kw == "passphrase.enter":
            # scdaemon logs its prompt before the question reaches gpg; a
            # repeat has no line of its own
            deadline = time.time() + (0.5 if last is not None else 5)
            prompts = scd_pin_prompts()
            while len(prompts) <= seen and time.time() < deadline:
                time.sleep(0.05)
                prompts = scd_pin_prompts()
            if len(prompts) > seen:
                seen, last = len(prompts), prompts[-1]
            reply = pin_for(last or "", pins)
            transcript.append("(PIN for %r)" % (last or "")[:40])
        else:
            reply = answers.get(kw, "")
            if isinstance(reply, list):         # a menu: these choices, then quit
                reply = reply.pop(0) if reply else "q"
        p.stdin.write(reply + "\n")
        p.stdin.flush()
        if reply == "quit":
            break
    p.stdin.close()
    err = p.stderr.read()
    p.wait(60)
    return p.returncode, "\n".join(transcript) + "\n" + err


def test_gnupg_generate_sign_encrypt_decrypt(gnupg):
    w = gnupg
    rc, log = card_edit(
        ["admin", "generate"],
        {"cardedit.genkeys.backup_enc": "n", "cardedit.genkeys.replace_keys": "y",
         "keygen.valid": "0", "keygen.name": "LibreFido Test", "keygen.email": "test@librefido.example",
         "keygen.comment": "", "keyedit.save.okay": "y"},
        {"user": USER_PIN, "admin": ADMIN_PIN})
    assert rc == 0 and "KEY_CREATED" in log, log

    status = gpg("--card-status").stdout.decode()
    assert "Signature key ....:" in status and "[none]" not in status.split("Signature key")[1].split("\n")[0], status

    msg = w / "msg.txt"
    msg.write_text("signed on a LibreFido card\n")
    gpg("--passphrase", USER_PIN, "--output", str(w / "msg.sig"), "--detach-sign", str(msg))
    assert b"Good signature" in gpg("--verify", str(w / "msg.sig"), str(msg)).stderr

    gpg("--trust-model", "always", "--recipient", "test@librefido.example", "--output", str(w / "msg.gpg"),
        "--encrypt", str(msg))
    out = gpg("--passphrase", USER_PIN, "--decrypt", str(w / "msg.gpg")).stdout
    assert out == msg.read_bytes()


GENERATE_ANSWERS = {"cardedit.genkeys.backup_enc": "n", "cardedit.genkeys.replace_keys": "y",
                    "keygen.valid": "0", "keygen.name": "LibreFido Test", "keygen.email": "test@librefido.example",
                    "keygen.comment": "", "keyedit.save.okay": "y"}


def sign_and_decrypt(w, recipient):
    msg = w / "msg.txt"
    msg.write_text("signed and decrypted on a LibreFido card\n")
    gpg("--passphrase", USER_PIN, "--output", str(w / "msg.sig"), "--detach-sign", str(msg))
    assert b"Good signature" in gpg("--verify", str(w / "msg.sig"), str(msg)).stderr
    gpg("--trust-model", "always", "--recipient", recipient, "--output", str(w / "msg.gpg"), "--encrypt", str(msg))
    assert gpg("--passphrase", USER_PIN, "--decrypt", str(w / "msg.gpg")).stdout == msg.read_bytes()


def test_gnupg_curve25519_on_card(gnupg):
    """key-attr to Curve 25519 for the three keys (ed25519, cv25519,
    ed25519), key generation on the card, signing and decryption."""
    rc, log = card_edit(["admin", "key-attr"],
                        {"cardedit.genkeys.algo": ["2", "2", "2"], "keygen.curve": ["1", "1", "1"]},
                        {"user": USER_PIN, "admin": ADMIN_PIN})
    assert rc == 0, log
    status = gpg("--card-status").stdout.decode()
    assert "Key attributes ...: ed25519 cv25519 ed25519" in status, status

    rc, log = card_edit(["admin", "generate"], dict(GENERATE_ANSWERS), {"user": USER_PIN, "admin": ADMIN_PIN})
    assert rc == 0 and "KEY_CREATED" in log, log
    keys = gpg("--with-colons", "--list-keys", "test@librefido.example").stdout.decode()
    curves = [f.split(":")[16] for f in keys.splitlines() if f.startswith(("pub:", "sub:"))]
    assert sorted(curves) == ["cv25519", "ed25519", "ed25519"], keys
    sign_and_decrypt(gnupg, "test@librefido.example")


def test_gnupg_curve25519_keytocard(gnupg):
    """Keys made by GnuPG and moved to the card (IMPORT DATA as scdaemon
    writes it): the card signs and decrypts with them."""
    w = gnupg
    uid = "Import Test <import@librefido.example>"
    gpg("--passphrase", "", "--quick-gen-key", uid, "ed25519", "sign,cert", "0")
    fpr = [f.split(":")[9] for f in gpg("--with-colons", "--list-keys", uid).stdout.decode().splitlines()
           if f.startswith("fpr:")][0]
    gpg("--passphrase", "", "--quick-add-key", fpr, "cv25519", "encr", "0")
    gpg("--passphrase", "", "--quick-add-key", fpr, "ed25519", "auth", "0")
    # a message for the encryption key while it is still in the key ring
    msg = w / "before.txt"
    msg.write_text("encrypted before keytocard\n")
    gpg("--trust-model", "always", "--recipient", fpr, "--output", str(w / "before.gpg"), "--encrypt", str(msg))

    pins = {"user": USER_PIN, "admin": ADMIN_PIN}
    for commands, slot in ((["key 1", "keytocard"], "2"), (["key 2", "keytocard"], "3"), (["keytocard"], "1")):
        rc, log = card_edit(commands + ["save"],
                            {"cardedit.genkeys.storekeytype": [slot], "keyedit.keytocard.use_primary": "y",
                             "keyedit.save.okay": "y"}, pins, args=("--edit-key", fpr))
        assert rc == 0, log
    status = gpg("--card-status").stdout.decode()
    assert "Key attributes ...: ed25519 cv25519 ed25519" in status, status
    secret = gpg("--with-colons", "--list-secret-keys", fpr).stdout.decode()
    # every secret key is now a stub for the card ('>' in field 15)
    assert all(line.split(":")[14].startswith("D2760001240") for line in secret.splitlines()
               if line.startswith(("sec:", "ssb:"))), secret
    assert gpg("--passphrase", USER_PIN, "--decrypt", str(w / "before.gpg")).stdout == msg.read_bytes()
    sign_and_decrypt(w, fpr)


def test_gnupg_pin_change_and_retries(gnupg):
    rc, log = card_edit(["admin", "passwd"], {"cardutil.change_pin.menu": ["1"]},
                        {"user": USER_PIN, "admin": ADMIN_PIN, "new": "654321"})
    assert rc == 0, log
    status = gpg("--card-status").stdout.decode()
    assert "PIN retry counter : 3 0 3" in status, status
