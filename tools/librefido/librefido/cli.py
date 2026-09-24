"""librefido: command line management of LibreFido devices."""

import argparse
import getpass
import json
import locale
import os
import sys

from smartcard.Exceptions import CardConnectionException

from . import __version__, policy
from .backup import BackupError, firmware_supports, read_file, write_file
from .firmware import FirmwareError
from .mgmt import Management, PinRequired, clip_name, display_name
from .pcsc import ApduError, list_devices

MAX_PROFILES = 4


def _first_line(path, what):
    """First line of a UTF-8 text file (a BOM and only the line end removed)."""
    try:
        with open(path, encoding="utf-8-sig", newline="") as f:
            p = f.readline()
    except UnicodeDecodeError:
        sys.exit("the %s file is not UTF-8 text" % what)
    for end in ("\r\n", "\n", "\r"):
        if p.endswith(end):
            return p[:-len(end)]
    return p


def legacy_passphrases(path):
    """The passphrases librefido-tools 2.0.0 derived from a --passphrase-file,
    so that the backups it wrote still open: it read the first line with the
    locale's encoding (the ANSI code page on Windows, e.g. cp936; UTF-8 on
    most other systems), kept a UTF-8 BOM and removed only the line end."""
    with open(path, "rb") as f:
        raw = f.read()
    ends = [i for i in (raw.find(b"\n"), raw.find(b"\r")) if i >= 0]
    line = raw[:min(ends)] if ends else raw     # every candidate encoding is ASCII compatible
    encodings = [locale.getpreferredencoding(False), "utf-8"]
    if hasattr(locale, "getencoding"):
        encodings.append(locale.getencoding())  # without UTF-8 mode
    if os.name == "nt":
        encodings.append("mbcs")
    out = []
    for enc in encodings:
        try:
            p = line.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        if p and p not in out:
            out.append(p)
    return out


def _passphrase(args, confirm):
    """Backup passphrase: the first line of --passphrase-file (UTF-8, a BOM
    and the line end removed) or a prompt. confirm (a new backup) refuses an
    empty passphrase: only --no-encrypt writes the keys in the clear.
    Without confirm (reading), a list: this passphrase, then the ones older
    versions derived from the same file (legacy_passphrases)."""
    path = getattr(args, "passphrase_file", None)
    if path:
        p = _first_line(path, "passphrase")
    else:
        p = getpass.getpass("Backup passphrase: ")
        if confirm and getpass.getpass("Repeat passphrase: ") != p:
            sys.exit("passphrases differ")
    if confirm:
        if not p:
            sys.exit("empty passphrase refused (--no-encrypt writes the keys in the clear)")
        return p
    return [p] + ([q for q in legacy_passphrases(path) if q != p] if path else [])


def _pin_file(args):
    path = getattr(args, "pin_file", None)
    return (_first_line(path, "PIN") or None) if path else None


def _fido_pin(m, given=None, no_pin=False, ask=False):
    """FIDO PIN of the active profile for export and firmware update: given,
    or asked for when the profile has one (or when the device cannot tell, or
    with ask). An empty PIN is never sent on a guess, since each attempt on a
    profile with a PIN costs one of its retries. Returns (pin or None,
    no_pin): no_pin means the user stated that the profile has none."""
    if given:
        return given, False
    if no_pin:
        return None, True
    has_pin = m.fido_pin_set()
    if has_pin:
        pin = getpass.getpass("FIDO PIN of the active profile: ")
        if not pin:
            sys.exit("the active profile has a FIDO PIN: it is needed")
        return pin, False
    if has_pin is False and not ask:
        return None, False
    pin = getpass.getpass("FIDO PIN of the active profile (empty if it has none): ")
    return (pin or None), not pin


def _with_pin(op, pin, no_pin):
    """Runs op(pin, no_pin). When it needs the FIDO PIN and none was given
    (the device may know better than getInfo, e.g. while its key store is
    locked), asks for it and runs op once more."""
    try:
        return op(pin, no_pin)
    except PinRequired as e:
        if pin or not e.ask:
            raise
        print(str(e), file=sys.stderr)
        if e.kind == "unknown":
            pin = getpass.getpass("FIDO PIN of the active profile (empty if it has none): ")
            return op(pin or None, not pin)
        pin = getpass.getpass("FIDO PIN of the active profile: ")
        if not pin:
            sys.exit("the active profile has a FIDO PIN: it is needed")
        return op(pin, False)


def _update_pin(m, info, args):
    """FIDO PIN for a firmware update or rollback and for the ROM loader: the
    device checks it only while its key storage is open."""
    if info["boot_status"] != "ok":
        return None, True
    return _fido_pin(m, _pin_file(args), no_pin=args.no_pin, ask=args.pin)


def _touch_hint(what=None, maybe=False):
    what = " to %s" % what if what else ""
    print(("If the key blinks, touch it%s..." if maybe else "Touch the key when it blinks%s...") % what,
          file=sys.stderr, flush=True)


def _progress(done, total):
    print("\r  %d / %d bytes" % (done, total), end="", file=sys.stderr, flush=True)
    if done >= total:
        print(file=sys.stderr)


def _print(obj, as_json):
    if as_json:
        print(json.dumps(obj, indent=2))
        return
    def walk(o, indent=0):
        pad = "  " * indent
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(v, (dict, list)):
                    print("%s%s:" % (pad, k))
                    walk(v, indent + 1)
                else:
                    print("%s%s: %s" % (pad, k, display_name(v) if isinstance(v, str) else v))
        elif isinstance(o, list):
            for v in o:
                walk(v, indent)
                print()
    walk(obj)


def _profiles(info, what):
    """The profile list, or a clear refusal when the device cannot report it
    (safe mode with an unusable system area)."""
    profiles = info.get("profiles")
    if profiles is None:
        sys.exit("refused: the device is in safe mode (%s): cannot %s" % (
            display_name(info.get("boot_message") or info.get("boot_status")), what))
    return profiles


def _describe(info, idx):
    """'profile N (name)' of slot idx, for prompts before destructive steps."""
    p = info["profiles"][idx]
    return "profile %d (%s%s)" % (idx + 1, display_name(p["name"]) if p["used"] else "empty",
                                  ", the active one" if p["used"] and idx == info.get("active") else "")


def cmd_list(args):
    for reader, answer in list_devices():
        print(reader)


def _with_level(info, as_json, keystore=None):
    """INFO with the protection level (policy.LEVELS) and the key store state
    of the active profile added."""
    out = dict(info)
    lvl = policy.protection_level(info["security"])
    out["protection_level"] = lvl if as_json else "%d / 3: %s" % (lvl, policy.LEVELS[lvl])
    if as_json:
        out["key_store_unlocked"] = keystore
    else:
        out["key_store"] = {True: "unlocked", False: "LOCKED (see `librefido provision plan`)"}.get(keystore, "unknown")
    return out


def cmd_info(args):
    with_session(args, lambda m: _print(_with_level(m.info(), args.json, m.keystore_unlocked()), args.json))


def cmd_health(args):
    with_session(args, lambda m: _print(m.health(scrub=args.scrub), args.json))


def cmd_profile(args):
    if args.action != "list":
        if args.index is None:
            sys.exit("profile %s needs %s" % (args.action, "a count (1..%d)" % MAX_PROFILES if args.action == "slots"
                                                else "a profile number (1..%d)" % MAX_PROFILES))
        if not 1 <= args.index <= MAX_PROFILES:
            sys.exit("the profile number must be 1..%d" % MAX_PROFILES)

    def run(m):
        if args.action == "list":
            info = m.info()
            for p in _profiles(info, "list the profiles"):
                mark = "*" if p["index"] == info.get("active") else " "
                state = display_name(p["name"]) if p["used"] else "(empty)"
                tags = []
                if p["used"] and p.get("secure"):
                    tags.append("[secure]")
                elif p["no_export"]:
                    tags.append("[no export]")
                if p["used"] and p.get("auto_presence"):
                    tags.append("[no touch: %s]" % ", ".join(p["auto_presence"]))
                print("%s %d  #%s  %s%s" % (mark, p["index"] + 1, p["color"], state,
                                           "".join("  " + t for t in tags)))
        elif args.action == "create-secure":
            info = m.info()
            profiles = _profiles(info, "create a secure profile")
            if profiles[args.index - 1]["used"] and not args.yes:
                answer = input("The keys of %s are erased: it becomes a new, empty secure profile. Type "
                               "'replace' to continue: " % _describe(info, args.index - 1))
                if answer != "replace":
                    sys.exit("aborted")
            _touch_hint("create a secure profile in slot %d" % args.index)
            m.create_secure_profile(args.index - 1)
            print("secure profile %d created, the device restarts" % args.index)
        elif args.action == "select":
            info = m.info()
            _profiles(info, "switch profiles")
            _touch_hint("switch to %s" % _describe(info, args.index - 1))
            m.select_profile(args.index - 1)
            print("switching to profile %d, the device restarts" % args.index)
        elif args.action == "set":
            if args.name is not None and clip_name(args.name) != args.name:
                print("the name is shortened to %r (23 bytes of UTF-8)" % clip_name(args.name), file=sys.stderr)
            # Allowing export needs a touch, other changes once the free ones are used up.
            if args.export == "on":
                _touch_hint("allow exporting profile %d" % args.index)
            else:
                _change_hint(m)
            m.set_profile(args.index - 1, name=args.name, color=args.color,
                          no_export=None if args.export is None else args.export == "off")
        elif args.action == "wipe":
            info = m.info()
            if _profiles(info, "wipe a profile")[args.index - 1]["used"]:
                _touch_hint("WIPE %s: its keys are erased" % _describe(info, args.index - 1))
            else:
                _touch_hint("create profile %d" % args.index)
            m.wipe_profile(args.index - 1)
            print("profile %d will be empty after the restart" % args.index)
        elif args.action == "delete":
            info = m.info()
            _profiles(info, "delete a profile")
            _touch_hint("DELETE %s: its keys are erased" % _describe(info, args.index - 1))
            m.delete_profile(args.index - 1)
        elif args.action == "slots":
            _change_hint(m)
            m.set_button_slots(args.index)
    with_session(args, run)


def _change_hint(m, info=None):
    """Touch prompt for a change that needs one once the free changes (INFO
    key 18) are used up: names, colours, button slots, board settings."""
    left = (info or m.info()).get("free_changes")
    if left == 0:
        _touch_hint("confirm the change (the free changes are used up)")
    elif left is None:
        _touch_hint(maybe=True)


def cmd_presence(args):
    """Automatic presence per application of a profile ("my device is safe")."""
    if not 1 <= args.slot <= MAX_PROFILES:
        sys.exit("the profile number must be 1..%d" % MAX_PROFILES)
    changes = {a: getattr(args, a) for a in policy.APPS if getattr(args, a) is not None}
    if args.all is not None:
        changes = dict({a: args.all for a in policy.APPS}, **changes)

    def run(m):
        info = m.info()
        p = _profiles(info, "change automatic presence")[args.slot - 1]
        if changes:
            current = set(p.get("auto_presence", []))
            if any(on and a not in current for a, on in changes.items()):
                print("warning: without a touch, any program on this computer can use the keys of %s of "
                      "this profile without you noticing" % ", ".join(a for a, on in changes.items() if on),
                      file=sys.stderr)
                _touch_hint("switch automatic presence on")
            else:
                _change_hint(m, info)               # (switching off only counts as a change)
            m.set_presence(args.slot - 1, **changes)
            p = _profiles(m.info(), "change automatic presence")[args.slot - 1]
        auto = p.get("auto_presence", [])
        if args.json:
            _print({"slot": args.slot, "auto_presence": auto, "secure": p.get("secure", False)}, True)
            return
        print("profile %d%s: %s" % (args.slot, " (secure: every presence needs a touch)" if p.get("secure") else "",
                                    ", ".join("%s: %s" % (a, "no touch" if a in auto else "touch")
                                              for a in policy.APPS)))
    with_session(args, run)


def cmd_board(args):
    def run(m):
        info = m.info()
        if args.led_brightness is not None:
            if not 0 <= args.led_brightness <= 255:
                sys.exit("the LED brightness must be 0..255")
            _change_hint(m, info)
            m.set_led_brightness(args.led_brightness)
            info = m.info()
        board = info.get("board")
        if board is None:
            sys.exit("the device reports no board settings (firmware before management protocol 3, or safe mode)")
        _print(board, args.json)
    with_session(args, run)


def cmd_export(args):
    passphrase = None if args.no_encrypt else _passphrase(args, confirm=True)
    def run(m):
        pin, no_pin = _fido_pin(m, _pin_file(args), args.no_pin, ask=args.pin)

        def export(pin, no_pin):
            _touch_hint("export the active profile")
            return m.export_profile(pin=pin, progress=_progress, no_pin=no_pin)
        stream = _with_pin(export, pin, no_pin)
        n = write_file(args.file, stream, passphrase, warn=lambda msg: print("warning: %s" % msg, file=sys.stderr))
        print("wrote %s (%d bytes, %s)" % (args.file, n, "encrypted" if passphrase is not None else
                                           "NOT encrypted: anyone with this file has the keys"))
    with_session(args, run)


def _read_blob(path):
    with open(path, "rb") as f:
        return f.read()                     # read once: the file cannot change between the steps


def _decrypt(args, blob, firmware=None):
    """(info, stream) of the backup in blob; asks for the passphrase when it
    is encrypted. firmware: the device the stream is meant for."""
    info, stream = read_file(blob, firmware=firmware)
    if info["encrypted"]:
        info, stream = read_file(blob, _passphrase(args, confirm=False), require_encryption=True,
                                 firmware=firmware)
    else:
        print("warning: %s is NOT encrypted, nothing proves it was not modified" % args.file, file=sys.stderr)
    return info, stream


def cmd_verify(args):
    blob = _read_blob(args.file)
    info, stream = _decrypt(args, blob)
    _print(info, args.json)
    min_fw = info["summary"]["header"]["min_firmware"]
    if not (args.device or args.restore_test):
        if not firmware_supports(__version__, min_fw):
            print("warning: the backup needs firmware %s or newer (this tool knows %s; no device was checked)"
                  % (min_fw, __version__), file=sys.stderr)
        return

    def run(m):
        fw = m.info()["firmware"]
        if not firmware_supports(fw, min_fw):
            sys.exit("the device runs firmware %s; this backup needs %s or newer" % (display_name(fw), min_fw))
        if args.restore_test:
            _touch_hint("start the restore test")
            res, ok = m.restore_test(stream, progress=_progress)
            print("device restore test: %s" % ("passed" if ok else "FAILED"))
            if not ok:
                sys.exit(1)
        else:
            m.check_backup(stream, progress=_progress)
            print("device check: the firmware accepts this backup")
    with_session(args, run)


def cmd_import(args):
    if not 1 <= args.profile <= MAX_PROFILES:
        sys.exit("the profile number must be 1..%d" % MAX_PROFILES)
    blob = _read_blob(args.file)
    head, _ = read_file(blob)
    if not head["encrypted"] and not args.allow_unencrypted:
        sys.exit("refused: %s is NOT encrypted, so nothing proves it was not replaced; add "
                 "--allow-unencrypted if you wrote it with --no-encrypt" % args.file)

    def run(m):
        # What the device can take is checked before the passphrase is asked for.
        dev = m.info()
        target = _profiles(dev, "import a backup")[args.profile - 1]
        if not firmware_supports(dev["firmware"], head["min_firmware"]):
            sys.exit("the device runs firmware %s; this backup needs %s or newer (update the firmware first)"
                     % (display_name(dev["firmware"]), head["min_firmware"]))
        info, stream = _decrypt(args, blob, firmware=dev["firmware"])
        h = info["summary"]["header"]
        print("backup: %s, UUID %s, serial %s, %d files, %s" % (
            display_name(h["name"]) or "-", h["uuid"], h["serial"], info["summary"]["files"],
            "encrypted" if info["encrypted"] else "NOT encrypted"), file=sys.stderr)
        # From protocol 3 on an import into the active profile asks for its FIDO PIN.
        pin, no_pin = None, False
        if dev.get("protocol", 1) >= 3 and args.profile - 1 == dev.get("active") and dev["boot_status"] == "ok":
            pin, no_pin = _fido_pin(m, _pin_file(args), args.no_pin, ask=args.pin)

        def do_import(pin, no_pin):
            _touch_hint("%s %s with it" % ("REPLACE" if target["used"] else "fill", _describe(dev, args.profile - 1)))
            return m.import_profile(stream, args.profile - 1, progress=_progress, pin=pin, no_pin=no_pin)
        res = _with_pin(do_import, pin, no_pin)
        print("imported %d files into profile %d" % (res["files"], args.profile))
    with_session(args, run)


def cmd_factory_reset(args):
    if not args.yes:
        answer = input("This erases every profile and key on the device. Type 'erase' to continue: ")
        if answer != "erase":
            sys.exit("aborted")
    def run(m):
        _touch_hint()
        m.factory_reset(legacy=args.legacy)
        print("factory reset done, the device restarts empty")
    with_session(args, run)


def cmd_firmware(args):
    from . import firmware
    if args.action == "info" and args.file:
        with open(args.file, "rb") as f:
            _print(firmware.parse(f.read()), args.json)
        return

    def run(m):
        if args.action == "info":
            _print(m.info().get("firmware_slot", {}), args.json)
        elif args.action == "update":
            if not args.file:
                sys.exit("firmware update needs the image file")
            with open(args.file, "rb") as f:
                image = f.read()
            new = firmware.parse(image)
            cur = m.info()
            print("device firmware %s (%s), image %s (%s, %s build, %d bytes)" % (
                display_name(cur["firmware"]), cur.get("firmware_slot", {}).get("platform", "?"), new["version"],
                new["platform"], new["build_profile"], new["size"]))
            if not args.yes and input("Install it? Key storage is not touched. [y/N] ").strip().lower() != "y":
                print("cancelled")
                return
            pin, no_pin = _update_pin(m, cur, args)

            def update(pin, no_pin):
                _touch_hint("install the firmware")
                return m.update_firmware(image, pin=pin, allow_downgrade=args.allow_downgrade, progress=_progress,
                                         confirm=not args.no_confirm, no_pin=no_pin)
            r = _with_pin(update, pin, no_pin)
            print("\nrunning %s in slot %s%s" % (r["installed"], r["slot"], "" if r["confirmed"] else
                                                  " (unconfirmed: the next reset goes back)"))
            if r.get("warning"):
                print("warning: %s" % r["warning"], file=sys.stderr)
        elif args.action == "confirm":
            m.confirm_firmware()
            print("firmware confirmed")
        elif args.action == "rollback":
            info = m.info()
            pin, no_pin = _update_pin(m, info, args) if info.get("protocol", 1) >= 2 else (None, True)

            def rollback(pin, no_pin):
                _touch_hint("go back to the previous firmware")
                return m.rollback_firmware(pin=pin, no_pin=no_pin)
            print("running %s" % display_name(_with_pin(rollback, pin, no_pin)))
    with_session(args, run)


def cmd_provision(args):
    from . import provision

    def run(m):
        info = m.info()
        keystore = m.keystore_unlocked()
        state = provision.state(info, keystore)
        lvl = policy.protection_level(info["security"])
        if args.action == "plan":
            steps = provision.plan(info, keystore)
            if args.json:
                _print({"protection_level": lvl,
                        "steps": [{k: s.get(k) for k in ("id", "title", "is_done", "automated", "command",
                                                         "irreversible", "effect", "brick_risk")} for s in steps]},
                       True)
                return
            print("device %s, %s build, %s" % (info["chip_serial"], display_name(info["build_profile"]),
                                                 info.get("firmware_slot", {}).get("platform", "?")))
            print("protection level %d / 3: %s" % (lvl, policy.LEVELS[lvl]))
            if keystore is False:
                print("the key store of the active profile is LOCKED")
            if state["held"]:
                print("\n" + provision.held_text(state) + "\n-> librefido provision bind-root-key --apply")
            elif state["none_recorded"]:
                print("\nThe active profile has no root key (its keys are derived from the device serial); that is "
                      "recorded on the chip.")
            print("\nSteps 1 and 2 lead to level 2; this tool does them (irreversible, a typed confirmation and "
                  "a touch each, neither can brick the board):")
            for i, s in enumerate(steps, 1):
                how = ("  ->  %s --apply" % s["command"]) if s["automated"] else \
                    "  (manual, see docs/ESP32S3_HARDENING.md)"
                print("\n%d. [%s] %s%s" % (i, "done" if s["is_done"] else "todo", s["title"],
                                           "" if s["is_done"] else how))
                if not s["is_done"]:
                    print("   irreversible: %s\n   effect: %s\n   brick risk: %s" % (
                        s["irreversible"], s["effect"], s["brick_risk"]))
            return
        step_id = "hmac" if args.action == "bind-root-key" else "lock_debug"
        s = {x["id"]: x for x in provision.plan(info, keystore)}[step_id]
        held = step_id == "hmac" and state["held"]
        if held:
            print("Bind the held %s of the active profile to this chip" %
                  ("state (no root key)" if state["held_none"] else "root key"))
        else:
            print("%s\n  irreversible: %s\n  effect: %s\n  brick risk: %s" % (
                s["title"], s["irreversible"], s["effect"], s["brick_risk"]))
        if not args.apply:
            provision.check_consistent(info, keystore, binding=step_id == "hmac")
            if held:
                print(provision.held_text(state))
            print("\n%s: nothing changed (add --apply to do it)" % ("already done" if s["is_done"] else "dry run"))
            return
        what = {"hmac": ("record that the profile has no root key" if state["held_none"] else "bind the root key")
                if held else "burn the eFuse key and bind the root key",
                "lock_debug": "burn the JTAG and download mode eFuses"}[step_id]

        def confirm(expected):
            text = input("Type '%s' to %s: " % (expected, what)).strip()
            if text == expected:
                _touch_hint(what)
            return text
        if step_id == "hmac":
            after = provision.bind_root_key(m, confirm, directory=args.metadata_dir)
            print("root key: %s" % after["security"]["root_key"])
        else:
            after = provision.lock_debug(m, confirm, directory=args.metadata_dir)
            print("JTAG disabled: %s, secure download mode: %s" % (after["security"]["jtag_disabled"],
                                                                   after["security"]["download_restricted"]))
        lvl = policy.protection_level(after["security"])
        print("protection level %d / 3: %s" % (lvl, policy.LEVELS[lvl]))
    try:
        with_session(args, run)
    except provision.ProvisionError as e:
        sys.exit("refused: %s" % e)


def cmd_reboot(args):
    def run(m):
        pin, no_pin = None, True
        if args.bootloader:
            info = m.info()
            if info.get("protocol", 1) >= 2:
                pin, no_pin = _update_pin(m, info, args)

        def reboot(pin, no_pin):
            _touch_hint("restart into the ROM loader" if args.bootloader else "restart")
            m.reboot(bootloader=args.bootloader, pin=pin, no_pin=no_pin)
        _with_pin(reboot, pin, no_pin)
    with_session(args, run)


def with_session(args, fn):
    m = Management.open(args.reader, timeout=args.wait)
    try:
        fn(m)
    finally:
        m.close()


def _pin_options(parser, what):
    parser.add_argument("--pin", action="store_true",
                        help="always ask for the FIDO PIN%s (by default it is asked for when the profile has one)"
                             % what)
    parser.add_argument("--pin-file", help="first line (UTF-8) is the FIDO PIN (never put a PIN on the "
                                           "command line: other users can see it)")
    parser.add_argument("--no-pin", action="store_true", help="the active profile has no FIDO PIN")


def main(argv=None):
    p = argparse.ArgumentParser(prog="librefido", description="Manage LibreFido devices over PC/SC.")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--reader", help="PC/SC reader name prefix of the device")
    p.add_argument("--wait", type=float, default=0.0, help="seconds to wait for a device")
    p.add_argument("--json", action="store_true", help="machine readable output")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="connected devices").set_defaults(fn=cmd_list)
    sub.add_parser("info", help="device, security and profile overview").set_defaults(fn=cmd_info)
    h = sub.add_parser("health", help="storage health report")
    h.add_argument("--scrub", action="store_true", help="verify and repair every sector first")
    h.set_defaults(fn=cmd_health)

    pr = sub.add_parser("profile", help="isolated profiles (each is a separate key)")
    pr.add_argument("action", choices=["list", "select", "set", "wipe", "delete", "slots", "create-secure"])
    pr.add_argument("index", type=int, nargs="?",
                    help="profile number 1..4, required except for 'list' (for 'slots': how many the "
                         "button cycles through)")
    pr.add_argument("--name", help="at most 23 bytes of UTF-8 (longer names are shortened)")
    pr.add_argument("--color", help="RGB hex, e.g. 00c000")
    pr.add_argument("--export", choices=["on", "off"], help="allow exporting this profile")
    pr.add_argument("--yes", action="store_true", help="create-secure: replace a used slot without asking")
    pr.set_defaults(fn=cmd_profile)

    ps = sub.add_parser("presence", help="automatic presence per application of a profile (\"my device is "
                                         "safe\"): without a touch any program can use those keys")
    ps.add_argument("slot", type=int, help="profile number 1..4")
    for app in policy.APPS:
        ps.add_argument("--" + app, action=argparse.BooleanOptionalAction, default=None,
                        help="%s without a touch (--no-%s: a touch again)" % (policy.APP_LABELS[app], app))
    ps.add_argument("--all", action=argparse.BooleanOptionalAction, default=None,
                    help="every application (--no-all: a touch for every one)")
    ps.set_defaults(fn=cmd_presence)

    bd = sub.add_parser("board", help="board settings shared by all profiles")
    bd.add_argument("--led-brightness", type=int, metavar="N", help="0..255, applied at once")
    bd.set_defaults(fn=cmd_board)

    ex = sub.add_parser("export", help="back up the active profile to a file")
    ex.add_argument("file")
    ex.add_argument("--no-encrypt", action="store_true", help="write the keys in the clear")
    _pin_options(ex, "")
    ex.add_argument("--passphrase-file", help="first line (UTF-8) is the passphrase")
    ex.set_defaults(fn=cmd_export)

    ve = sub.add_parser("verify", help="check a backup file without importing it")
    ve.add_argument("file")
    ve.add_argument("--device", action="store_true", help="also let the firmware validate it")
    ve.add_argument("--restore-test", action="store_true",
                    help="let the device restore it into scratch space and compare (reboots)")
    ve.add_argument("--passphrase-file", help="first line (UTF-8) is the passphrase")
    ve.set_defaults(fn=cmd_verify)

    im = sub.add_parser("import", help="restore / clone a backup into a profile slot")
    im.add_argument("file")
    im.add_argument("--profile", type=int, required=True, help="target profile number 1..4")
    im.add_argument("--passphrase-file", help="first line (UTF-8) is the passphrase")
    im.add_argument("--allow-unencrypted", action="store_true",
                    help="accept a backup written with --no-encrypt (nothing authenticates its content)")
    _pin_options(im, " (an import into the active profile needs it)")
    im.set_defaults(fn=cmd_import)

    fr = sub.add_parser("factory-reset", help="erase everything")
    fr.add_argument("--legacy", action="store_true", help="also erase the pre-2.0 store")
    fr.add_argument("--yes", action="store_true")
    fr.set_defaults(fn=cmd_factory_reset)

    fw = sub.add_parser("firmware", help="firmware version, update (A/B with rollback)")
    fw.add_argument("action", choices=["info", "update", "confirm", "rollback"])
    fw.add_argument("file", nargs="?", help="firmware image (.bin on ESP32)")
    fw.add_argument("--allow-downgrade", action="store_true")
    fw.add_argument("--no-confirm", action="store_true",
                    help="leave the new firmware unconfirmed (a reset rolls back)")
    _pin_options(fw, " for update and rollback")
    fw.add_argument("-y", "--yes", action="store_true")
    fw.set_defaults(fn=cmd_firmware)
    pv = sub.add_parser("provision", help="chip security: plan (read only), bind the root key to the chip, "
                                          "lock debugging (JTAG, secure download mode)")
    pv.add_argument("action", choices=["plan", "bind-root-key", "lock-debug"])
    pv.add_argument("--apply", action="store_true", help="really burn the eFuses (default: dry run)")
    pv.add_argument("--metadata-dir", default=".", help="where the device metadata is saved first")
    pv.set_defaults(fn=cmd_provision)
    rb = sub.add_parser("reboot", help="restart the device (touch)")
    rb.add_argument("--bootloader", action="store_true",
                    help="ESP32 ROM download mode (recovery flash; the FIDO PIN is asked for like for an update)")
    _pin_options(rb, " (with --bootloader)")
    rb.set_defaults(fn=cmd_reboot)

    args = p.parse_args(argv)
    try:
        args.fn(args)
    except (ApduError, BackupError, FirmwareError, RuntimeError, OSError, CardConnectionException) as e:
        sys.exit("error: %s" % e)


if __name__ == "__main__":
    main()
