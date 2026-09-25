"""librefido: command line management of LibreFido devices."""

import argparse
import getpass
import json
import locale
import os
import sys
import time

from smartcard.Exceptions import CardConnectionException

from . import __version__, keyio, policy, stdformats
from .backup import BackupError, _write_private, firmware_supports, read_file, write_file
from .firmware import FirmwareError
from .keyfile import SingleKey, is_key_file, read_key_file, write_key_file
from .keyio import KeyTransferError
from .mgmt import APPS, KEY_ID_MAX, Management, PinRequired, clip_name, display_name
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


def _passphrase(args, confirm, what="Backup", clear_option="--no-encrypt"):
    """Backup (or key file, what) passphrase: the first line of
    --passphrase-file (UTF-8, a BOM and the line end removed) or a prompt.
    confirm (a new file) refuses an empty passphrase: only clear_option
    writes the keys in the clear. Without confirm (reading), a list: this
    passphrase, then the ones older versions derived from the same file
    (legacy_passphrases)."""
    path = getattr(args, "passphrase_file", None)
    if path:
        p = _first_line(path, "passphrase")
    else:
        p = getpass.getpass("%s passphrase: " % what)
        if confirm and getpass.getpass("Repeat passphrase: ") != p:
            sys.exit("passphrases differ")
    if confirm:
        if not p:
            sys.exit("empty passphrase refused (%s writes the keys in the clear)" % clear_option)
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


def _resolve_aaguid(value):
    """--aaguid UUID|HEX|NAME to 16 raw bytes: a preset name
    (policy.AAGUID_PRESETS), the UUID form or 32 hex digits. 'default' is
    handled by the caller (None, not a call here)."""
    for name, _, hex_value in policy.AAGUID_PRESETS:
        if value == name:
            return bytes.fromhex(hex_value)
    try:
        return policy.parse_aaguid(value)
    except ValueError as e:
        sys.exit("--aaguid: not a preset name and not an AAGUID (%s): %r" % (e, value))


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
                build_defaults = {h for name, _, h in policy.AAGUID_PRESETS if name in ("standard", "hardened")}
                if p.get("aaguid") and p["aaguid"] not in build_defaults:
                    tags.append("[aaguid: %s]" % policy.format_aaguid(p["aaguid"]))
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
            if args.aaguid is not None:
                info = m.info()
                if info.get("active") != args.index - 1:
                    sys.exit("--aaguid only changes the AAGUID of the active profile (profile %d is not "
                             "active); switch to it first" % args.index)
                aaguid = None if args.aaguid == "default" else _resolve_aaguid(args.aaguid)
                _touch_hint("set the AAGUID of %s" % _describe(info, args.index - 1))
                m.set_aaguid(aaguid)
            if args.name is not None or args.color is not None or args.export is not None:
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


# -- single keys (docs/KEY_TRANSFER.md) ---------------------------------------------
# The helpers that ask nothing are shared with the GUI.

KEY_FORMATS = {"lfkey": None, "otpauth": "oath", "pem": "piv"}      # format: the only application it takes
KEY_SOURCE_MAX = 1024 * 1024        # key files, PEM and OpenPGP key files are far smaller
PGP_SLOTS = ("sig", "dec", "aut")
COSE_ALGS = {-7: "ES256", -8: "EdDSA", -35: "ES384", -36: "ES512", -47: "ES256K", -257: "RS256"}
PIV_PIN_POLICIES = {0: "default", 1: "never", 2: "once", 3: "always"}
PIV_TOUCH_POLICIES = {0: "default", 1: "never", 2: "always", 3: "cached"}
NOT_EXPORTABLE = "this profile or build does not let secret keys out (a secure or no-export profile, or a " \
                 "HARDENED build)"
FIDO_EXPORT_NOTE = ("the passkey stays on this key as well. A site that checks signature counters may take a "
                    "passkey used on two keys for a clone and block it: use it on one key only.")
FIDO_IMPORT_NOTE = ("the passkey's signature counter goes on from the one of the key it was exported from, as it "
                    "was at the export. If that key keeps using the passkey, a site that checks signature counters "
                    "may take it for a clone and block it: use it on one key only.")
_IMAGE_MAGIC = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a")
_LINK_SCHEMES = ("otpauth:", "otpauth-migration:")
_KEY_LIST_REFUSALS = {
    0x6985: "the key store of the active profile is locked, or its storage is not ready or a restart is pending "
            "(see `librefido info`)",
    0x6983: "the FIDO PIN is blocked",
    0x6A81: "this firmware lists no %s keys",
    0x6D00: "the firmware cannot list single keys (LibreFido 2.1.0 or newer)",
}
# Why a listing waits for a touch: the device never lists more than the
# application itself gives out without its secret.
_KEY_LIST_TOUCH = {
    "fido": "without the FIDO PIN, the device lists passkeys only after a touch",
    "oath": "while an OATH password or OTP PIN is set, the device lists the accounts only after a touch",
}
_SECRET_OPTIONS = {"oath": "--oath-password", "otp": "--access-code", "openpgp": "--admin-pin", "piv": "--mgmt-key"}
# FIDO without a verified FIDO PIN lists what a getAssertion with user presence
# alone gives: the credProtect 1 passkeys, without user names (docs/KEY_TRANSFER.md)
FIDO_NO_PIN_NOTE = ("the passkeys were listed without the FIDO PIN: passkeys that need user verification are only "
                    "listed with the FIDO PIN, and user names only then (--pin asks for it, --pin-file reads it; a "
                    "profile without a FIDO PIN lists them once one is set)")


def key_entry_text(app, entry, T=lambda s: s):
    """(name, details) of an entry of Management.list_keys() as text safe to
    show (names from the device through display_name); T translates the
    fixed words and the joiner of the details (the GUI: full-width in
    Chinese)."""
    def text(v):
        if isinstance(v, bytes):
            v = v.decode("utf-8", "replace")
        return display_name(v) if isinstance(v, str) else "?"
    e = entry
    sep = T(", ")
    try:
        if app == "fido":
            user = [text(v) for v in (e.get(4), e.get(5)) if v]
            if len(user) == 2 and user[0] == user[1]:
                user.pop()
            who = "%s (%s)" % tuple(user) if len(user) == 2 else user[0] if user else "ID " + e[6].hex()
            details = [T("user %s") % who, COSE_ALGS.get(e.get(3), "alg %s" % e.get(3))]
            if e.get(7):
                details.append(T("imported"))
            return text(e[2]), sep.join(details)
        if app == "oath":
            details = ["%s %s" % ("HOTP" if e[2] & 0xF0 == stdformats.OATH_HOTP else "TOTP",
                                  stdformats.OATH_ALGORITHM_NAMES.get(e[2] & 0x0F, "?")), T("%d digits") % e[3]]
            if e.get(4):
                details.append(T("touch"))
            return text(e[1]), sep.join(details)
        if app == "otp":
            return T("slot %s") % e[1][0], text(e.get(2)) + (sep + T("access code") if e.get(3) else "")
        if app == "openpgp":
            fp = e[3].hex().upper()
            details = [stdformats.pgp_attr_name(e[2]),
                       T("fingerprint %s") % " ".join(fp[i:i + 4] for i in range(0, len(fp), 4))]
            if e.get(4):
                details.append(T("created %s") % time.strftime("%Y-%m-%d", time.gmtime(e[4])))
            return T("%s key" % keyio.PGP_SLOT_NAMES[e[1][0]]), sep.join(details)
        if app == "piv":
            details = [stdformats.PIV_ALGORITHMS.get(e[2], "algorithm %s" % e[2])]
            if 3 in e:
                details.append(T("PIN policy %s") % T(PIV_PIN_POLICIES.get(e[3], str(e[3]))))
            if 4 in e:
                details.append(T("touch policy %s") % T(PIV_TOUCH_POLICIES.get(e[4], str(e[4]))))
            return T("slot %s") % ("%02X" % e[1][0]), sep.join(details)
    except (KeyError, IndexError, TypeError, ValueError, AttributeError, OverflowError, OSError):
        pass
    return "?", T("malformed entry")


def key_list_error(app, e, touch=False):
    """KeyTransferError with a clear message for a refused KEY_LIST (e an
    ApduError other than PinRequired). touch: the listing may have waited
    for a touch (Management.list_needs_touch), which 6985 then most likely
    means was not given."""
    text = _KEY_LIST_REFUSALS.get(e.sw)
    if e.sw == 0x6985 and touch:
        text = "the key was not touched: %s. Touch the key when it blinks and list again (if it did not blink: %s)" \
               % (_KEY_LIST_TOUCH[app], text)
    if text is None:
        return KeyTransferError(str(e), e.sw)
    return KeyTransferError("key list (%s): %s (SW %04X)" % (app, text % app if "%s" in text else text, e.sw), e.sw)


def list_all_keys(m, apps, pin=None, no_pin=False, touch_hint=None):
    """The keys of the applications apps (names, in this order): ([(app,
    entry)], exportable, listed), exportable being whether secret keys can
    be exported (None when no application answered) and listed the
    applications that did. With more than one application, one whose keys
    this firmware does not list (6A81) is left out; other refusals raise
    KeyTransferError (key_list_error), a missing FIDO PIN PinRequired.
    touch_hint(app) is called before the listing of an application that may
    wait for a touch."""
    rows, exportable, listed = [], None, []
    for app in apps:
        touch = m.list_needs_touch(app, pin)
        if touch and touch_hint:
            touch_hint(app)
        try:
            entries, exportable = m.list_keys(app, pin=pin, no_pin=no_pin)
        except PinRequired:
            raise
        except ApduError as e:
            if e.sw == 0x6A81 and len(apps) > 1:
                continue
            raise key_list_error(app, e, touch) from e
        listed.append(app)
        rows += [(app, entry) for entry in entries]
    return rows, exportable, listed


def already_there(e):
    """Whether a KeyTransferError of keyio.import_single refuses to replace
    a key already where the new one goes (replace=True would replace it).
    Not every such refusal carries 6A89 (keyio checks some itself), but all
    of them say so."""
    return getattr(e, "sw", None) == 0x6A89 or "replace it explicitly" in str(e)


def write_key(path, key, fmt, passphrase, warn=None):
    """Writes key (a SingleKey) to path in format fmt (KEY_FORMATS): a key
    file, a PEM file (PIV) or an otpauth:// link (OATH: always in the clear).
    passphrase None writes the key in the clear, which must be the user's
    confirmed choice. Written privately and atomically; returns the size."""
    if KEY_FORMATS.get(fmt, key.app) not in (None, key.app):
        raise ValueError("format %s does not take %s keys" % (fmt, key.app))
    if fmt == "lfkey":
        return write_key_file(path, key, passphrase, warn=warn)
    if fmt == "pem":
        data = stdformats.piv_record_to_pem(key.record, passphrase)
    else:
        if passphrase is not None:
            raise ValueError("an otpauth:// link cannot be encrypted")
        data = (stdformats.oath_record_to_uri(key.record) + "\n").encode("utf-8")
    _write_private(path, data, plaintext=passphrase is None, warn=warn)
    return len(data)


def key_source_kind(data):
    """What a file to add a key from holds, from its first bytes: "lfkey",
    "links" (otpauth:// text), "image" (a QR code), "openpgp", "piv" (PEM,
    DER, PKCS#12), or None."""
    head = bytes(data[:64])
    if is_key_file(head):
        return "lfkey"
    if head.startswith(_IMAGE_MAGIC) or (head[:4] == b"RIFF" and head[8:12] == b"WEBP"):
        return "image"
    if head.lstrip(b"\xef\xbb\xbf \t\r\n").lower().startswith(tuple(s.encode() for s in _LINK_SCHEMES)):
        return "links"
    if b"-----BEGIN PGP " in data:
        return "openpgp"
    if b"-----BEGIN " in data:
        return "piv"
    if head[:1] and head[0] & 0x80:
        return "openpgp"                    # binary packets (gpg --export-secret-keys)
    if head[:1] == b"\x30":
        return "piv"                        # DER: PKCS#8, PKCS#1 / SEC1 or PKCS#12
    return None


def read_key_source(path, app=None):
    """(data, kind) of a file to add a key from, kind as key_source_kind()
    tells; app (an application name) settles what the file holds for it.
    data is None for an image (the QR code is decoded from its file). Raises
    FormatError for a file larger than KEY_SOURCE_MAX (images excepted) or
    one that app cannot take."""
    with open(path, "rb") as f:
        data = f.read(KEY_SOURCE_MAX + 1)
    kind = key_source_kind(data)
    if app is not None and kind != "lfkey":
        if app == "oath":
            kind = kind if kind in ("links", "image") else "image"
        elif app in ("openpgp", "piv"):
            kind = app
        else:
            raise stdformats.FormatError("%s keys are added from LibreFido key files only" % app)
    if kind == "image":
        return None, kind
    if len(data) > KEY_SOURCE_MAX:
        raise stdformats.FormatError("%s is larger than %d KiB: not a key file" % (path, KEY_SOURCE_MAX // 1024))
    return data, kind


def is_link(text):
    return text.strip().lower().startswith(_LINK_SCHEMES)


def oath_keys_from_links(texts):
    """OATH keys (SingleKeys) of otpauth:// and otpauth-migration:// links
    (blank lines ignored) and what the user must be told: (keys, left_out,
    missing). left_out: why accounts of a Google Authenticator export were
    left out (the device cannot hold them); missing: {export ID: [QR code
    numbers, from 1]} of exports split over several QR codes not all among
    texts. Raises FormatError."""
    links = [t.strip() for t in texts if t.strip()]
    if not links:
        raise stdformats.FormatError("no otpauth:// link")
    keys, left_out = [], []
    for link in links:
        try:
            records = stdformats.parse_otpauth(link)
        except stdformats.FormatError as e:
            if not link.lower().startswith("otpauth-migration:"):
                raise
            records = stdformats.parse_otpauth(link, skip_unsupported=True)
            left_out.append(str(e))
        keys += [SingleKey("oath", r) for r in records]
    if not keys:
        raise stdformats.FormatError("; ".join(left_out) or "no account in the link")
    missing = {bid: [i + 1 for i in idx] for bid, idx in stdformats.missing_batches(links).items()}
    return keys, left_out, missing


def qr_links(path):
    """(otpauth links, number of other QR codes) of the QR codes of an image
    file. Raises FormatError (no QR code, none with a link, no decoder)."""
    texts = stdformats.decode_qr_image(path)
    links = [t for t in texts if is_link(t)]
    if not links:
        raise stdformats.FormatError("no QR code with an otpauth:// link in %s" % path)
    return links, len(texts) - len(links)


def pgp_key_text(k):
    """One line about a key of an OpenPGP key file (parse_openpgp_secret)."""
    return "%s %s [%s]%s %s" % (k["algorithm"], k["key_id"] or "?", ", ".join(sorted(k["usage"])) or "-",
                                " (primary)" if k["primary"] else "",
                                display_name(k["user_ids"][0]) if k["user_ids"] else "")


def _key_selector(text):
    """(application, number or None, key ID or None) of a key selector: APP:N
    (N as `key list` numbers the keys) or APP:hex:ID."""
    app, sep, rest = text.partition(":")
    app = app.strip().lower()
    usage = "key selector %r: APP:N or APP:hex:ID, APP one of %s" % (text, ", ".join(APPS))
    if not sep or app not in APPS:
        sys.exit(usage)
    if rest[:4].lower() == "hex:":
        try:
            key_id = bytes.fromhex(rest[4:])
        except ValueError:
            sys.exit(usage + " (ID: hex digits)")
        if not 1 <= len(key_id) <= KEY_ID_MAX:
            sys.exit(usage + " (ID: 1 to %d bytes)" % KEY_ID_MAX)
        return app, None, key_id
    try:
        number = int(rest, 10)
    except ValueError:
        number = 0
    if number < 1:
        sys.exit(usage)
    return app, number, None


def _key_support(m, direction, app, verb=None):
    """Exits with a clear refusal unless the firmware itself exports
    (direction "export", which includes listing) or imports keys of app."""
    support = m.key_transfer()
    if app not in support[direction]:
        verb = verb or direction
        if not support["export"] and not support["import"]:
            sys.exit("refused: the firmware of this device cannot %s single keys (LibreFido 2.1.0 or newer)" % verb)
        sys.exit("refused: the firmware of this device cannot %s %s keys" % (verb, app))


def _list_touch_hint(app):
    """Before a listing that may wait for a touch (list_all_keys): certain
    for FIDO without the PIN, for OATH only while it has a password or an
    OTP PIN."""
    _touch_hint("list the %s keys" % app, maybe=app != "fido")


def _key_at(m, app, number, pin, no_pin, touch_hint=_list_touch_hint):
    """(key ID, entry) of the number-th key of app as `key list` numbers
    them; exits when there is none, and before the touch when secret keys
    cannot be exported. A FIDO listing without the PIN says what it left out."""
    rows, exportable, _ = list_all_keys(m, [app], pin, no_pin, touch_hint)
    if app == "fido" and not pin:
        print("note: %s" % FIDO_NO_PIN_NOTE, file=sys.stderr)
    if not exportable:
        sys.exit("refused: %s" % NOT_EXPORTABLE)
    if number > len(rows):
        sys.exit("%s:%d: the device lists %d %s key%s (librefido key list --app %s)"
                 % (app, number, len(rows), app, "" if len(rows) == 1 else "s", app))
    entry = rows[number - 1][1]
    key_id = entry.get(1)
    if not isinstance(key_id, bytes) or not 1 <= len(key_id) <= KEY_ID_MAX:
        sys.exit("%s:%d: malformed entry from the device" % (app, number))
    return key_id, entry


def _confirm_plaintext(args, what):
    """The second confirmation of --plaintext: --yes-plaintext, or typed. The
    question goes to stderr: with -o - standard output is the link itself,
    which a redirection would otherwise carry the question in front of."""
    if args.yes_plaintext:
        return
    print("%s: anyone with it has your key. Continue? [y/N] " % what, end="", file=sys.stderr, flush=True)
    answer = sys.stdin.readline()           # "" at the end of the input
    if answer.strip().lower() not in ("y", "yes"):
        sys.exit("aborted (--yes-plaintext confirms --plaintext without asking)")


def _admin_pin(args):
    """OpenPGP Admin PIN (PW3): the first line of --admin-pin-file, or typed."""
    path = getattr(args, "admin_pin_file", None)
    pin = _first_line(path, "Admin PIN") if path else getpass.getpass("OpenPGP Admin PIN: ")
    if not pin:
        sys.exit("the OpenPGP Admin PIN is needed")
    return pin


def _file_secret(args, prompt):
    """Password of a PIV or OpenPGP key file: the first line of
    --passphrase-file, or typed."""
    path = getattr(args, "passphrase_file", None)
    return _first_line(path, "passphrase") if path else getpass.getpass(prompt)


def cmd_key_list(args):
    def run(m):
        support = m.key_transfer()["export"]
        if not support:
            sys.exit("refused: the firmware of this device cannot list single keys (LibreFido 2.1.0 or newer)")
        if args.app != "all" and args.app not in support:
            sys.exit("refused: the firmware of this device lists no %s keys" % args.app)
        apps = [a for a in APPS if a in support and args.app in ("all", a)]
        pin, no_pin = _fido_pin(m, _pin_file(args), args.no_pin, ask=args.pin)
        used = []                               # the PIN of the listing that answered (_with_pin may ask)

        def listing(pin, no_pin):
            used[:] = [pin]
            return list_all_keys(m, apps, pin, no_pin, _list_touch_hint)
        rows, exportable, listed = _with_pin(listing, pin, no_pin)
        if "fido" in listed and not used[0]:
            print("note: %s" % FIDO_NO_PIN_NOTE, file=sys.stderr)
        keys, numbers = [], dict.fromkeys(listed, 0)
        for app, entry in rows:
            numbers[app] += 1
            name, details = key_entry_text(app, entry)
            key_id = entry.get(1)
            keys.append({"app": app, "selector": "%s:%d" % (app, numbers[app]), "name": name, "details": details,
                         "id": key_id.hex() if isinstance(key_id, bytes) else None})
        if args.json:
            _print({"exportable": exportable, "applications": listed, "keys": keys}, True)
            return
        for app in listed:
            n = numbers[app]
            print("%s: %s" % (app, "%d key%s" % (n, "" if n == 1 else "s") if n else "no keys"))
            for k in keys:
                if k["app"] == app:
                    print("  %-9s %s  %s" % (k["selector"], k["name"], k["details"]))
        if exportable is not None:
            print("secret keys can be exported: %s" % ("yes" if exportable else "no: " + NOT_EXPORTABLE))
    with_session(args, run)


def cmd_key_export(args):
    app, number, key_id = _key_selector(args.selector)
    fmt = args.format
    if KEY_FORMATS[fmt] not in (None, app):
        sys.exit("--format %s is for %s keys only" % (fmt, KEY_FORMATS[fmt]))
    if (args.admin_pin or args.admin_pin_file) and app != "openpgp":
        sys.exit("--admin-pin is for OpenPGP keys")
    if args.yes_plaintext and not args.plaintext:
        sys.exit("--yes-plaintext confirms --plaintext, which is missing")
    if fmt == "otpauth" and not args.plaintext:
        sys.exit("refused: an otpauth:// link holds the secret in the clear; add --plaintext to write one "
                 "(--format lfkey writes an encrypted key file)")
    if args.output == "-" and fmt != "otpauth":
        sys.exit("-o - (standard output) is for --format otpauth only")
    passphrase = None
    if args.plaintext:
        _confirm_plaintext(args, "The otpauth:// link holds the secret in the clear" if fmt == "otpauth" else
                           "The key will NOT be encrypted")
    else:
        passphrase = _passphrase(args, confirm=True, what="Key file" if fmt == "lfkey" else "PEM",
                                 clear_option="--plaintext")

    def run(m):
        _key_support(m, "export", app)
        pin, no_pin = _fido_pin(m, _pin_file(args), args.no_pin, ask=args.pin)
        admin = _admin_pin(args) if app == "openpgp" else None      # asked before the touch

        def export(pin, no_pin):
            # fido:N without the PIN: the listing that finds N needs a touch of its own
            two = key_id is None and app == "fido" and m.list_needs_touch(app, pin)
            if key_id is not None:
                kid, what = key_id, "%s key %s" % (app, key_id.hex())
            elif two:
                kid, entry = _key_at(m, app, number, pin, no_pin, lambda a: _touch_hint(
                    "list the fido keys (touch 1 of 2: without the FIDO PIN, the listing and the export need one "
                    "each)"))
                what = "%s:%d (%s), touch 2 of 2" % (app, number, key_entry_text(app, entry)[0])
            else:
                kid, entry = _key_at(m, app, number, pin, no_pin)
                what = "%s:%d (%s)" % (app, number, key_entry_text(app, entry)[0])
            _touch_hint("export %s" % what)
            return keyio.export_single(m, app, kid, pin=pin, no_pin=no_pin, secret=admin)
        key = _with_pin(export, pin, no_pin)
        if app == "fido":
            print("note (sign counter): %s" % FIDO_EXPORT_NOTE, file=sys.stderr)
        if args.output == "-":
            print(stdformats.oath_record_to_uri(key.record))
            return
        n = write_key(args.output, key, fmt, passphrase, warn=lambda msg: print("warning: %s" % msg, file=sys.stderr))
        print("wrote %s (%d bytes, %s): %s" % (args.output, n, "encrypted" if passphrase is not None else
                                                "NOT encrypted: anyone with this file has the key", keyio.describe(key)))
    with_session(args, run)


def _read_key_file(args, path, data):
    info, key = read_key_file(data)
    if info["encrypted"]:
        info, key = read_key_file(data, _passphrase(args, confirm=False, what="Key file"), require_encryption=True)
    elif not args.allow_unencrypted:
        sys.exit("refused: %s is NOT encrypted, so nothing proves it was not replaced; add --allow-unencrypted if "
                 "you wrote it with --plaintext" % path)
    else:
        print("warning: %s is NOT encrypted, nothing proves it was not modified" % path, file=sys.stderr)
    return key


def _oath_keys(texts):
    keys, left_out, missing = oath_keys_from_links(texts)
    for why in left_out:
        print("warning: left out: %s" % why, file=sys.stderr)
    for numbers in missing.values():
        print("warning: this Google Authenticator export is split over several QR codes: number%s %s %s not "
              "here (add %s too)" % ("" if len(numbers) == 1 else "s", ", ".join(map(str, numbers)),
                                     "is" if len(numbers) == 1 else "are", "it" if len(numbers) == 1 else "them"),
              file=sys.stderr)
    return keys


def _read_piv_key(args, path, data):
    try:
        found = stdformats.load_piv_key(data)
    except stdformats.PassphraseRequired:
        found = stdformats.load_piv_key(data, _file_secret(args, "Password of %s: " % path))
    if len(found) != 1:
        sys.exit("%s holds %d private keys: add them from files with one each" % (path, len(found)))
    record, cert = found[0]
    if cert:
        record[8] = cert
    return SingleKey("piv", record)


def _read_pgp_key(args, path, data):
    """The key of an OpenPGP key file to add, and its card slot: --key-id and
    --slot choose among the keys the card can take (not revoked)."""
    try:
        found = stdformats.parse_openpgp_secret(data)
    except stdformats.PassphraseRequired:
        found = stdformats.parse_openpgp_secret(data, _file_secret(args, "Passphrase of the OpenPGP key: "))
    usable = [k for k in found if k["record"] is not None and not k["revoked"]]
    for k in found:
        if k not in usable:
            print("note: %s left out: %s" % (pgp_key_text(k), "revoked" if k["revoked"] else k["unsupported"]),
                  file=sys.stderr)
    slot = args.slot
    if slot is not None and slot not in PGP_SLOTS:
        sys.exit("--slot of an OpenPGP key: sig, dec or aut")
    if args.key_id:
        want = args.key_id.replace(" ", "").upper()
        want = want[2:] if want.startswith("0X") else want
        usable = [k for k in usable if want and k["fingerprint"].hex().upper().endswith(want)]
    elif slot:
        usable = [k for k in usable if slot in k["usage"]]
    if len(usable) != 1:
        sys.exit("%s: %s; choose one with --key-id (and --slot sig, dec or aut):\n%s" % (
            path, "no key the card can take fits" if not usable else "%d keys fit" % len(usable),
            "\n".join("  " + pgp_key_text(k) for k in (usable or found))))
    k = usable[0]
    if slot is None:
        fits = [s for s in PGP_SLOTS if s in k["usage"]]
        if len(fits) != 1:
            sys.exit("--slot sig, dec or aut: where the key %s goes (it is for %s)" % (
                k["key_id"], ", ".join(sorted(k["usage"])) or "nothing"))
        slot = fits[0]
    return SingleKey("openpgp", k["record"]), slot


def _key_source(args):
    """The keys of the import SOURCE, read, decrypted and checked (one, or
    the OATH accounts of links or QR codes), and the OpenPGP slot the chosen
    key of an OpenPGP key file goes to (else None)."""
    src, app = args.source, args.app
    if src == "-" or is_link(src):
        if app not in (None, "oath"):
            sys.exit("an otpauth link holds OATH accounts, not a %s key" % app)
        if src != "-":
            print("warning: the link is on the command line, where other users of this computer can see it (- "
                  "reads it from standard input)", file=sys.stderr)
            return _oath_keys([src]), None
        return _oath_keys(sys.stdin.read(KEY_SOURCE_MAX).splitlines()), None
    data, kind = read_key_source(src, app)
    if kind is None:
        sys.exit("cannot tell what %s holds: --app names the application" % src)
    if kind == "lfkey":
        key = _read_key_file(args, src, data)
        if app not in (None, key.app):
            sys.exit("%s holds a %s key, --app says %s" % (src, key.app, app))
        return [key], None
    if kind == "links":
        return _oath_keys(data.decode("utf-8", "replace").splitlines()), None
    if kind == "image":
        links, others = qr_links(src)
        if others:
            print("note: %d QR code%s without an otpauth link left out" % (others, "" if others == 1 else "s"),
                  file=sys.stderr)
        return _oath_keys(links), None
    if kind == "piv":
        return [_read_piv_key(args, src, data)], None
    key, slot = _read_pgp_key(args, src, data)
    return [key], slot


def _import_hint(app, e):
    if already_there(e):
        return " (--replace replaces it)"
    if str(e).endswith("give it") and app in _SECRET_OPTIONS:
        return " (%s)" % _SECRET_OPTIONS[app]
    return ""


def cmd_key_import(args):
    if args.slot is not None:
        args.slot = args.slot.strip().lower()
    keys, pgp_slot = _key_source(args)          # the passphrase before the device: the file says which key it is
    app = keys[0].app
    for option, owner in (("oath_password", "oath"), ("access_code", "otp"), ("mgmt_key", "piv"),
                          ("admin_pin", "openpgp"), ("admin_pin_file", "openpgp")):
        if getattr(args, option) and app != owner:
            sys.exit("--%s is for %s keys (this is a %s key)" % (option.replace("_", "-"), owner, app))
    opts = {}
    if args.slot is not None:
        if app in ("fido", "oath"):
            sys.exit("--slot is not used for %s keys" % app)
        if app == "openpgp" and args.slot not in PGP_SLOTS:
            sys.exit("--slot of an OpenPGP key: sig, dec or aut")
        opts[{"otp": "target", "piv": "piv_slot", "openpgp": "pgp_key_ref"}[app]] = args.slot
    if pgp_slot:
        opts["pgp_key_ref"] = pgp_slot
    if app == "piv" and "piv_slot" not in opts and not isinstance(keys[0].record.get(1), int):
        sys.exit("--slot is needed: the PIV slot for the key (9A, 9C, 9D, 9E or 82 to 95)")
    # The applications' own secrets, before the device is opened.
    if args.oath_password:
        opts["oath_password"] = getpass.getpass("OATH password: ")
    if args.access_code:
        opts["otp_access_code"] = getpass.getpass("Access code of the target OTP slot (12 hex digits): ")
    if app == "openpgp":
        opts["pgp_admin_pin"] = _admin_pin(args)
    if args.mgmt_key:
        opts["piv_mgmt_key"] = getpass.getpass("PIV management key (hex): ") if args.mgmt_key == "-" \
            else args.mgmt_key

    def run(m):
        pin, no_pin = None, False
        if app in ("fido", "otp"):
            _key_support(m, "import", app)
            pin, no_pin = _fido_pin(m, _pin_file(args), args.no_pin, ask=args.pin)
        if app == "fido":
            print("note (sign counter): %s" % FIDO_IMPORT_NOTE, file=sys.stderr)
        for i, key in enumerate(keys):
            def add(pin, no_pin, key=key):
                if key.app in ("fido", "otp"):
                    _touch_hint("add the %s" % keyio.describe(key))
                return keyio.import_single(m, key, pin=pin, no_pin=no_pin, replace=args.replace, **opts)
            try:
                print(_with_pin(add, pin, no_pin))
            except KeyTransferError as e:
                sys.exit("refused: %s%s%s" % (e, _import_hint(app, e), " (%d added before it)" % i if i else ""))
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
    pr.add_argument("--aaguid", metavar="UUID|NAME|default",
                    help="the AAGUID this profile (must be the active one) reports from now on: a UUID "
                         "(8-4-4-4-12 or 32 hex digits), a preset name (%s), or 'default' for the firmware's own. Never set this "
                         "to a real vendor's AAGUID (docs/COMPATIBILITY.md); always a touch."
                         % ", ".join(name for name, _, _ in policy.AAGUID_PRESETS))
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

    ky = sub.add_parser("key", help="single keys of the active profile: list, export one, add one "
                                    "(docs/KEY_TRANSFER.md)")
    ksub = ky.add_subparsers(dest="action", required=True)
    kl = ksub.add_parser("list", help="the keys of the active profile, numbered for export (a touch for FIDO "
                                      "without the PIN, which then lists only the passkeys that need no user "
                                      "verification, without user names; for OATH with a password)")
    kl.add_argument("--app", choices=list(APPS) + ["all"], default="all")
    _pin_options(kl, "")
    kl.set_defaults(fn=cmd_key_list)
    ke = ksub.add_parser("export", help="one key to a file, encrypted with a passphrase (touch, FIDO PIN if set; "
                                        "fido:N without the FIDO PIN: two touches, listing and export)")
    ke.add_argument("selector", help="APP:N as `key list` numbers the keys (e.g. fido:2), or APP:hex:ID (the IDs: "
                                     "librefido --json key list)")
    ke.add_argument("-o", "--output", required=True, metavar="FILE",
                    help="the file to write (- : standard output, for --format otpauth only)")
    ke.add_argument("--format", choices=list(KEY_FORMATS), default="lfkey",
                    help="lfkey: LibreFido key file (default); otpauth: otpauth:// link of an OATH account (always "
                         "in the clear); pem: PKCS#8 PEM of a PIV key and its certificate")
    ke.add_argument("--plaintext", action="store_true", help="write the key in the clear (asks to confirm)")
    ke.add_argument("--yes-plaintext", action="store_true", help="confirm --plaintext without asking (scripts)")
    ke.add_argument("--passphrase-file", help="first line (UTF-8) is the passphrase")
    ke.add_argument("--admin-pin", action="store_true",
                    help="ask for the OpenPGP Admin PIN (always asked for an OpenPGP key)")
    ke.add_argument("--admin-pin-file", help="first line (UTF-8) is the OpenPGP Admin PIN")
    _pin_options(ke, "")
    ke.set_defaults(fn=cmd_key_export)
    ki = ksub.add_parser("import", help="add one key (or the OATH accounts of a link): a key file, an otpauth:// "
                                        "or otpauth-migration:// link, a QR code image, a PIV key (PEM, DER, "
                                        "PKCS#12) or an OpenPGP secret key file")
    ki.add_argument("source", help="a file, a link, or - to read links from standard input (a link on the command "
                                   "line can be seen by other users)")
    ki.add_argument("--app", choices=APPS, help="what SOURCE holds, when the file does not tell")
    ki.add_argument("--slot", help="OTP: 1 or 2; PIV: 9A, 9C, 9D, 9E, 82..95; OpenPGP: sig, dec or aut (default: "
                                   "the key file's)")
    ki.add_argument("--key-id", help="OpenPGP key file: the key to add (key ID or fingerprint, hex)")
    ki.add_argument("--replace", action="store_true", help="replace a key already there (otherwise refused)")
    ki.add_argument("--passphrase-file", help="first line (UTF-8) is the passphrase of the key file (or the "
                                              "password of the PIV or OpenPGP key)")
    ki.add_argument("--allow-unencrypted", action="store_true",
                    help="accept a key file written with --plaintext (nothing authenticates its content)")
    ki.add_argument("--oath-password", action="store_true",
                    help="ask for the OATH password (when the OATH application has one)")
    ki.add_argument("--access-code", action="store_true",
                    help="ask for the access code of the target OTP slot (12 hex digits)")
    ki.add_argument("--admin-pin", action="store_true",
                    help="ask for the OpenPGP Admin PIN (always asked for an OpenPGP key)")
    ki.add_argument("--admin-pin-file", help="first line (UTF-8) is the OpenPGP Admin PIN")
    ki.add_argument("--mgmt-key", metavar="HEX|-",
                    help="PIV management key, or - to type it (a key on the command line can be seen by other "
                         "users); default: the default key, when the device still has it")
    _pin_options(ki, " (FIDO and OTP keys)")
    ki.set_defaults(fn=cmd_key_import)

    args = p.parse_args(argv)
    try:
        args.fn(args)
    except (ApduError, BackupError, FirmwareError, RuntimeError, OSError, CardConnectionException,
            KeyTransferError, stdformats.FormatError) as e:
        sys.exit("error: %s" % e)


if __name__ == "__main__":
    main()
