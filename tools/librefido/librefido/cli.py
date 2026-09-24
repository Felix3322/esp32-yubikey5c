"""librefido: command line management of LibreFido devices."""

import argparse
import getpass
import json
import sys

from . import __version__
from .backup import BackupError, read_file, write_file
from .mgmt import Management
from .pcsc import ApduError, list_devices


def _passphrase(args, confirm):
    if getattr(args, "passphrase_file", None):
        with open(args.passphrase_file) as f:
            return f.readline().rstrip("\n")
    p = getpass.getpass("Backup passphrase: ")
    if confirm and getpass.getpass("Repeat passphrase: ") != p:
        sys.exit("passphrases differ")
    return p


def _touch_hint():
    print("Touch the key when it blinks...", file=sys.stderr, flush=True)


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
                    print("%s%s: %s" % (pad, k, v))
        elif isinstance(o, list):
            for v in o:
                walk(v, indent)
                print()
    walk(obj)


def cmd_list(args):
    for reader, answer in list_devices():
        print(reader)


def cmd_info(args):
    with_session(args, lambda m: _print(m.info(), args.json))


def cmd_health(args):
    with_session(args, lambda m: _print(m.health(scrub=args.scrub), args.json))


def cmd_profile(args):
    def run(m):
        if args.action == "list":
            info = m.info()
            for p in info["profiles"]:
                mark = "*" if p["index"] == info["active"] else " "
                state = p["name"] if p["used"] else "(empty)"
                print("%s %d  #%s  %s%s" % (mark, p["index"] + 1, p["color"], state,
                                           "  [no export]" if p["no_export"] else ""))
        elif args.action == "select":
            m.select_profile(args.index - 1)
            print("switching to profile %d, the device restarts" % args.index)
        elif args.action == "set":
            m.set_profile(args.index - 1, name=args.name, color=args.color,
                          no_export=None if args.export is None else args.export == "off")
        elif args.action == "wipe":
            _touch_hint()
            m.wipe_profile(args.index - 1)
            print("profile %d will be empty after the restart" % args.index)
        elif args.action == "delete":
            _touch_hint()
            m.delete_profile(args.index - 1)
        elif args.action == "slots":
            m.set_button_slots(args.index)
    with_session(args, run)


def cmd_export(args):
    passphrase = None if args.no_encrypt else _passphrase(args, confirm=True)
    def run(m):
        pin = args.pin
        if pin is None and not args.no_pin:
            pin = getpass.getpass("FIDO PIN of the profile (empty if none): ") or None
        _touch_hint()
        stream = m.export_profile(pin=pin, progress=_progress)
        n = write_file(args.file, stream, passphrase)
        print("wrote %s (%d bytes, %s)" % (args.file, n, "encrypted" if passphrase else "NOT encrypted"))
    with_session(args, run)


def cmd_verify(args):
    info, stream = read_file(args.file)
    if info["encrypted"]:
        info, stream = read_file(args.file, _passphrase(args, confirm=False))
    _print(info, args.json)
    if args.device or args.restore_test:
        def run(m):
            if args.restore_test:
                res, ok = m.restore_test(stream, progress=_progress)
                print("device restore test: %s" % ("passed" if ok else "FAILED"))
                if not ok:
                    sys.exit(1)
            else:
                m.check_backup(stream, progress=_progress)
                print("device check: the firmware accepts this backup")
        with_session(args, run)


def cmd_import(args):
    info, stream = read_file(args.file)
    if info["encrypted"]:
        info, stream = read_file(args.file, _passphrase(args, confirm=False))
    def run(m):
        _touch_hint()
        res = m.import_profile(stream, args.profile - 1, progress=_progress)
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


def cmd_reboot(args):
    with_session(args, lambda m: m.reboot(bootloader=args.bootloader))


def with_session(args, fn):
    m = Management.open(args.reader, timeout=args.wait)
    try:
        fn(m)
    finally:
        m.close()


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
    pr.add_argument("action", choices=["list", "select", "set", "wipe", "delete", "slots"])
    pr.add_argument("index", type=int, nargs="?", default=1,
                    help="profile number 1..4 (for 'slots': how many the button cycles through)")
    pr.add_argument("--name")
    pr.add_argument("--color", help="RGB hex, e.g. 00c000")
    pr.add_argument("--export", choices=["on", "off"], help="allow exporting this profile")
    pr.set_defaults(fn=cmd_profile)

    ex = sub.add_parser("export", help="back up the active profile to a file")
    ex.add_argument("file")
    ex.add_argument("--no-encrypt", action="store_true", help="write the keys in the clear")
    ex.add_argument("--pin", help="FIDO PIN of the profile (prompted otherwise)")
    ex.add_argument("--no-pin", action="store_true", help="the profile has no FIDO PIN")
    ex.add_argument("--passphrase-file")
    ex.set_defaults(fn=cmd_export)

    ve = sub.add_parser("verify", help="check a backup file without importing it")
    ve.add_argument("file")
    ve.add_argument("--device", action="store_true", help="also let the firmware validate it")
    ve.add_argument("--restore-test", action="store_true",
                    help="let the device restore it into scratch space and compare (reboots)")
    ve.add_argument("--passphrase-file")
    ve.set_defaults(fn=cmd_verify)

    im = sub.add_parser("import", help="restore / clone a backup into a profile slot")
    im.add_argument("file")
    im.add_argument("--profile", type=int, required=True, help="target profile number 1..4")
    im.add_argument("--passphrase-file")
    im.set_defaults(fn=cmd_import)

    fr = sub.add_parser("factory-reset", help="erase everything")
    fr.add_argument("--legacy", action="store_true", help="also erase the pre-2.0 store")
    fr.add_argument("--yes", action="store_true")
    fr.set_defaults(fn=cmd_factory_reset)

    rb = sub.add_parser("reboot")
    rb.add_argument("--bootloader", action="store_true", help="ESP32 ROM download mode (recovery flash)")
    rb.set_defaults(fn=cmd_reboot)

    args = p.parse_args(argv)
    try:
        args.fn(args)
    except (ApduError, BackupError, RuntimeError) as e:
        sys.exit("error: %s" % e)


if __name__ == "__main__":
    main()
