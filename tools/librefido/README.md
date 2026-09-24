# librefido-tools

Desktop tools for LibreFido keys, over PC/SC (no administrator rights on
Windows, unlike raw FIDO HID access).

> 安全性和便利性不可兼得，本项目只专注于便利性，请勿存档任何有价值的数据。
> Security and convenience cannot both be had: do not keep anything valuable
> on a LibreFido key.

```bash
pip install "./tools/librefido[gui]"     # PySide6 for the GUI
librefido-gui                            # English or Chinese (system locale, LIBREFIDO_LANG=zh)
librefido --help
```

| Command | What it does |
|---|---|
| `librefido list`, `info`, `health [--scrub]` | devices, security state and protection level, profiles (secure flag, automatic presence), LED brightness, storage health |
| `librefido profile list` | isolated profiles (each one a separate key) |
| `librefido profile select/set/wipe/delete/slots N` | the profile number (or for `slots` the count) is required; `--name` holds 23 bytes of UTF-8 |
| `librefido profile create-secure N [--yes]` | a new, empty secure profile in slot N (touch; asks first when the slot is in use) |
| `librefido presence N [--fido/--no-fido] [--oath/--no-oath] [--otp/--no-otp] [--openpgp/--no-openpgp] [--piv/--no-piv] [--all/--no-all]` | automatic presence per application ("my device is safe"); without options it shows the setting |
| `librefido board [--led-brightness N]` | board settings shared by all profiles (LED brightness 0..255, applied at once) |
| `librefido export FILE [--no-encrypt] [--pin \| --pin-file F \| --no-pin] [--passphrase-file F]` | back up the active profile (touch, FIDO PIN if set); encrypted with a passphrase unless `--no-encrypt` (an empty passphrase is refused) |
| `librefido verify FILE [--device] [--restore-test]` | check a backup without importing it: offline, on the device, or by a full restore into scratch space |
| `librefido import FILE --profile N [--allow-unencrypted] [--pin \| --pin-file F \| --no-pin]` | restore or clone a backup into a profile slot; an unencrypted backup is refused without `--allow-unencrypted` |
| `librefido firmware info/update/confirm/rollback [--pin \| --pin-file F \| --no-pin]` | A/B firmware update with rollback |
| `librefido provision plan / bind-root-key / lock-debug [--apply]` | chip security, see docs/PROVISIONING.md; bind-root-key also binds a held root key (below) |
| `librefido factory-reset`, `reboot [--bootloader] [--pin \| --pin-file F \| --no-pin]` | erase everything; restart (or into the ESP32 ROM loader) |

FIDO PIN: export, firmware update and rollback, the ROM loader and (from
management protocol 3 on) an import into the active profile need the PIN of
the active profile when it has one. The tools ask the device (CTAP
getInfo) whether it has one and ask for the PIN only then; they never send
an empty PIN on a guess, because on older firmware every attempt on a
profile with a PIN uses up one of its 8 retries. While the key store is
locked getInfo reports no PIN; when the device then asks for one, the tools
ask for it and try once more. `--pin` always asks, `--pin-file F` reads it
from the first line of a UTF-8 file (a PIN is never taken from the command
line, where other users can see it), `--no-pin` states that the profile has
none (only needed when the device cannot tell).

Passphrase files are read as UTF-8 (a BOM is ignored); only the line end of
the first line is removed. Passphrases are Unicode-normalized (NFC), so the
same passphrase typed anywhere opens the file. Backups that version 2.0.0
wrote from a passphrase file (which it read with the locale's encoding, e.g.
the ANSI code page on Windows, keeping a BOM) still open with the same file.

Security modes (docs/SECURITY_MODES.md):

- Protection level 0..3 (`librefido info`, `provision plan`, GUI "Security"
  tab). The tool itself does the two steps to level 2, each irreversible,
  as a dry run unless `--apply`, with the typed confirmation
  `BURN <chip serial>`, the device metadata saved first, a touch, and a
  check afterwards: `provision bind-root-key` (HMAC eFuse key) and
  `provision lock-debug` (JTAG disabled, secure download mode: esptool still
  flashes firmware, `--no-stub`, but can no longer read the flash). Neither
  can brick the board. Secure Boot and flash encryption (level 3) stay
  guided manual steps (docs/ESP32S3_HARDENING.md).
- Secure profile (`profile create-secure N`): made empty on the device,
  never exported or imported into, every presence needs a press. Needs the
  root key bound first.
- Automatic presence (`presence N --fido ...`): a presence request of that
  application is confirmed without a press, so any program on the computer
  can use those keys. Switching it on needs a touch, off does not; never for
  secure profiles or HARDENED builds; resets, exports, imports, updates and
  provisioning always need a press.
- Names, colours, button slots and the LED brightness need no touch for a
  number of changes (`info`: free_changes), then one each.

The GUI "Security" tab offers the same: the level with the two provisioning
buttons (typed confirmation), "require a touch" per application with the "my
device is safe" switch, secure profile creation and the LED brightness
slider.

Held profiles: when the chip already has its HMAC key and Secure Boot, the
firmware keeps a profile's key store locked (`librefido info`: key_store
LOCKED) until the binding is confirmed with that profile active, if its root
key is
- stored in plain (created before the binding, or written by someone who
  could write the flash), or
- missing: a profile without root key, whose keys are derived from the device
  serial (migrated from a store without eFuse key, or restored from a backup
  without its root key). INFO reports its root key as "none" whether it is
  held or not, so the tools check the key store.
`librefido provision bind-root-key --apply` (GUI: the bind button) explains
which case it is and, after the same typed confirmation and a touch, binds
the root key or records on the chip that the profile has none (the eFuse is
not burned again); restart the key afterwards and check that `librefido
info` shows key_store: unlocked. Secure profiles and HARDENED builds never
use a profile without root key (wipe it or restore a backup with its root
key). A firmware update after which the active profile's key store is locked
(it was open before) is not confirmed automatically, so a restart still goes
back to the previous firmware.

Backup files (`.lfbk`): magic `LFBACKUP`, format version, firmware and
minimum firmware version, profile UUID, payload length and SHA-256, then the
device's backup stream, optionally encrypted with a passphrase (scrypt
N=2^17, r=8, p=1 and ChaCha20-Poly1305 over the header as associated data).
Future firmware keeps reading format 1. Only an encrypted file is
authenticated (the SHA-256 of an unencrypted one can be recomputed by anyone
who changes it), which is why imports expect encrypted files. Files are
written atomically and readable by their owner only: mode 0600 on POSIX; on
Windows an owner-only ACL set when the file is created, on NTFS/ReFS. FAT and
exFAT drives cannot restrict access: an unencrypted backup is not written
there, an encrypted one is written with a warning. The GUI keeps no
decrypted backup between operations (a device check reads the file again).

Every management command, and export, import and firmware transfers as a
whole, hold a PC/SC transaction that first selects the management applet, so
no other PC/SC program can talk to the key in between (also right after it
restarted). This does not cover the key's other USB interfaces (the
WinUSB/WebUSB smart card interface, FIDO HID): with firmware before
management protocol 2 a program using them could read an export, and until
the firmware limits the applet to the PC/SC interface one can abort (not
read or alter) a transfer, which the tool then reports. A transfer that is
interrupted (Ctrl-C) or fails is ended on the device; if the device cannot
be reached for that, the card is reset. A firmware update counts as done
only when the key restarted into the new image (another slot, same version
and build profile as installed); otherwise the tool reports that it went back
to the previous firmware, and if the check after the restart fails it says
how to confirm the new firmware.

Library use:

```python
from librefido.mgmt import Management
m = Management.open(timeout=5)
print(m.info()["profiles"])
```
