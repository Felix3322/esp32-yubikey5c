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
| `librefido key list [--app fido\|oath\|otp\|openpgp\|piv\|all]` | the single keys of the active profile, numbered (`fido:1`, `oath:2`, ...); the FIDO PIN if set; a touch for FIDO without the PIN and for OATH with a password or OTP PIN; `--json` adds the key IDs |
| `librefido key export APP:N\|APP:hex:ID -o FILE [--format lfkey\|otpauth\|pem] [--plaintext [--yes-plaintext]] [--admin-pin-file F]` | one key to a file, encrypted with a passphrase (below) |
| `librefido key import SOURCE [--app A] [--slot S] [--key-id K] [--replace] [--oath-password] [--access-code] [--mgmt-key HEX\|-] [--admin-pin-file F]` | add one key: a `.lfkey` file, an `otpauth://` / `otpauth-migration://` link (or `-`: from standard input), a QR code image, a PIV key (PEM, DER, PKCS#12) or an OpenPGP secret key file |
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

Single keys (firmware 2.1.0 on, docs/KEY_TRANSFER.md): one FIDO passkey,
OATH account, OTP slot, OpenPGP key or PIV key (with its certificate) out
of the active profile, or one onto the device.

- Export needs a touch and the FIDO PIN of the profile (asked for as for a
  backup), an OpenPGP key also the OpenPGP Admin PIN. It is refused by
  secure and no-export profiles and HARDENED builds; `key list` says so, and
  `key export` refuses before the touch.
- Key files (`.lfkey`, magic `LFKEYFIL`) are protected like backups (scrypt,
  ChaCha20-Poly1305, written privately and atomically) and asked for the
  same way: a passphrase typed twice or `--passphrase-file`, an empty one
  refused. A key in the clear needs `--plaintext` and a second confirmation
  (typed, or `--yes-plaintext` in scripts); importing such a file needs
  `--allow-unencrypted`. `--format pem` writes a PIV key as encrypted PKCS#8
  with its certificate; `--format otpauth` an OATH account as an
  `otpauth://` link, which always holds the secret in the clear (so it needs
  `--plaintext`; `-o -` prints it, e.g. for a QR code).
- Import: FIDO passkeys and OTP slots go through the management applet (a
  touch, the FIDO PIN); FIDO passkeys are refused by secure profiles and
  HARDENED builds. OATH accounts, OpenPGP keys and PIV keys go through their
  own applications with their own secrets, as on any card of the kind: the
  OATH password (`--oath-password` asks for it), the OpenPGP Admin PIN
  (always asked for, or `--admin-pin-file`), the PIV management key (the
  default key unless `--mgmt-key`; `-` asks for it). `--slot` chooses the
  OTP slot (1, 2), the PIV slot (9A, 9C, 9D, 9E, 82..95) or the OpenPGP slot
  (sig, dec, aut); an OpenPGP key file with several keys needs `--key-id`
  (or a `--slot` that only one of them fits). A key already where the new
  one goes is replaced only with `--replace`; an OTP slot with an access code
  needs it (`--access-code`). A Google Authenticator export adds all its
  accounts; those the device cannot hold (MD5, 7 digits) and QR codes of the
  export not given are named. A link on the command line can be seen by
  other users: `-` reads links from standard input. QR code images need
  OpenCV (`pip install "./tools/librefido[qr]"`), or zxing-cpp or pyzbar
  with Pillow.
- Sign counter: an exported passkey stays on the source key, and an imported
  one goes on from the source key's counter at the export. A site that
  checks signature counters may take a passkey used on two keys for a clone
  and block it: use it on one key only. Both commands print this note.

The GUI "Keys" tab offers the same: an application filter, the list
(Refresh), "Export selected..." (encrypted by default; no encryption needs a
second confirmation), "Import file...", "Import otpauth link..." and "Import
QR image...", asking for the FIDO PIN, the OpenPGP Admin PIN, the OATH
password, the OTP access code or the PIV management key where needed, and
before replacing a key.

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
