# LibreFido 2

> **安全性和便利性不可兼得，本项目只专注于便利性，请勿存档任何有价值的数据。**
>
> *Security and convenience cannot both be had. This project focuses on
> convenience only: do not keep anything valuable on it.*
>
> LibreFido keys can be backed up, exported and cloned, run on a general
> purpose microcontroller and are not certified by anyone. That is the point
> of the project, and it is also why a LibreFido key is **not** a substitute
> for a secure element or a certified authenticator. Use it where losing or
> leaking a key is an inconvenience, not a disaster.

LibreFido turns an **ESP32-S3** (primary target: N16R8, 16 MB flash, 8 MB
PSRAM) into a USB security key with several independent applications:

| Application | What it does | Details |
|---|---|---|
| FIDO2 / WebAuthn, U2F | passkeys, second factor, CTAP 2.1 | [docs/FIDO2.md](docs/FIDO2.md) |
| OpenPGP card 3.4 | GnuPG signing, decryption, SSH | [docs/OPENPGP.md](docs/OPENPGP.md) |
| PIV | smart card logon, S/MIME, SSH (PKCS#11) | [docs/PIV.md](docs/PIV.md) |
| OATH | TOTP / HOTP codes (YKOATH protocol) | [docs/OATH_OTP.md](docs/OATH_OTP.md) |
| OTP | slots typed by the button (keyboard) | [docs/OATH_OTP.md](docs/OATH_OTP.md) |

What makes it *LibreFido 2*:

- **Several keys in one device.** Up to four *profiles*, each a complete,
  isolated authenticator (own root key, serial, PINs, credentials, counters,
  OpenPGP/PIV/OATH data). Hold the button for 5 s to switch; the LED colour
  shows the active profile. After a switch the host sees another key.
- **Backups, clones and restore tests.** Export a profile to a versioned,
  optionally passphrase-encrypted file, verify a backup without importing it
  (offline, on the device, or with a full restore test), import it into any
  slot of any LibreFido device.
- **Storage that survives power cuts and ageing flash.** Journaled
  transactions, two copies of every sector, Reed-Solomon parity, generation
  counters and a scrub at every boot ([docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md)).
- **Firmware updates with rollback.** A/B slots: a new firmware that is not
  confirmed after the restart is rolled back; key storage is never touched by
  an update.
- **Desktop tools.** `librefido` (command line) and `librefido-gui`
  (PySide6, English/Chinese) over PC/SC, no administrator rights needed
  ([tools/librefido](tools/librefido/README.md)).

LibreFido is a fork of the community edition of pico-fido2 (December 2025).
It is **not** affiliated with Yubico, Nitrokey or anyone else, uses its own
AAGUID, its own USB identity and self attestation, and never presents itself
as another vendor's product.

## Quick start (ESP32-S3)

Build (ESP-IDF 5.5):

```bash
git clone --recursive <this repository> librefido && cd librefido
idf.py set-target esp32s3
idf.py build
```

Flash (first time; the board's USB port, hold BOOT while plugging in if the
board does not enter the loader by itself):

```bash
esptool --chip esp32s3 -p COM6 write-flash @build/flash_args
```

Later updates go through the key itself (A/B, with rollback):

```bash
librefido firmware update build/pico_fido2.bin
```

Install the tools and look at the device:

```bash
pip install "./tools/librefido[gui]"
librefido info
librefido-gui
```

Flashing never burns eFuses. Chip security (binding the root key to the
chip, Secure Boot, flash encryption) is a separate, explicit and partly
irreversible step: read [docs/PROVISIONING.md](docs/PROVISIONING.md) and
[docs/ESP32S3_HARDENING.md](docs/ESP32S3_HARDENING.md) first.

## Build profiles

| | DEVELOPMENT | STANDARD (default) | HARDENED |
|---|---|---|---|
| Profiles, backups, clones | yes | yes | no export (keys never leave) |
| APDU tracing | on request | on request | refused at build time |
| Maintenance writes (rescue applet) | touch | touch | refused |
| Firmware updates | touch (+ FIDO PIN) | touch (+ FIDO PIN) | only with Secure Boot, no downgrade |
| Key store unlocked | always | always | only with the full chip security state |
| AAGUID | LibreFido 2 | LibreFido 2 | LibreFido 2 hardened |

Select with `-DLIBREFIDO_PROFILE_DEVELOPMENT=1` or
`-DLIBREFIDO_PROFILE_HARDENED=1` (compile definitions).

## Documentation

- [docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) — keys, storage, profiles, backups, updates, threat model
- [docs/ESP32S3_HARDENING.md](docs/ESP32S3_HARDENING.md) — eFuses, Secure Boot, flash encryption, brick-risk boundaries
- [docs/PROVISIONING.md](docs/PROVISIONING.md) — the provisioning tool and its rules
- [docs/FIDO2.md](docs/FIDO2.md), [docs/OPENPGP.md](docs/OPENPGP.md), [docs/PIV.md](docs/PIV.md), [docs/OATH_OTP.md](docs/OATH_OTP.md)
- [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) — what works with which client, and what does not
- [docs/TESTING.md](docs/TESTING.md) — emulator, test suites, hardware tests

## Other platforms

The RP2040/RP2350 builds of the original project still compile (Pico SDK,
`PICO_SDK_PATH=... cmake .. -DPICO_BOARD=...`) but use the single-profile
legacy store: profiles, backups, firmware updates and the resilient storage
are ESP32-S3 (and emulator) features.

## USB identity

The default VID/PID `1D50:619B` was given to the original project by
[OpenMoko](https://wiki.openmoko.org/wiki/USB_Product_IDs) and may only be
used for builds distributed under a free license. Builds with another
vendor's identity (`-DVIDPID=...`) are for personal experiments only and must
not be distributed; Yubico's identity is refused by the build and by the
firmware.

## License

GNU Affero General Public License v3 (AGPLv3), see `LICENSE`, which also
lists the third-party code this project uses.
