# LibreFido 2

> **Security at a glance.** Every key is stored encrypted and authenticated
> under the profile's root key. Bind that root key to the chip (one
> irreversible eFuse step, one click in the GUI) and a flash dump no longer
> reveals any key; add Secure Boot and flash encryption and only physical
> attacks on the chip remain. A *secure profile* keeps its keys on the device
> for good, like a YubiKey; a standard profile can be backed up and cloned.
> The ESP32-S3 is a general purpose microcontroller, not a secure element,
> and LibreFido is not FIDO certified. What each protection level resists:
> [docs/SECURITY_MODES.md](docs/SECURITY_MODES.md).
>
> 密钥在 flash 中始终加密并带认证存储。把根密钥绑定到芯片后，读出 flash
> 也得不到密钥；再启用 Secure Boot 和 flash 加密后只剩针对芯片的物理攻击。
> "安全环境"中的密钥永不离开设备。ESP32-S3 不是安全芯片（Secure Element），
> 本项目也未经 FIDO 认证，各防护等级的边界见上面的文档。

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
- **Secure profiles and per-application presence.** A secure profile keeps
  its keys on the device for good, like a YubiKey. On a machine you trust,
  each application of a standard profile can instead skip the button press
  ("my device is safe"); resets, exports and updates always need it
  ([docs/SECURITY_MODES.md](docs/SECURITY_MODES.md)).
- **Modern algorithms everywhere.** Ed25519 in FIDO2, Ed25519/Cv25519 in
  OpenPGP, Ed25519/X25519 in PIV, next to RSA and the NIST, brainpool and
  secp256k1 curves.
- **Desktop tools.** `librefido` (command line) and `librefido-gui`
  (PySide6, English/Chinese) over PC/SC, no administrator rights needed
  ([tools/librefido](tools/librefido/README.md)).

LibreFido is a fork of the community edition of pico-fido2 (December 2025).
It is **not** affiliated with Yubico, Nitrokey or anyone else, and uses its
own AAGUID, its own USB identity and self attestation. It speaks the
YubiKey-compatible management, OATH and OTP protocols so that tools such as
`ykman` work with it; those tools name devices after protocol fields, and
`ykman` prints "YubiKey 5A" for it ([docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)).

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
| Key store unlocked | unless the root key is held | unless the root key is held | only with the full chip security state |
| AAGUID | LibreFido 2 | LibreFido 2 | LibreFido 2 hardened |

Select with `idf.py menuconfig` → LibreFido → Build profile, or with the
CMake variable `-DLIBREFIDO_PROFILE=development|standard|hardened` (which
wins). The same menu sets the button GPIO, debounce, presence timeout, LED
GPIO and the eFuse block for the root key binding.

## Documentation

- [docs/SECURITY_MODES.md](docs/SECURITY_MODES.md) — protection levels, secure profiles, presence per application, LED
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
