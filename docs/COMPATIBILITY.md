# Compatibility

Status words: **tested** = exercised by an automated test or on hardware
here; **expected** = standard protocol, not tested here; **no** = known not
to work.

## Hosts and transports

| Client | Transport | Status | Notes |
|---|---|---|---|
| Windows 11 WebAuthn (browsers, `webauthn.dll`) | HID | tested on hardware | registration + assertion, ESP32-S3 N16R8 |
| Windows 11, non-admin process, raw FIDO HID | HID | **no** | Windows reserves FIDO HID for its WebAuthn service |
| Windows 11, non-admin process, FIDO over PC/SC | CCID | **no** | Windows refuses SELECT of the FIDO AID (SCARD_E_NO_ACCESS) |
| Windows 11 PC/SC (librefido, OpenPGP, PIV, OATH) | CCID | tested on hardware | no admin rights needed |
| Linux pcsc-lite | CCID | tested (emulator) | |
| Linux hidraw + python-fido2 / libfido2 | HID | tested (emulator) | |
| macOS | HID, CCID | expected | |

## Tools

| Tool | Status | Notes |
|---|---|---|
| librefido / librefido-gui | tested | management applet (profiles, backups, health, firmware) |
| python-fido2 | tested | upstream FIDO suite, 203 tests |
| yubikit (Python) | tested | PIV sessions, OATH, OpenPGP parsing; its OpenPGP key generation is gated on YubiKey versions |
| GnuPG / scdaemon | tested (card status) | key generation and signing through GnuPG: expected |
| ykman (CLI) | expected | talks the same protocols; may label the device from version numbers |
| OpenSC / PKCS#11 (PIV) | expected | |
| Yubico Authenticator (OATH) | expected | |

## Known differences from a YubiKey 5

| Area | LibreFido | Why |
|---|---|---|
| Attestation | self attestation, own AAGUID | clonable profiles; no vendor CA |
| Certification | none (no FIDO L1/L2, no FIPS) | general purpose MCU |
| Secure element | none | ESP32-S3 flash + eFuses |
| NFC | none | no hardware |
| EdDSA in FIDO | not in the ESP32 build | mbedTLS without EdDSA there |
| Several keys in one device | yes (4 profiles) | LibreFido feature |
| Export / clone / restore test | yes (not in HARDENED) | LibreFido feature |
| Firmware update | yes, A/B with rollback | LibreFido feature |

## USB identity

VID/PID `1D50:619B` (OpenMoko, free-software projects), product "LibreKeys
One", interfaces FIDO HID, CCID ("... CCID OTP FIDO Interface") and, only
when an OTP slot types, a keyboard. Every profile has its own USB serial.
