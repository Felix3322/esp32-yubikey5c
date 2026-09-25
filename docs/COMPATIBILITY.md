# Compatibility and YubiKey 5 parity

LibreFido aims at the software feature set of the YubiKey 5 series on an
ESP32-S3. It is **not** a YubiKey, never presents Yubico's identity (USB
VID/PID, AAGUID, attestation) and is not certified by anyone.

Status words used below:

- **PASS**: exercised by an automated test in this repository (test named),
  run against the emulator build of the same sources.
- **PASS (hardware)**: also exercised on an ESP32-S3 N16R8 board.
- **UNTESTED**: implemented (standard protocol), no test here.
- **PARTIAL / NO**: see the note.

Automated results of this revision are in [TESTING.md](TESTING.md).

## 1. Implemented

### FIDO2 / WebAuthn / U2F

| Feature | Status | Evidence |
|---|---|---|
| CTAP 2.0 / 2.1 / 2.2 (getInfo: U2F_V2, FIDO_2_0, FIDO_2_1, FIDO_2_2) | PASS | `pico-fido/tests/pico-fido` (upstream suite + LibreFido additions), `test_034_getinfo_features.py` |
| U2F (CTAP1) register / authenticate | PASS | `test_020_register.py`, `test_021_authenticate.py`, `test_053_u2f_extra.py` |
| Discoverable credentials, credential management | PASS | `test_022_discoverable.py`, `test_040_cred_mgmt.py`, `test_041_cred_mgmt_extra.py` |
| ClientPIN, PIN protocols 1 and 2, pinUvAuthToken with permissions, expiry, RP binding | PASS | `test_010_pin.py`, `test_023_core_extra.py` |
| Extensions: credProtect, hmac-secret, hmac-secret-mc, credBlob, largeBlobKey, minPinLength, thirdPartyPayment | PASS | `test_031_blob.py`, `test_033_credprotect.py`, `test_035_hmac_secret.py`, `test_037_minpinlength.py`, `test_034_getinfo_features.py` |
| largeBlobs, authenticatorConfig (setMinPINLength, enterprise attestation) | PASS | `test_032_largeblob_status.py`, `test_038_config_extra.py` |
| Algorithms ES256, EdDSA (Ed25519), ES384, ES512 (ES256K optional) | PASS | `test_024_eddsa.py`, `test_020`/`test_021` `test_algorithms` |
| libfido2 1.17 (ES256 and EdDSA flows: make/get, hmac-secret, credman, largeblob, reset) | PASS | `tests/libfido2` |
| Windows 11 WebAuthn (browsers) | PASS (hardware) on firmware 2.0.0 | manual, 2026-09-23 |
| Signature counter never repeats (power cut) | PASS | `tests/profiles/test_sign_counter.py` |
| User presence cannot be forged over USB; one press = one request; stale presses rejected | PASS | `tests/profiles/test_pin_up_only.py`, `tests/transport` |

### OpenPGP card 3.4

| Feature | Status | Evidence |
|---|---|---|
| RSA 2048/3072/4096 (1024 import only), NIST P-256/384/521, brainpool 256/384/512, secp256k1 | PASS | `tests/openpgp/test_openpgp_interop.py`, `test_openpgp_access.py` |
| Ed25519 (sign, auth) and Cv25519 (decrypt) | PASS | `test_openpgp_25519.py`, `test_gnupg_flow.py` (GnuPG 2.4.4: key-attr, generate, keytocard, sign, decrypt) |
| PW1/PW3/Reset Code, retry counters durable before comparison | PASS | `test_pin_retry_durable.py`, `test_gnupg_flow.py::test_gnupg_pin_change_and_retries` |
| UIF (touch) per key | PASS | `test_presence_policy.py` |
| KDF-DO | UNTESTED | |
| GnuPG: card-status, generate, sign, encrypt/decrypt, passwd, keytocard | PASS | `test_gnupg_flow.py` |
| SSH through gpg-agent (Ed25519, NIST P-256, RSA 2048 authentication key) | PASS (emulator) | `tests/manager/test_mgr_pgp.py::test_gnupg_signs_with_the_authentication_key` (GnuPG 2.4.4 gpg-agent, `ssh-keygen -Y sign` / `-Y verify`); SSH data signed as given: `test_openpgp_25519.py::test_internal_authenticate_signs_the_data_as_given` |
| Authentication key as an OpenPGP signing subkey | PASS for RSA and ECDSA; Ed25519 needs GnuPG 2.5.8 or later | `test_gnupg_signs_with_the_authentication_key`; see [GnuPG and an Ed25519 authentication key](#gnupg-and-an-ed25519-authentication-key) |

### PIV (SP 800-73-4 plus YubiKey extensions)

| Feature | Status | Evidence |
|---|---|---|
| Slots 9A/9C/9D/9E, retired 82–95, 9B management, F9 attestation | PASS | `tests/piv/test_piv_access.py`, `test_piv_tools.py` |
| RSA 1024–4096, ECC P-256/P-384, Ed25519 (E0), X25519 (E1) | PASS | `test_piv_tools.py`, `test_piv_25519.py` |
| Management key 3DES / AES-128/192/256 | PASS | `test_piv_access.py` |
| PIN and touch policies (YubiKey defaults), PIN-always, cached touch | PASS | `test_piv_access.py`, `test_presence_policy.py` |
| Attestation (own F9 key and certificate chain) | PASS | `test_piv_25519.py`, `test_piv_access.py` |
| OpenSC 0.25 (`OPENSC_DRIVER=PIV-II`), pkcs11-tool sign/decrypt | PASS | `test_piv_tools.py` |
| yubico-piv-tool 2.2, yubikit 5.9 | PASS | `test_piv_tools.py`, `test_piv_25519.py` |
| Windows smart card logon / minidriver | UNTESTED | |

### OATH and OTP

| Feature | Status | Evidence |
|---|---|---|
| YKOATH TOTP/HOTP, access code, touch, paging of long lists | PASS | `pico-fido/tests/pico-fido/test_070_oath.py`, `tests/oath/test_oath_security.py` (yubikit) |
| OTP slots: Yubico OTP, HOTP, static password, HMAC-SHA1 / Yubico challenge-response, swap, update, access codes | PASS | `tests/oath/test_otp_management.py` (yubikit over CCID) |
| Keyboard typing (HOTP, static password) | PASS | `test_otp_management.py` (emulator keyboard log) |
| ykman 5.9 CLI over PC/SC (`ykman --reader "<reader>" info / oath ... / otp ...`) | PASS (emulator) | OATH accounts add/list/code, TOTP codes equal to RFC 6238 computed independently, OATH password; OTP slot commands through yubikit (`test_otp_management.py`) |
| Yubico Authenticator (desktop), KeePassXC challenge-response | UNTESTED | same protocols as yubikit |
| Yubico Authenticator for Android over USB | UNTESTED, expected NO | the app opens USB devices with Yubico's vendor ID only; LibreFido has its own (see USB identity) |
| OTP typed into a phone (USB OTG keyboard) | UNTESTED | a plain HID keyboard; a Yubico OTP validates only on a server that knows the slot's key (not YubiCloud) |

### LibreFido features (not in a YubiKey)

| Feature | Status | Evidence |
|---|---|---|
| Up to four isolated profiles, switched by the button, LED colour per profile | PASS | `tests/profiles/test_profiles_backup.py` |
| Versioned, optionally encrypted backups, clone, restore test, offline verify | PASS | `test_profiles_backup.py`, `tests/tools` |
| Single-key export / import (firmware 2.1.0): FIDO discoverable credentials, OATH accounts, OTP slots, OpenPGP and PIV keys, encrypted `.lfkey` files ([KEY_TRANSFER.md](KEY_TRANSFER.md)) | PASS | `tests/keys`; host side `tests/tools/test_keyfile.py`, `test_cli.py`, `test_gui.py` |
| Keys from standard formats: `otpauth://` and Google Authenticator export links and QR codes, PIV PEM / DER / PKCS#12, OpenPGP secret key files (`gpg --export-secret-keys`) | PASS (QR codes: checked by hand on Windows with OpenCV 4.13; the automated test environment has no decoder) | `tests/tools/test_stdformats.py`, `tests/keys` |
| Power-cut safe storage, A/B copies, Reed-Solomon parity, self repair | PASS | `tests/storage`, `tests/unit` |
| A/B firmware update with rollback and storage-format rule | PASS | `test_firmware_update.py` |
| Secure profiles, per-application automatic presence, LED brightness | PASS | `tests/profiles/test_policies.py`, `tests/fido/test_presence_policy.py` |
| Keys sealed at rest (AES-256-GCM under the root key) | PASS | `test_piv_access.py::test_keys_are_sealed_at_rest`, `test_openpgp_at_rest.py`, `tests/oath` |
| Chip provisioning: bind root key, lock debug (JTAG, secure download) | PASS (emulated eFuses) | `test_provision.py`, `test_mgmt_security.py::test_lock_debug` |
| Desktop tools `librefido` / `librefido-gui` (English/Chinese) | PASS | `tests/tools`, `tests/profiles/test_gui_smoke.py` |

## 2. Partially implemented

| Feature | What is missing |
|---|---|
| Attestation | FIDO: self attestation with LibreFido AAGUIDs, no vendor CA and no FIDO MDS entry. PIV: own F9 hierarchy per device (self generated). OpenPGP: no attestation key (YubiKey's OpenPGP attestation is Yubico specific). |
| YubiKey management applet (ykman) | Device info and configuration protocol, for tools that use it to find the applications. It reports the device's own serial number, the firmware's own version and form factor code 0x01 (USB-A); ykman derives a product name from those fields and prints "YubiKey 5A" (checked with ykman 5.9). The project owner decided (2026-09-24) to accept that label for compatibility. LibreFido makes no such claim itself: its USB identity, AAGUIDs and attestation are its own. |
| OTP over the keyboard interface | A slot that requires touch answers challenge-response only over CCID, or over the keyboard when automatic presence is on for OTP. |
| Ed448 / X448 (OpenPGP) | Only with the optional mbedTLS EdDSA fork (Ed448) or an mbedTLS with Curve448 (X448, emulator build). The ESP32-S3 build does not offer them. |
| libfido2 credential listing | libfido2 1.17 cannot parse ES512, ES256K or ESP256/384/512 keys: listing an RP that has such a credential fails in libfido2 (the credentials work in browsers). |

## 3. Not implemented

| Feature | Note |
|---|---|
| toggleAlwaysUv / alwaysUv | not advertised |
| YubiHSM Auth applet | |
| FIDO U2F/FIDO2 over NFC, OTP over NFC | no NFC hardware (see 4) |
| Yubico OTP validation service (YubiCloud upload) | Yubico's service; own validation server needed |

## 4. Impossible without other hardware

| Feature | Why |
|---|---|
| NFC | the ESP32-S3 has no NFC front end |
| Biometric user verification | no fingerprint sensor |
| Secure element / protection against invasive attacks | the ESP32-S3 is a general purpose MCU. With the root key bound to an eFuse HMAC key, Secure Boot and flash encryption (protection level 3) only physical attacks remain (fault injection, side channels, decapping). ECC private keys are in internal RAM during an operation. See [SECURITY_MODES.md](SECURITY_MODES.md). |
| Hardware protected ECC | the ESP32-S3 has no ECC engine with key isolation |

## 5. Needs external certification

FIDO Certified (L1/L2/L3+), FIPS 140-2/140-3, Common Criteria, CSPN: none of
these apply to LibreFido. Relying parties that require a certified or
allow-listed authenticator (attestation with a vendor CA, MDS status) will
refuse it; LibreFido does not try to get around such policies.

## Hosts

| Client | Transport | Status | Notes |
|---|---|---|---|
| Windows 11 WebAuthn | HID | PASS (hardware, firmware 2.0.0) | |
| Windows 11 raw FIDO HID or FIDO over PC/SC, non-admin | HID / CCID | NO | Windows reserves FIDO for its WebAuthn service: the SELECT of the FIDO application fails with SCARD_E_NO_ACCESS (seen on hardware with 2.1.0). The key manager's passkey page and the FIDO PIN need the GUI started as administrator (`LibreFido GUI (Admin)`, not yet checked on hardware); single-key transfer uses the management applet and is not affected |
| Windows 11 PC/SC (librefido, OpenPGP, PIV, OATH) | CCID | PASS (hardware, firmware 2.0.0) | no admin rights needed |
| Linux pcsc-lite, python-fido2, libfido2 | CCID, HID | PASS (emulator) | |
| macOS | HID, CCID | UNTESTED | |

### GnuPG and an Ed25519 authentication key

GnuPG before 2.5.8 (the 2.4 series: 2.4.4 of Ubuntu 24.04 tested, the code of
2.4.5 to 2.4.9 read) makes BAD
signatures with a signing subkey made from the card's **Ed25519
authentication key** ("Existing key from card", key 3). SSH with that key and
signing with the card's signature key are not affected, nor are RSA and ECDSA
authentication keys. It is a GnuPG bug (GnuPG bug 7589, fixed by GnuPG commit
eb7d5d4d85, first released in 2.5.8); the card behaves as the OpenPGP card
specification 3.4 (7.2.13) says, and firmware 2.1.0 does not work around it:

- For a signature with the authentication key, scdaemon (`do_sign`, then
  `do_auth`) puts the 19-byte SHA-2 DigestInfo in front of the hash, and
  before INTERNAL AUTHENTICATE strips 19 bytes of it for ECDSA but only 15
  for EdDSA (15 is the SHA-1 DigestInfo that gpg-agent puts in front of
  SSH data).
- The scdaemon log (`debug-level guru`) of GnuPG 2.4.4 against the emulator
  shows `00 88 00 00 44 05 00 04 40 <64-byte SHA-512 hash>`: 68 bytes, the
  last 4 bytes of the DigestInfo, then the hash. For SSH it sends the SSH
  data as it is.
- For EdDSA the card signs the data field as given (PureEdDSA), whatever it
  looks like; so the signature is valid for those 68 bytes, not for the hash
  GnuPG verifies. A card that guessed and stripped a prefix would sign
  something other than what the host sent.

Use GnuPG 2.5.8 or later for such a subkey, or sign with the signature key
(key 1), or use an RSA or ECDSA authentication key.

## USB identity

VID/PID `1D50:619B` (OpenMoko, free-software projects), product "LibreKeys
One". Interfaces: FIDO HID, CCID, and a keyboard only when an OTP slot types.
The WebUSB/WinUSB (WCID) interface is off by default. Every profile has its
own USB serial.
