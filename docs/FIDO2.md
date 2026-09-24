# FIDO2 / WebAuthn / U2F

## What the authenticator reports (getInfo)

| Field | Value |
|---|---|
| versions | U2F_V2, FIDO_2_0, FIDO_2_1, FIDO_2_2 |
| extensions | credBlob, credProtect, hmac-secret, hmac-secret-mc, largeBlobKey, minPinLength, thirdPartyPayment |
| AAGUID | `08c228d9-7ea0-2bc8-d08e-0d22a6d13f7d` (HARDENED: `6c86ea00-e576-2756-4e8a-6234f544e3fd`) |
| options | ep, rk, credMgmt, authnrCfg, clientPin, largeBlobs, pinUvAuthToken, setMinPINLength |
| PIN/UV protocols | 1, 2 |
| transports | usb |
| algorithms | ES256, EdDSA (Ed25519), ES384, ES512, ES256K, in this order (ES256K on the ESP32 only when enabled in the board options; EdDSA in every build that has Ed25519, see below) |
| maxMsgSize | 1024 |
| max credentials in list / credential ID length | 16 / 1024 |
| maxSerializedLargeBlobArray | 2048 |
| forcePINChange, minPINLength, firmwareVersion | current values |
| maxCredBlobLength | 128 |
| vendorPrototypeConfigCommands | AUT_ENABLE, AUT_DISABLE, EA_UPLOAD (ESP32: also the PHY_* board settings) |
| attestation | self attestation (packed, signed by the credential key) |

Only what is implemented and covered by a test is advertised
(`pico-fido/tests/pico-fido/test_034_getinfo_features.py` checks the list):

- `FIDO_2_2`: its features that are advertised, `hmac-secret-mc` (the PRF
  output at creation equals the later assertion's) and `thirdPartyPayment`
  (stored per credential, reported by getAssertion and credMgmt), are
  tested; unknown request keys (e.g. `attestationFormatsPreference`) are
  ignored. Not verified against a FIDO conformance tool.
- `alwaysUv` is not reported: toggleAlwaysUv is not implemented (upstream
  reported `alwaysUv: true` whenever a PIN was set, without enforcing it).
- `pinComplexityPolicy` / `pinComplexityPolicyURL` are not reported, and the
  vendor command that set them is gone: no complexity rule beyond
  minPINLength is enforced.
- Fully specified algorithms ESP256/ESP384/ESP512 are accepted in
  makeCredential (the credential key then carries that `alg`); brainpool
  (ESB*) is not accepted for new credentials. Brainpool credentials made by
  earlier firmware keep working: getAssertion signs with them and
  credential management lists them with a proper COSE EC2 key (crv 256/258/
  259, alg -265/-267/-268) and can delete them. (Earlier firmware returned an
  invalid COSE key for them at registration, so relying parties could not
  verify them anyway.)

## EdDSA (Ed25519)

getInfo lists `{"alg": -8, "type": "public-key"}` only when the build can
make and use Ed25519 keys. That is every build of this tree (ESP32-S3 and
the emulator included): Ed25519 comes from `pico-keys-sdk/src/crypto/
lf_25519.c` (`LF_HAVE_25519`), which needs no particular mbedTLS. A build
with the mbedTLS EdDSA fork (`ENABLE_EDDSA`, `MBEDTLS_EDDSA_C`) uses the fork
instead, and also has Ed448 (-53, not advertised).

- **makeCredential**: pubKeyCredParams are taken in the relying party's
  order, the first algorithm the authenticator has wins: `[-8, -7]` makes an
  Ed25519 credential, `[-7, -8]` a P-256 one. -19 (the fully specified
  "Ed25519") is accepted as well (same key and signature, not advertised);
  the credential keeps the `alg` it was created with.
- **Public key**: COSE OKP `{1: 1, 3: -8, -1: 6, -2: x}`, x the 32-byte
  RFC 8032 public key; credential management reports the same key for
  discoverable credentials.
- **Signatures**: pure Ed25519 (no prehash), 64 bytes (R || S, not DER),
  over `authenticatorData || clientDataHash`: the self attestation (packed,
  `alg` -8, no x5c) and every assertion. An enterprise attestation is still
  made with the device key (ES256 and its certificate, `alg` -7).
- **Key**: derived like every other credential key, never stored: the
  credential ID's key path through the HKDF-SHA512 chain from the device key;
  the first 32 bytes of that key material are the Ed25519 seed (a P-256 key
  reads the same bytes as a big-endian scalar). The seed and everything
  derived from it are wiped after each use. The mbedTLS EdDSA fork reads the
  same 32 bytes as its (little-endian) private key and hashes them unchanged,
  so credentials made by firmware built with it, discoverable or not, keep
  their public key and work unchanged. (The fork refused about 1 in 256 of
  these keys, whose last byte is 0: makeCredential failed with OTHER, so no
  such credential exists. lf_25519 accepts them.)
- **hmac-secret, credProtect, credBlob, largeBlobKey, excludeList** work as
  for any other credential.
- **U2F** is P-256 only: an Ed25519 credential ID sent as a U2F key handle is
  refused (6A80), as before.
- **Firmware without EdDSA** (earlier LibreFido builds, or a build with
  neither lf_25519 nor the fork): getInfo does not list -8, makeCredential
  with only -8 answers UNSUPPORTED_ALGORITHM, and stored Ed25519 credentials
  are listed by credential management without a public key and can be
  deleted; getAssertion does not offer them
  (`tests/fido/test_eddsa_compat.py`, with a build of this tree configured
  with `-DCMAKE_C_FLAGS=-ULF_HAVE_25519`).
- **Cost**: a makeCredential or getAssertion derives the key (one
  fixed-base scalar multiplication for the public key, which the signature
  hashes) and signs (one more). In the emulator both algorithms take the
  same ~48 ms per command, which is the emulator's transport, not the
  crypto: lf_25519 itself takes 2.6 ms for a public key or a signature and
  5.2 ms for a verification on the x86-64 host at the emulator's -O0
  (0.74 / 1.5 ms at -O2). The firmware only signs, it never verifies. Not
  yet measured on the ESP32-S3.

## Behaviour that differs from upstream pico-fido

- **User presence** is a press collected for the command that asked for it;
  a press is consumed once and never carried to a later command.
- **Automatic presence** ("my device is safe", per profile, opt-in): when
  the user switches it on for FIDO (never in a secure profile or a HARDENED
  build), the everyday operations succeed without a press: makeCredential
  and getAssertion presence, U2F register/authenticate,
  authenticatorSelection. authenticatorReset, every device key command
  (AUT_ENABLE/AUT_DISABLE, export, restore) and the board option that turns
  off the reset window always need a physical press. In the code the two
  are different functions (`fido_wait_everyday_presence()`,
  `fido_wait_physical_press()`); `tests/fido/test_presence_policy.py`
  checks which operation uses which.
- **PIN and user presence**: with a PIN set, assertions that only need user
  presence (U2F, userVerification="discouraged", credProtect level 1) work
  after a power cycle without entering the PIN. The PIN protects user
  verification through its retry counter (8 tries, 3 per power cycle).
- **Signature counter**: one global counter per profile, stored before it is
  signed, starting at 1, never wrapping; kept in the store's counter log so
  a signature costs no file system transaction.
- **Reset** (authenticatorReset) erases the FIDO state of the active profile
  only: OATH, OTP, OpenPGP, PIV, the device configuration and the profile's
  identity stay. It needs a touch.
- **No per-site behaviour**: every relying party is treated alike (upstream
  had a table of 40 sites with special attestation and counter handling).
- **Attestation**: self attestation always; enterprise attestation only if
  the user enables it through authenticatorConfig.
- **Vendor key protection** (authenticatorConfig AUT_ENABLE/AUT_DISABLE,
  CTAPHID 0xC1 MSE/UNLOCK/BACKUP, also the FIDO applet's INS 0x41 over
  CCID): every command needs the PIN (a pinUvAuthToken with the acfg
  permission over
  `32 x 0xFF || 0xC1 || cmd || vendorCmd || vendorParam || vendorKey`), there
  is no path without a PIN, and the commands that change the device key also
  need a physical press.
  - AUT_ENABLE seals the real device key under a 32-byte host key K sent
    over MSE (checked to open before the plain key is removed; the device
    keeps working until the next power up, then needs UNLOCK with K). While
    the key is sealed nothing writes it back in another form: a PIN change
    (also one forced by setMinPINLength) neither needs nor touches it, and
    works while the key is locked.
  - A restore (BACKUP 0x02) takes the 60-byte blob and K (map key 3, over
    MSE). Before anything is written it checks that the blob opens with K and
    holds a valid P-256 key, and builds the new device certificate. The
    enterprise attestation certificate is removed when the key changes (it
    certified the old one). Resident credentials made with another device
    key stay stored: credential management lists them by ID only and can
    delete them, and they work again if that key is restored.
  - AUT_ENABLE, export (BACKUP 0x01) and restore move the device key in or
    out: they are refused in a secure profile and in HARDENED builds
    (CTAP2_ERR_OPERATION_DENIED); AUT_ENABLE and export, which hand the key
    out, are also refused in a profile marked no-export (the flag that blocks
    profile exports; restore is an import and does not check it). On boards
    with the power-on reset
    window (ESP32) they need the first 10 s after power up, whatever the
    board option that disables the window for authenticatorReset. Switching
    that board option on (authenticatorConfig PHY_OPTS) needs a physical
    press.
  - The MSE session key protects one secret only.
  - **Earlier firmware** let a restore run without a PIN. Such a device stays
    locked after the update: UNLOCK answers 0x35 (PIN_NOT_SET). Set a PIN
    (clientPIN setPIN works while the key is locked), get a pinUvAuthToken
    with the acfg permission, then send UNLOCK with K and that token; the
    stored blob stays valid. A tool that sends UNLOCK without a token gets
    0x36 (PUAT_REQUIRED). If K is lost, only authenticatorReset (which
    creates a new device key and removes every FIDO credential) makes the
    device usable again.
- **pinUvAuthToken**: expires when unused for 30 s after it was issued, or
  10 minutes after its last use, on every path that accepts it (the check
  runs before each use, the CCID vendor command included); makeCredential
  consumes it (flags and permissions except lbw are cleared, as getAssertion
  does); authenticatorReset stops it and drops the command state of the
  wiped profile (getNextAssertion, credential enumeration, MSE session,
  a pending largeBlob write), also when it comes from the management applet.
  The persistent read-only token (pcmr) survives power cycles until the PIN
  changes.
- **credentialManagement 0x41** (CTAP 2.1-PRE command byte) is an alias of
  0x0A with the same permission and RP checks.
- **Discoverable credential IDs** created by this firmware carry no
  per-device constant; existing credentials keep the ID they were created
  with. Earlier firmware (development builds before this change) derives the
  ID again instead of reading the stored one: after a rollback (A/B update)
  to such a build, or a profile imported into it, discoverable credentials
  created by this firmware are reported under a different ID (the relying
  party does not recognise them), and those renamed with updateUserInformation
  are not listed at all. Nothing is lost: updating again restores them. No
  released firmware has the old derivation together with A/B rollback or
  profile import.
- **Credential management** lists every stored discoverable credential, so
  the counts of getCredsMetadata, enumerateRPs and enumerateCredentials
  agree and every record can be deleted. A record that cannot be used for
  signing is listed without a public key: a credential on a curve this build
  does not have (e.g. Ed25519 without EdDSA), or, by credential ID only with
  an empty user entity, one that does not decrypt with the device key (made
  with another device key, or damaged). getAssertion never uses those. While
  the device key is sealed and locked, enumerateCredentials answers
  NOT_ALLOWED instead of listing everything as unreadable.
- **U2F**: the key handle must be exactly the announced length and is
  checked before a touch is asked for; CTAP2 credentials with credProtect
  userVerificationRequired cannot be used through U2F; browsers' dummy
  registrations get a normal answer.
- **Errors of CBOR commands** are always the status byte of the response
  (CTAPHID_ERROR only for transport errors, e.g. an empty message).

## What protects the stored FIDO data

The profile root key is `otp_key_1` (the device root key, bound to the chip
on provisioned ESP32 boards). The secure key store (sks, `pico-keys-sdk/src/
sec/sks.h`) seals records with AES-256-GCM under
HKDF(root key, salt SHA-256(serial), "LibreFido/sks/v1" || namespace ||
epoch), bound to the file ID. authenticatorReset rotates the FIDO epoch, so
leftover copies of FIDO sks records can no longer be opened.

| Stored item | Protection |
|---|---|
| device key (EF_KEY_DEV) | sks record (SKS_NS_FIDO). Formats of earlier firmware (0x01: AES-256-CBC under kbase, no integrity; 0x02 and the upstream MKEK format: bound to the PIN) are read, and sealed the first time they are used once the firmware is confirmed; only a profile created secure refuses them |
| host-sealed device key (EF_KEY_DEV_ENC, AUT_ENABLE / restore) | ChaCha20-Poly1305 under the host key K, stored inside an sks record (the plain blob of earlier firmware is sealed when read, once the firmware is confirmed) |
| persistent pinUvAuthToken (EF_PAUTHTOKEN) | sks record (a plain token of earlier firmware is sealed at the first boot of confirmed firmware) |
| credential IDs, resident records (EF_CRED) | the sealed credential: ChaCha20-Poly1305 under a key derived from the device key (user entity, credBlob, credProtect, options inside); user updates: ChaCha20-Poly1305 under another device-key-derived key, bound to the record. Private keys, hmac-secret and largeBlobKey are derived from the device key and the credential, never stored. The RP ID hash and the resident credential ID are stored in clear (needed to find records) |
| relying parties (EF_RP) | RP ID and a count, in clear (metadata, returned by credential management) |
| largeBlob array (EF_LARGEBLOB) | entries encrypted by the platform with AES-256-GCM under each credential's largeBlobKey (derived from the device key); the array's trailing hash is an unkeyed integrity check, as in CTAP 2.1 |
| PIN record (EF_PIN) | retry counter, length and a verifier HKDF(HMAC(kbase, SHA-256(PIN))) with kbase derived from the root key; not a secret by itself |
| certificates, counters, options, minPINLength RP hashes | not secret |

Without a device root key (the emulator, an unprovisioned board) the sks
and kbase keys come from the serial number only: that is obfuscation, not
protection against someone reading the flash.

**Updates.** Sealing waits until the running firmware is confirmed
(`lf_migrate_ok()`): an unconfirmed update can still roll back to 2.0.0,
which reads only the earlier formats (it would take a sealed device key for
no key and derive every credential from zeros). Until then the device key,
the host-sealed blob and the pcmr token are only read; new ones are written
in the earlier format (device key 0x01, plain blob, plain token), and a
device key bound to the PIN session is moved to 0x01 when the PIN is
verified, as 2.0.0 does. The first use after confirmation seals them. A
profile created secure seals from the start and never accepts the earlier
formats; other profiles of a HARDENED build (written by 2.0.0) keep reading
them.

## Profiles

Each profile is a separate authenticator: its own device key, PIN,
credentials and counter. A credential registered in profile 1 is unknown to
profile 2. After a clone (backup restored on another device) both devices
hold the same credentials and counter; relying parties that check counters
may notice when both are used.

## Tests

`pico-fido/tests/pico-fido` (the upstream suite plus the LibreFido
regression tests `test_012`, `test_023`, `test_024` (EdDSA), `test_032`,
`test_034`, `test_038`, `test_039`, `test_041`, `test_053`), `tests/libfido2`
(Yubico's libfido2 against the emulator, ES256 and then EdDSA credentials),
`tests/fido` (presence policy, Ed25519 credentials on a build without EdDSA,
secure
profiles with `LF_EMU_BIN_HARDENED`, state of the previous firmware with the
baseline emulator: run without a parallel test slot), plus `tests/profiles`
and `tests/isolation`; see [TESTING.md](TESTING.md).
