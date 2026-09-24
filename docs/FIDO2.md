# FIDO2 / WebAuthn / U2F

## What the authenticator reports (getInfo)

| Field | Value |
|---|---|
| versions | U2F_V2, FIDO_2_0, FIDO_2_1, FIDO_2_2 |
| extensions | credBlob, credProtect, hmac-secret, hmac-secret-mc, largeBlobKey, minPinLength, thirdPartyPayment |
| AAGUID | `08c228d9-7ea0-2bc8-d08e-0d22a6d13f7d` (HARDENED: `6c86ea00-e576-2756-4e8a-6234f544e3fd`) |
| options | rk, credMgmt, authnrCfg, clientPin, largeBlobs, pinUvAuthToken, setMinPINLength, alwaysUv, ep |
| PIN/UV protocols | 1, 2 |
| transports | usb |
| algorithms | ES256, ES384, ES512, ES256K (EdDSA only in builds with `MBEDTLS_EDDSA_C`, not in the ESP32 and emulator builds today) |
| maxMsgSize | 1024 |
| max credentials in list / credential ID length | 16 / 1024 |
| maxSerializedLargeBlobArray | 2048 |
| attestation | self attestation (packed, signed by the credential key) |

`FIDO_2_2` and `thirdPartyPayment` are advertised by the upstream code;
they are covered by the upstream test suite but not verified against a FIDO
2.2 conformance tool: treat them as untested.

## Behaviour that differs from upstream pico-fido

- **User presence** is a physical press collected for the command that asked
  for it; a press is consumed once and never carried to a later command.
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
- **Vendor commands**: the command that replaces the device key needs a
  touch and, with a PIN set, a pinUvAuthToken with the acfg permission.

## Profiles

Each profile is a separate authenticator: its own device key, PIN,
credentials and counter. A credential registered in profile 1 is unknown to
profile 2. After a clone (backup restored on another device) both devices
hold the same credentials and counter; relying parties that check counters
may notice when both are used.

## Tests

`pico-fido/tests/pico-fido` (upstream suite, 203 tests) plus
`tests/profiles` and `tests/isolation`; see [TESTING.md](TESTING.md).
