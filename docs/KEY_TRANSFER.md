# Single-key transfer

Firmware 2.1.0 copies one key of one application of the active profile into
a file, or adds one key to a device: a FIDO discoverable credential
(passkey), an OATH account, an OTP slot, an OpenPGP key or a PIV key with
its certificate. A backup (`librefido export` / `import`,
[SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md)) moves a whole profile;
a single-key transfer moves one key and leaves everything else on both
devices as it is. Like backups it is an ESP32-S3 (and emulator) feature.

An export is a **copy**: the key stays on the source device. What that means
for each kind of key is under *Limitations*.

Host side: `librefido key list | export | import` and the GUI tab "Keys"
([tools/librefido/README.md](../tools/librefido/README.md)). A short guide in
Chinese is at the end ([快速上手](#快速上手)).

Firmware side: the management applet (`pico-keys-sdk/src/fs/lf_mgmt.c`)
applies the device policies and calls the hooks each application registers
(`pico-keys-sdk/src/fs/lf_keyio.h`): `lf_keyio_fido.c`, `lf_keyio_oath.c`,
`lf_keyio_otp.c` (pico-fido) and `lf_keyio_pgp.c` (pico-openpgp, OpenPGP and
PIV).

## What can be transferred

| Application | A key is | Export | Import | Standard formats |
|---|---|---|---|---|
| FIDO2 | a discoverable credential (passkey), named by its credential ID | touch, FIDO PIN¹ | management applet: touch, FIDO PIN¹; refused by secure profiles and HARDENED builds | none |
| OATH | an account (TOTP or HOTP), named as YKOATH stores it: `[period/][issuer:]account` | touch, FIDO PIN¹ | the OATH application (YKOATH PUT), with the OATH password when one is set | in: `otpauth://` links, Google Authenticator export links (`otpauth-migration://`), QR code images of both; out: `otpauth://` link |
| OTP | slot 1 or 2 (its whole configuration) | touch, FIDO PIN¹ | management applet: touch, FIDO PIN¹, and the access code of a programmed target slot that has one | none |
| OpenPGP | the private key of the signature, decryption or authentication slot, with its fingerprint, time and touch policy | touch, FIDO PIN¹ and the OpenPGP Admin PIN | the OpenPGP application (PUT DATA / IMPORT DATA), with the Admin PIN | in: OpenPGP secret key files (`gpg --export-secret-keys`, armored or binary) |
| PIV | the private key of slot 9A, 9C, 9D, 9E or 82–95, with its policies and certificate | touch, FIDO PIN¹; the tools add the slot's certificate | the PIV application (IMPORT ASYMMETRIC KEY, PUT DATA), with the management key | in: PEM (PKCS#8, PKCS#1, SEC1, encrypted or not), DER, PKCS#12; out: PEM (encrypted PKCS#8 and the certificate) |

¹ When the active profile has a FIDO PIN. Without one a touch alone lets a
key out (as for a backup): set a FIDO PIN on a profile whose keys matter.

Every kind of key can also be written to, and read from, a LibreFido key file
(`.lfkey`, below), encrypted with a passphrase unless the user asks twice for
it in the clear.

Not transferable one at a time:

- **Non-discoverable FIDO credentials and U2F registrations.** Their keys are
  derived from the profile's FIDO device key and the credential ID the
  relying party keeps; the device holds nothing that names them. Only a full
  backup, which carries the device key, moves them.
- FIDO credentials on curves without a record format here (anything but
  P-256, P-384, P-521, secp256k1 and Ed25519), and the Ed25519 FIDO
  credentials and Ed25519 / Cv25519 OpenPGP keys of builds with the mbedTLS
  EdDSA fork (`ENABLE_EDDSA`, not the default): not listed, or `6A81`.
- The FIDO device key, the OpenPGP data key, the PIV management key (9B) and
  the PIV attestation key (F9): never listed or exported.
- PINs and passwords: the FIDO PIN, the OATH password, the OpenPGP PINs and
  Reset Code, the PIV PIN, PUK and management key are not part of a key.
  (An OTP slot's access code is part of its configuration and does travel,
  see *OTP*.)
- Entries of the Nitrokey password safe (login, password, metadata): not
  OATH accounts; they are not listed, and the fields of an account that has
  them do not travel.

## Security rules

- **Export is refused (`6986`)** wherever a profile export is: secure
  profiles, no-export profiles and every profile of a HARDENED build
  (`LF_ALLOW_SECRET_EXPORT` 0; the FIDO, OpenPGP and PIV hooks refuse on
  their own too). Also refused while the root key is unavailable (`6982`),
  the key store is locked, storage is not ready or a reboot is pending
  (`6985`). Listing stays possible everywhere: it shows no secret, and its
  answer says whether the profile lets keys out.
- **An export needs the FIDO PIN** of the active profile when it has one
  (checked as for `EXPORT_BEGIN`, with its retry counter) **and a physical
  touch** collected for that command (`wait_button()`; automatic presence,
  "my device is safe", never counts). The listing needs the FIDO PIN too.
- **A listing never shows more than the application itself does with the
  same credentials.** FIDO lists sites and users like credential management
  with the FIDO PIN verified (the PIN given, not merely "no PIN set"): no
  touch. Otherwise it lists, after a touch, what a getAssertion with user
  presence alone gives: the credProtect 1 passkeys, each with its site and
  user ID but no user name or display name (CTAP answers those only with
  user verification). credProtect 2 and 3 passkeys, which CTAP only uses
  with user verification or their credential ID, are listed with the PIN
  only: on a profile without a FIDO PIN, set one to list them. (The one
  thing a listing adds: it names the sites, which a getAssertion caller
  must know.) OATH lists its
  accounts after a touch while an OATH password or OTP PIN is set (YKOATH
  LIST refuses without them; the FIDO PIN does not stand in for them). The
  touch is physical, as for an export, and asked for the first page only:
  the pages after it carry the list session ID the first answered, which
  belongs to the interface, the application and the command stream (any
  other management command ends it), goes forward only (each page once, in
  order) and lasts 10 seconds from the first page. OTP (slot status: programmed, mode;
  whether an access code is set shows in the answer of a slot update),
  OpenPGP (GET DATA: algorithm attributes, fingerprints, times) and PIV
  (GET METADATA: algorithm, policies) list what their applets give any host:
  no touch.
- **An OpenPGP key also needs the Admin PIN (PW3).** The OpenPGP keys are
  encrypted at rest with the data key, which only a verified PW opens. PW3
  is verified with its normal retry counter (a wrong PIN costs a try,
  `63Cx`, blocked `6983`), and the OpenPGP session ends with no PW verified
  and the data key closed, whatever happens. PIV keys, OATH accounts and OTP
  slots have no further secret: at rest they are sealed with the profile's
  root key, not behind the PIV PIN, the OATH password or an access code, so
  the bar is that of a full backup, which carries them too.
- **The touch comes last**: after every check that can fail without it
  (unknown key, missing or wrong secret, invalid record, conflict, no space)
  and before any key material is decrypted or anything is written. No touch
  in time: `6985`, nothing changed. One touch confirms one command: a hook
  that asks a second time gets "no" without a new wait, and the management
  applet answers no success without the touch.
- **Imports**: FIDO credentials and OTP slots go through the management
  applet (FIDO PIN, touch). A FIDO credential is refused (`6986`) by secure
  profiles and HARDENED builds, whose FIDO credentials are always made on
  the device (a HARDENED profile can still be restored from a whole backup,
  see [SECURITY_MODES.md](SECURITY_MODES.md)). OTP slots are taken
  everywhere (a YubiKey takes programmed OTP secrets too). OATH accounts,
  OpenPGP keys and PIV keys are added through their own applications with
  their own authentication, as on any card of the kind: YKOATH PUT (after
  VALIDATE when the OATH application has a password), OpenPGP PUT DATA and
  IMPORT DATA (PW3), PIV IMPORT ASYMMETRIC KEY and PUT DATA (management key).
  The tools never replace a key that is already there unless told to.
- The PINs and secrets of a command are copied out of the receive buffer and
  wiped, with the command data, when the command ends; every buffer that held
  key material is wiped on every path; the answer buffer is wiped when an
  export fails after the hook started encoding.
- No relying party, application name or vendor is treated specially.

| | Standard profile | No-export profile | Secure profile | HARDENED build |
|---|---|---|---|---|
| List keys | FIDO PIN¹; touch² | FIDO PIN¹; touch² | FIDO PIN¹; touch² | FIDO PIN¹; touch² |
| Export a key | touch, FIDO PIN¹ (+ Admin PIN) | refused | refused | refused |
| Import a FIDO credential | touch, FIDO PIN¹ | touch, FIDO PIN¹ | refused | refused |
| Import an OTP slot | touch, FIDO PIN¹ | touch, FIDO PIN¹ | touch, FIDO PIN¹ | touch, FIDO PIN¹ |
| Add an OATH, OpenPGP or PIV key | the application's own authentication | same | same | same |

² Once per listing: FIDO without a verified FIDO PIN (no PIN set; it then
lists the credProtect 1 passkeys only, without user names), OATH while an
OATH password or OTP PIN is set.

## Limitations

### FIDO

- **Signature counter.** The device has one signature counter per profile,
  shared by its credentials. An import raises it to at least the counter
  the exporting device had at the export (record key 14), never lowers it,
  so the imported credential never signs below what the relying party last
  saw from the source at that moment. If both devices keep using the
  credential, their counters interleave: a relying party that checks
  counters can see one go backwards and take the credential for a clone
  (WebAuthn leaves the consequence to it; some refuse the sign-in or block
  the credential). Use a transferred passkey on one device only, and delete
  it on the other with any CTAP 2.1 credential management client (browser
  or system passkey settings, libfido2's `fido2-token`). The tools print
  this note with every FIDO export and import.
- **A copy is a second authenticator holding the same key.** A relying
  party cannot tell the two apart: whoever holds either device (and its
  PIN) can sign in.
- **Non-discoverable credentials** cannot be exported one at a time (above):
  full backup only.
- **largeBlob data is not copied**, only the credential's largeBlobKey. The
  large-blob array (CTAP 2.1 `authenticatorLargeBlobs`) is one store per
  profile; what a site put there stays on the source device. A platform that
  reads it from the source can write it to the target, where the same key
  opens it.
- **Attestation is not copied.** The relying party registered the exporting
  device (its AAGUID and attestation statement); assertions carry neither,
  so it keeps seeing the credential it registered. The target's own AAGUID
  and attestation play no part.
- The credential keeps its ID, user, credProtect level, hmac-secret key
  (the same hmac-secret outputs), largeBlobKey, credBlob and creation time.
  User verification uses the target's FIDO PIN.
- An imported credential is found only through its stored record: U2F
  (CTAP1), which only knows key handles, cannot use it.
- Firmware older than 2.1.0 cannot read imported credentials (*Compatibility*).

### OATH and OTP

- A copy of a HOTP account or HOTP / Yubico OTP slot shares its counter with
  the source: codes made on both devices overlap, and a server accepts each
  counter value once. Use one of the two.
- A Yubico OTP slot moves on by one usage counter at the import (a new
  session, as at power up), so the target never types an OTP the source had
  typed by the export.
- The OTP access code is part of the slot's configuration: the imported slot
  is protected by the same code. Replacing a programmed slot that has an
  access code needs that code (`librefido key import --access-code`).
- The OATH password protects the OATH application, not an account: the
  target's password (if any) applies.

### OpenPGP and PIV

- The OpenPGP PINs, the PIV PIN, PUK and management key stay those of the
  target.
- RSA keys use the public exponent 65537 (the card keeps p and q only):
  keys with another exponent are refused on import.
- An OpenPGP import writes the algorithm attributes first (a new algorithm
  deletes the slot's key, fingerprint and time), then the key, fingerprint,
  time and touch policy (UIF). If a later step fails the slot may be left
  without a usable key. UIF values 02 and 04 (permanent) cannot be changed
  once set: an import whose UIF differs is refused before anything is
  written.
- An imported PIV key is recorded as imported: PIV attestation (F9) refuses
  it (`6A80`), as for any key that was not generated on the device. Its
  certificate is written with it; without one, the slot's old certificate
  is removed (it belonged to the key replaced).

## Management commands

Management applet (AID `F0 4C 49 42 52 45 46 49 44 4F`, "\xF0LIBREFIDO",
over CCID / PC/SC), CLA `80`, P1 = P2 = `00`. Data and answers are CBOR maps
with integer keys. Application numbers are those of `lf_app_t`
(`lf_policy.h`): 0 FIDO, 1 OATH, 2 OTP, 3 OpenPGP, 4 PIV. Each of the three
commands ends a backup or firmware transfer in progress. In every request an
unknown or repeated key, a value of the wrong type, trailing bytes, an
application number of 5 or more, a missing required field, an empty key ID
or target, a FIDO PIN over 64 bytes or a secret over 127 bytes answer `6A80`.

**INFO (`01`)** has key 19: `{1: export mask, 2: import mask}`, bit n set when
application n lists and exports / imports keys through these commands.
Firmware before 2.1.0 has no key 19. A 2.1.0 build with every application
answers `{1: 0x1F, 2: 0x05}`: all five export, FIDO and OTP import (OATH and
OTP only when built in). The masks say what the firmware can do; whether
the active profile lets keys out is INFO key 14 and KEY_LIST key 2.

**KEY_LIST (`60`)** `{1: app, 2: FIDO PIN (bytes, optional), 3: cursor
(uint, optional, default 0), 4: list session ID (8 bytes, optional, only
with a cursor above 0)}`. Checks of a first page (no key 4), in this order:
storage ready, no reboot pending, key store unlocked (`6985`); the request;
the application lists keys (`6A81`); the FIDO PIN; when the application
itself gives its listing out only with a secret (`list_protected`, see
Security rules: FIDO without a verified FIDO PIN, OATH with a password or
OTP PIN), a physical touch (`6985` without; a cursor above 0 without key 4
is then `6982`). No secret in the answer: `{1: entries, 2: exportable
(bool), 3: next cursor, 4: list session ID}`. The entries are an
indefinite-length array (`9F ... FF`) of maps whose key 1 is the key ID to
export. One answer holds at most about 3 KB of entries
(`LF_KEYIO_PAGE_BUDGET`); keys 3 and 4 are there while the list goes on,
and a host asks again with that cursor and that ID until they are absent.
Such a later page needs neither the PIN nor a touch; the same ID is
answered on every page. The listing belongs to the interface, the
application and the command stream that started it: any other management
command, another interface, a card reset or another application selected
ends it; a wrong ID, any cursor but the one the page before answered (a
page again, a rewind, a page skipped) or a page more than 10 seconds
after the first (`KEY_LIST_SESSION_MS`) ends it too (`6982`), and so does
the last page. A
listing without a touch may also be paged without the ID, each page then
checked as a first one (the FIDO PIN on every page).

| Application | Entry |
|---|---|
| FIDO | `{1: credential ID (42 bytes), 2: rpId (text), 3: COSE alg (int), 4: user name (text, optional), 5: displayName (text, optional), 6: user ID (bytes), 7: imported (bool)}`; texts cut on a UTF-8 boundary to 64 bytes (rpId 128) for the listing only. Without a verified FIDO PIN: credProtect 1 credentials only, without keys 4 and 5 |
| OATH | `{1: name (bytes, as stored), 2: type\|algorithm (YKOATH: 0x10 HOTP / 0x20 TOTP \| 1 SHA-1 / 2 SHA-256 / 3 SHA-512), 3: digits, 4: touch (bool)}` |
| OTP | `{1: slot (1 byte: 1 or 2), 2: mode (text: "yubico-otp", "hotp", "static", "chal-hmac", "chal-yubico"), 3: access code set (bool)}` |
| OpenPGP | `{1: key ref (1 byte: 1 sig, 2 dec, 3 aut), 2: algorithm attributes (bytes, the C1–C3 value), 3: fingerprint (20 bytes, zeros if unset), 4: generation time (uint, 0 if unset)}` |
| PIV | `{1: slot (1 byte: 9A, 9C–9E, 82–95), 2: algorithm (06 RSA1024, 07 RSA2048, 05 RSA3072, 16 RSA4096, 11 P-256, 14 P-384, E0 Ed25519, E1 X25519), 3: PIN policy, 4: touch policy}` |

Listed: FIDO credentials that load and use a transferable curve, OATH HOTP
and TOTP accounts, OTP slots whose record opens, OpenPGP slots holding a
private key, PIV slots holding a key.

**KEY_EXPORT (`61`)** `{1: app, 2: key ID (bytes), 3: FIDO PIN (optional), 4:
application secret (bytes, optional: the OpenPGP Admin PIN)}`. Order:
storage ready and no reboot pending (`6985`); export allowed (`6986`); root
key available (`6982`); key store unlocked (`6985`); the request; the
application exports keys (`6A81`); the FIDO PIN; then the application: no
such key `6A88`, a key it cannot export `6A81`, secret missing `6982` /
wrong `63Cx` / blocked `6983` (an OpenPGP card without PW3: `6985`), no touch
`6985`. Answer `{1: app, 2: record}`.

**KEY_IMPORT (`62`)** `{1: app, 2: record (map), 3: FIDO PIN (optional), 4:
application secret (bytes, optional: the access code of the target OTP
slot), 5: replace (bool, optional), 6: target (bytes, optional: the OTP slot,
1 byte)}`. Order: storage ready and writable, no reboot pending, key store
unlocked (`6985`); root key available (`6982`); the request; the application
imports here (`6A81`: OATH, OpenPGP and PIV do not); a FIDO credential into
a secure profile or a HARDENED build (`6986`); the FIDO PIN; then the
application: invalid record `6A80`, unsupported curve or algorithm `6A81`, a
key already there and replace not set `6A89`, no space `6A84`, access code
missing or wrong `6982`, no touch `6985`. Answer `{1: app, 2: key ID of the
imported key}`.

Status words of the three commands:

| SW | Meaning |
|---|---|
| `9000` | done |
| `6982` | root key unavailable; FIDO PIN required, or not checkable now (no retry used); application secret missing (export) or OTP access code missing or wrong (import); KEY_LIST: a wrong list session ID, none on a later page of a listing that needs a touch, or the listing is over |
| `63Cx` | wrong FIDO PIN or OpenPGP Admin PIN, x tries left |
| `6983` | that PIN is blocked |
| `6985` | storage not ready, reboot pending, key store locked, the FIDO device key not usable, FIDO PIN needs a power cycle, no touch (export, import, and a listing that needs one) |
| `6986` | export not allowed by the profile or build; FIDO import into a secure profile or a HARDENED build |
| `6A80` | malformed request or invalid record |
| `6A81` | the application does not list / export / import through this command, or the key's curve or algorithm is not supported |
| `6A84` | no space for the key |
| `6A88` | no such key |
| `6A89` | a key is already there and replace is not set |
| `6400`, `6581` | internal error, flash write failed |
| `6D00` | firmware before 2.1.0 |

## Records

What KEY_EXPORT answers, what KEY_IMPORT takes and what a key file carries.
Keys marked optional may be absent; unknown keys are skipped on import.

### FIDO

`{1: rpId (text), 2: credential ID (42 bytes), 3: user ID (bytes), 4: user
name (text, optional), 5: displayName (text, optional), 6: COSE alg (int), 7:
COSE curve (int: 1 P-256, 2 P-384, 3 P-521, 6 Ed25519, 8 secp256k1), 8:
private key (bytes: EC scalar big endian at the curve's length; Ed25519
32-byte seed), 9: credProtect (1..3), 10: hmac-secret key (64 bytes,
CredRandomWithoutUV || CredRandomWithUV), 11: largeBlobKey (32 bytes), 12:
credBlob (bytes), 13: use sign counter (bool), 14: sign counter of the
exporting device at the export, 15: creation time (seconds), 16:
thirdPartyPayment (bool)}`. Keys 4, 5 and 9 to 16 are optional on import.

- Transferable: P-256 (ES256 `-7`, ESP256 `-9`), P-384 (ES384 `-35`, ESP384
  `-51`), P-521 (ES512 `-36`, ESP512 `-52`), secp256k1 (ES256K `-47`) and
  Ed25519 (EdDSA `-8`, Ed25519 `-19`) in builds with the lf_25519
  implementation (the default).
- Native credentials always export key 10: this firmware answers
  hmac-secret for every credential. Key 11 is there when the credential was
  made with largeBlobKey. A credential imported without key 10 answers no
  hmac-secret output.
- Import checks: rpId 1..255 bytes, user ID 1..64 bytes, texts well-formed
  UTF-8 without NUL (an empty name is no name), a credential ID of the
  resident form (42 bytes, bytes 4..7 `F1 D0 02 03`), the alg/curve pair
  above, a private key of the curve's length with an EC scalar in [1, n-1],
  credProtect 1..3, credBlob at most 128 bytes, counter below 0xFFFFFFFF
  (the device could not sign again otherwise).
- A stored credential with the same credential ID, or the same rpId and user
  ID, answers `6A89` unless replace is set; then it is replaced (both, when
  those are two different credentials).
- The device sign counter is raised first (to at least key 14, never
  lowered): should the write of the credential fail, a higher counter harms
  nothing.
- An imported credential is an explicit-key credential (credential.h): the
  stored record is `rp_id_hash || credential ID (the imported one, verbatim)
  || sealed credential`, the sealed part `"\xf1\xd0\x02\x04" || iv[12] ||
  ChaCha20-Poly1305(CBOR) || tag[16]` under a key of its own with the
  rp_id_hash as associated data. Its CBOR has the fields of a native
  credential plus 0x20 credential ID (which authenticates the stored one),
  0x21 private key, 0x22 hmac-secret key and 0x23 largeBlobKey (both
  optional). getAssertion, credential management, excludeList,
  updateUserInformation, delete and largeBlobs use the stored material for
  it. Its credential ID carries no key: the credential is found only through
  its stored record (allowList and excludeList entries match it as they
  match any stored credential), never decoded from the ID as a
  non-discoverable credential or a U2F key handle. The key material is
  decrypted only while it is used.
- Exporting an imported credential again gives the record it came from,
  apart from key 14 (and keys 4 / 5 after an updateUserInformation).

### OATH

`{1: name (bytes, as stored, at most 64), 2: type|algorithm, 3: digits, 4:
secret (bytes, as stored), 5: HOTP moving factor (HOTP only), 6: touch
(bool)}`. The TOTP period is part of the name (`30/` is left out, as
YKOATH clients do). There is no firmware import: the host adds the account
with YKOATH PUT (after VALIDATE when the application has a password; the
host also checks the device's answer to its own challenge), the counter as
IMF (4 bytes, 8 above 0xFFFFFFFF) and touch as the property `78 02`. The
tools accept 6 to 8 digits, SHA-1 / SHA-256 / SHA-512 and secrets of at
most 128 bytes.

### OTP

`{1: slot (1 or 2, the source slot), 2: configuration (52 bytes: the stored
YubiKey slot configuration, access code included), 3: counter area (8
bytes: Yubico OTP usage counter, 16 bit big endian, or the HOTP moving
factor, 64 bit big endian), 4: mode (text, informational)}`.

Import: the target slot is KEY_IMPORT key 6, else record key 1. A programmed
target slot needs replace (`6A89`) and, when its configuration has an access
code, KEY_IMPORT key 4 with exactly that code (6 bytes; `6982`, compared in
constant time). The configuration is checked like a slot write through the
OTP application (not all zeros, reserved bytes zero, CRC) and stored the
same way, with the programming sequence moved on. A Yubico OTP slot starts a
new session as at power up: the usage counter moves on by one and the
session counter starts at 0. The HOTP moving factor is stored as imported.

### OpenPGP

`{1: key ref (1 sig, 2 dec, 3 aut), 2: algorithm attributes (bytes, the
C1–C3 value), 3: private key (map), 4: fingerprint (20 bytes), 5: generation
time (uint), 6: UIF (2 bytes, optional)}`. The private key is a map of byte
strings in the form the card uses:

- RSA `{1: e, 2: p, 3: q}`, unsigned big endian without leading zeros; e is
  always 65537.
- EC (NIST, Brainpool, secp256k1) `{6: d, big endian at the byte length of
  the group order, 7: public key 04 || x || y}`.
- Ed25519 `{6: the RFC 8032 seed, 7: public key (32 bytes)}`.
- X25519 (Cv25519) `{6: the scalar in RFC 7748 (little-endian) order, as the
  card stores it (clamped when the card generated it), 7: public key
  (32 bytes)}`. IMPORT DATA tag 92 takes the scalar byte-reversed, as GnuPG
  keeps it.

There is no firmware import: the host verifies PW3, writes the attributes
(C1–C3), then IMPORT DATA (`PUT DATA 3FFF`, extended header list `4D`: RSA
`91` e, `92` p, `93` q; EC `92` the scalar, `99` the public key), the
fingerprint (C7–C9), the generation time (CE–D0) and the UIF (D6–D8), and
ends the PW3 session (`VERIFY FF 83`). An ECDH key does not go into the
signature slot, an ECDSA or EdDSA key not into the decryption slot.

### PIV

`{1: slot, 2: algorithm, 3: private key (map, as OpenPGP), 4: PIN policy, 5:
touch policy, 8: certificate (DER, optional)}`. The firmware never adds key
8: the tools read the slot's certificate (GET DATA, decompressed when stored
compressed) and add it. The policies are the ones stored with the key. There
is no firmware import: the host authenticates with the management key
(mutual authentication, 3DES or AES as the device's metadata says; the key
given, or else the default 3DES key unless the device reports that it was
changed) and sends IMPORT ASYMMETRIC KEY (`INS FE`, P1 the algorithm, P2 the
slot; RSA `01` p, `02` q, `03` dp, `04` dq, `05` qinv; EC `06` the scalar;
Ed25519 `07` the seed; X25519 `08` the scalar as in the record; `AA` / `AB`
the policies), then the certificate with PUT DATA (`70` the DER, `71 00`,
`FE`), or an empty object to remove the old one. The host checks that the
certificate belongs to the key before anything is sent.

## Key files

`.lfkey` files (`tools/librefido/librefido/keyfile.py`) are built and
protected like backup files: the same construction, key derivation and
cipher (`librefido.backup`), a shorter header.

    offset  size  field
    0       8     magic "LFKEYFIL"
    8       2     file format version, little endian: 1
    10      2     flags, little endian: bit 0 = payload encrypted (no other bit)
    12      4     payload length as stored, little endian
    16      32    SHA-256 of the payload as stored
    48      2     length L of the parameters, little endian (0 in the clear)
    50      L     parameters (CBOR, encrypted files only)
    50+L          payload

- Parameters: `{1: "scrypt", 2: salt (16 bytes), 3: log2(N), 4: r, 5: p, 6:
  "chacha20-poly1305", 7: nonce (12 bytes)}`. The tools write N = 2^17,
  r = 8, p = 1 and read at most N = 2^20 (checked before any work, so a
  crafted file cannot exhaust memory).
- Key: scrypt of the passphrase (UTF-8, Unicode NFC) to 32 bytes. Payload:
  ChaCha20-Poly1305 of the content with bytes 0..15 of the header and the
  parameters as associated data; its length includes the 16-byte tag.
- Content (CBOR): `{1: "librefido-key", 2: 1 (content format), 3: application
  name ("fido", "oath", "otp", "openpgp", "piv"), 4: record, 5: {1: created
  (unix time), 2: firmware of the source device, 3: label, 4: tool
  version}}`.
- Only an encrypted file is authenticated; the SHA-256 only detects damage.
  The tools write an encrypted file unless told twice not to (`--plaintext`
  and a confirmation), refuse an empty passphrase, and read a file in the
  clear only when told to (`--allow-unencrypted`). They write the file
  privately (mode 0600, or an owner-only ACL on Windows) and atomically, and
  refuse to write a file in the clear on a Windows drive without access
  control (FAT, exFAT).

## Standard formats

Read and written by `tools/librefido/librefido/stdformats.py`, without a
device.

- **`otpauth://totp|hotp/[issuer:]account?secret=...`**: base32 secret
  (spaces, hyphens and missing padding accepted), `issuer`, `algorithm`
  (SHA1, SHA256, SHA512), `digits` (6 to 8), `period` (TOTP) or `counter`
  (HOTP). The account is named as YKOATH clients name it. Secrets longer
  than the hash block are hashed and shorter ones padded to 14 bytes, as
  YKOATH clients store them: the codes are the same. An exported account
  becomes such a link again (always in the clear).
- **`otpauth-migration://offline?data=...`** (Google Authenticator
  "Transfer accounts"): every account of the link. Accounts the device
  cannot hold (MD5, an unknown number of digits) are left out and named. An
  export split over several QR codes carries a batch number: the tools name
  the QR codes that were not given.
- **QR code images** of either link (PNG, JPEG and the other formats the
  decoder reads; an image may hold several codes): decoded with OpenCV
  (`pip install "./tools/librefido[qr]"`), or zxing-cpp or pyzbar with
  Pillow.
- **PIV keys**: PEM (PKCS#8, PKCS#1 RSA, SEC1 EC, encrypted with a password
  or not, certificates in the same file), DER (PKCS#8 or traditional), and
  PKCS#12 (its certificate goes with the key). One private key per file;
  the certificate taken is the one whose public key matches. RSA 1024–4096
  (e = 65537), P-256, P-384, Ed25519, X25519. OpenSSH private keys are
  refused with the command that converts them. A PIV key is exported as
  PKCS#8 PEM, encrypted with a passphrase, followed by its certificate.
- **OpenPGP secret keys** (armored or binary, as `gpg --export-secret-keys`
  writes them): version 4 keys; RSA 1024–4096 with e = 65537; ECDSA and ECDH
  on NIST P-256/384/521, secp256k1, brainpoolP256r1/384r1/512r1; EdDSA
  Ed25519 and ECDH Cv25519 (also as the RFC 9580 algorithms Ed25519 and
  X25519 in version 4 packets). Key protection: none, S2K usage 254 and 255
  (AES-128/192/256 CFB) and 253 (AEAD, OCB or GCM), S2K simple, salted and
  iterated-salted. Each key's usage (sign, decrypt, authenticate) comes from
  the key flags of its self-signatures; revoked keys, GnuPG stubs (a key on
  a card or kept offline) and algorithms the card cannot hold are left out
  and named. From a file with several keys the tools add one per import:
  `--key-id` and `--slot` choose it. The private key is checked against the
  public key, and the fingerprint is computed from the public key packet.

## Compatibility

- Firmware before 2.1.0 answers `6D00` to the three commands and has no INFO
  key 19; the tools say that the firmware is too old. OATH accounts,
  OpenPGP keys and PIV keys can still be added to such firmware from key
  files and standard formats: that goes through their own applications.
- The store format stays 2: going back to 2.0.1 remains possible. 2.0.1
  keeps an imported FIDO credential but cannot use it: it is not found by
  its ID, not offered for a discoverable sign-in, and credential management
  lists it by ID only. Back on 2.1.0 it works again. A new credential 2.0.1
  makes for the same user goes into another slot.
- Backup streams written by 2.1.0 need firmware 2.1.0 to be imported
  (`LFBK_MIN_FW`): a profile may hold imported FIDO credentials that older
  firmware would carry over unusable. Backups of 2.0.0 and 2.0.1 still
  import.
- Key files need librefido-tools 2.1.0 or newer; a file of a newer format
  version is refused with a message, not misread.

## 快速上手

单个密钥的导出和导入需要固件 2.1.0 与 librefido-tools 2.1.0：

```bash
pip install "./tools/librefido[gui]"     # 读取二维码图片另需 "./tools/librefido[qr]"
```

几条规则：

- 导出只是**复制**，源设备上的密钥仍在。安全环境、禁止导出的环境和
  HARDENED 构建不能导出；导出需要按一下设备上的按键，环境设有 FIDO PIN
  时还需输入 FIDO PIN，OpenPGP 密钥另需 OpenPGP 管理员 PIN（Admin PIN）。
- 导出的文件默认用口令加密（.lfkey，与备份文件相同的加密方式）。明文导出
  需要 `--plaintext` 并再次确认，导入明文文件需要 `--allow-unencrypted`。
- 通行密钥复制后，两台设备的签名计数器会交错：会校验计数器的网站可能把它
  视为克隆并停用。请只在一台设备上使用，并在另一台上删除它。
- 非可发现凭据（非驻留凭据）只能随完整备份转移；largeBlob 数据和证明
  （attestation）不会复制；各类 PIN、OATH 密码和 PIV 管理密钥不属于密钥，
  使用目标设备上的设置。
- 导入过 FIDO 通行密钥的设备回退到 2.0.1 后无法使用这些凭据（升级回
  2.1.0 后恢复）；2.1.0 写出的备份只能导入 2.1.0 及以上的固件。

### 命令行

```bash
# 1. 列出当前环境的密钥（环境设有 FIDO PIN 时会询问；未输入已验证的 FIDO PIN 时，
#    列出 FIDO 通行密钥需按键一次；OATH 设有密码或 OTP PIN 时同样需按键）
librefido key list
librefido key list --app fido

# 2. 按列表中的编号导出一个密钥，设备闪烁时按键确认；口令输入两次
librefido key export fido:1 -o passkey.lfkey
librefido key export openpgp:1 -o sig.lfkey                 # 另询问 OpenPGP 管理员 PIN
librefido key export piv:1 --format pem -o piv.pem          # PIV 密钥及证书（加密的 PKCS#8 PEM）
librefido key export oath:2 --format otpauth --plaintext -o -   # 输出 otpauth:// 明文链接（需再次确认）

# 3. 在另一台设备（或另一个环境）上导入
librefido key import passkey.lfkey                          # FIDO / OTP：按键确认，需要时输入 FIDO PIN
librefido key import otp.lfkey --slot 2 --replace --access-code
librefido key import -                                      # 从标准输入粘贴 otpauth:// 或 otpauth-migration:// 链接
librefido key import accounts.png                           # 谷歌身份验证器“转移账号”的二维码截图
librefido key import key.p12 --slot 9a                      # PIV：默认管理密钥，否则加 --mgmt-key -
librefido key import secret.asc --slot sig                  # OpenPGP：询问密钥文件口令和管理员 PIN
```

设备上已有同一位置的密钥时，导入会被拒绝，除非加 `--replace`。链接不要直接
写在命令行上（其他用户可能看到），用 `-` 从标准输入读取。

### 图形界面

1. 运行 `librefido-gui`，打开“密钥”标签页。
2. 选择应用（或“全部应用”），点击“刷新”，列出当前环境的密钥（可能需要输入
   FIDO PIN；按键闪烁时请触摸：没有 FIDO PIN 时列出通行密钥、OATH 设有密码时
   列出账户，都需按键一次）。
3. 导出：选中一行，点击“导出所选…”；OATH 和 PIV 密钥可选择文件格式；输入
   密钥文件口令（选择不加密需要再次确认）；OpenPGP 密钥输入管理员 PIN；选择
   保存位置，设备闪烁时按键。
4. 导入：点击“从文件导入…”（.lfkey、PEM/DER/PKCS#12、OpenPGP 密钥文件、
   二维码图片）、“导入 otpauth 链接…”或“导入二维码图片…”，按提示输入口令、
   FIDO PIN、OpenPGP 管理员 PIN、OATH 密码、OTP 访问码或 PIV 管理密钥。目标
   位置已有密钥时会先询问是否替换。
