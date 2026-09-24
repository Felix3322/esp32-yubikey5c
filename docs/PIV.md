# PIV

NIST SP 800-73-4 card application (AID `A000000308`), used through PKCS#11
(OpenSC, ykcs11), Windows minidriver-compatible tools and yubikit.

## Keys and objects

| Slot | Use |
|---|---|
| 9A, 9C, 9D, 9E | authentication, signature, key management, card authentication |
| 82 – 95 | retired key management keys |
| 9B | card management key (3DES, AES-128/192/256) |
| F9 | attestation key (generated on the device, survives a PIV reset) |

Algorithms: RSA 1024/2048 (generate and import), RSA 3072/4096 (import),
ECC P-256/P-384, Ed25519 (E0) and X25519 (E1) as on YubiKey 5.7 (generate
and import, see [Ed25519 and X25519](#ed25519-and-x25519)). Defaults: PIN
`123456`, PUK `12345678`, management key
`010203040506070801020304050607080102030405060708` (3DES, as on PIV cards
before AES management keys, so clients such as yubico-piv-tool 2.2 that know
no other work; earlier versions tagged it AES-192 and are switched over on
the next selection while the key is still the default). **Change all
three**; a new management key may be 3DES or AES-128/192/256.

SELECT answers the application property template: PIX with version
(`4F 06 000010000100`), the coexistent tag allocation authority
(`79 07 4F 05 A000000308`), the label `LibreFido PIV` and one `80 01 xx` per
algorithm the card implements (03, 06, 07, 08, 0A, 0C, 11, 14, E0, E1),
closed by `06 00`. The template comes back also for a SELECT without Le.

Certificates the card makes itself (the self-signed certificate of a
generated key, the attestation certificate F9) are stored as bare DER; GET
DATA gives them as SP 800-73-4 certificate objects (`70` certificate, `71
00`), as it gives the certificates clients write, so yubikit, yubico-piv-tool
and OpenSC read them (earlier versions answered the bare DER).

## Ed25519 and X25519

Algorithm E0 (Ed25519) and E1 (X25519), as YubiKey 5.7 has them, with the
code of `pico-keys-sdk/src/crypto/lf_25519.c` (RFC 8032, RFC 7748, constant
time; in every build, `LF_HAVE_25519`). yubikit enables them because GET
VERSION answers 5.7.0.

- GENERATE (`AC { 80 E0|E1 [AA pin] [AB touch] }`) answers
  `7F49 { 86 20 <public key> }`. An Ed25519 key gets a self-signed
  certificate in its slot, like the other keys; an X25519 key cannot sign,
  so its slot has no certificate (the one of the key it replaces is
  deleted).
- IMPORT (INS FE, P1 E0/E1): tag 07 is the 32-byte Ed25519 seed, tag 08 the
  32-byte X25519 scalar (little endian, RFC 7748), as yubikit's `put_key`
  sends them.
- GENERAL AUTHENTICATE: Ed25519 signs the data of tag 81 as given
  (PureEdDSA, no hashing on the host) and answers the 64-byte signature in
  82; X25519 takes the other party's 32-byte u in tag 85 and answers the
  32-byte shared secret in 82 (a point of small order, all-zero secret: 6984).
  An Ed25519 key refuses 85 and an X25519 key refuses 81.
- GET METADATA reports the algorithm, the policies, the origin and the
  public key (`04 { 86 20 ... }`).
- ATTEST (INS F9) gives a certificate for a generated key whose public key
  info is id-Ed25519 or id-X25519 (RFC 8410), signed by the attestation key
  F9 (ECDSA with SHA-256), with the extensions of the other attestation
  certificates (firmware version, serial, PIN and touch policy, form factor)
  and key usage digitalSignature (Ed25519) or keyAgreement (X25519).
- PIN and touch policies, MOVE KEY, DELETE KEY (MOVE to FF) and sealed
  storage (SKS_NS_PIV, bound to the key's file) as for every other key; the
  record is a type byte and the 32-byte seed or scalar. The public key is
  derived from the seed for every signature.
- Speed, estimated for the ESP32-S3 at 240 MHz: an Ed25519 signature about
  175 ms, a key agreement about 50 ms, GENERATE about 90 ms (Ed25519, plus
  its self-signed certificate: another 175 ms) or 50 ms (X25519).

## Using it with OpenSC

This is a composite card with a PIV and an OpenPGP application, and OpenSC
(opensc-tool, pkcs11-tool, opensc-pkcs11.so) serves one of them, the one of
the first card driver that accepts the card. OpenSC 0.25 tries its PIV
driver before its OpenPGP driver, so without a choice it takes the PIV
application. Earlier firmware answered SELECT PIV with a malformed template,
the PIV driver gave up and OpenSC fell back to OpenPGP: set the driver
explicitly rather than rely on the order.

    OPENSC_DRIVER=PIV-II pkcs11-tool --module opensc-pkcs11.so --list-objects
    OPENSC_DRIVER=openpgp pkcs11-tool --module opensc-pkcs11.so --list-objects

or permanently in `opensc.conf`:

    app default {
        card_drivers = PIV-II, internal;      # or: openpgp, internal
    }

OpenSC lists retired key slots (82-95) only as far as the key history
object (5FC10C) counts certificates on the card; tools that write retired
certificates without it (yubico-piv-tool) leave them out of PKCS#11.

yubico-piv-tool and ykcs11 only look at readers whose name starts with
"Yubico" unless told otherwise: give the reader with `-r`
(`yubico-piv-tool -r "Virtual PCD" ...`). PIV commands sent without Le (as
libykpiv does) get their answer directly, up to 256 bytes.

## Access rules

| Operation | Needs |
|---|---|
| sign / decrypt / key agreement | the key's PIN policy and touch policy (below) |
| generate, import, move, delete keys | management key |
| PUT DATA (certificates, CHUID, ...) | management key |
| GET DATA of printed information, fingerprints, facial image, iris, pairing code (5FC109, 5FC103, 5FC108, 5FC121, 5FC123) | PIN |
| SET MANAGEMENT KEY | management key |
| SET RETRIES (resets PIN and PUK to their defaults) | management key and PIN |
| RESET | PIN and PUK both blocked, and a press of the button |

- **PIN policy.** NEVER, ONCE (the PIN verified in this selection) or
  ALWAYS: the PIN must have been verified by the command right before the
  operation (a PIN status query in between is allowed), as SP 800-73-4 and
  YubiKey have it; any other command, and any key operation, uses the grant
  up. Defaults as on YubiKey: ONCE, ALWAYS for 9C, NEVER for 9E.
- **Touch policy.** NEVER, ALWAYS or CACHED (a touch covers 15 s) is
  enforced for every private key operation and for the management key.
  Defaults as on YubiKey: keys generated or imported without a touch policy,
  and the default management key, need no touch; ask for one with
  `--touch-policy=always` (yubico-piv-tool), `--touch-policy ALWAYS` (ykman)
  or, for the management key, `set-mgm-key --touch`.
- **Presence.** The touch of a private key operation is a press of the
  button, or automatic presence if the user switched that on for PIV in the
  profile ("my device is safe", switched on with a press, never available in
  secure profiles and HARDENED builds). Automatic presence satisfies the
  touch policy of private key operations only. The touch of the management
  key (it guards replacing, moving and deleting keys and the security
  settings) always needs a physical press, as RESET does; a CACHED touch of
  a key operation does not count for it.
- **Keys of earlier firmware.** Earlier firmware stored a touch policy
  (ALWAYS by default) but never enforced it. Keys whose metadata was written
  by it keep working without a touch, and GET METADATA and attestation
  report the touch policy as NEVER, which is what the card does. Metadata
  written by this firmware carries a version byte; its touch policy is
  enforced.
- **PIN checks.** Every PIN or PUK attempt is counted, and the count is
  committed to flash, before the PIN is compared: cutting the power when an
  answer seems late does not give a wrong guess back.
- **Algorithm.** GENERAL AUTHENTICATE must name the algorithm the key has
  (its metadata); the management key only encrypts host data inside a mutual
  authentication whose witness was right. A witness or challenge serves one
  attempt, right or wrong, and a new attempt ends the administrator session.
  Both the mutual (80 / 80 + 81) and the external (81 / 82) flow
  authenticate the administrator.
- **Logout.** VERIFY with P1 FF (no data) resets the PIN status. The PIN,
  management key and challenge state also end with the selection of another
  application or a card reset.
- New PINs and PUKs are 8 bytes: 6 to 8 characters padded with FF.
- GENERATE accepts only the exponent 65537 for RSA; IMPORT refuses a key
  whose size is not the one P1 names. PIN and touch policy values other than
  the ones above are refused.
- MOVE KEY moves the key together with its metadata (algorithm, policies,
  origin); a key cannot be moved onto itself, and the management key cannot
  be moved.

Key reference 93 (retired key 18) is stored in file 0x96 and reference F9
in 0xFB, because 0x93 and 0xF9 are OpenPGP data objects on the same card;
GET METADATA only accepts PIV key references.

## Key storage

PIV private keys, the management key, the attestation key and the PIN and
PUK verifiers (the PIN length and a hash of the PIN) are stored sealed
(AES-256-GCM, key derived from the profile's root key, PIV namespace of the
secure key store, bound to the record's file): a flash dump without the
root key reveals no key, and a PIN cannot be guessed offline from it.

Earlier firmware stored them in plaintext. Such records keep working as
they are (also in HARDENED builds: only a profile created as a secure
profile refuses plaintext records), and are sealed at the first selection
of the PIV application once the running firmware is confirmed. While an
update runs unconfirmed (a reset would roll it back), nothing written by
earlier firmware is rewritten, so the previous firmware still reads it
after a rollback; the default management key also keeps its earlier AES-192
tag until then (it is switched to 3DES afterwards). Records written during
such a trial run (the defaults when PIV is first selected, keys generated
or imported, a new management key, PIN or PUK) keep the plaintext format
of the previous firmware, unless the record they replace is sealed already,
and are sealed with the others once the firmware is confirmed. A key moved
from a sealed record stays sealed. Until the PIN and PUK verifiers are
sealed, they can be guessed offline from a dump of a flash that is not
encrypted.

While the key store is locked (a root key held until `librefido provision
bind-root-key` binds it, or a HARDENED build on a chip that does not meet
its requirements), the application answers SELECT, GET DATA, GET METADATA,
GET SERIAL and GET VERSION, and refuses everything else (6985): nothing is
provisioned, used or written.

## Reset

RESET (both PIN and PUK blocked, and a press of the button) erases the PIV
keys, certificates, data objects, PIN, PUK, management key and their
metadata, and restores the defaults. The PIV namespace of the key store
gets a new epoch, so copies of old key records left in the store can no
longer be opened (a profile backup made before the reset carries the old
epoch with it and restores it). The attestation key (sealed again under the
new epoch, in the same commit) and its certificate stay. OpenPGP, FIDO,
OATH and the profile identity are not touched.

## Version and attestation

GET VERSION (a Yubico extension) answers 5.7.0 because yubikit gates
features on that number; LibreFido does not claim to be a YubiKey. The
attestation certificate chain ends in a certificate generated on the device
(`CN=... PIV Slot F9`), not in any vendor CA: attestation proves "generated
on this LibreFido profile", nothing more (and a cloned profile carries the
same attestation key). The PIN and touch policies it reports are the ones
the card enforces.
