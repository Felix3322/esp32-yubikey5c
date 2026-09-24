# OpenPGP card

OpenPGP card 3.4 application (AID `D276000124 01`), used by GnuPG
(scdaemon), OpenSSH through gpg-agent, and yubikit.

- Three keys: signature, decryption, authentication. RSA 2048/3072/4096,
  ECDSA/ECDH on NIST P-256/P-384/P-521, and Curve 25519 (GnuPG's default
  keys: EdDSA ed25519 for signature and authentication, ECDH cv25519 for
  decryption) in every build, the ESP32 one included (see
  [Curve 25519](#curve-25519)). Ed448 only in builds with the EdDSA mbedTLS
  (`ENABLE_EDDSA`, emulator only).
- Key generation on the card, key import, KDF-DO, User Interaction Flags
  (touch per key), signature counter, cardholder certificate.
- No private DOs (0101-0104) and no symmetric (AES) PSO: the extended
  capabilities say so.
- Defaults: PW1 `123456`, PW3 (admin) `12345678`. **Change both.** No Reset
  Code is set (its retry counter reads 0) until PW3 sets one.

## Access rules

| Operation | Needs |
|---|---|
| PSO: COMPUTE DIGITAL SIGNATURE | PW1 (VERIFY 81) |
| PSO: DECIPHER, INTERNAL AUTHENTICATE | PW1 (VERIFY 82) |
| GENERATE, IMPORT DATA (key import) | PW3 |
| PUT DATA (every data object, the PW status byte, key attributes, UIF, Reset Code, KDF-DO, fingerprints, times, certificate) | PW3 |
| RESET RETRY COUNTER | Reset Code, or PW3 |

- PW3 does not use the keys: signing and decryption need PW1.
- Authentication (PW1 in both modes, PW3, Reset Code) ends when the
  application is selected again, another application is selected or the
  card is reset; VERIFY FF 8x ends one PW; a wrong VERIFY ends that PW.
- PW1 is 6 to 127 bytes, PW3 and the Reset Code 8 to 127.
- Every PW1, PW3 and Reset Code attempt is counted, and the count is
  committed to flash, before the PIN is compared: cutting the power when an
  answer seems late does not give a wrong guess back. A blocked PW is not
  compared at all.
- The Reset Code: PUT DATA D3 with 8 to 127 bytes sets it (and its retry
  counter), with no data removes it. **Reset Codes set with earlier
  firmware are removed** at the next selection of the application: that
  firmware stored the data key for them in another form, and recovering
  PW1 with such a code would have given PW1 a wrong data key (keys unusable
  until PW3 repairs it). Set a new Reset Code with PW3. (Earlier firmware
  also installed `12345678`, the default admin PIN, as Reset Code without
  saying so.)
- CHANGE REFERENCE DATA and RESET RETRY COUNTER take the data key from the
  slot of the PW the command verified (never from another PW that happens
  to be verified too), and write it back before the new PW; if the PW
  cannot be written the data key file is put back as it was.
- A new key algorithm (PUT DATA C1/C2/C3) deletes the key of that slot with
  its public key, fingerprint and generation time; only algorithms the card
  implements are accepted (RSA 1024-4096 with e = 65537, the curves above
  for the use they fit).
- UIF (D6-D8): 2 bytes, value 0-4 then 20. "Permanently enabled" (2, 4) can
  only be undone by resetting the application. Any value other than 0 asks
  for presence at every use: a press of the button, or automatic presence if
  the user switched that on for OpenPGP in the profile ("my device is safe",
  switched on with a press, never available in secure profiles and HARDENED
  builds).
- PUT DATA with no data deletes a data object.

## Keys at rest

The private keys are encrypted with the data key; the data key is wrapped
under PW1, the Reset Code and PW3 (EF_DEK). That file and the PIN verifiers
(the PIN length and a hash of the PIN, for PW1, the Reset Code and PW3) are
sealed by the secure key store (OpenPGP namespace, key derived from the
profile's root key). With both sealed, guessing a PIN offline from a flash
dump needs the root key (bound to the chip once `librefido provision
bind-root-key` was run). Records of earlier firmware are in plaintext: they
keep working and are sealed at the first selection of OpenPGP or PIV once
the running firmware is confirmed. While an update runs unconfirmed, new
records are written in plaintext too, so that the previous firmware can
still read them. **Until the records are sealed, a PIN can be guessed
offline from a dump of a flash that is not encrypted** (the verifier is an
unkeyed hash salted with the serial number); flash encryption protects
them either way. A verifier that does not open (tampered with) matches no
PIN; attempts are still counted, so the PW can be blocked and the
application reset. Sealed records travel with a profile backup, which
carries the root key and the profile identity.

While the key store is locked (a root key held until `librefido provision
bind-root-key` binds it, or a HARDENED build on a chip that does not meet
its requirements), the application answers SELECT, GET DATA, SELECT DATA,
GET CHALLENGE and the version, and refuses everything that needs a PW, a
key or the data key, or writes (6985). The data key is bound to the root
key: a key opened or written without it would be wrong, and lost after the
binding.

## Curve 25519

EdDSA and X25519 come from `pico-keys-sdk/src/crypto/lf_25519.c` (RFC 8032
Ed25519 and RFC 7748 X25519 in portable C, constant time; built in
everywhere, `LF_HAVE_25519`), since the mbedTLS of ESP-IDF has no EdDSA. A
build with the EdDSA fork of mbedTLS (`ENABLE_EDDSA`) keeps using that
instead for OpenPGP.

| | Algorithm attributes (C1-C3) | |
|---|---|---|
| signature (C1), authentication (C3) | `16 2B06010401DA470F01` | EdDSA, ed25519 (1.3.6.1.4.1.11591.15.1) |
| decryption (C2) | `12 2B060104019755010501` | ECDH, cv25519 (1.3.6.1.4.1.3029.1.5.1) |

- Both are listed in the algorithm information DO (FA). PUT DATA accepts
  ed25519 on C1 and C3, cv25519 on C2 (and C3, which MSE can make the
  decryption key), with or without the trailing FF of the import format;
  EdDSA or ECDSA on the other curve is refused. `gpg --card-edit`, `key-attr`,
  ECC, Curve 25519 sets all three.
- GENERATE and reading the public key answer `7F49 { 86 20 <32 bytes> }`,
  the native form (Ed25519 point encoding, X25519 u coordinate).
- IMPORT DATA as scdaemon writes it (keytocard): 92 is the Ed25519 seed or
  the cv25519 scalar in GnuPG's MPI form (big endian), both at most 32 bytes
  (leading zero bytes may be missing); 99, if given, is the public key
  (32 bytes, or 40 and 32 bytes) and must be the private key's, or the
  import is refused (6700) and the slot keeps its key.
- PSO:CDS and INTERNAL AUTHENTICATE sign the data as given (PureEdDSA, 64
  bytes R || S); GnuPG hashes and sends the hash, OpenSSH sends its data.
  PSO:DECIPHER takes `A6 { 7F49 { 86 <u> } }` with a 32-byte u (or 40 and
  u) and answers the 32-byte X25519 shared secret; a point of small order
  (all-zero secret) is refused with 6984. An EdDSA key never deciphers and an
  X25519 key never signs (6985), also after MSE.
- The private key record is a type byte and the 32-byte seed or scalar,
  encrypted with the data key like every OpenPGP key (the data key file is
  sealed, see above). A cv25519 key of earlier firmware (mbedTLS) has the
  same record and keeps working.
- The public key is derived from the seed for every signature, never read
  from its file: Ed25519 signing with a public key that is not the seed's
  would give the private key away (two signatures of one message).

Speed, estimated for the ESP32-S3 at 240 MHz from the instruction counts
of the compiled code (see `tests/unit/test_25519.py` for the host figures):
a signature about 175 ms (two scalar multiplications: the nonce point and
the public key), Ed25519 key generation about 90 ms, a decryption or
cv25519 key generation (X25519) about 50 ms.

## Data objects

GET DATA, GET NEXT DATA, SELECT DATA and PUT DATA accept OpenPGP data
objects only: the file table of the firmware also holds the PIV and FIDO
files and the device files (root key, ...), and any other tag answers
6A88. Readable: 4F, 5B, 5E, 65, 6E, 73, 7A, 93, C0-D0, D6-D8, DE, F9, FA,
5F2D, 5F35, 5F50, 5F52, 7F21, 7F66, 7F74.

GET DATA returns a constructed data object with its own tag (Application
Related Data 6E, Cardholder Related Data 65, Security Support Template 7A,
...) and a simple data object as its value only, for every client. Earlier
versions left the 6E tag out unless another applet had been selected before,
which broke yubikit. The cardholder certificate (7F21) is returned as
stored, for the instance chosen by SELECT DATA (the first by default).

## Reset

TERMINATE DF (after PW3, or with PW3 blocked, and a press of the button,
whatever the presence setting) + ACTIVATE FILE erase the OpenPGP keys, PWs,
Reset Code, DOs and signature counter and restore the defaults. PIV, FIDO, OATH and the profile identity are not touched; the
shared data key file keeps its IV and PIV mark. Like the FIDO, OATH and
PIV resets it starts a new epoch of its namespace of the secure key store
(once the data key file is sealed): copies of the old sealed data key file
and PIN verifiers left in the store no longer open. The keys and data
objects go first; the new epoch, the new data key file and the default PWs
then become durable together, and the PW status last, so a reset cut short
leaves PWs that open the data key file there and PW3 still blocked if it
was.

## Tested clients

`tests/openpgp`: yubikit parses the application data, PIN status, key
attributes and signature counter of a card with a key generated and used on
it; `gpg --card-status` reads the card through scdaemon; `gpg --card-edit`
generates keys on the card (RSA, and Curve 25519 after `key-attr`), signs,
encrypts and decrypts with them and changes the PIN; `keytocard` moves
ed25519 and cv25519 keys made by GnuPG to the card, which then signs and
decrypts with them (GnuPG 2.4.4). `test_openpgp_25519.py` checks the Curve
25519 keys with plain APDUs against Python cryptography: signatures of
imported keys are RFC 8032's byte for byte, shared secrets match. yubikit's
own key generation calls are gated on YubiKey firmware versions this card
does not claim; generate keys with GnuPG or plain APDUs.

scdaemon (GnuPG 2.4) also finds the PIV application of the card (earlier
firmware answered its SELECT with a malformed template) and uses both,
selecting OpenPGP again before OpenPGP commands. Selecting the application
ends its PIN verification, so GnuPG may ask for the user or admin PIN more
than once in one `--card-edit` session (e.g. during `generate`). For OpenSC,
see [PIV.md](PIV.md): pick its OpenPGP driver with `OPENSC_DRIVER=openpgp`.
