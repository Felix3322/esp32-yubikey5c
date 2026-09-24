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

Algorithms: RSA 1024/2048/3072/4096, ECC P-256/P-384. Defaults: PIN
`123456`, PUK `12345678`, management key `010203040506070801020304050607080102030405060708`
(AES-192). **Change all three.**

## Access rules

| Operation | Needs |
|---|---|
| sign / decrypt / key agreement | PIN (and a touch if the key's touch policy says so) |
| generate, import, move, delete keys | management key |
| PUT DATA (certificates, CHUID, ...) | management key |
| SET MANAGEMENT KEY | management key |
| SET RETRIES (resets PIN and PUK to their defaults) | management key and PIN |
| RESET | PIN and PUK both blocked |

The PIN, management key and challenge state end with the selection of
another application; they never last until power off. Earlier versions did
not check the management key for SET MANAGEMENT KEY, PUT DATA, IMPORT,
MOVE and SET RETRIES: anyone could take over the application.

Key reference 93 (retired key 18) is stored in file 0x96 and reference F9
in 0xFB, because 0x93 and 0xF9 are OpenPGP data objects on the same card;
GET METADATA only accepts PIV key references.

## Reset

RESET (both PIN and PUK blocked) erases the PIV keys, certificates, data
objects, PIN, PUK, management key and their metadata, and restores the
defaults. The attestation key and its certificate stay. OpenPGP, FIDO, OATH
and the profile identity are not touched.

## Version and attestation

GET VERSION (a Yubico extension) answers 5.7.0 because yubikit gates
features on that number; LibreFido does not claim to be a YubiKey. The
attestation certificate chain ends in a certificate generated on the device
(`CN=... PIV Slot F9`), not in any vendor CA: attestation proves "generated
on this LibreFido profile", nothing more (and a cloned profile carries the
same attestation key).
