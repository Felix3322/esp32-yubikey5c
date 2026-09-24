# OpenPGP card

OpenPGP card 3.4 application (AID `D276000124 01`), used by GnuPG
(scdaemon), OpenSSH through gpg-agent, and yubikit.

- Three keys: signature, decryption, authentication. RSA 2048/3072/4096,
  ECDSA/ECDH on NIST P-256/P-384/P-521, Ed25519/Curve25519 where the build
  enables EdDSA (tested here: P-256).
- Key generation on the card, key import, KDF-DO, User Interaction Flags
  (touch per key), signature counter, private DOs, cardholder certificate.
- Defaults: PW1 `123456`, PW3 (admin) `12345678`. **Change both.**

## Data objects

GET DATA returns a constructed data object with its own tag (Application
Related Data 6E, Cardholder Related Data 65, Security Support Template 7A,
Cardholder Certificate 7F21, ...) and a simple data object as its value
only, for every client. Earlier versions left the 6E tag out unless another
applet had been selected before, which broke yubikit.

## Reset

TERMINATE DF (after PW3, or with PW3 blocked) + ACTIVATE FILE erase the
OpenPGP keys, PWs, DOs and signature counter and restore the defaults. PIV,
FIDO, OATH and the profile identity are not touched; the shared data key
file keeps its IV and PIV part.

## Tested clients

`tests/openpgp`: yubikit parses the application data, PIN status, key
attributes and signature counter of a card with a key generated and used on
it; `gpg --card-status` reads the card through scdaemon. yubikit's own key
generation calls are gated on YubiKey firmware versions this card does not
claim; generate keys with GnuPG or plain APDUs.
