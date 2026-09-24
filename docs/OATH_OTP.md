# OATH and OTP

## OATH (YKOATH protocol)

TOTP and HOTP credentials (HMAC-SHA1/256/512, 6 or 8 digits, touch
property), optional access password, used by yubikit / Yubico Authenticator
compatible clients over CCID. Credentials belong to the active profile.

Secrets are stored in the profile store as they are: at rest they are
protected only by flash encryption (after hardening), not by a PIN or the
root key. Keep that in mind before storing codes that matter.

A FIDO, OpenPGP or PIV reset does not touch OATH; the OATH RESET command
does not touch the others.

## OTP slots

Two slots (a single press while idle fires slot 1, a double press slot 2)
with the YubiKey OTP configuration protocol: Yubico OTP, OATH-HOTP, static
password and HMAC-SHA1 challenge-response. Typed slots need the USB keyboard
interface, which is only enabled while a slot that types is configured (a
plain security key never enumerates as a keyboard).

Button use: a press is either a presence confirmation for the command that
asked for it, an OTP slot event while idle, or (held 5 s while idle) a
profile switch. A pending presence request always wins.
