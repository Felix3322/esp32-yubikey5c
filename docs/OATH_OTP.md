# OATH and OTP

## OATH (YKOATH protocol)

TOTP and HOTP credentials (HMAC-SHA1/256/512, 6 to 8 digits, touch
property), optional access password, used by yubikit / Yubico Authenticator
compatible clients over CCID, and by Nitrokey-style clients over the HID
vendor command (CTAPHID_OTP). Credentials belong to the active profile.

Credential records, the access password key and the OTP PIN record are
sealed at rest (authenticated encryption with a key derived from the
device root key, namespace OATH; see SECURITY_ARCHITECTURE.md). While the
key store is locked (HARDENED build on a chip that is not ready, or a root
key held until it is bound) OATH and OTP answer SELECT only, everything
else is `6985`, and the button types nothing: no record is used, not even a
plaintext one of earlier firmware. A FIDO,
OpenPGP or PIV reset does not touch OATH; the OATH RESET command does not
touch the others.

### Access password and sessions

- There is one session per way to reach the applet: the smart card
  interfaces (CCID, WCID) and the HID vendor command. A session starts with a
  SELECT command, the first use of the applet on its transport, or (HID) a new
  CTAPHID channel, and ends when another application is selected or the card
  is reset. With an access password set, every command that reads or changes
  credentials (LIST, CALCULATE, CALCULATE ALL, PUT, DELETE, RENAME, SET CODE,
  GET CREDENTIAL, VERIFY CODE, SET/CHANGE PIN) answers `6982` until VALIDATE
  succeeded in that session, also right after a power cycle.
- VALIDATE needs the full HMAC over the SELECT challenge (compared in
  constant time); a shorter or longer answer is refused. After a successful
  VALIDATE the challenge is used up. SET CODE checks the host's proof the
  same way. After 10 wrong answers in a row VALIDATE answers `6983` until
  the next power cycle (online guessing of the password).
- An authentication only counts for the session and interface it happened
  on: one client's VALIDATE does not unlock another interface, and what one
  session does (select, failed VALIDATE, paging) never ends another one.
  Clients sharing one PC/SC connection share the session, as on any smart
  card.
- On HID an authorization belongs to the CTAPHID channel that made it (a
  client on another channel starts logged out) and ends after 15 s without
  an OATH command: HID has no card reset that tells when a client is gone.
- SET CODE keeps the session that set the password authorized, as on a
  YubiKey; every other session needs the new password.
- RESET (`04 DE AD`) needs no password but a button press (it is not
  covered by automatic presence), and wipes every OATH credential, the
  password and the OTP PIN.

### Touch

A credential added with "require touch" is never used without a fresh
button press: CALCULATE ALL reports it as "touch required", CALCULATE, VERIFY
CODE and GET CREDENTIAL (password-safe fields) wait for the press (`6985`
when nobody touches). With automatic presence for OATH in the profile
("my device is safe", not in secure profiles or HARDENED builds) no press is
needed. The property is read in the YKOATH form clients send (tag `78` and
one value byte, no length).

### Limits and long answers

Names are 1 to 64 bytes, secrets at most 128 bytes (clients shorten longer
HMAC keys), digits 6 to 8, the password-safe fields at most 128 bytes each.
Length bytes of 128 to 255 are also accepted in the one-byte form (tlv8)
Nitrokey clients send. LIST and CALCULATE ALL answers longer than one USB
transfer (about 2 KB) are paged the YKOATH way: `61xx`, then SEND REMAINING
(`A5`) until `9000`. yubikit and Yubico Authenticator do this on their own.
Any other command drops what was left.

### Nitrokey extensions

- OTP PIN (SET/CHANGE/VERIFY PIN): once set, every command that reads or
  changes credentials also needs VERIFY PIN in the session, in addition to
  the access password when one is set; neither replaces the other. Three
  tries, spent before the comparison, shared by VERIFY and CHANGE PIN; a
  blocked PIN (`6983`) is only cleared by RESET.
- GET CREDENTIAL returns the password-safe fields under the same rules and
  the touch property; lengths up to 255 are written in one byte, as the
  Nitrokey client reads them.
- VERIFY CODE (HOTP checked by the key, as used for boot integrity) accepts
  a code within 10 counters ahead and moves the counter past it, so a code
  is accepted once. After 10 misses in a row it answers `6983` until the next
  power cycle or RESET.

### Stored records

Credentials are stored as TLV records (name, key, property, 8-byte moving
factor for HOTP, password-safe fields). Records written by earlier firmware
(the PUT data as the host sent it: bare property `78 xx`, or `78 01 xx`,
one-byte lengths up to 255, bytes left over by its in-place counter
padding) are read as they are and rewritten in the current form, keeping
anything that is no clean element, when a HOTP counter moves or the
credential is renamed. Plaintext records of earlier firmware are sealed at
the first OATH command after boot once the running firmware is confirmed
(an unconfirmed update may still roll back to firmware that cannot read
them). Until then, new and rewritten plaintext records keep the form the
previous firmware reads: the elements as the client sent them (the property
in its stored form, never the new private tag), only the name (RENAME) and
the 8-byte moving factor replaced. A sealed record is never written back in
plaintext. PUT also accepts the property in the length form (`78 01 xx`).

## OTP slots

Four slots (a single press while idle fires slot 1, a double press slot 2,
three and four presses slots 3 and 4) with the YubiKey OTP configuration
protocol: Yubico OTP, OATH-HOTP, static password and HMAC-SHA1 / Yubico OTP
challenge-response. Typed slots need the USB keyboard interface. Slot
records (secrets, static passwords, access codes) are sealed at rest
(namespace OTP), with the same migration rule as OATH (at boot or at the
first SELECT once the firmware is confirmed).

- A slot protected by an access code is only changed, deleted or swapped
  when the current code is sent with the command (6 bytes after the
  configuration; for SWAP the 6-byte code field yubikit and ykpers send, or
  after the two offset bytes of the smart card extension). A slot update
  needs the slot's "allow update" flag and keeps the secrets and the
  counter.
- OATH-HOTP slots type RFC 4226 codes (6 or 8 digits, initial moving factor
  from the configuration). A HOTP or Yubico OTP counter is stored before the
  code is typed.
- Challenge-response with "require touch" waits for the press on the smart
  card interface (yubikit over CCID). The keyboard interface (feature
  reports, ykpers-style tools) is served by the USB stack, which cannot wait
  for a press: there such a slot is refused (the host reports no data),
  unless the profile gives OTP automatic presence, then it answers at once.
  Slots without touch answer on both interfaces.
- Keyboard feature reports never disturb another interface's command: while
  one runs the keyboard interface reports the last status, and a keyboard
  command that arrives meanwhile shows "busy" (the host keeps polling) and
  runs as soon as the device is idle.

Button use: a press is either a presence confirmation for the command that
asked for it, an OTP slot event while idle, or (held 5 s while idle) a
profile switch. A pending presence request always wins.

## Management applet (YubiKey compatible)

READ CONFIG reports the device information; WRITE CONFIG changes only the
settings it carries (enabled applications, device flags, timeouts) and
refuses unknown or malformed settings. A configuration lock code is not
supported and is refused rather than silently ignored. The management RESET
command resets FIDO only, needs a button press, and reports `6985` when it
was refused (power-on window over, no touch).
