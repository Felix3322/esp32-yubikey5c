/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * Per-profile policies.
 *
 * Secure profile: created empty (never imported, never converted from an
 * exportable one), keys never leave it, the root key must be bound to the
 * chip (HMAC eFuse key), and every presence request needs a physical press.
 *
 * Automatic presence ("my device is safe"): per application, a presence
 * request of that application succeeds without a press. Opt-in, needs a
 * physical press to switch on, never available to secure profiles or
 * HARDENED builds.
 *
 * Only the everyday operations of an application ask through
 * lf_wait_presence(app) (sign, authenticate, calculate). Destructive and
 * copying operations (resets, key replacement, exports and imports,
 * firmware, profile and board changes) call wait_button() directly, which
 * always needs a physical press.
 */

#ifndef _LF_POLICY_H_
#define _LF_POLICY_H_

#include <stdbool.h>
#include <stdint.h>

/* Profile flags (lf_profile_entry_t.flags) owned by the policies; bit 0 is
 * LF_PROFILE_F_NO_EXPORT (lf_sys.h). */
#define LF_PROFILE_F_SECURE         0x02
#define LF_PROFILE_F_AUTO_FIDO      0x04    /* then one bit per lf_app_t */
#define LF_PROFILE_F_AUTO_ALL       0x7C

typedef enum {
    LF_APP_FIDO = 0,        /* CTAP2, U2F (HID and CCID) */
    LF_APP_OATH,
    LF_APP_OTP,             /* challenge-response */
    LF_APP_OPENPGP,
    LF_APP_PIV,
    LF_APP_COUNT,
} lf_app_t;

/* Profile flag that switches automatic presence on for app, 0 if none. */
extern uint8_t lf_auto_flag(uint8_t app);

/* True when a presence request of app succeeds without a press (active
 * profile, not secure, not HARDENED). */
extern bool lf_presence_automatic(uint8_t app);

/* Presence for an everyday operation of app. Same contract as wait_button():
 * returns true when NO presence was obtained. */
extern bool lf_wait_presence(uint8_t app);

/* The active profile is a secure profile (or the build is HARDENED). */
extern bool lf_profile_is_secure(void);

/* The mounted profile was CREATED as a secure profile (flag SECURE): every
 * record in it was written sealed, so plaintext can only be injected.
 * Unlike lf_profile_is_secure() this is false for profiles of a HARDENED
 * build that were written by earlier firmware. */
extern bool lf_profile_sealed_only(void);

/* Records written by earlier firmware may be rewritten in a newer format
 * (e.g. sealed) only once the running firmware is confirmed: an unconfirmed
 * update can still roll back to firmware that cannot read the new format. */
extern bool lf_migrate_ok(void);

#endif
