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
 * Runtime profile management (button gesture and management applet).
 *
 * A profile is a complete, isolated authenticator: its own store region, root
 * key, serial, PINs, FIDO credentials and counters, OpenPGP/PIV keys, OATH
 * and OTP data. Only one is mounted at a time; switching persists the choice
 * and reboots, so the host sees a different device (new USB serial). Changes
 * that need the profile unmounted (wipe, delete, import) are recorded as a
 * pending operation and carried out, verified, by the next boot (lf_boot.c).
 */

#ifndef _LF_PROFILE_H_
#define _LF_PROFILE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* LED palette colour (led.h) of profile idx. */
extern uint8_t lf_profile_led_color(uint8_t idx);

/* Makes idx the active profile from the next boot on; a slot without a
 * profile gets a new, empty one. The system area is only changed if the
 * record could be written. */
extern int lf_profile_select(uint8_t idx);
/* Button gesture: next of the first lf_sys()->button_slots profiles. */
extern int lf_profile_select_next(void);

/* Profile whose store is mounted: the active profile of this boot. After a
 * switch lf_sys()->active already names the next one, but the data (and the
 * policies) are still those of this one until the reboot. */
extern uint8_t lf_profile_mounted(void);

/* System area changes the host asks for without a touch (names, colours,
 * button slots, board settings, switching automatic presence off): the
 * first LF_FREE_SYS_CHANGES since the last touch-confirmed change are free,
 * then each one needs a touch, which renews the allowance. The count is part
 * of the system record, so restarts do not renew it and host software alone
 * cannot wear the system area out. Call right before the commit that makes
 * the change (it carries the count). */
#define LF_FREE_SYS_CHANGES     16
extern bool lf_sys_change_allowed(void);
/* The change about to be committed was confirmed with a touch. */
extern void lf_sys_change_confirmed(void);
/* Changes left before a touch is needed. */
extern uint8_t lf_sys_free_changes(void);

/* Name (UTF-8, NULL = keep), RGB colour (NULL = keep), flags (< 0 = keep).
 * Nothing is written when nothing changes. */
extern int lf_profile_set(uint8_t idx, const char *name, const uint8_t rgb[3], int flags);
/* True if lf_profile_set() with these arguments would change profile idx. */
extern bool lf_profile_differs(uint8_t idx, const char *name, const uint8_t rgb[3], int flags);

/* A profile name is at most LF_PROFILE_NAME_MAX - 1 bytes of valid UTF-8
 * without NUL (INFO returns it as a CBOR text string). */
extern bool lf_profile_name_valid(const char *name, size_t len);
/* Cuts name[size] to its longest valid UTF-8 prefix (at most size - 1
 * bytes) and NUL-pads the rest: names written by older firmware or carried
 * in a backup may end inside a character. */
extern void lf_profile_name_sanitize(char *name, size_t size);

/* Records a pending LF_OP_* for profile idx, applied by the next boot. */
extern int lf_profile_request(uint8_t op, uint8_t idx);
/* Records a new, empty profile in slot idx with these flags (0, or
 * LF_PROFILE_F_NO_EXPORT | LF_PROFILE_F_SECURE for a secure profile),
 * replacing what the slot holds: a pending LF_OP_WIPE whose boot keeps the
 * flags of a secure profile. */
extern int lf_profile_create(uint8_t idx, uint8_t flags);

/* Erases every profile, the staging area and the system area (and the
 * legacy store if asked). The device comes back empty after the reboot. */
extern int lf_factory_reset(bool legacy_too);

/* Reboots once the current response has been sent. */
extern void lf_reboot_later(uint32_t delay_ms);
/* A reboot was requested and has not happened yet. */
extern bool lf_reboot_scheduled(void);
/* Core 0 loop: performs a requested reboot when it is due. */
extern void lf_reboot_poll(void);

#endif
