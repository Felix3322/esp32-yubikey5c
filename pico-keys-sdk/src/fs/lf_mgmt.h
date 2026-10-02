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
 * LibreFido management applet (CCID, AID F0 "LIBREFIDO"): device and storage
 * information, health, profiles, backup export / import / verification,
 * factory reset. Used by the librefido host tools (tools/librefido).
 *
 * Requests use CLA 0x80; structured data is CBOR (integer keys). Anything
 * that destroys, copies or installs keys, creates or switches a profile,
 * switches automatic presence on, installs firmware, burns eFuses, changes
 * the mounted profile's AAGUID or restarts the device needs a physical
 * touch of the button collected for that command (wait_button(), never
 * automatic presence); an export, a
 * firmware update or rollback, the ROM loader and an import into the active
 * slot also need the FIDO PIN of the mounted profile when one is set. Names,
 * colours, button slots, board settings and switching automatic presence off
 * need no touch for the first LF_FREE_SYS_CHANGES changes since the last
 * confirmed one (lf_profile.h), then one each. See docs/PROVISIONING.md.
 *
 * Protocol 3 (INFO key 2): every transfer belongs to the client and the USB
 * interface that started it. EXPORT_BEGIN, IMPORT_BEGIN and FW_BEGIN answer
 * a CBOR map with a session ID (EXPORT_BEGIN key 3, the others key 1) that
 * every following command of the transfer carries: EXPORT_READ, IMPORT_WRITE
 * and FW_WRITE after the 4-byte offset, IMPORT_END and FW_END as their data.
 * A wrong ID, or a command of the transfer from another interface, ends the
 * transfer (6982).
 *
 * Single-key transfer (firmware 2.1.0, INFO key 19: {1: export mask, 2:
 * import mask}, bit n for application n of lf_app_t that registered the
 * hook; see lf_keyio.h and docs/KEY_TRANSFER.md). Each is one command and
 * ends any transfer in progress. Their data is a CBOR map; an unknown key, a
 * repeated key, a value of the wrong type, trailing bytes or an application
 * number >= LF_APP_COUNT answer 6A80. The PINs and secrets of the request
 * are wiped once the command is done.
 *   KEY_LIST {1: app, 2: FIDO PIN (optional), 3: cursor (optional, 0), 4:
 *     list session ID (optional, only with a cursor > 0)}: storage ready,
 *     no reboot pending and the key store unlocked (6985), the application
 *     lists keys (6A81), the FIDO PIN as for an export. A listing the
 *     application itself only gives out with a secret (FIDO without a
 *     verified PIN, OATH with a password or OTP PIN set) needs a touch for
 *     its first page (6985 without). Answer {1: entries (indefinite-length
 *     array of maps, key 1 of each the key ID), 2: exportable (bool), 3:
 *     next cursor (absent once the list is complete), 4: list session ID
 *     (8 bytes, with key 3)}. The next pages carry that ID in key 4 and
 *     need neither the PIN nor a touch; the listing belongs to the
 *     interface, the application and the command stream (any other command
 *     ends it); a wrong ID, or none on a later page of a listing that
 *     needs a touch, answers 6982 and ends it. A listing that needs no
 *     touch may also be paged without the ID (each page then checked as a
 *     first one).
 *   KEY_EXPORT {1: app, 2: key ID, 3: FIDO PIN (optional), 4: application
 *     secret (optional)}: storage ready and no reboot pending (6985),
 *     exports allowed (6986, as EXPORT_BEGIN), the root key in use (6982),
 *     the key store unlocked (6985), the application exports keys (6A81),
 *     the FIDO PIN; then the application checks its own rules and asks for
 *     the touch. Answer {1: app, 2: record (map)}.
 *   KEY_IMPORT {1: app, 2: record (map), 3: FIDO PIN (optional), 4:
 *     application secret (optional), 5: replace (bool, optional), 6: target
 *     (optional)}: storage ready and writable, no reboot pending, the key
 *     store unlocked (6985), the root key in use (6982), the application
 *     imports here (6A81: OATH, OpenPGP and PIV keys go through their own
 *     applets), no FIDO import into a secure profile or in a HARDENED build
 *     (6986: their credentials are always born on the device), the FIDO
 *     PIN; then the application checks the record and asks for the touch.
 *     Answer {1: app, 2: key ID}.
 */

#ifndef _LF_MGMT_H_
#define _LF_MGMT_H_

#include <stdint.h>

/* Checks the FIDO PIN of the mounted profile (exports, firmware updates).
 * Returns an ISO 7816 status word: 9000 (correct), 6A88 (no PIN set), 63Cx
 * (wrong, x tries left), 6983 (blocked), 6985 (power cycle needed), 6982
 * (PIN required, no retry used: none or no plausible PIN was given, or a
 * PIN is set but cannot be checked now because the root key it was derived
 * with is not loaded). */
typedef uint16_t (*lf_mgmt_pin_cb_t)(const uint8_t *pin, uint16_t len);
extern void lf_mgmt_set_pin_verifier(lf_mgmt_pin_cb_t cb);

/* The AAGUID of the mounted profile: get_cb fills out[16] with the value in
 * force (the application's own default when the profile never set one) and
 * returns PICOKEY_OK; set_cb writes a new 16-byte value, or clears it back
 * to that default when aaguid_or_null is NULL. The application (pico-fido)
 * registers both, since the value lives in its own file, not the system
 * area: it is per profile, travels with a backup/clone like any other
 * profile file, and is unknown for a slot that is not mounted. */
typedef int (*lf_mgmt_aaguid_get_cb_t)(uint8_t out[16]);
typedef int (*lf_mgmt_aaguid_set_cb_t)(const uint8_t *aaguid_or_null);
extern void lf_mgmt_set_aaguid_hooks(lf_mgmt_aaguid_get_cb_t get_cb, lf_mgmt_aaguid_set_cb_t set_cb);

#define LF_MGMT_INS_INFO            0x01
#define LF_MGMT_INS_HEALTH          0x02
#define LF_MGMT_INS_PROFILE_SELECT  0x10
#define LF_MGMT_INS_PROFILE_SET     0x11
#define LF_MGMT_INS_PROFILE_WIPE    0x12
#define LF_MGMT_INS_PROFILE_DELETE  0x13
#define LF_MGMT_INS_BUTTON_SLOTS    0x14
#define LF_MGMT_INS_PROFILE_CREATE_SECURE 0x15
#define LF_MGMT_INS_BOARD_SET       0x16
#define LF_MGMT_INS_PROFILE_AAGUID_SET 0x17
#define LF_MGMT_INS_EXPORT_BEGIN    0x20
#define LF_MGMT_INS_EXPORT_READ     0x21
#define LF_MGMT_INS_EXPORT_END      0x22
#define LF_MGMT_INS_IMPORT_BEGIN    0x28
#define LF_MGMT_INS_IMPORT_WRITE    0x29
#define LF_MGMT_INS_IMPORT_END      0x2A
#define LF_MGMT_INS_FACTORY_RESET   0x30
#define LF_MGMT_INS_FW_BEGIN        0x40
#define LF_MGMT_INS_FW_WRITE        0x41
#define LF_MGMT_INS_FW_END          0x42
#define LF_MGMT_INS_FW_CONFIRM      0x43
#define LF_MGMT_INS_FW_ROLLBACK     0x44
#define LF_MGMT_INS_PROVISION_HMAC  0x50
#define LF_MGMT_INS_KEY_LIST        0x60
#define LF_MGMT_INS_KEY_EXPORT      0x61
#define LF_MGMT_INS_KEY_IMPORT      0x62
#define LF_MGMT_INS_REBOOT          0x3F

#endif
