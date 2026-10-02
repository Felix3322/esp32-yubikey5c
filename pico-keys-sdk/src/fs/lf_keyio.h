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
 * Single-key transfer: the management applet (lf_mgmt.c, KEY_LIST,
 * KEY_EXPORT, KEY_IMPORT) lists, exports and imports one key of one
 * application at a time. The applications own their formats: each
 * registers the hooks below for its application number (lf_app_t,
 * lf_policy.h) and encodes / decodes the records documented in
 * docs/KEY_TRANSFER.md. The management applet applies the device policies
 * (storage state, export policy of the profile, FIDO PIN) before a hook is
 * called; a hook applies the rules of its application (its own secrets,
 * key checks) and asks for the touch.
 *
 * Every hook answers an ISO 7816 status word (0x9000 on success). A hook
 * never leaves key material behind: every buffer that held a key is wiped
 * before it returns, on every path.
 */

#ifndef _LF_KEYIO_H_
#define _LF_KEYIO_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "cbor.h"

/* List cursor: nothing more to list. */
#define LF_KEYIO_END            0xFFFFFFFFu
/* Most bytes one list page may add to the answer: a hook stops before the
 * worst case of its next entry would exceed it. */
#define LF_KEYIO_PAGE_BUDGET    3072
/* Longest key ID (the value of entry key 1, KEY_EXPORT key 2). */
#define LF_KEYIO_ID_MAX         64

/* The physical touch of this command (never automatic presence). A hook
 * calls it exactly once, after every check that can fail without a touch
 * (unknown key, wrong or missing application secret, invalid record, no
 * space) and before any key material is decrypted or anything is written.
 * false: no touch in time; the hook then answers 6985 and changes nothing. */
typedef bool (*lf_keyio_confirm_t)(void);

typedef struct {
    /* Appends the descriptors (CBOR maps, no secrets) of the keys at and
     * after *cursor (0: the first) to arr, an array being built, at most
     * LF_KEYIO_PAGE_BUDGET bytes of them. Sets *cursor to where the next
     * page starts, or LF_KEYIO_END. pin_verified: as for list_protected(),
     * for the first page of the listing (the pages after it keep it); a
     * hook leaves out what its application only shows after user
     * verification. NULL: the application has nothing to list. */
    uint16_t (*list)(uint32_t *cursor, bool pin_verified, CborEncoder *arr);

    /* Encodes the record (one CBOR map) of the key id into enc. secret: the
     * application secret the request carried (KEY_EXPORT key 4), or NULL.
     * Answers 6A88 (no such key), 6982 (secret required), 63Cx / 6983
     * (wrong secret, x tries left / blocked), 6985 (no touch), 6A81
     * (the key cannot be exported, e.g. a format this hook cannot read). */
    uint16_t (*export_key)(const uint8_t *id, size_t id_len, const uint8_t *secret, size_t secret_len,
                           lf_keyio_confirm_t confirm, CborEncoder *enc);

    /* Imports the record (a CBOR map, as export_key encodes it). target:
     * where to put it (KEY_IMPORT key 6), NULL for the default. replace:
     * a key already there may be replaced. Answers 6A80 (invalid record),
     * 6A89 (a key is there and replace is false), 6A84 (no space), 6982 /
     * 63Cx / 6983 (secret), 6985 (no touch), 6A81 (unsupported algorithm);
     * on success the ID of the imported key in id (at most
     * LF_KEYIO_ID_MAX bytes) and *id_len. NULL: imports of this
     * application go through its own applet (docs/KEY_TRANSFER.md). */
    uint16_t (*import_key)(const CborValue *record, const uint8_t *secret, size_t secret_len,
                           const uint8_t *target, size_t target_len, bool replace,
                           lf_keyio_confirm_t confirm, uint8_t id[LF_KEYIO_ID_MAX], size_t *id_len);

    /* Whether the listing is something the application itself only gives
     * out to a user who proved presence or a secret, now. pin_verified: the
     * request carried the FIDO PIN of the mounted profile and it was
     * verified (not merely "no PIN set"). true: KEY_LIST asks for a touch
     * before its first page (the pages after it follow with the list
     * session ID that page answered, no touch again). NULL, or false: the
     * listing is metadata the application answers any host (as a FIDO
     * credential management with a verified PIN does); no touch. Together
     * with list(): KEY_LIST never reveals more than the application does
     * with the same credentials, apart from naming the keys (FIDO: the RP
     * IDs a getAssertion needs the caller to know). */
    bool (*list_protected)(bool pin_verified);
} lf_keyio_ops_t;

/* Called once at boot by the applications (picokey_init()); ops must stay
 * valid (a static const table). */
extern void lf_keyio_register(uint8_t app, const lf_keyio_ops_t *ops);
/* The hooks of an application, NULL when none are registered. */
extern const lf_keyio_ops_t *lf_keyio_ops(uint8_t app);

/* Registration functions of the applications. */
extern void lf_keyio_fido_register(void);           /* pico-fido lf_keyio_fido.c */
extern void lf_keyio_oath_register(void);           /* pico-fido lf_keyio_oath.c */
extern void lf_keyio_otp_register(void);            /* pico-fido lf_keyio_otp.c */
extern void lf_keyio_openpgp_piv_register(void);    /* pico-openpgp lf_keyio_pgp.c */

#endif
