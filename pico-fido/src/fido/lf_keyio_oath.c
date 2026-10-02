/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
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

/* Single-key transfer of OATH accounts (lf_keyio.h). The key ID is the
 * account name as stored. Accounts are added through the OATH applet (PUT,
 * with its own password), as on a YubiKey: there is no import hook.
 *
 * Record: {1: name (bytes), 2: type|algorithm byte (uint), 3: digits (uint),
 * 4: secret (bytes, as stored), 5: HOTP moving factor (uint, HOTP only),
 * 6: touch required (bool)}. */

#include <string.h>
#include "pico_keys.h"
#include "lf_keyio.h"
#include "lf_policy.h"
#include "mbedtls/platform_util.h"

/* oath.c */
extern bool oath_keyio_next(uint16_t *index, uint8_t *name, uint16_t name_cap, uint16_t *name_len,
                            uint8_t *type_alg, uint8_t *digits, bool *touch);
extern int oath_keyio_find(const uint8_t *name, uint16_t name_len, uint16_t *index);
extern int oath_keyio_read(uint16_t index, const uint8_t *name, uint16_t name_len, uint8_t *key, uint16_t key_cap,
                           uint16_t *key_len, uint64_t *imf, bool *touch);
extern bool oath_keyio_protected(void);

/* Longest key oath.c stores: type/algorithm, digits and a secret of at most
 * the HMAC block size of SHA-512. */
#define OATH_KEY_MAX        (2 + 128)
#define OATH_TYPE_MASK      0xf0
#define OATH_TYPE_HOTP      0x10

/* Largest list entry: map header, name (64 bytes, 2-byte header), two
 * one-byte uints (2 bytes each), a bool, four one-byte keys. */
#define OATH_ENTRY_MAX      (1 + 4 + (2 + LF_KEYIO_ID_MAX) + 2 + 2 + 1)

static uint16_t oath_keyio_list(uint32_t *cursor, bool pin_verified, CborEncoder *arr) {
    (void) pin_verified;        /* the FIDO PIN does not stand in for the OATH secrets */
    uint8_t name[LF_KEYIO_ID_MAX];
    uint16_t index = *cursor < UINT16_MAX ? (uint16_t) *cursor : UINT16_MAX, name_len = 0;
    uint8_t type_alg = 0, digits = 0;
    bool touch = false;
    uint32_t used = 0;
    CborError e = CborNoError;
    while (e == CborNoError && oath_keyio_next(&index, name, sizeof(name), &name_len, &type_alg, &digits, &touch)) {
        if (used + OATH_ENTRY_MAX > LF_KEYIO_PAGE_BUDGET) {
            *cursor = index;
            return 0x9000;
        }
        CborEncoder m;
        e |= cbor_encoder_create_map(arr, &m, 4);
        e |= cbor_encode_uint(&m, 1);
        e |= cbor_encode_byte_string(&m, name, name_len);
        e |= cbor_encode_uint(&m, 2);
        e |= cbor_encode_uint(&m, type_alg);
        e |= cbor_encode_uint(&m, 3);
        e |= cbor_encode_uint(&m, digits);
        e |= cbor_encode_uint(&m, 4);
        e |= cbor_encode_boolean(&m, touch);
        e |= cbor_encoder_close_container(arr, &m);
        used += OATH_ENTRY_MAX;
        index++;
    }
    if (e != CborNoError) {
        return 0x6400;
    }
    *cursor = LF_KEYIO_END;
    return 0x9000;
}

/* No application secret: the OATH password (and the OTP PIN of the
 * Nitrokey extension) guard the use of the applet by a host, as on a
 * YubiKey. An export is gated like a full backup, which carries these
 * accounts too: the export policy of the profile, the FIDO PIN and a
 * touch. */
static uint16_t oath_keyio_export(const uint8_t *id, size_t id_len, const uint8_t *secret, size_t secret_len,
                                  lf_keyio_confirm_t confirm, CborEncoder *enc) {
    (void) secret;
    (void) secret_len;
    if (id == NULL || id_len == 0 || id_len > LF_KEYIO_ID_MAX) {
        return 0x6A88;
    }
    /* The command data is not read again once the touch was waited for. */
    uint8_t name[LF_KEYIO_ID_MAX];
    uint16_t name_len = (uint16_t) id_len, index = 0;
    memcpy(name, id, name_len);
    int r = oath_keyio_find(name, name_len, &index);
    if (r == PICOKEY_ERR_FILE_NOT_FOUND) {
        return 0x6A88;
    }
    if (r != PICOKEY_OK) {
        return 0x6A81;
    }
    if (!confirm()) {
        return 0x6985;
    }
    uint8_t key[OATH_KEY_MAX];
    uint16_t key_len = 0;
    uint64_t imf = 0;
    bool touch = false;
    uint16_t sw = 0x9000;
    r = oath_keyio_read(index, name, name_len, key, sizeof(key), &key_len, &imf, &touch);
    if (r == PICOKEY_ERR_FILE_NOT_FOUND) {
        sw = 0x6A88;
    }
    else if (r != PICOKEY_OK) {
        sw = 0x6A81;
    }
    else {
        bool hotp = (key[0] & OATH_TYPE_MASK) == OATH_TYPE_HOTP;
        CborEncoder m;
        CborError e = CborNoError;
        e |= cbor_encoder_create_map(enc, &m, hotp ? 6 : 5);
        e |= cbor_encode_uint(&m, 1);
        e |= cbor_encode_byte_string(&m, name, name_len);
        e |= cbor_encode_uint(&m, 2);
        e |= cbor_encode_uint(&m, key[0]);
        e |= cbor_encode_uint(&m, 3);
        e |= cbor_encode_uint(&m, key[1]);
        e |= cbor_encode_uint(&m, 4);
        e |= cbor_encode_byte_string(&m, key + 2, key_len - 2);
        if (hotp) {
            e |= cbor_encode_uint(&m, 5);
            e |= cbor_encode_uint(&m, imf);
        }
        e |= cbor_encode_uint(&m, 6);
        e |= cbor_encode_boolean(&m, touch);
        e |= cbor_encoder_close_container(enc, &m);
        if (e != CborNoError) {
            sw = 0x6400;
        }
    }
    mbedtls_platform_zeroize(key, sizeof(key));
    return sw;
}

/* YKOATH LIST answers the account names only once the OATH password (and
 * the OTP PIN of the Nitrokey extension) was given in the session: while
 * either is set, the listing takes a touch. The FIDO PIN does not stand in
 * for them. */
static bool oath_keyio_list_protected(bool pin_verified) {
    (void) pin_verified;
    return oath_keyio_protected();
}

static const lf_keyio_ops_t oath_keyio_ops = {
    .list = oath_keyio_list,
    .export_key = oath_keyio_export,
    .import_key = NULL,
    .list_protected = oath_keyio_list_protected,
};

void lf_keyio_oath_register(void) {
    lf_keyio_register(LF_APP_OATH, &oath_keyio_ops);
}
