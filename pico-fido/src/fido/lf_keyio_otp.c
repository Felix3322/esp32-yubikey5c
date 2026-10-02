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

/* Single-key transfer of OTP slots (lf_keyio.h): slots 1 and 2, the key ID
 * is the slot number (one byte).
 *
 * Record: {1: slot (uint, the source slot), 2: configuration (bytes 52: the
 * stored YubiKey slot configuration, access code included), 3: counter area
 * (bytes 8, as stored), 4: mode (text, informational)}. */

#include <string.h>
#include "pico_keys.h"
#include "lf_keyio.h"
#include "lf_policy.h"
#include "mbedtls/platform_util.h"

/* otp.c */
extern int otp_keyio_get(uint8_t n, uint8_t *cfg, uint8_t *ctr, bool *acc_set, const char **mode);
extern uint16_t otp_keyio_check(uint8_t n, const uint8_t *cfg, bool replace, const uint8_t *code, size_t code_len);
extern uint16_t otp_keyio_put(uint8_t n, const uint8_t *cfg, const uint8_t *ctr);

#define OTP_CFG_SIZE        52
#define OTP_CTR_SIZE        8
#define OTP_KEYIO_SLOTS     2

/* Largest list entry: map header, slot (1-byte bytes), the longest mode
 * name, a bool, three one-byte keys. */
#define OTP_ENTRY_MAX       (1 + 3 + 2 + (1 + 11) + 1)

/* Slot index (0, 1) of a key ID or import target: one byte, 1 or 2. */
static int otp_keyio_slot(const uint8_t *id, size_t id_len) {
    if (id == NULL || id_len != 1 || id[0] < 1 || id[0] > OTP_KEYIO_SLOTS) {
        return -1;
    }
    return id[0] - 1;
}

static uint16_t otp_keyio_list(uint32_t *cursor, bool pin_verified, CborEncoder *arr) {
    (void) pin_verified;        /* slot status: given to any host */
    uint32_t used = 0;
    CborError e = CborNoError;
    for (uint32_t n = *cursor; n < OTP_KEYIO_SLOTS && e == CborNoError; n++) {
        bool acc_set = false;
        const char *mode = NULL;
        /* Only slots whose record opens: the others cannot be exported. */
        if (otp_keyio_get((uint8_t) n, NULL, NULL, &acc_set, &mode) != PICOKEY_OK) {
            continue;
        }
        if (used + OTP_ENTRY_MAX > LF_KEYIO_PAGE_BUDGET) {
            *cursor = n;
            return 0x9000;
        }
        uint8_t slot = (uint8_t) (n + 1);
        CborEncoder m;
        e |= cbor_encoder_create_map(arr, &m, 3);
        e |= cbor_encode_uint(&m, 1);
        e |= cbor_encode_byte_string(&m, &slot, 1);
        e |= cbor_encode_uint(&m, 2);
        e |= cbor_encode_text_stringz(&m, mode);
        e |= cbor_encode_uint(&m, 3);
        e |= cbor_encode_boolean(&m, acc_set);
        e |= cbor_encoder_close_container(arr, &m);
        used += OTP_ENTRY_MAX;
    }
    if (e != CborNoError) {
        return 0x6400;
    }
    *cursor = LF_KEYIO_END;
    return 0x9000;
}

/* No application secret: the access code of a slot guards changes of its
 * configuration, not reading it (which a YubiKey does not offer at all). An
 * export is gated like a full backup, which carries the slots too: the
 * export policy of the profile, the FIDO PIN and a touch. */
static uint16_t otp_keyio_export(const uint8_t *id, size_t id_len, const uint8_t *secret, size_t secret_len,
                                 lf_keyio_confirm_t confirm, CborEncoder *enc) {
    (void) secret;
    (void) secret_len;
    int n = otp_keyio_slot(id, id_len);
    if (n < 0) {
        return 0x6A88;
    }
    bool acc_set = false;
    const char *mode = NULL;
    int r = otp_keyio_get((uint8_t) n, NULL, NULL, &acc_set, &mode);
    if (r == PICOKEY_ERR_FILE_NOT_FOUND) {
        return 0x6A88;
    }
    if (r != PICOKEY_OK) {
        return 0x6A81;
    }
    if (!confirm()) {
        return 0x6985;
    }
    uint8_t cfg[OTP_CFG_SIZE], ctr[OTP_CTR_SIZE];
    uint16_t sw = 0x9000;
    r = otp_keyio_get((uint8_t) n, cfg, ctr, &acc_set, &mode);
    if (r == PICOKEY_ERR_FILE_NOT_FOUND) {
        sw = 0x6A88;
    }
    else if (r != PICOKEY_OK) {
        sw = 0x6A81;
    }
    else {
        CborEncoder m;
        CborError e = CborNoError;
        e |= cbor_encoder_create_map(enc, &m, 4);
        e |= cbor_encode_uint(&m, 1);
        e |= cbor_encode_uint(&m, (uint64_t) n + 1);
        e |= cbor_encode_uint(&m, 2);
        e |= cbor_encode_byte_string(&m, cfg, sizeof(cfg));
        e |= cbor_encode_uint(&m, 3);
        e |= cbor_encode_byte_string(&m, ctr, sizeof(ctr));
        e |= cbor_encode_uint(&m, 4);
        e |= cbor_encode_text_stringz(&m, mode);
        e |= cbor_encoder_close_container(enc, &m);
        if (e != CborNoError) {
            sw = 0x6400;
        }
    }
    mbedtls_platform_zeroize(cfg, sizeof(cfg));
    mbedtls_platform_zeroize(ctr, sizeof(ctr));
    return sw;
}

/* A byte string of exactly len bytes into out. */
static bool otp_keyio_bytes(CborValue *it, uint8_t *out, size_t len) {
    size_t n = 0;
    if (!cbor_value_is_byte_string(it) || cbor_value_get_string_length(it, &n) != CborNoError || n != len) {
        return false;
    }
    n = len;
    return cbor_value_copy_byte_string(it, out, &n, it) == CborNoError && n == len;
}

/* The record, parsed into cfg and ctr (the command data is not read again
 * once the touch was waited for). Every key once; unknown keys are
 * skipped. The slot of the record (key 1) in *slot. */
static bool otp_keyio_parse(const CborValue *record, uint8_t cfg[OTP_CFG_SIZE], uint8_t ctr[OTP_CTR_SIZE],
                            int *slot) {
    CborValue it;
    bool have_slot = false, have_cfg = false, have_ctr = false, have_mode = false;
    if (record == NULL || !cbor_value_is_map(record) || cbor_value_enter_container(record, &it) != CborNoError) {
        return false;
    }
    while (!cbor_value_at_end(&it)) {
        uint64_t k = 0;
        if (!cbor_value_is_unsigned_integer(&it) || cbor_value_get_uint64(&it, &k) != CborNoError ||
            cbor_value_advance_fixed(&it) != CborNoError || cbor_value_at_end(&it)) {
            return false;
        }
        if (k == 1) {
            uint64_t v = 0;
            if (have_slot || !cbor_value_is_unsigned_integer(&it) || cbor_value_get_uint64(&it, &v) != CborNoError ||
                v < 1 || v > OTP_KEYIO_SLOTS || cbor_value_advance_fixed(&it) != CborNoError) {
                return false;
            }
            *slot = (int) v - 1;
            have_slot = true;
        }
        else if (k == 2) {
            if (have_cfg || !otp_keyio_bytes(&it, cfg, OTP_CFG_SIZE)) {
                return false;
            }
            have_cfg = true;
        }
        else if (k == 3) {
            if (have_ctr || !otp_keyio_bytes(&it, ctr, OTP_CTR_SIZE)) {
                return false;
            }
            have_ctr = true;
        }
        else if (k == 4) {
            /* Informational: the configuration tells the mode. */
            if (have_mode || !cbor_value_is_text_string(&it) || cbor_value_advance(&it) != CborNoError) {
                return false;
            }
            have_mode = true;
        }
        else if (cbor_value_is_tag(&it) || cbor_value_advance(&it) != CborNoError) {
            return false;                   /* never a tag, see lf_mgmt.c */
        }
    }
    return have_slot && have_cfg && have_ctr;
}

/* Allowed in every profile and build: a YubiKey takes programmed OTP
 * secrets too, and a slot write through the OTP applet stores the same. The
 * application secret is the access code of the configuration in the target
 * slot, when it has one. */
static uint16_t otp_keyio_import(const CborValue *record, const uint8_t *secret, size_t secret_len,
                                 const uint8_t *target, size_t target_len, bool replace,
                                 lf_keyio_confirm_t confirm, uint8_t id[LF_KEYIO_ID_MAX], size_t *id_len) {
    uint8_t cfg[OTP_CFG_SIZE], ctr[OTP_CTR_SIZE];
    int slot = -1, n = -1;
    uint16_t sw;
    if (!otp_keyio_parse(record, cfg, ctr, &slot)) {
        sw = 0x6A80;
    }
    else if (target != NULL && (n = otp_keyio_slot(target, target_len)) < 0) {
        sw = 0x6A80;
    }
    else {
        if (target == NULL) {
            n = slot;
        }
        sw = otp_keyio_check((uint8_t) n, cfg, replace, secret, secret_len);
        if (sw == 0x9000 && !confirm()) {
            sw = 0x6985;
        }
        if (sw == 0x9000) {
            sw = otp_keyio_put((uint8_t) n, cfg, ctr);
        }
        if (sw == 0x9000) {
            id[0] = (uint8_t) (n + 1);
            *id_len = 1;
        }
    }
    mbedtls_platform_zeroize(cfg, sizeof(cfg));
    mbedtls_platform_zeroize(ctr, sizeof(ctr));
    return sw;
}

/* No list_protected: which slots are programmed and in which mode, the
 * extended status (P1 14: ticket and configuration flags) answers any host;
 * whether an access code is set shows in the answer of a slot update. */
static const lf_keyio_ops_t otp_keyio_ops = {
    .list = otp_keyio_list,
    .export_key = otp_keyio_export,
    .import_key = otp_keyio_import,
};

void lf_keyio_otp_register(void) {
    lf_keyio_register(LF_APP_OTP, &otp_keyio_ops);
}
