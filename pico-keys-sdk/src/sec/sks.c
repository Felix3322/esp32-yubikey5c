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

#include <stdlib.h>
#include "pico_keys.h"
#include "sks.h"
#include "security.h"
#include "crypto_utils.h"
#include "random.h"
#include "otp.h"
#include "low_flash.h"
#include "lf_policy.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/platform_util.h"

#define SKS_EPOCH_LEN 16

extern file_t *ef_sks_epochs;

static void epoch_get(uint8_t ns, uint8_t epoch[SKS_EPOCH_LEN]) {
    memset(epoch, 0, SKS_EPOCH_LEN);
    if (file_has_data(ef_sks_epochs) && file_get_size(ef_sks_epochs) >= (uint16_t)(ns + 1) * SKS_EPOCH_LEN) {
        memcpy(epoch, file_get_data(ef_sks_epochs) + ns * SKS_EPOCH_LEN, SKS_EPOCH_LEN);
    }
}

/* Key material never leaves this function other than as the derived key. */
static int ns_key(uint8_t ns, uint8_t key[32]) {
    if (!security_keystore_unlocked()) {
        return PICOKEY_ERR_BLOCKED;
    }
    uint8_t ikm[32], info[16 + 1 + SKS_EPOCH_LEN];
    if (otp_key_1) {
        memcpy(ikm, otp_key_1, sizeof(ikm));
    }
    else {
        derive_kbase(ikm); /* legacy stores without a device root */
    }
    memcpy(info, "LibreFido/sks/v1", 16);
    info[16] = ns;
    epoch_get(ns, info + 17);
    int r = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), pico_serial_hash, sizeof(pico_serial_hash),
                         ikm, sizeof(ikm), info, sizeof(info), key, 32);
    mbedtls_platform_zeroize(ikm, sizeof(ikm));
    return r == 0 ? PICOKEY_OK : PICOKEY_EXEC_ERROR;
}

static void make_aad(uint8_t *aad, const uint8_t *hdr, uint16_t id) {
    memcpy(aad, hdr, SKS_HDR_LEN);
    put_uint16_t_be(id, aad + SKS_HDR_LEN);
}

int sks_seal(uint8_t ns, uint16_t id, const uint8_t *pt, size_t len, uint8_t *out) {
    if (ns == 0 || ns >= SKS_NS_MAX || (!pt && len)) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    uint8_t key[32], aad[SKS_HDR_LEN + 2];
    int r = ns_key(ns, key);
    if (r != PICOKEY_OK) {
        return r;
    }
    out[0] = 'L';
    out[1] = 'K';
    out[2] = SKS_VERSION;
    out[3] = ns;
    random_gen(NULL, out + SKS_HDR_LEN, SKS_NONCE_LEN);
    make_aad(aad, out, id);
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    r = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    mbedtls_platform_zeroize(key, sizeof(key));
    if (r == 0) {
        r = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len, out + SKS_HDR_LEN, SKS_NONCE_LEN, aad, sizeof(aad),
                                      pt, out + SKS_HDR_LEN + SKS_NONCE_LEN, SKS_TAG_LEN,
                                      out + SKS_HDR_LEN + SKS_NONCE_LEN + len);
    }
    mbedtls_gcm_free(&gcm);
    return r == 0 ? PICOKEY_OK : PICOKEY_EXEC_ERROR;
}

bool sks_is_sealed(uint8_t ns, const uint8_t *in, size_t in_len) {
    return in && in_len >= SKS_OVERHEAD && in[0] == 'L' && in[1] == 'K' && in[2] == SKS_VERSION && in[3] == ns;
}

int sks_open(uint8_t ns, uint16_t id, const uint8_t *in, size_t in_len, uint8_t *pt) {
    if (!sks_is_sealed(ns, in, in_len)) {
        return PICOKEY_WRONG_DATA;
    }
    uint8_t key[32], aad[SKS_HDR_LEN + 2];
    int r = ns_key(ns, key);
    if (r != PICOKEY_OK) {
        return r;
    }
    size_t len = in_len - SKS_OVERHEAD;
    make_aad(aad, in, id);
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    r = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    mbedtls_platform_zeroize(key, sizeof(key));
    if (r == 0) {
        r = mbedtls_gcm_auth_decrypt(&gcm, len, in + SKS_HDR_LEN, SKS_NONCE_LEN, aad, sizeof(aad),
                                     in + SKS_HDR_LEN + SKS_NONCE_LEN + len, SKS_TAG_LEN,
                                     in + SKS_HDR_LEN + SKS_NONCE_LEN, pt);
    }
    mbedtls_gcm_free(&gcm);
    if (r != 0) {
        mbedtls_platform_zeroize(pt, len);
        return PICOKEY_WRONG_DATA;
    }
    return PICOKEY_OK;
}

int sks_file_put(uint8_t ns, file_t *ef, const uint8_t *pt, size_t len) {
    if (!ef || len + SKS_OVERHEAD > 0xFFFF) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    uint8_t *rec = (uint8_t *) calloc(1, len + SKS_OVERHEAD);
    if (!rec) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    int r = sks_seal(ns, ef->fid, pt, len, rec);
    if (r == PICOKEY_OK) {
        r = file_put_data(ef, rec, (uint16_t) (len + SKS_OVERHEAD));
    }
    mbedtls_platform_zeroize(rec, len + SKS_OVERHEAD);
    free(rec);
    return r;
}

int sks_file_get(uint8_t ns, const file_t *ef, uint8_t *pt, size_t cap, size_t *len, bool *legacy) {
    *len = 0;
    *legacy = false;
    if (!file_has_data(ef)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    const uint8_t *in = file_get_data(ef);
    size_t n = file_get_size(ef);
    if (!sks_is_sealed(ns, in, n)) {
        /* Written before sealing existed (also in HARDENED builds updated
         * from earlier firmware). A profile created secure was sealed from
         * the start, so plaintext there can only be an injected record. */
        if (lf_profile_sealed_only() || n > cap) {
            return PICOKEY_WRONG_DATA;
        }
        memcpy(pt, in, n);
        *len = n;
        *legacy = true;
        return PICOKEY_OK;
    }
    if (n - SKS_OVERHEAD > cap) {
        return PICOKEY_WRONG_LENGTH;
    }
    int r = sks_open(ns, ef->fid, in, n, pt);
    if (r == PICOKEY_OK) {
        *len = n - SKS_OVERHEAD;
    }
    return r;
}

int sks_rotate(uint8_t ns) {
    if (ns == 0 || ns >= SKS_NS_MAX) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    uint8_t epochs[SKS_NS_MAX * SKS_EPOCH_LEN];
    memset(epochs, 0, sizeof(epochs));
    if (file_has_data(ef_sks_epochs)) {
        memcpy(epochs, file_get_data(ef_sks_epochs), MIN(sizeof(epochs), (size_t) file_get_size(ef_sks_epochs)));
    }
    random_gen(NULL, epochs + ns * SKS_EPOCH_LEN, SKS_EPOCH_LEN);
    int r = file_put_data(ef_sks_epochs, epochs, sizeof(epochs));
    if (r != PICOKEY_OK) {
        return r;
    }
    low_flash_available();
    return PICOKEY_OK;
}
