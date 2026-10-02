/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
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

#include "pico_keys.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/sha256.h"
#include "credential.h"
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#endif
#include "hid/ctap_hid.h"
#include "fido.h"
#include "ctap.h"
#include "random.h"
#include "files.h"
#include "otp.h"
#include "crypto_utils.h"

extern bool has_set_rtc();
int credential_derive_chacha_key(uint8_t *outk, const uint8_t *);
static int credential_explicit_open(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash, uint8_t *out);

/* Tag checked by a silent probe (up=false, uv=false) when the credential
 * does not decrypt. It is keyed with the device key as well: keyed on the
 * chip alone it outlived authenticatorReset, and a probe with a credential
 * ID from before the reset still reported the credential as present. */
static int credential_silent_tag(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash, uint8_t *outk) {
    uint8_t keydev[32];
    if (load_keydev(keydev) != PICOKEY_OK) {
        mbedtls_platform_zeroize(keydev, sizeof(keydev));
        return -1;
    }
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    if (otp_key_1) {
        mbedtls_sha256_update(&ctx, otp_key_1, 32);
    }
    else {
        mbedtls_sha256_update(&ctx, pico_serial.id, sizeof(pico_serial.id));
    }
    mbedtls_sha256_update(&ctx, keydev, sizeof(keydev));
    mbedtls_sha256_update(&ctx, rp_id_hash, 32);
    mbedtls_sha256_finish(&ctx, outk);
    mbedtls_sha256_free(&ctx);
    mbedtls_platform_zeroize(keydev, sizeof(keydev));

    return mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), outk, 32, cred_id, cred_id_len - CRED_SILENT_TAG_LEN, outk);
}

int credential_verify(uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash, bool silent) {
    if (cred_id_len < 4 + 12 + 16) {
        return -1;
    }
    /* An explicit-key credential is only valid in its record (it has no
     * silent tag, and its key is not the one derived from this ID). */
    if (credential_is_explicit(cred_id, cred_id_len)) {
        return -1;
    }
    uint8_t key[32] = {0}, *iv = cred_id + CRED_PROTO_LEN, *cipher = cred_id + CRED_PROTO_LEN + CRED_IV_LEN,
            *tag = cred_id + cred_id_len - CRED_TAG_LEN;
    cred_proto_t proto = CRED_PROTO_21;
    if (memcmp(cred_id, CRED_PROTO_22_S, CRED_PROTO_LEN) == 0) { // New format
        /* Too short to hold both tags: reject before the length arithmetic
         * below can wrap. */
        if (cred_id_len < CRED_PROTO_LEN + CRED_IV_LEN + CRED_TAG_LEN + CRED_SILENT_TAG_LEN) {
            return -1;
        }
        tag = cred_id + cred_id_len - CRED_SILENT_TAG_LEN - CRED_TAG_LEN;
        proto = CRED_PROTO_22;
    }
    int ret = 0;
    if (!silent) {
        int hdr_len = CRED_PROTO_LEN + CRED_IV_LEN + CRED_TAG_LEN;
        if (proto == CRED_PROTO_22) {
            hdr_len += CRED_SILENT_TAG_LEN;
        }
        if (credential_derive_chacha_key(key, cred_id) != 0) {
            return -1;
        }
        mbedtls_chachapoly_context chatx;
        mbedtls_chachapoly_init(&chatx);
        mbedtls_chachapoly_setkey(&chatx, key);
        ret = mbedtls_chachapoly_auth_decrypt(&chatx, cred_id_len - hdr_len, iv, rp_id_hash, 32, tag, cipher, cipher);
        mbedtls_chachapoly_free(&chatx);
    }
    else {
        if (proto <= CRED_PROTO_21) {
            return -1;
        }
        uint8_t outk[32];
        if (credential_silent_tag(cred_id, cred_id_len, rp_id_hash, outk) != 0) {
            return -1;
        }
        ret = ct_memcmp(outk, cred_id + cred_id_len - CRED_SILENT_TAG_LEN, CRED_SILENT_TAG_LEN);
    }
    mbedtls_platform_zeroize(key, sizeof(key));
    return ret;
}

int credential_create(CborCharString *rpId,
                      CborByteString *userId,
                      CborCharString *userName,
                      CborCharString *userDisplayName,
                      CredOptions *opts,
                      CredExtensions *extensions,
                      bool use_sign_count,
                      int alg,
                      int curve,
                      uint8_t *cred_id,
                      uint16_t *cred_id_len) {
    CborEncoder encoder, mapEncoder, mapEncoder2;
    CborError error = CborNoError;
    uint8_t rp_id_hash[32];
    mbedtls_sha256((uint8_t *) rpId->data, rpId->len, rp_id_hash, 0);
    cbor_encoder_init(&encoder, cred_id + CRED_PROTO_LEN + CRED_IV_LEN,
                      MAX_CRED_ID_LENGTH - (CRED_PROTO_LEN + CRED_IV_LEN + CRED_TAG_LEN + CRED_SILENT_TAG_LEN), 0);
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder,  CborIndefiniteLength));
    CBOR_APPEND_KEY_UINT_VAL_STRING(mapEncoder, 0x01, *rpId);
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, rp_id_hash, 32));
    CBOR_APPEND_KEY_UINT_VAL_BYTES(mapEncoder, 0x03, *userId);
    CBOR_APPEND_KEY_UINT_VAL_STRING(mapEncoder, 0x04, *userName);
    CBOR_APPEND_KEY_UINT_VAL_STRING(mapEncoder, 0x05, *userDisplayName);
    CBOR_APPEND_KEY_UINT_VAL_UINT(mapEncoder, 0x06, board_millis());
    if (extensions->present == true) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x07));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2,  CborIndefiniteLength));
        if (extensions->credBlob.present == true &&
            extensions->credBlob.len <= MAX_CREDBLOB_LENGTH) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "credBlob"));
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, extensions->credBlob.data, extensions->credBlob.len));
        }
        if (extensions->credProtect != 0) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "credProtect"));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder2, extensions->credProtect));
        }
        if (extensions->hmac_secret != NULL) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "hmac-secret"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, *extensions->hmac_secret));
        }
        if (extensions->largeBlobKey == ptrue) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "largeBlobKey"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, true));
        }
        if (extensions->thirdPartyPayment == ptrue) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "thirdPartyPayment"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, true));
        }
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));
    }
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x08));
    CBOR_CHECK(cbor_encode_boolean(&mapEncoder, use_sign_count));
    if (alg != FIDO2_ALG_ES256 || curve != FIDO2_CURVE_P256) {
        CBOR_APPEND_KEY_UINT_VAL_INT(mapEncoder, 0x09, alg);
        CBOR_APPEND_KEY_UINT_VAL_INT(mapEncoder, 0x0A, curve);
    }
    if (opts->present == true) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0B));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2,  CborIndefiniteLength));
        if (opts->rk != NULL) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "rk"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, opts->rk == ptrue));
        }
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));
    }
    if (has_set_rtc()) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0C));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, (uint64_t) get_rtc_time()));
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    size_t rs = cbor_encoder_get_buffer_size(&encoder, cred_id);
    *cred_id_len = CRED_PROTO_LEN + CRED_IV_LEN + (uint16_t)rs + CRED_TAG_LEN + CRED_SILENT_TAG_LEN;
    uint8_t key[32] = {0};
    if (credential_derive_chacha_key(key, (const uint8_t *)CRED_PROTO) != 0) {
        CBOR_ERROR(CTAP1_ERR_OTHER);    /* device key locked */
    }
    uint8_t iv[CRED_IV_LEN] = {0};
    random_gen(NULL, iv, sizeof(iv));
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, key);
    int ret = mbedtls_chachapoly_encrypt_and_tag(&chatx, rs, iv, rp_id_hash, 32,
                                                 cred_id + CRED_PROTO_LEN + CRED_IV_LEN,
                                                 cred_id + CRED_PROTO_LEN + CRED_IV_LEN,
                                                 cred_id + CRED_PROTO_LEN + CRED_IV_LEN + rs);
    mbedtls_chachapoly_free(&chatx);
    mbedtls_platform_zeroize(key, sizeof(key));
    if (ret != 0) {
        CBOR_ERROR(CTAP1_ERR_OTHER);
    }
    memcpy(cred_id, CRED_PROTO, CRED_PROTO_LEN);
    memcpy(cred_id + CRED_PROTO_LEN, iv, CRED_IV_LEN);
    /* The HMAC output is 32 bytes, the tag slot 16: through a temporary,
     * so a maximum-size ID is never written past its buffer. */
    uint8_t tag[32];
    if (credential_silent_tag(cred_id, *cred_id_len, rp_id_hash, tag) != 0) {
        CBOR_ERROR(CTAP1_ERR_OTHER);
    }
    memcpy(cred_id + CRED_PROTO_LEN + CRED_IV_LEN + rs + CRED_TAG_LEN, tag, CRED_SILENT_TAG_LEN);

err:
    if (error != CborNoError) {
        if (error == CborErrorImproperValue) {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        if (error == CborErrorOutOfMemory) {
            return CTAP2_ERR_REQUEST_TOO_LARGE;  /* rp/user fields too long */
        }
        return error;
    }
    return 0;
}

/* cred_idr: the resident ID stored with cred_id, NULL for a bare ID (which
 * is never an explicit-key credential). */
static int credential_load_ex(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash,
                              const uint8_t *cred_idr, Credential *cred) {
    int ret = 0;
    CborError error = CborNoError;
    bool explicit_key = credential_is_explicit(cred_id, cred_id_len), idr_ok = false;
    uint8_t *copy_cred_id = (uint8_t *) calloc(1, cred_id_len);
    if (!cred || !copy_cred_id) {
        CBOR_ERROR(CTAP2_ERR_INVALID_CREDENTIAL);
    }
    memset(cred, 0, sizeof(Credential));
    memcpy(copy_cred_id, cred_id, cred_id_len);
    if (explicit_key) {
        ret = cred_idr ? credential_explicit_open(copy_cred_id, cred_id_len, rp_id_hash, copy_cred_id + CRED_PROTO_LEN + CRED_IV_LEN) : -1;
    }
    else {
        ret = credential_verify(copy_cred_id, cred_id_len, rp_id_hash, false);
    }
    if (ret != 0) { // U2F?
        if (cred_id_len != KEY_HANDLE_LEN || verify_key(rp_id_hash, cred_id, NULL) != 0) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CREDENTIAL);
        }
    }
    else {
        CborParser parser;
        CborValue map;
        memset(cred, 0, sizeof(Credential));
        cred->curve = FIDO2_CURVE_P256;
        cred->alg = FIDO2_ALG_ES256;
        CBOR_CHECK(cbor_parser_init(copy_cred_id + 4 + 12, cred_id_len - (4 + 12 + 16), 0, &parser,
                                    &map));
        CBOR_PARSE_MAP_START(map, 1)
        {
            uint64_t val_u = 0;
            CBOR_FIELD_GET_UINT(val_u, 1);
            if (val_u == 0x01) {
                CBOR_FIELD_GET_TEXT(cred->rpId, 1);
            }
            else if (val_u == 0x03) {
                CBOR_FIELD_GET_BYTES(cred->userId, 1);
            }
            else if (val_u == 0x04) {
                CBOR_FIELD_GET_TEXT(cred->userName, 1);
            }
            else if (val_u == 0x05) {
                CBOR_FIELD_GET_TEXT(cred->userDisplayName, 1);
            }
            else if (val_u == 0x06) {
                CBOR_FIELD_GET_UINT(cred->board_creation, 1);
            }
            else if (val_u == 0x07) {
                cred->extensions.present = true;
                CBOR_PARSE_MAP_START(_f1, 2)
                {
                    CBOR_FIELD_GET_KEY_TEXT(2);
                    CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "hmac-secret", cred->extensions.hmac_secret);
                    CBOR_FIELD_KEY_TEXT_VAL_UINT(2, "credProtect", cred->extensions.credProtect);
                    CBOR_FIELD_KEY_TEXT_VAL_BYTES(2, "credBlob", cred->extensions.credBlob);
                    CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "largeBlobKey", cred->extensions.largeBlobKey);
                    CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "thirdPartyPayment", cred->extensions.thirdPartyPayment);
                    CBOR_ADVANCE(2);
                }
                CBOR_PARSE_MAP_END(_f1, 2);
            }
            else if (val_u == 0x08) {
                CBOR_FIELD_GET_BOOL(cred->use_sign_count, 1);
            }
            else if (val_u == 0x09) {
                CBOR_FIELD_GET_INT(cred->alg, 1);
            }
            else if (val_u == 0x0A) {
                CBOR_FIELD_GET_INT(cred->curve, 1);
            }
            else if (val_u == 0x0B) {
                cred->opts.present = true;
                CBOR_PARSE_MAP_START(_f1, 2)
                {
                    CBOR_FIELD_GET_KEY_TEXT(2);
                    CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "rk", cred->opts.rk);
                    CBOR_ADVANCE(2);
                }
                CBOR_PARSE_MAP_END(_f1, 2);
            }
            else if (val_u == 0x0C) {
                CBOR_FIELD_GET_UINT(cred->rtc_creation, 1);
            }
            else if (val_u == 0x20 && explicit_key) {
                /* the stored resident ID is the one sealed with the key */
                uint8_t idr[CRED_RESIDENT_LEN];
                size_t idr_len = sizeof(idr);
                CBOR_ASSERT(cbor_value_is_byte_string(&_f1) == true);
                if (cbor_value_copy_byte_string(&_f1, idr, &idr_len, &_f1) != CborNoError ||
                    idr_len != sizeof(idr) || memcmp(idr, cred_idr, sizeof(idr)) != 0) {
                    CBOR_ERROR(CTAP2_ERR_INVALID_CREDENTIAL);
                }
                idr_ok = true;
            }
            else {
                CBOR_ADVANCE(1);
            }
        }
        if (explicit_key && !idr_ok) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CREDENTIAL);
        }
    }
    cred->id.present = true;
    cred->id.data = (uint8_t *) calloc(1, cred_id_len);
    memcpy(cred->id.data, cred_id, cred_id_len);
    cred->id.len = cred_id_len;
    cred->present = true;
err:
    if (copy_cred_id) {
        /* the decrypted credential: the user entity, credBlob, and for an
         * explicit-key credential its keys */
        mbedtls_platform_zeroize(copy_cred_id, cred_id_len);
        free(copy_cred_id);
    }
    if (error != CborNoError) {
        if (error == CborErrorImproperValue) {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        return error;
    }
    return 0;
}

int credential_load(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash, Credential *cred) {
    return credential_load_ex(cred_id, cred_id_len, rp_id_hash, NULL, cred);
}

void credential_free(Credential *cred) {
    if (cred) {
        CBOR_FREE_BYTE_STRING(cred->rpId);
        CBOR_FREE_BYTE_STRING(cred->userId);
        CBOR_FREE_BYTE_STRING(cred->userName);
        CBOR_FREE_BYTE_STRING(cred->userDisplayName);
        CBOR_FREE_BYTE_STRING(cred->id);
        if (cred->extensions.present) {
            CBOR_FREE_BYTE_STRING(cred->extensions.credBlob);
        }
        cred->present = false;
        cred->extensions.present = false;
        cred->opts.present = false;
    }
}

int credential_store(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash) {
    int sloti = -1, rp_sloti = -1;
    Credential cred = { 0 };
    int ret = 0;
    bool new_record = true;
    uint8_t *data = NULL;
    ret = credential_load(cred_id, cred_id_len, rp_id_hash, &cred);
    if (ret != 0) {
        credential_free(&cred);
        return ret;
    }
    for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
        file_t *ef = search_dynamic_file(EF_CRED + i);
        Credential rcred = { 0 };
        if (!file_has_data(ef)) {
            if (sloti == -1) {
                sloti = i;
            }
            continue;
        }
        resident_record_t rec;
        if (credential_resident_parse(ef, &rec) != 0 || memcmp(rec.rp_id_hash, rp_id_hash, 32) != 0) {
            continue;
        }
        /* through the record: an imported credential of this user is
         * replaced like any other */
        ret = credential_load_ex(rec.cred_id, rec.cred_id_len, rp_id_hash, rec.cred_idr, &rcred);
        if (ret != 0) {
            credential_free(&rcred);
            continue;
        }
        if (rcred.userId.len == cred.userId.len && memcmp(rcred.userId.data, cred.userId.data, rcred.userId.len) == 0) {
            sloti = i;
            credential_free(&rcred);
            new_record = false;
            break;
        }
        credential_free(&rcred);
    }
    if (sloti == -1) {
        ret = CTAP2_ERR_KEY_STORE_FULL;
        goto out;
    }
    uint16_t files_needed = search_dynamic_file((uint16_t)(EF_CRED + sloti)) ? 0 : 1;
    if (new_record == true) {
        for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
            file_t *ef = search_dynamic_file(EF_RP + i);
            if (!file_has_data(ef)) {
                if (rp_sloti == -1) {
                    rp_sloti = i;
                }
                continue;
            }
            if (file_get_size(ef) >= 1 + 32 && memcmp(file_get_data(ef) + 1, rp_id_hash, 32) == 0) {
                /* The per-RP count is one byte. */
                if (*file_get_data(ef) == UINT8_MAX) {
                    ret = CTAP2_ERR_KEY_STORE_FULL;
                    goto out;
                }
                rp_sloti = i;
                break;
            }
        }
        if (rp_sloti == -1) {
            ret = CTAP2_ERR_KEY_STORE_FULL;
            goto out;
        }
        if (!search_dynamic_file((uint16_t)(EF_RP + rp_sloti))) {
            files_needed++;
        }
    }
    /* Room for both files is checked before anything is written, so a full
     * table can never leave a credential without its RP entry. */
    if (dynamic_files + files_needed > MAX_DYNAMIC_FILES) {
        ret = CTAP2_ERR_KEY_STORE_FULL;
        goto out;
    }
    uint8_t cred_idr[CRED_RESIDENT_LEN] = {0};
    credential_new_resident_id(cred_id, cred_id_len, cred_idr);
    data = (uint8_t *) calloc(1, cred_id_len + 32 + CRED_RESIDENT_LEN);
    if (data == NULL) {
        ret = CTAP2_ERR_KEY_STORE_FULL;
        goto out;
    }
    memcpy(data, rp_id_hash, 32);
    memcpy(data + 32, cred_idr, CRED_RESIDENT_LEN);
    memcpy(data + 32 + CRED_RESIDENT_LEN, cred_id, cred_id_len);
    file_t *ef = file_new((uint16_t)(EF_CRED + sloti));
    if (file_put_data(ef, data, (uint16_t)cred_id_len + 32 + CRED_RESIDENT_LEN) != PICOKEY_OK) {
        ret = CTAP2_ERR_KEY_STORE_FULL;
        goto out;
    }
    free(data);
    data = NULL;

    if (new_record == true) { //increase rps
        ef = search_dynamic_file((uint16_t)(EF_RP + rp_sloti));
        if (file_has_data(ef)) {
            uint16_t rp_size = file_get_size(ef);
            data = (uint8_t *) calloc(1, rp_size);
            if (data == NULL) {
                ret = CTAP2_ERR_KEY_STORE_FULL;
                goto out;
            }
            memcpy(data, file_get_data(ef), rp_size);
            data[0] += 1;
            ret = file_put_data(ef, data, rp_size);
        }
        else {
            ef = file_new((uint16_t)(EF_RP + rp_sloti));
            data = (uint8_t *) calloc(1, 1 + 32 + cred.rpId.len);
            if (data == NULL) {
                ret = CTAP2_ERR_KEY_STORE_FULL;
                goto out;
            }
            data[0] = 1;
            memcpy(data + 1, rp_id_hash, 32);
            memcpy(data + 1 + 32, cred.rpId.data, cred.rpId.len);
            ret = file_put_data(ef, data, (uint16_t)(1 + 32 + cred.rpId.len));
        }
        if (ret != PICOKEY_OK) {
            ret = CTAP2_ERR_KEY_STORE_FULL;
            goto out;
        }
    }
    ret = 0;
    low_flash_available();
out:
    free(data);
    credential_free(&cred);
    return ret;
}

int credential_derive_hmac_key(const uint8_t *cred_id, size_t cred_id_len, uint8_t *outk) {
    memset(outk, 0, 64);
    int r = 0;
    if ((r = load_keydev(outk)) != 0) {
        return r;
    }
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);

    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "SLIP-0022", 9, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) cred_id, CRED_PROTO_LEN, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "hmac-secret", 11, outk);
    mbedtls_md_hmac(md_info, outk, 32, cred_id, cred_id_len, outk);
    return 0;
}

int credential_derive_chacha_key(uint8_t *outk, const uint8_t *proto) {
    memset(outk, 0, 32);
    int r = 0;
    if ((r = load_keydev(outk)) != 0) {
        return r;
    }
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "SLIP-0022", 9, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) (proto ? proto : (const uint8_t *)CRED_PROTO), CRED_PROTO_LEN, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "Encryption key", 14, outk);
    return 0;
}

int credential_derive_large_blob_key(const uint8_t *cred_id, size_t cred_id_len, uint8_t *outk) {
    memset(outk, 0, 32);
    int r = 0;
    if ((r = load_keydev(outk)) != 0) {
        return r;
    }
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "SLIP-0022", 9, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) cred_id, CRED_PROTO_LEN, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "largeBlobKey", 12, outk);
    mbedtls_md_hmac(md_info, outk, 32, cred_id, cred_id_len, outk);
    return 0;
}

int credential_derive_resident(const uint8_t *cred_id, size_t cred_id_len, uint8_t *outk) {
    memset(outk, 0, CRED_RESIDENT_LEN);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t *cred_idr = outk + CRED_RESIDENT_HEADER_LEN;
    mbedtls_md_hmac(md_info, cred_idr, 32, pico_serial.id, sizeof(pico_serial.id), outk);
    memcpy(outk + 4, CRED_PROTO_RESIDENT, CRED_PROTO_RESIDENT_LEN);
    outk[4 + CRED_PROTO_RESIDENT_LEN] = 0x00;
    outk[4 + CRED_PROTO_RESIDENT_LEN + 1] = 0x00;

    mbedtls_md_hmac(md_info, cred_idr, 32, (uint8_t *) "SLIP-0022", 9, cred_idr);
    mbedtls_md_hmac(md_info, cred_idr, 32, (uint8_t *) cred_id, CRED_PROTO_LEN, cred_idr);
    mbedtls_md_hmac(md_info, cred_idr, 32, (uint8_t *) "resident", 8, cred_idr);
    mbedtls_md_hmac(md_info, cred_idr, 32, cred_id, cred_id_len, cred_idr);
    return 0;
}

/* Resident ID of a NEW credential. credential_derive_resident() leaves the
 * first 4 bytes at HMAC(0^32, serial)[0..3]: the same in every resident ID
 * of the device, for every RP and across resets, so RPs could link them.
 * New IDs take those bytes from the per-credential part. Stored records keep
 * the ID they were created with (credential_resident_id()). */
void credential_new_resident_id(const uint8_t *cred_id, size_t cred_id_len, uint8_t *outk) {
    uint8_t tmp[32];
    credential_derive_resident(cred_id, cred_id_len, outk);
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), outk + CRED_RESIDENT_HEADER_LEN, 32,
                    (const uint8_t *) "LibreFido resident ID", 21, tmp);
    memcpy(outk, tmp, 4);
    mbedtls_platform_zeroize(tmp, sizeof(tmp));
}

static bool credential_explicit_authentic(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash);

/* idr is the resident ID of cred_id, in either derivation. An imported ID
 * cannot re-derive: there the sealed credential must authenticate at exactly
 * this length (credential_load_record() then checks the ID it seals). */
static bool credential_resident_id_valid(const uint8_t *rp_id_hash, const uint8_t *cred_id, size_t cred_id_len, const uint8_t *idr) {
    if (credential_is_explicit(cred_id, cred_id_len)) {
        return credential_explicit_authentic(cred_id, cred_id_len, rp_id_hash);
    }
    uint8_t d[CRED_RESIDENT_LEN];
    credential_new_resident_id(cred_id, cred_id_len, d);
    if (memcmp(d, idr, CRED_RESIDENT_LEN) == 0) {
        return true;
    }
    credential_derive_resident(cred_id, cred_id_len, d);
    return memcmp(d, idr, CRED_RESIDENT_LEN) == 0;
}

void credential_resident_id(const resident_record_t *rec, uint8_t *out) {
    if (rec->cred_idr) {
        memcpy(out, rec->cred_idr, CRED_RESIDENT_LEN);
    }
    else {
        credential_derive_resident(rec->cred_id, rec->cred_id_len, out);
    }
}

int credential_resident_id_lookup(const uint8_t *rp_id_hash, const uint8_t *cred_id, size_t cred_id_len, uint8_t *out) {
    for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
        resident_record_t rec;
        if (credential_resident_parse(search_dynamic_file((uint16_t)(EF_CRED + i)), &rec) != 0 ||
            memcmp(rec.rp_id_hash, rp_id_hash, 32) != 0) {
            continue;
        }
        if (rec.cred_id_len == cred_id_len && memcmp(rec.cred_id, cred_id, cred_id_len) == 0) {
            credential_resident_id(&rec, out);
            return 0;
        }
    }
    credential_derive_resident(cred_id, cred_id_len, out);
    return -1;
}

bool credential_curve_supported(int64_t curve) {
#ifdef FIDO_ED25519_LF
    if (curve == FIDO2_CURVE_ED25519) {
        return true;                    /* lf_25519, no mbedTLS group */
    }
#endif
    mbedtls_ecp_group_id grp = fido_curve_to_mbedtls((int) curve);
    /* the curve info exists only for the curves this build has */
    return grp != MBEDTLS_ECP_DP_NONE && mbedtls_ecp_curve_info_from_grp_id(grp) != NULL;
}

bool credential_is_resident(const uint8_t *cred_id, size_t cred_id_len) {
    if (cred_id_len < 4 + CRED_PROTO_RESIDENT_LEN) {
        return false;
    }
    return memcmp(cred_id + 4, CRED_PROTO_RESIDENT, CRED_PROTO_RESIDENT_LEN) == 0;
}

#define CRED_MIN_ID_LEN     (CRED_PROTO_LEN + CRED_IV_LEN + CRED_TAG_LEN)
#define CRED_USER_PT_MAX    (1 + 2 * (1 + 2 + CRED_USER_FIELD_MAX))
#define CRED_USER_AAD_LEN   (CRED_USER_TRAILER_MAGIC_LEN + 32 + CRED_RESIDENT_LEN)
#define CRED_USER_TRAILER_OVERHEAD (2 + CRED_USER_TRAILER_MAGIC_LEN)

int credential_resident_parse(const file_t *ef, resident_record_t *rec) {
    memset(rec, 0, sizeof(*rec));
    if (!file_has_data(ef)) {
        return -1;
    }
    const uint8_t *p = file_get_data(ef);
    size_t len = file_get_size(ef);
    if (len < 32 + CRED_MIN_ID_LEN) {
        return -1;
    }
    rec->rp_id_hash = p;
    if (!credential_is_resident(p + 32, len - 32)) {
        rec->cred_id = p + 32;
        rec->cred_id_len = len - 32;
        return 0;
    }
    if (len < 32 + CRED_RESIDENT_LEN + CRED_MIN_ID_LEN) {
        return -1;
    }
    rec->cred_idr = p + 32;
    const uint8_t *body = p + 32 + CRED_RESIDENT_LEN;
    size_t body_len = len - 32 - CRED_RESIDENT_LEN;
    rec->cred_id = body;
    rec->cred_id_len = body_len;
    if (body_len > CRED_MIN_ID_LEN + CRED_IV_LEN + CRED_TAG_LEN + CRED_USER_TRAILER_OVERHEAD &&
        memcmp(body + body_len - CRED_USER_TRAILER_MAGIC_LEN, CRED_USER_TRAILER_MAGIC, CRED_USER_TRAILER_MAGIC_LEN) == 0) {
        size_t sealed_len = get_uint16_t_le(body + body_len - CRED_USER_TRAILER_OVERHEAD);
        if (sealed_len >= CRED_IV_LEN + CRED_TAG_LEN &&
            sealed_len + CRED_USER_TRAILER_OVERHEAD + CRED_MIN_ID_LEN <= body_len) {
            size_t cred_id_len = body_len - CRED_USER_TRAILER_OVERHEAD - sealed_len;
            if (credential_resident_id_valid(p, body, cred_id_len, rec->cred_idr)) {
                rec->cred_id_len = cred_id_len;
                rec->user_sealed = body + cred_id_len;
                rec->user_sealed_len = sealed_len;
            }
        }
    }
    return 0;
}

bool credential_resident_matches(const resident_record_t *rec, const uint8_t *id, size_t id_len) {
    if (id == NULL) {
        return false;
    }
    if (rec->cred_idr) {
        return id_len == CRED_RESIDENT_LEN && memcmp(rec->cred_idr, id, CRED_RESIDENT_LEN) == 0;
    }
    if (id_len == rec->cred_id_len && memcmp(rec->cred_id, id, id_len) == 0) {
        return true;
    }
    if (id_len == CRED_RESIDENT_LEN) {
        /* getAssertion and credMgmt report the derived ID for these records. */
        uint8_t idr[CRED_RESIDENT_LEN];
        credential_derive_resident(rec->cred_id, rec->cred_id_len, idr);
        return memcmp(idr, id, CRED_RESIDENT_LEN) == 0;
    }
    return false;
}

static int credential_user_key(uint8_t key[32]) {
    int r = load_keydev(key);
    if (r != 0) {
        return r;
    }
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_hmac(md_info, key, 32, (const uint8_t *) "SLIP-0022", 9, key);
    mbedtls_md_hmac(md_info, key, 32, (const uint8_t *) "LibreFido user entity", 21, key);
    return 0;
}

static void credential_user_aad(const uint8_t *rp_id_hash, const uint8_t *cred_idr, uint8_t aad[CRED_USER_AAD_LEN]) {
    memcpy(aad, CRED_USER_TRAILER_MAGIC, CRED_USER_TRAILER_MAGIC_LEN);
    memcpy(aad + CRED_USER_TRAILER_MAGIC_LEN, rp_id_hash, 32);
    memcpy(aad + CRED_USER_TRAILER_MAGIC_LEN + 32, cred_idr, CRED_RESIDENT_LEN);
}

static int credential_apply_user_update(const resident_record_t *rec, Credential *cred) {
    CborError error = CborNoError;
    CborCharString name = { 0 }, displayName = { 0 };
    uint8_t key[32], aad[CRED_USER_AAD_LEN], pt[CRED_USER_PT_MAX];
    size_t pt_len = rec->user_sealed_len - CRED_IV_LEN - CRED_TAG_LEN;
    if (pt_len > sizeof(pt) || credential_user_key(key) != 0) {
        return -1;
    }
    credential_user_aad(rec->rp_id_hash, rec->cred_idr, aad);
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, key);
    int ret = mbedtls_chachapoly_auth_decrypt(&chatx, pt_len, rec->user_sealed, aad, sizeof(aad),
                                              rec->user_sealed + CRED_IV_LEN + pt_len,
                                              rec->user_sealed + CRED_IV_LEN, pt);
    mbedtls_chachapoly_free(&chatx);
    mbedtls_platform_zeroize(key, sizeof(key));
    if (ret != 0) {
        return -1;
    }
    CborParser parser;
    CborValue map;
    CBOR_CHECK(cbor_parser_init(pt, pt_len, 0, &parser, &map));
    CBOR_PARSE_MAP_START(map, 1)
    {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_u == 0x04) {
            CBOR_FIELD_GET_TEXT(name, 1);
        }
        else if (val_u == 0x05) {
            CBOR_FIELD_GET_TEXT(displayName, 1);
        }
        else {
            CBOR_ADVANCE(1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);
    CBOR_FREE_BYTE_STRING(cred->userName);
    CBOR_FREE_BYTE_STRING(cred->userDisplayName);
    cred->userName = name;
    cred->userDisplayName = displayName;
    name.data = NULL;
    displayName.data = NULL;
err:
    CBOR_FREE_BYTE_STRING(name);
    CBOR_FREE_BYTE_STRING(displayName);
    mbedtls_platform_zeroize(pt, sizeof(pt));
    return error == CborNoError ? 0 : -1;
}

int credential_load_record(const resident_record_t *rec, const uint8_t *rp_id_hash, Credential *cred) {
    int ret = credential_load_ex(rec->cred_id, rec->cred_id_len, rp_id_hash, rec->cred_idr, cred);
    if (ret == 0 && rec->user_sealed != NULL && credential_apply_user_update(rec, cred) != 0) {
        /* Only the display fields are lost; the credential stays usable. */
        printf("credential: stored user entity update is unreadable\n");
    }
    return ret;
}

int credential_load_resident(const file_t *ef, const uint8_t *rp_id_hash, Credential *cred) {
    resident_record_t rec;
    if (credential_resident_parse(ef, &rec) != 0) {
        memset(cred, 0, sizeof(*cred));
        return CTAP2_ERR_INVALID_CREDENTIAL;
    }
    return credential_load_record(&rec, rp_id_hash, cred);
}

size_t credential_utf8_truncate(const char *s, size_t len, size_t max) {
    if (len <= max) {
        return len;
    }
    size_t n = max;
    while (n > 0 && ((uint8_t) s[n] & 0xC0) == 0x80) {
        n--;
    }
    return n;
}

int credential_update_user(file_t *ef, const CborCharString *name, const CborCharString *displayName) {
    CborError error = CborNoError;
    resident_record_t rec;
    CborEncoder encoder, mapEncoder;
    uint8_t cred_idr[CRED_RESIDENT_LEN], key[32], aad[CRED_USER_AAD_LEN], pt[CRED_USER_PT_MAX];
    uint8_t *buf = NULL;
    size_t total = 0;
    bool has_name = name && name->present && name->len > 0;
    bool has_display = displayName && displayName->present && displayName->len > 0;

    if (credential_resident_parse(ef, &rec) != 0) {
        return CTAP2_ERR_NOT_ALLOWED;
    }
    if (rec.cred_idr) {
        memcpy(cred_idr, rec.cred_idr, sizeof(cred_idr));
    }
    else {
        /* Records without a resident ID gain one; it is the ID getAssertion
         * and credMgmt already report for them. */
        credential_derive_resident(rec.cred_id, rec.cred_id_len, cred_idr);
    }

    cbor_encoder_init(&encoder, pt, sizeof(pt), 0);
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, (size_t) has_name + (size_t) has_display));
    if (has_name) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
        CBOR_CHECK(cbor_encode_text_string(&mapEncoder, name->data, credential_utf8_truncate(name->data, name->len, CRED_USER_FIELD_MAX)));
    }
    if (has_display) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
        CBOR_CHECK(cbor_encode_text_string(&mapEncoder, displayName->data, credential_utf8_truncate(displayName->data, displayName->len, CRED_USER_FIELD_MAX)));
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    size_t pt_len = cbor_encoder_get_buffer_size(&encoder, pt);

    size_t base_len = 32 + CRED_RESIDENT_LEN + rec.cred_id_len;
    size_t sealed_len = CRED_IV_LEN + pt_len + CRED_TAG_LEN;
    total = base_len + sealed_len + CRED_USER_TRAILER_OVERHEAD;
    if (total > UINT16_MAX) {
        CBOR_ERROR(CTAP2_ERR_KEY_STORE_FULL);
    }
    buf = (uint8_t *) calloc(1, total);
    if (buf == NULL) {
        CBOR_ERROR(CTAP2_ERR_KEY_STORE_FULL);
    }
    /* Everything is copied out of the record before the file is rewritten. */
    memcpy(buf, rec.rp_id_hash, 32);
    memcpy(buf + 32, cred_idr, CRED_RESIDENT_LEN);
    memcpy(buf + 32 + CRED_RESIDENT_LEN, rec.cred_id, rec.cred_id_len);

    uint8_t *sealed = buf + base_len;
    random_gen(NULL, sealed, CRED_IV_LEN);
    if (credential_user_key(key) != 0) {
        CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
    }
    credential_user_aad(buf, cred_idr, aad);
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, key);
    int ret = mbedtls_chachapoly_encrypt_and_tag(&chatx, pt_len, sealed, aad, sizeof(aad), pt,
                                                 sealed + CRED_IV_LEN, sealed + CRED_IV_LEN + pt_len);
    mbedtls_chachapoly_free(&chatx);
    if (ret != 0) {
        CBOR_ERROR(CTAP1_ERR_OTHER);
    }
    put_uint16_t_le((uint16_t) sealed_len, sealed + sealed_len);
    memcpy(sealed + sealed_len + 2, CRED_USER_TRAILER_MAGIC, CRED_USER_TRAILER_MAGIC_LEN);
    if (file_put_data(ef, buf, (uint16_t) total) != PICOKEY_OK) {
        CBOR_ERROR(CTAP2_ERR_KEY_STORE_FULL);
    }
    low_flash_available();
err:
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(pt, sizeof(pt));
    if (buf) {
        mbedtls_platform_zeroize(buf, total);
        free(buf);
    }
    if (error != CborNoError) {
        return error == CborErrorImproperValue ? CTAP2_ERR_CBOR_UNEXPECTED_TYPE : (int) error;
    }
    return 0;
}

/* ---- Explicit-key credentials (credential.h) ---- */

#define CRED_EXPLICIT_OVERHEAD  (CRED_PROTO_LEN + CRED_IV_LEN + CRED_TAG_LEN)
#define CRED_EXPLICIT_PT_MAX    (CRED_EXPLICIT_MAX_LEN - CRED_EXPLICIT_OVERHEAD)

bool credential_is_explicit(const uint8_t *cred_id, size_t cred_id_len) {
    return cred_id_len >= CRED_PROTO_LEN && memcmp(cred_id, CRED_PROTO_24_S, CRED_PROTO_LEN) == 0;
}

/* Sealing key of the explicit-key credentials. Not the key
 * credential_derive_chacha_key() derives from their prefix: firmware before
 * 2.1.0 takes every ID that is not CRED_PROTO_22_S for its first format,
 * sealed under that key, so it would open them and sign with a key derived
 * from the ID. */
static int credential_explicit_key(uint8_t outk[32]) {
    memset(outk, 0, 32);
    int r = load_keydev(outk);
    if (r != 0) {
        mbedtls_platform_zeroize(outk, 32);
        return r;
    }
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_hmac(md_info, outk, 32, (const uint8_t *) "SLIP-0022", 9, outk);
    mbedtls_md_hmac(md_info, outk, 32, (const uint8_t *) CRED_PROTO_24_S, CRED_PROTO_LEN, outk);
    mbedtls_md_hmac(md_info, outk, 32, (const uint8_t *) "LibreFido explicit key", 22, outk);
    return 0;
}

static bool credential_explicit_len_ok(size_t cred_id_len) {
    return cred_id_len > CRED_EXPLICIT_OVERHEAD && cred_id_len <= CRED_EXPLICIT_MAX_LEN;
}

/* Decrypts the CBOR of the explicit-key credential cred_id, sealed for
 * rp_id_hash, into out (cred_id_len - CRED_EXPLICIT_OVERHEAD bytes; it may be
 * the ciphertext itself). out is wiped when it does not authenticate. */
static int credential_explicit_open(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash, uint8_t *out) {
    if (!credential_explicit_len_ok(cred_id_len)) {
        return -1;
    }
    uint8_t key[32];
    if (credential_explicit_key(key) != 0) {
        return -1;
    }
    size_t pt_len = cred_id_len - CRED_EXPLICIT_OVERHEAD;
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    int ret = mbedtls_chachapoly_setkey(&chatx, key);
    if (ret == 0) {
        ret = mbedtls_chachapoly_auth_decrypt(&chatx, pt_len, cred_id + CRED_PROTO_LEN, rp_id_hash, 32,
                                              cred_id + cred_id_len - CRED_TAG_LEN,
                                              cred_id + CRED_PROTO_LEN + CRED_IV_LEN, out);
    }
    mbedtls_chachapoly_free(&chatx);
    mbedtls_platform_zeroize(key, sizeof(key));
    return ret == 0 ? 0 : -1;
}

/* cred_id authenticates as an explicit-key credential of rp_id_hash at exactly
 * this length. Nothing of the plaintext is kept (the keystream goes through a
 * small scratch buffer): only the tag is compared. */
static bool credential_explicit_authentic(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash) {
    if (!credential_explicit_len_ok(cred_id_len)) {
        return false;
    }
    uint8_t key[32], chunk[64], mac[CRED_TAG_LEN];
    if (credential_explicit_key(key) != 0) {
        return false;
    }
    const uint8_t *ct = cred_id + CRED_PROTO_LEN + CRED_IV_LEN;
    size_t ct_len = cred_id_len - CRED_EXPLICIT_OVERHEAD;
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    int ret = mbedtls_chachapoly_setkey(&chatx, key);
    if (ret == 0) {
        ret = mbedtls_chachapoly_starts(&chatx, cred_id + CRED_PROTO_LEN, MBEDTLS_CHACHAPOLY_DECRYPT);
    }
    if (ret == 0) {
        ret = mbedtls_chachapoly_update_aad(&chatx, rp_id_hash, 32);
    }
    for (size_t off = 0; ret == 0 && off < ct_len; off += sizeof(chunk)) {
        size_t n = ct_len - off < sizeof(chunk) ? ct_len - off : sizeof(chunk);
        ret = mbedtls_chachapoly_update(&chatx, n, ct + off, chunk);
    }
    if (ret == 0) {
        ret = mbedtls_chachapoly_finish(&chatx, mac);
    }
    bool ok = ret == 0 && ct_memcmp(mac, cred_id + cred_id_len - CRED_TAG_LEN, CRED_TAG_LEN) == 0;
    mbedtls_chachapoly_free(&chatx);
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(chunk, sizeof(chunk));
    mbedtls_platform_zeroize(mac, sizeof(mac));
    return ok;
}

typedef struct explicit_keys {
    uint8_t key[CRED_KEY_MAX];
    size_t key_len;
    uint8_t hmac[CRED_HMAC_KEY_LEN];
    bool has_hmac;
    uint8_t large_blob_key[CRED_LARGE_BLOB_KEY_LEN];
    bool has_large_blob_key;
} explicit_keys_t;

/* The keys stored in the explicit-key credential cred, loaded for
 * rp_id_hash. Opened again for every use, so a loaded Credential (kept
 * between getAssertion and getNextAssertion) never holds them. k is wiped on
 * failure; the caller wipes it after use. */
static int credential_explicit_keys(const Credential *cred, const uint8_t *rp_id_hash, explicit_keys_t *k) {
    CborError error = CborNoError;
    CborParser parser;
    CborValue map;
    uint8_t pt[CRED_EXPLICIT_PT_MAX];
    memset(k, 0, sizeof(*k));
    if (cred->id.present != true || credential_explicit_open(cred->id.data, cred->id.len, rp_id_hash, pt) != 0) {
        return -1;
    }
    CBOR_CHECK(cbor_parser_init(pt, cred->id.len - CRED_EXPLICIT_OVERHEAD, 0, &parser, &map));
    CBOR_PARSE_MAP_START(map, 1)
    {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        uint8_t *dst = NULL;
        size_t cap = 0;
        if (val_u == 0x21) {
            dst = k->key;
            cap = sizeof(k->key);
        }
        else if (val_u == 0x22) {
            dst = k->hmac;
            cap = sizeof(k->hmac);
        }
        else if (val_u == 0x23) {
            dst = k->large_blob_key;
            cap = sizeof(k->large_blob_key);
        }
        if (dst == NULL) {
            CBOR_ADVANCE(1);
            continue;
        }
        size_t n = cap;
        CBOR_ASSERT(cbor_value_is_byte_string(&_f1) == true);
        CBOR_CHECK(cbor_value_copy_byte_string(&_f1, dst, &n, &_f1));
        if (val_u == 0x21) {
            k->key_len = n;
        }
        else if (n != cap) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CREDENTIAL);
        }
        else if (val_u == 0x22) {
            k->has_hmac = true;
        }
        else {
            k->has_large_blob_key = true;
        }
    }
    CBOR_PARSE_MAP_END(map, 1);
    if (k->key_len == 0) {
        CBOR_ERROR(CTAP2_ERR_INVALID_CREDENTIAL);
    }
err:
    mbedtls_platform_zeroize(pt, sizeof(pt));
    if (error != CborNoError) {
        mbedtls_platform_zeroize(k, sizeof(*k));
        return -1;
    }
    return 0;
}

int credential_key_load(const Credential *cred, const uint8_t *rp_id_hash, fido_cred_key_t *key) {
    if (!credential_is_explicit(cred->id.data, cred->id.len)) {
        return fido_cred_key_load(key, (int) cred->curve, cred->id.data);
    }
    explicit_keys_t k;
    int ret = credential_explicit_keys(cred, rp_id_hash, &k);
    if (ret == 0) {
        ret = fido_cred_key_import(key, (int) cred->curve, k.key, k.key_len);
    }
    mbedtls_platform_zeroize(&k, sizeof(k));
    return ret;
}

bool credential_hmac_capable(const Credential *cred) {
    return !credential_is_explicit(cred->id.data, cred->id.len) || cred->extensions.hmac_secret == ptrue;
}

int credential_hmac_key(const Credential *cred, const uint8_t *rp_id_hash, uint8_t *outk) {
    if (!credential_is_explicit(cred->id.data, cred->id.len)) {
        return credential_derive_hmac_key(cred->id.data, cred->id.len, outk);
    }
    explicit_keys_t k;
    int ret = credential_explicit_keys(cred, rp_id_hash, &k);
    if (ret == 0 && k.has_hmac) {
        memcpy(outk, k.hmac, CRED_HMAC_KEY_LEN);
    }
    else {
        ret = -1;
    }
    mbedtls_platform_zeroize(&k, sizeof(k));
    return ret;
}

int credential_large_blob_key(const Credential *cred, const uint8_t *rp_id_hash, uint8_t *outk) {
    if (!credential_is_explicit(cred->id.data, cred->id.len)) {
        return credential_derive_large_blob_key(cred->id.data, cred->id.len, outk);
    }
    explicit_keys_t k;
    int ret = credential_explicit_keys(cred, rp_id_hash, &k);
    if (ret == 0 && k.has_large_blob_key) {
        memcpy(outk, k.large_blob_key, CRED_LARGE_BLOB_KEY_LEN);
    }
    else {
        ret = -1;
    }
    mbedtls_platform_zeroize(&k, sizeof(k));
    return ret;
}

/* The RP entry (EF_RP) of rp_id_hash, NULL if there is none; *free_slot: the
 * first free RP slot, -1 if none. */
static file_t *credential_rp_find(const uint8_t *rp_id_hash, int *free_slot) {
    *free_slot = -1;
    for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
        file_t *ef = search_dynamic_file((uint16_t)(EF_RP + i));
        if (!file_has_data(ef)) {
            if (*free_slot < 0) {
                *free_slot = i;
            }
            continue;
        }
        if (file_get_size(ef) >= 1 + 32 && memcmp(file_get_data(ef) + 1, rp_id_hash, 32) == 0) {
            return ef;
        }
    }
    return NULL;
}

/* Adds delta to the credential count of the RP entry of rp_id_hash, as
 * credential_store() and credential management do: an entry that drops to
 * zero is removed. rp_id (the credential just stored) keeps an entry at one
 * credential at least and makes a missing one. scratch holds the new entry. */
static int credential_rp_count(const uint8_t *rp_id_hash, int delta, const char *rp_id, size_t rp_id_len,
                               uint8_t *scratch, size_t cap) {
    int free_slot = -1;
    file_t *ef = credential_rp_find(rp_id_hash, &free_slot);
    if (ef) {
        int count = *file_get_data(ef) + delta;
        if (rp_id != NULL && count < 1) {
            count = 1;
        }
        if (count == *file_get_data(ef)) {
            return 0;
        }
        if (count <= 0) {
            return delete_file(ef) == 0 ? 0 : CTAP1_ERR_OTHER;
        }
        uint16_t size = file_get_size(ef);
        if (count > UINT8_MAX || size > cap) {
            return CTAP2_ERR_KEY_STORE_FULL;
        }
        memcpy(scratch, file_get_data(ef), size);
        scratch[0] = (uint8_t) count;
        return file_put_data(ef, scratch, size) == PICOKEY_OK ? 0 : CTAP2_ERR_KEY_STORE_FULL;
    }
    if (rp_id == NULL) {
        return 0;
    }
    if (free_slot < 0 || 1 + 32 + rp_id_len > cap || (ef = file_new((uint16_t)(EF_RP + free_slot))) == NULL) {
        return CTAP2_ERR_KEY_STORE_FULL;
    }
    scratch[0] = 1;
    memcpy(scratch + 1, rp_id_hash, 32);
    memcpy(scratch + 1 + 32, rp_id, rp_id_len);
    return file_put_data(ef, scratch, (uint16_t)(1 + 32 + rp_id_len)) == PICOKEY_OK ? 0 : CTAP2_ERR_KEY_STORE_FULL;
}

int credential_import_check(credential_import_t *imp, const credential_explicit_t *x, bool replace) {
    CborError error = CborNoError;
    CborEncoder encoder, mapEncoder, mapEncoder2;
    uint8_t *rp_id_hash = imp->record, *cred_idr = imp->record + 32;
    uint8_t *pt = imp->record + 32 + CRED_RESIDENT_LEN + CRED_PROTO_LEN + CRED_IV_LEN;
    int id_slot = -1, user_slot = -1, free_slot = -1;

    memset(imp, 0, sizeof(*imp));
    imp->slot = -1;
    imp->drop = -1;
    if (x->rp_id_len == 0 || x->rp_id_len > sizeof(imp->rp_id) || x->user_id_len == 0 ||
        x->key_len == 0 || x->key_len > CRED_KEY_MAX) {
        CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
    }
    mbedtls_sha256((const uint8_t *) x->rp_id, x->rp_id_len, rp_id_hash, 0);
    memcpy(cred_idr, x->resident_id, CRED_RESIDENT_LEN);
    memcpy(imp->rp_id, x->rp_id, x->rp_id_len);
    imp->rp_id_len = x->rp_id_len;

    /* The keys credential_create() writes (bar the rp_id_hash, which the AAD
     * binds), so credential_load() reads it like any credential. */
    cbor_encoder_init(&encoder, pt, CRED_EXPLICIT_PT_MAX, 0);
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, CborIndefiniteLength));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
    CBOR_CHECK(cbor_encode_text_string(&mapEncoder, x->rp_id, x->rp_id_len));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, x->user_id, x->user_id_len));
    if (x->user_name) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
        CBOR_CHECK(cbor_encode_text_string(&mapEncoder, x->user_name, x->user_name_len));
    }
    if (x->display_name) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
        CBOR_CHECK(cbor_encode_text_string(&mapEncoder, x->display_name, x->display_name_len));
    }
    CBOR_APPEND_KEY_UINT_VAL_UINT(mapEncoder, 0x06, board_millis());
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x07));
    CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, CborIndefiniteLength));
    if (x->cred_blob) {
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "credBlob"));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, x->cred_blob, x->cred_blob_len));
    }
    CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "credProtect"));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder2, x->cred_protect));
    if (x->hmac_key) {
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "hmac-secret"));
        CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, true));
    }
    if (x->large_blob_key) {
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "largeBlobKey"));
        CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, true));
    }
    if (x->third_party_payment) {
        CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "thirdPartyPayment"));
        CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, true));
    }
    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));
    CBOR_APPEND_KEY_UINT_VAL_BOOL(mapEncoder, 0x08, x->use_sign_count);
    CBOR_APPEND_KEY_UINT_VAL_INT(mapEncoder, 0x09, x->alg);
    CBOR_APPEND_KEY_UINT_VAL_INT(mapEncoder, 0x0A, x->curve);
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0B));
    CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2, 1));
    CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "rk"));
    CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, true));
    CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));
    if (x->creation_time != 0) {
        CBOR_APPEND_KEY_UINT_VAL_UINT(mapEncoder, 0x0C, x->creation_time);
    }
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x20));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, cred_idr, CRED_RESIDENT_LEN));
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x21));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, x->key, x->key_len));
    if (x->hmac_key) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x22));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, x->hmac_key, CRED_HMAC_KEY_LEN));
    }
    if (x->large_blob_key) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x23));
        CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, x->large_blob_key, CRED_LARGE_BLOB_KEY_LEN));
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    imp->pt_len = cbor_encoder_get_buffer_size(&encoder, pt);

    /* A credential ID names one credential on the device, whatever its RP;
     * an RP has one credential per user (makeCredential replaces it). */
    for (int i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
        file_t *ef = search_dynamic_file((uint16_t)(EF_CRED + i));
        resident_record_t rec;
        if (!file_has_data(ef)) {
            if (free_slot < 0) {
                free_slot = i;
            }
            continue;
        }
        if (credential_resident_parse(ef, &rec) != 0) {
            continue;
        }
        if (id_slot < 0 && credential_resident_matches(&rec, cred_idr, CRED_RESIDENT_LEN)) {
            id_slot = i;
            memcpy(imp->gone_rp[imp->gone++], rec.rp_id_hash, 32);
            continue;
        }
        if (user_slot < 0 && memcmp(rec.rp_id_hash, rp_id_hash, 32) == 0) {
            Credential rcred = { 0 };
            if (credential_load_ex(rec.cred_id, rec.cred_id_len, rp_id_hash, rec.cred_idr, &rcred) == 0 &&
                rcred.userId.len == x->user_id_len && memcmp(rcred.userId.data, x->user_id, x->user_id_len) == 0) {
                user_slot = i;
                memcpy(imp->gone_rp[imp->gone++], rec.rp_id_hash, 32);
            }
            credential_free(&rcred);
        }
    }
    if ((id_slot >= 0 || user_slot >= 0) && !replace) {
        CBOR_ERROR(CTAP2_ERR_CREDENTIAL_EXCLUDED);
    }
    if (id_slot >= 0) {
        imp->slot = id_slot;
        imp->drop = user_slot;
    }
    else {
        imp->slot = user_slot >= 0 ? user_slot : free_slot;
    }
    if (imp->slot < 0) {
        CBOR_ERROR(CTAP2_ERR_KEY_STORE_FULL);
    }

    /* Room for the record and its RP entry is checked before anything is
     * written, as in credential_store(). */
    int same = 0, rp_free = -1;
    for (uint8_t g = 0; g < imp->gone; g++) {
        same += memcmp(imp->gone_rp[g], rp_id_hash, 32) == 0;
    }
    uint16_t files_needed = search_dynamic_file((uint16_t)(EF_CRED + imp->slot)) ? 0 : 1;
    file_t *rp_ef = credential_rp_find(rp_id_hash, &rp_free);
    if (rp_ef) {
        if (*file_get_data(rp_ef) + 1 - same > UINT8_MAX) {
            CBOR_ERROR(CTAP2_ERR_KEY_STORE_FULL);
        }
    }
    else {
        if (rp_free < 0) {
            CBOR_ERROR(CTAP2_ERR_KEY_STORE_FULL);
        }
        if (!search_dynamic_file((uint16_t)(EF_RP + rp_free))) {
            files_needed++;
        }
    }
    if (dynamic_files + files_needed > MAX_DYNAMIC_FILES) {
        CBOR_ERROR(CTAP2_ERR_KEY_STORE_FULL);
    }
err:
    if (error != CborNoError) {
        mbedtls_platform_zeroize(imp->record, sizeof(imp->record));
        imp->slot = -1;
        if (error == CborErrorOutOfMemory) {
            return CTAP2_ERR_REQUEST_TOO_LARGE;
        }
        return error == CborErrorImproperValue ? CTAP2_ERR_CBOR_UNEXPECTED_TYPE : (int) error;
    }
    return 0;
}

int credential_import_store(credential_import_t *imp) {
    uint8_t *sealed = imp->record + 32 + CRED_RESIDENT_LEN, rp_id_hash[32], key[32];
    if (imp->slot < 0 || imp->pt_len == 0 || imp->pt_len > CRED_EXPLICIT_PT_MAX) {
        return CTAP1_ERR_OTHER;
    }
    memcpy(rp_id_hash, imp->record, sizeof(rp_id_hash));
    if (credential_explicit_key(key) != 0) {
        return CTAP1_ERR_OTHER;
    }
    memcpy(sealed, CRED_PROTO_24_S, CRED_PROTO_LEN);
    random_gen(NULL, sealed + CRED_PROTO_LEN, CRED_IV_LEN);
    uint8_t *pt = sealed + CRED_PROTO_LEN + CRED_IV_LEN;
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    int ret = mbedtls_chachapoly_setkey(&chatx, key);
    if (ret == 0) {
        ret = mbedtls_chachapoly_encrypt_and_tag(&chatx, imp->pt_len, sealed + CRED_PROTO_LEN, rp_id_hash, 32,
                                                 pt, pt, pt + imp->pt_len);
    }
    mbedtls_chachapoly_free(&chatx);
    mbedtls_platform_zeroize(key, sizeof(key));
    if (ret != 0) {
        return CTAP1_ERR_OTHER;
    }
    size_t total = 32 + CRED_RESIDENT_LEN + CRED_EXPLICIT_OVERHEAD + imp->pt_len;
    file_t *ef = file_new((uint16_t)(EF_CRED + imp->slot));
    if (ef == NULL || file_put_data(ef, imp->record, (uint16_t) total) != PICOKEY_OK) {
        return CTAP2_ERR_KEY_STORE_FULL;
    }
    /* The record buffer is scratch space from here on. A deletion moves the
     * file table: every file is looked up again after it. */
    if (imp->drop >= 0) {
        ef = search_dynamic_file((uint16_t)(EF_CRED + imp->drop));
        if (ef && delete_file(ef) != 0) {
            ret = CTAP1_ERR_OTHER;
        }
    }
    int same = 0;
    for (uint8_t g = 0; g < imp->gone; g++) {
        if (memcmp(imp->gone_rp[g], rp_id_hash, 32) == 0) {
            same++;
        }
        else {
            int r = credential_rp_count(imp->gone_rp[g], -1, NULL, 0, imp->record, sizeof(imp->record));
            ret = ret != 0 ? ret : r;
        }
    }
    int r = credential_rp_count(rp_id_hash, 1 - same, imp->rp_id, imp->rp_id_len, imp->record, sizeof(imp->record));
    ret = ret != 0 ? ret : r;
    low_flash_available();
    return ret;
}
