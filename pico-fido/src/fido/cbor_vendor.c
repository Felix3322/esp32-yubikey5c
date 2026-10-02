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
#include "ctap2_cbor.h"
#include "fido.h"
#include "ctap.h"
#include "hid/ctap_hid.h"
#include "files.h"
#include "apdu.h"
#include "random.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/x509_csr.h"
#include "crypto_utils.h"
#include "sks.h"
#include "lf_policy.h"
#include "profile.h"
#ifdef LF_STORE_V2
#include "lf_boot.h"
#include "lf_profile.h"
#include "lf_sys.h"
#endif

extern uint8_t keydev_dec[32];
extern bool has_keydev_dec;

mse_t mse = { .init = false };

/* The MSE session key protects a single secret: it is dropped after every
 * use, so the same key and nonce never encrypt two messages. */
static void mse_clear(void) {
    mbedtls_platform_zeroize(&mse, sizeof(mse));
    mse.init = false;
}

/* authenticatorReset: no session survives the profile it was made for. */
void vendor_reset_state(void) {
    mse_clear();
}

/* Decrypts in place a secret the host sent over the MSE session
 * (ciphertext || tag[16], the host public key as AAD). */
int mse_decrypt_ct(uint8_t *data, size_t len) {
    if (mse.init == false || data == NULL || len < 16) {
        return -1;
    }
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, mse.key_enc + 12);
    int ret = mbedtls_chachapoly_auth_decrypt(&chatx, len - 16, mse.key_enc, mse.Qpt, sizeof(mse.Qpt), data + len - 16, data, data);
    mbedtls_chachapoly_free(&chatx);
    mse_clear();
    return ret;
}

/* Device key protected by a key K that the host keeps (AUT_ENABLE, restore):
 * the blob
 *     iv[12] || ChaCha20-Poly1305_K(device key[32]) || tag[16]
 * is kept in ef_keydev_enc, itself stored as an sks record under the profile
 * root key (the plain 60-byte blob of earlier firmware is still read, and
 * re-sealed when read). ef_keydev is empty then. After a power up nothing can
 * be derived until the host sends K again (CTAP_VENDOR_UNLOCK). K always
 * travels encrypted under a fresh MSE session: ChaCha20-Poly1305(K[32]) ||
 * tag[16].
 *
 * Moving the device key in or out (AUT_ENABLE, export, restore) needs the
 * PIN (acfg token), a physical press, the strict power-up window and a
 * profile that is not secure. */
#define KEYDEV_ENC_LEN      (12 + 32 + 16)
#define KEYDEV_K_CT_LEN     (32 + 16)

static int keydev_enc_get(uint8_t blob[KEYDEV_ENC_LEN]) {
    size_t len = 0;
    bool legacy = false;
    int ret = sks_file_get(SKS_NS_FIDO, ef_keydev_enc, blob, KEYDEV_ENC_LEN, &len, &legacy);
    if (ret != PICOKEY_OK || len != KEYDEV_ENC_LEN) {
        mbedtls_platform_zeroize(blob, KEYDEV_ENC_LEN);
        return -1;
    }
    /* re-sealed only once the firmware is confirmed (fido_seal_now) */
    if (legacy && lf_migrate_ok() && sks_file_put(SKS_NS_FIDO, ef_keydev_enc, blob, KEYDEV_ENC_LEN) == PICOKEY_OK) {
        low_flash_available();
    }
    return 0;
}

/* The plain 60-byte blob while the firmware is unconfirmed (earlier
 * firmware reads only that), an sks record otherwise. */
static int keydev_enc_put(const uint8_t blob[KEYDEV_ENC_LEN]) {
    if (fido_seal_now()) {
        return sks_file_put(SKS_NS_FIDO, ef_keydev_enc, blob, KEYDEV_ENC_LEN);
    }
    return file_put_data(ef_keydev_enc, blob, KEYDEV_ENC_LEN);
}

/* Zeroes, then empties, a file; true when it is gone. */
static bool file_scrub(file_t *ef) {
    if (!file_has_data(ef)) {
        return true;
    }
    uint16_t size = file_get_size(ef);
    uint8_t *zeros = (uint8_t *) calloc(1, size);
    bool ok = zeros != NULL && file_put_data(ef, zeros, size) == PICOKEY_OK;
    free(zeros);
    ok = file_put_data(ef, NULL, 0) == PICOKEY_OK && ok;
    return ok && !file_has_data(ef);
}

/* key is only written when the blob authenticates with k. */
static int keydev_unseal(const uint8_t *blob, size_t blob_len, const uint8_t k[32], uint8_t key[32]) {
    if (blob == NULL || blob_len != KEYDEV_ENC_LEN) {
        return -1;
    }
    uint8_t tmp[32];
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, k);
    int ret = mbedtls_chachapoly_auth_decrypt(&chatx, sizeof(tmp), blob, NULL, 0, blob + 12 + 32, blob + 12, tmp);
    mbedtls_chachapoly_free(&chatx);
    if (ret == 0) {
        memcpy(key, tmp, sizeof(tmp));
    }
    mbedtls_platform_zeroize(tmp, sizeof(tmp));
    return ret;
}

static int keydev_seal(const uint8_t k[32], const uint8_t key[32], uint8_t blob[KEYDEV_ENC_LEN]) {
    random_gen(NULL, blob, 12);
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, k);
    int ret = mbedtls_chachapoly_encrypt_and_tag(&chatx, 32, blob, NULL, 0, key, blob + 12, blob + 12 + 32);
    mbedtls_chachapoly_free(&chatx);
    return ret;
}

/* Decrypts K (sent over MSE) into k. */
static int keydev_read_k(const uint8_t *k_ct, size_t k_ct_len, uint8_t k[32]) {
    uint8_t buf[KEYDEV_K_CT_LEN];
    if (k_ct == NULL || k_ct_len != sizeof(buf)) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    memcpy(buf, k_ct, sizeof(buf));
    int ret = mse_decrypt_ct(buf, sizeof(buf));
    if (ret == 0) {
        memcpy(k, buf, 32);
    }
    mbedtls_platform_zeroize(buf, sizeof(buf));
    return ret == 0 ? 0 : CTAP1_ERR_INVALID_PARAMETER;
}

/* Makes blob (checked by the caller to open to key) the stored device key
 * and key its RAM copy, then removes the plain device key file. Nothing is
 * changed when the sealed copy cannot be written. Once it is written the
 * sealed state is authoritative: a plain copy that could not be removed is
 * ignored by load_keydev and removed by the next UNLOCK. */
static int keydev_install_sealed(const uint8_t blob[KEYDEV_ENC_LEN], const uint8_t key[32]) {
    if (keydev_enc_put(blob) != PICOKEY_OK) {
        low_flash_available();
        return CTAP2_ERR_PROCESSING;
    }
    memcpy(keydev_dec, key, sizeof(keydev_dec));
    has_keydev_dec = true;
    if (!file_scrub(ef_keydev)) {
        printf("device key: the plain copy could not be removed yet\n");
    }
    low_flash_available();
    return 0;
}

/* The operations that move the device key in or out. */
static int keydev_move_allowed(void) {
    if (lf_profile_is_secure()) {
        return CTAP2_ERR_OPERATION_DENIED;  /* keys never leave a secure profile */
    }
    if (!fido_in_strict_power_up_window()) {
        return CTAP2_ERR_NOT_ALLOWED;
    }
    return 0;
}

/* Those that hand the device key out (AUT_ENABLE picks K, export returns
 * the blob): also refused in a profile marked no-export, the rule the
 * management applet applies to profile exports. Fails closed. Imports
 * (restore) are not exports and do not check it. */
static int keydev_export_allowed(void) {
    int ret = keydev_move_allowed();
    if (ret != 0) {
        return ret;
    }
#ifdef LF_STORE_V2
    if (!lf_storage_ready()) {
        return CTAP2_ERR_OPERATION_DENIED;
    }
    uint8_t idx = lf_profile_mounted();
    const lf_sys_t *s = lf_sys();
    if (idx >= LF_MAX_PROFILES || !s->profile[idx].used ||
        (s->profile[idx].flags & (LF_PROFILE_F_NO_EXPORT | LF_PROFILE_F_SECURE))) {
        return CTAP2_ERR_OPERATION_DENIED;
    }
#endif
    return LF_ALLOW_SECRET_EXPORT ? 0 : CTAP2_ERR_OPERATION_DENIED;
}

/* authenticatorConfig AUT_ENABLE (the acfg token is checked by the caller):
 * seals the current device key under K. The device keeps working until the
 * next power up; the blob is checked to open with K before the plain device
 * key is removed. */
int keydev_protect(const uint8_t *k_ct, size_t k_ct_len) {
    uint8_t k[32] = { 0 }, key[32] = { 0 }, check[32] = { 0 }, blob[KEYDEV_ENC_LEN];
    int ret = keydev_export_allowed();
    if (ret != 0) {
        return ret;
    }
    if (!file_has_data(ef_keydev) || keydev_is_sealed() || mse.init == false) {
        return CTAP2_ERR_NOT_ALLOWED;
    }
    if (k_ct == NULL || k_ct_len != KEYDEV_K_CT_LEN) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    if (fido_wait_physical_press() == true) {
        return fido_up_error();
    }
    if ((ret = keydev_read_k(k_ct, k_ct_len, k)) != 0) {
        goto out;
    }
    if (load_keydev(key) != PICOKEY_OK) {
        ret = CTAP2_ERR_PROCESSING;
        goto out;
    }
    if (keydev_seal(k, key, blob) != 0 || keydev_unseal(blob, sizeof(blob), k, check) != 0 ||
        memcmp(check, key, sizeof(key)) != 0) {
        ret = CTAP2_ERR_PROCESSING;
        goto out;
    }
    ret = keydev_install_sealed(blob, key);
out:
    mbedtls_platform_zeroize(k, sizeof(k));
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(check, sizeof(check));
    mbedtls_platform_zeroize(blob, sizeof(blob));
    return ret;
}

/* authenticatorConfig AUT_DISABLE: stores the (unlocked) device key in the
 * normal format again and forgets the RAM copy. */
int keydev_unprotect(void) {
    if (!keydev_is_sealed() || has_keydev_dec == false) {
        return CTAP2_ERR_NOT_ALLOWED;
    }
    if (fido_wait_physical_press() == true) {
        return fido_up_error();
    }
    if (keydev_store_unsealing(keydev_dec) != PICOKEY_OK) {
        return CTAP2_ERR_PROCESSING;    /* still sealed, RAM copy kept */
    }
    mbedtls_platform_zeroize(keydev_dec, sizeof(keydev_dec));
    has_keydev_dec = false;
    return 0;
}

/* The key management commands need the PIN: a pinUvAuthToken with the acfg
 * permission over
 *     32 x 0xFF || 0xC1 || cmd || vendorCmd || vendorParam || vendorKey
 * (vendorParam and vendorKey when present). There is no path without a PIN. */
static int vendor_check_token(uint8_t cmd, uint8_t vendor_cmd, const CborByteString *param, const CborByteString *key,
                              uint64_t protocol, const CborByteString *pin_uv_auth_param) {
    if (!file_has_data(ef_pin)) {
        return CTAP2_ERR_PIN_NOT_SET;
    }
    if (pin_uv_auth_param->present == false) {
        return CTAP2_ERR_PUAT_REQUIRED;
    }
    if (protocol == 0) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (protocol != 1 && protocol != 2) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    size_t plen = param->present ? param->len : 0, klen = key->present ? key->len : 0;
    size_t len = 32 + 3 + plen + klen;
    if (len > UINT16_MAX) {
        return CTAP1_ERR_INVALID_LEN;
    }
    uint8_t *payload = (uint8_t *) calloc(1, len);
    if (payload == NULL) {
        return CTAP2_ERR_PROCESSING;
    }
    memset(payload, 0xff, 32);
    payload[32] = (uint8_t) CTAP_VENDOR_CBOR;
    payload[33] = cmd;
    payload[34] = vendor_cmd;
    if (plen > 0) {
        memcpy(payload + 35, param->data, plen);
    }
    if (klen > 0) {
        memcpy(payload + 35 + plen, key->data, klen);
    }
    /* verify() also stops an expired token first */
    int ret = verify((uint8_t) protocol, paut.data, payload, (uint16_t) len, pin_uv_auth_param->data, pin_uv_auth_param->len);
    free(payload);
    if (ret != 0 || !paut.in_use || !(paut.permissions & CTAP_PERMISSION_ACFG)) {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    return 0;
}

/* Vendor restore: validates everything, and builds the new device
 * certificate, before any write. key is the unsealed new device key. */
static int keydev_restore(const uint8_t blob[KEYDEV_ENC_LEN], const uint8_t key[32]) {
    uint8_t cert[2048], old[32];
    size_t clen = 0;
    /* also rejects 32 bytes that are no P-256 private key (0, >= n) */
    if (fido_certdev_build(key, cert, sizeof(cert), &clen) != PICOKEY_OK) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    /* Unknown (locked) counts as a different key. */
    bool same_key = load_keydev(old) == PICOKEY_OK && ct_memcmp(old, key, sizeof(old)) == 0;
    mbedtls_platform_zeroize(old, sizeof(old));
    int ret = keydev_install_sealed(blob, key);
    if (ret != 0) {
        return ret;                     /* nothing was changed */
    }
    /* From here the new key is installed: the certificates follow it. A
     * certificate that cannot be written is removed rather than left for the
     * old key; the device certificate is then made again when needed. */
    if (file_put_data(ef_certdev, cert + sizeof(cert) - clen, (uint16_t) clen) != PICOKEY_OK) {
        file_put_data(ef_certdev, NULL, 0);
    }
    if (!same_key) {
        /* The enterprise attestation certificate certifies the old key. */
        file_t *ef_ee_ea = search_by_fid(EF_EE_DEV_EA, NULL, SPECIFY_EF);
        if (file_has_data(ef_ee_ea)) {
            file_put_data(ef_ee_ea, NULL, 0);
        }
    }
    low_flash_available();
    return 0;
}

int cbor_vendor_generic(uint8_t cmd, const uint8_t *data, size_t len) {
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    CborByteString pinUvAuthParam = { 0 }, vendorParam = { 0 }, vendorKey = { 0 }, kax = { 0 }, kay = { 0 };
    size_t resp_size = 0;
    uint64_t vendorCmd = 0, pinUvAuthProtocol = 0;
    int64_t kty = 0, alg = 0, crv = 0;
    CborEncoder encoder, mapEncoder, mapEncoder2;
    uint8_t k[32] = { 0 }, key[32] = { 0 }, blob[KEYDEV_ENC_LEN] = { 0 };

    CBOR_CHECK(cbor_parser_init(data, len, 0, &parser, &map));
    uint64_t val_c = 1;
    CBOR_PARSE_MAP_START(map, 1)
    {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_c <= 1 && val_c != val_u) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (val_u < val_c) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        }
        val_c = val_u + 1;
        if (val_u == 0x01) {
            CBOR_FIELD_GET_UINT(vendorCmd, 1);
        }
        else if (val_u == 0x02) {
            uint64_t subpara = 0;
            CBOR_PARSE_MAP_START(_f1, 2)
            {
                CBOR_FIELD_GET_UINT(subpara, 2);
                if (subpara == 0x01) {
                    CBOR_FIELD_GET_BYTES(vendorParam, 2);
                }
                else if (subpara == 0x02) {
                    CBOR_CHECK(COSE_read_key(&_f2, &kty, &alg, &crv, &kax, &kay));
                }
                else if (subpara == 0x03) {
                    CBOR_FIELD_GET_BYTES(vendorKey, 2);
                }
                else {
                    CBOR_ADVANCE(2);
                }
            }
            CBOR_PARSE_MAP_END(_f1, 2);
        }
        else if (val_u == 0x03) {
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
        }
        else if (val_u == 0x04) {
            CBOR_FIELD_GET_BYTES(pinUvAuthParam, 1);
        }
        else {
            CBOR_ADVANCE(1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);

    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_CBOR_PAYLOAD, 0);

    if (cmd == CTAP_VENDOR_BACKUP) {
        if (vendorCmd == 0x01) {
            /* Export of the sealed device key: it opens with K only, but
             * with K it is every credential, so the PIN and a touch too
             * (and the no-export flag may have been set since AUT_ENABLE). */
            int ret = keydev_export_allowed();
            if (ret != 0) {
                CBOR_ERROR(ret);
            }
            if (has_keydev_dec == false || !keydev_is_sealed()) {
                CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
            }
            ret = vendor_check_token(cmd, (uint8_t) vendorCmd, &vendorParam, &vendorKey, pinUvAuthProtocol, &pinUvAuthParam);
            if (ret != 0) {
                CBOR_ERROR(ret);
            }
            if (fido_wait_physical_press() == true) {
                CBOR_ERROR(fido_up_error());
            }
            if (keydev_enc_get(blob) != 0) {
                CBOR_ERROR(CTAP2_ERR_INTEGRITY_FAILURE);
            }
            CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, blob, sizeof(blob)));
        }
        else if (vendorCmd == 0x02) {
            /* Restore: replaces the device key with a sealed one. It needs
             * what authenticatorReset needs (power-up window, here without
             * the board option that disables it; physical press) and the
             * PIN, and K (vendorKey, over MSE) to prove that the blob opens.
             * Everything is checked before anything is written. Resident
             * credentials of another key stay stored: they are reported by
             * credential management by ID only (and can be deleted), and
             * work again if that key is restored. */
            if (vendorParam.present == false || vendorKey.present == false) {
                CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
            }
            if (vendorParam.len != KEYDEV_ENC_LEN || vendorKey.len != KEYDEV_K_CT_LEN) {
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
            int ret = keydev_move_allowed();
            if (ret != 0) {
                CBOR_ERROR(ret);
            }
            ret = vendor_check_token(cmd, (uint8_t) vendorCmd, &vendorParam, &vendorKey, pinUvAuthProtocol, &pinUvAuthParam);
            if (ret != 0) {
                CBOR_ERROR(ret);
            }
            if (mse.init == false) {
                CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
            }
            if (fido_wait_physical_press() == true) {
                CBOR_ERROR(fido_up_error());
            }
            if ((ret = keydev_read_k(vendorKey.data, vendorKey.len, k)) != 0) {
                CBOR_ERROR(ret);
            }
            if (keydev_unseal(vendorParam.data, vendorParam.len, k, key) != 0) {
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
            if ((ret = keydev_restore(vendorParam.data, key)) != 0) {
                CBOR_ERROR(ret);
            }
            goto err;
        }
        else {
            CBOR_ERROR(CTAP2_ERR_INVALID_SUBCOMMAND);
        }
    }
    else if (cmd == CTAP_VENDOR_MSE) {
        if (vendorCmd == 0x01) { // KeyAgreement
            if (kax.present == false || kay.present == false || alg == 0) {
                CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
            }
            mse_clear();
            mbedtls_ecdh_context hkey;
            mbedtls_ecdh_init(&hkey);
            uint8_t buf[MBEDTLS_ECP_MAX_BYTES];
            size_t olen = 0;
            int ret = mbedtls_ecdh_setup(&hkey, MBEDTLS_ECP_DP_SECP256R1);
            if (ret == 0) {
                ret = mbedtls_ecdh_gen_public(&hkey.ctx.mbed_ecdh.grp, &hkey.ctx.mbed_ecdh.d, &hkey.ctx.mbed_ecdh.Q, random_gen, NULL);
            }
            if (ret == 0) {
                ret = mbedtls_mpi_lset(&hkey.ctx.mbed_ecdh.Qp.Z, 1);
            }
            if (ret == 0) {
                ret = mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.X, kax.data, kax.len);
            }
            if (ret == 0) {
                ret = mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.Y, kay.data, kay.len);
            }
            if (ret == 0) {
                ret = mbedtls_ecp_point_write_binary(&hkey.ctx.mbed_ecdh.grp, &hkey.ctx.mbed_ecdh.Qp, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, mse.Qpt, sizeof(mse.Qpt));
            }
            if (ret == 0) {
                /* rejects a point that is not on the curve */
                ret = mbedtls_ecdh_calc_secret(&hkey, &olen, buf, sizeof(buf), random_gen, NULL);
            }
            if (ret == 0) {
                ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, buf, olen, mse.Qpt, sizeof(mse.Qpt), mse.key_enc, sizeof(mse.key_enc));
            }
            mbedtls_platform_zeroize(buf, sizeof(buf));
            if (ret != 0) {
                mbedtls_ecdh_free(&hkey);
                mse_clear();
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
            mse.init = true;

            error = cbor_encoder_create_map(&encoder, &mapEncoder, 1);
            if (error == CborNoError) {
                error = cbor_encode_uint(&mapEncoder, 0x01);
            }
            if (error == CborNoError) {
                error = COSE_key_shared(&hkey, &mapEncoder, &mapEncoder2);
            }
            mbedtls_ecdh_free(&hkey);
            if (error != CborNoError) {
                mse_clear();
                goto err;
            }
        }
        else {
            CBOR_ERROR(CTAP2_ERR_INVALID_SUBCOMMAND);
        }
    }
    else if (cmd == CTAP_VENDOR_UNLOCK) {
        /* Makes a protected device key usable until the next power up. It
         * needs the PIN like every key management command; a device sealed
         * without a PIN by earlier firmware first gets one (setPIN works
         * while the key is locked). */
        if (!keydev_is_sealed()) {
            CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }
        if (vendorParam.present == false) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (vendorParam.len != KEYDEV_K_CT_LEN) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        int ret = vendor_check_token(cmd, (uint8_t) vendorCmd, &vendorParam, &vendorKey, pinUvAuthProtocol, &pinUvAuthParam);
        if (ret != 0) {
            CBOR_ERROR(ret);
        }
        if (mse.init == false) {
            CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }
        if ((ret = keydev_read_k(vendorParam.data, vendorParam.len, k)) != 0) {
            CBOR_ERROR(ret);
        }
        if (keydev_enc_get(blob) != 0) {
            CBOR_ERROR(CTAP2_ERR_INTEGRITY_FAILURE);
        }
        /* A wrong K leaves the current state (and keydev_dec) untouched. */
        if (keydev_unseal(blob, sizeof(blob), k, key) != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        memcpy(keydev_dec, key, sizeof(keydev_dec));
        has_keydev_dec = true;
        /* The sealed copy is authoritative: a plain copy next to it (left
         * by an interrupted AUT_DISABLE/restore, or by older firmware's PIN
         * change) would make the key usable without K after a power up. */
        if (!file_scrub(ef_keydev)) {
            printf("device key: the plain copy could not be removed\n");
        }
        /* made again if a restore could not write it */
        fido_certdev_generate(false);
        low_flash_available();
        goto err;
    }
    else if (cmd == CTAP_VENDOR_EA) {
        if (vendorCmd == 0x01) {
            /* The key lives in the keypair the pk context allocates, so
             * mbedtls_pk_free() releases (and wipes) it on every path; it
             * used to be replaced by a stack key and leaked on every call,
             * which needs no authentication. */
            uint8_t buffer[1024];
            uint8_t keydev[32] = {0};
            if (load_keydev(keydev) != 0) {
                CBOR_ERROR(CTAP1_ERR_OTHER);
            }
            mbedtls_pk_context key_ctx;
            mbedtls_pk_init(&key_ctx);
            int ret = mbedtls_pk_setup(&key_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
            mbedtls_ecp_keypair *ek = ret == 0 ? mbedtls_pk_ec(key_ctx) : NULL;
            if (ret == 0) {
                ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, ek, keydev, 32);
            }
            mbedtls_platform_zeroize(keydev, sizeof(keydev));
            if (ret == 0) {
                ret = mbedtls_ecp_mul(&ek->grp, &ek->Q, &ek->d, &ek->grp.G, random_gen, NULL);
            }
            if (ret != 0) {
                mbedtls_pk_free(&key_ctx);
                CBOR_ERROR(CTAP2_ERR_PROCESSING);
            }
            mbedtls_x509write_csr ctx;
            mbedtls_x509write_csr_init(&ctx);
            snprintf((char *) buffer, sizeof(buffer), "C=ES,O=Pico Keys,OU=Authenticator Attestation,CN=Pico Fido EE Serial %s", pico_serial_str);
            mbedtls_x509write_csr_set_subject_name(&ctx, (char *) buffer);
            mbedtls_x509write_csr_set_key(&ctx, &key_ctx);
            mbedtls_x509write_csr_set_md_alg(&ctx, MBEDTLS_MD_SHA256);
            uint8_t csr_aaguid[16];
            fido_get_aaguid(csr_aaguid);
            mbedtls_x509write_csr_set_extension(&ctx, "\x2B\x06\x01\x04\x01\x82\xE5\x1C\x01\x01\x04", 0xB, 0, csr_aaguid, sizeof(csr_aaguid));
            ret = mbedtls_x509write_csr_der(&ctx, buffer, sizeof(buffer), random_gen, NULL);
            mbedtls_x509write_csr_free(&ctx);
            mbedtls_pk_free(&key_ctx);
            if (ret <= 0) {
                CBOR_ERROR(CTAP2_ERR_PROCESSING);
            }
            CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, buffer + sizeof(buffer) - ret, ret));
        }
        else {
            CBOR_ERROR(CTAP2_ERR_INVALID_SUBCOMMAND);
        }
    }
#ifndef ENABLE_EMULATION
    else if (cmd == CTAP_VENDOR_PHY_OPTS) {
        if (vendorCmd == 0x01) {
            /* The options in force (loaded at boot, updated by phy_save()),
             * the same value authenticatorConfig PHY_OPTS writes. */
            CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, phy_data.opts));
        }
        else {
            CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_OPTION);
        }
    }
#endif
    else if (cmd == CTAP_VENDOR_MEMORY) {
        if (vendorCmd == 0x01) {
            CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 5));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, flash_free_space()));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, flash_used_space()));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, flash_total_space()));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, flash_num_files()));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, flash_size()));
        }
        else {
            CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_OPTION);
        }
    }
    else {
        CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_OPTION);
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);

err:
    mbedtls_platform_zeroize(k, sizeof(k));
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(blob, sizeof(blob));
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);
    CBOR_FREE_BYTE_STRING(vendorParam);
    CBOR_FREE_BYTE_STRING(vendorKey);
    CBOR_FREE_BYTE_STRING(kax);
    CBOR_FREE_BYTE_STRING(kay);

    if (error != CborNoError) {
        if (error == CborErrorImproperValue) {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        return error;
    }
    res_APDU_size = (uint16_t)resp_size;
    return 0;
}

int cbor_vendor(const uint8_t *data, size_t len) {
    if (len == 0) {
        return CTAP1_ERR_INVALID_LEN;
    }
    if (data[0] >= CTAP_VENDOR_BACKUP) {
        return cbor_vendor_generic(data[0], data + 1, len - 1);
    }
    return CTAP2_ERR_INVALID_CBOR;
}
