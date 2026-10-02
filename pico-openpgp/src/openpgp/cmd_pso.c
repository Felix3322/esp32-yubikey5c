/*
 * This file is part of the Pico OpenPGP distribution (https://github.com/polhenarejos/pico-openpgp).
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

#ifdef ESP_PLATFORM
#include "esp_compat.h"
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#else
#include "common.h"
#endif
#include "openpgp.h"
#include "do.h"
#include "random.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/asn1.h"
#include "mbedtls/platform_util.h"

/* PSO: COMPUTE DIGITAL SIGNATURE (9E 9A, PW1 81) and DECIPHER (80 86,
 * PW1 82), OpenPGP card 3.4, 7.2.10 and 7.2.11. The admin PIN does not use
 * the keys. Symmetric (AES) PSO is not offered: the card has no AES key. */
int cmd_pso() {
    uint16_t algo_fid = 0x0, pk_fid = 0x0;
    if (P1(apdu) == 0x9E && P2(apdu) == 0x9A) {
        if (!has_pw1) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        algo_fid = EF_ALGO_PRIV1;
        pk_fid = EF_PK_SIG;
    }
    else if (P1(apdu) == 0x80 && P2(apdu) == 0x86) {
        if (!has_pw2) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        algo_fid = algo_dec;
        pk_fid = pk_dec;
    }
    else {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc == 0) {
        return SW_WRONG_LENGTH();
    }
    file_t *algo_ef = search_by_fid(algo_fid, NULL, SPECIFY_EF);
    if (!algo_ef) {
        return SW_REFERENCE_NOT_FOUND();
    }
    const uint8_t *algo = algorithm_attr_rsa2k + 1;
    uint16_t algo_len = algorithm_attr_rsa2k[0];
    if (algo_ef && algo_ef->data) {
        algo = file_get_data(algo_ef);
        algo_len = file_get_size(algo_ef);
    }
    file_t *ef = search_by_fid(pk_fid, NULL, SPECIFY_EF);
    if (!ef) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (wait_button_pressed_fid(pk_fid == EF_PK_SIG ? EF_UIF_SIG : EF_UIF_DEC) == true) {
        return SW_SECURE_MESSAGE_EXEC_ERROR();
    }
    int r = PICOKEY_OK;
    if (algo[0] == ALGO_RSA) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        r = load_private_key_rsa(&ctx, ef, KEY_MODE_DEK);
        if (r != PICOKEY_OK) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        if (P1(apdu) == 0x9E && P2(apdu) == 0x9A) {
            size_t olen = 0;
            r = rsa_sign(&ctx, apdu.data, apdu.nc, res_APDU, &olen);
            mbedtls_rsa_free(&ctx);
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            res_APDU_size = olen;
            //apdu.ne = key_size;
            inc_sig_count();
        }
        else if (P1(apdu) == 0x80 && P2(apdu) == 0x86) {
            /* padding indicator 00, then the cryptogram, left-padded to the
             * modulus length when the host dropped leading zeros */
            size_t key_size = mbedtls_rsa_get_len(&ctx), clen = apdu.nc - 1;
            if (apdu.data[0] != 0x00 || clen == 0 || clen > key_size) {
                mbedtls_rsa_free(&ctx);
                return SW_WRONG_DATA();
            }
            if (clen < key_size) {
                memmove(apdu.data + 1 + (key_size - clen), apdu.data + 1, clen);
                memset(apdu.data + 1, 0, key_size - clen);
            }
            size_t olen = 0;
            r = mbedtls_rsa_pkcs1_decrypt(&ctx,
                                          random_gen,
                                          NULL,
                                          &olen,
                                          apdu.data + 1,
                                          res_APDU,
                                          key_size);
            mbedtls_rsa_free(&ctx);
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            res_APDU_size = olen;
        }
    }
#ifdef OPGP_LF_25519
    else if (lf25519_attr_curve(algo, algo_len) != 0) {
        int curve = lf25519_attr_curve(algo, algo_len);
        uint8_t secret[32];
        if (P1(apdu) == 0x9E && P2(apdu) == 0x9A) {
            /* EdDSA over the data as given (PureEdDSA) */
            if (curve != LF_CURVE_ED25519) {
                return SW_CONDITIONS_NOT_SATISFIED();
            }
            if (lf25519_load(ef, curve, secret, KEY_MODE_DEK) != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
            /* the public key is derived from the seed, never taken from
             * a file: a wrong one would give the private key away */
            r = lf_ed25519_sign(res_APDU, apdu.data, apdu.nc, secret, NULL);
            mbedtls_platform_zeroize(secret, sizeof(secret));
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            res_APDU_size = LF_ED25519_SIG_LEN;
            inc_sig_count();
        }
        else {
            /* A6 { 7F49 { 86 <u, 32 bytes (or 40 || u)> } }: the shared
             * secret, 32 bytes */
            uint8_t *data = apdu.data, *end = data + apdu.nc;
            size_t len = 0;
            if (curve != LF_CURVE_X25519) {
                return SW_CONDITIONS_NOT_SATISFIED();
            }
            if (mbedtls_asn1_get_tag(&data, end, &len, 0xA6) != 0 || data >= end || *data++ != 0x7f ||
                mbedtls_asn1_get_tag(&data, end, &len, 0x49) != 0 ||
                mbedtls_asn1_get_tag(&data, end, &len, 0x86) != 0) {
                return SW_WRONG_DATA();
            }
            if (len == 33 && data[0] == 0x40) {
                data++;
                len--;
            }
            if (len != LF_X25519_LEN) {
                return SW_WRONG_DATA();
            }
            if (lf25519_load(ef, curve, secret, KEY_MODE_DEK) != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
            r = lf_x25519(res_APDU, secret, data);
            mbedtls_platform_zeroize(secret, sizeof(secret));
            if (r != 0) {
                return SW_DATA_INVALID();       /* a point of small order */
            }
            res_APDU_size = LF_X25519_LEN;
        }
    }
#endif
    else if (algo[0] == ALGO_ECDH || algo[0] == ALGO_ECDSA || algo[0] == ALGO_EDDSA) {
        if (P1(apdu) == 0x9E && P2(apdu) == 0x9A) {
            mbedtls_ecp_keypair ctx;
            mbedtls_ecp_keypair_init(&ctx);
            r = load_private_key_ecdsa(&ctx, ef, KEY_MODE_DEK);
            if (r != PICOKEY_OK) {
                mbedtls_ecp_keypair_free(&ctx);
                return SW_EXEC_ERROR();
            }
            size_t olen = 0;
            r = ecdsa_sign(&ctx, apdu.data, apdu.nc, res_APDU, &olen);
            mbedtls_ecp_keypair_free(&ctx);
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            res_APDU_size = olen;
            inc_sig_count();
        }
        else if (P1(apdu) == 0x80 && P2(apdu) == 0x86) {
            /* A6 { 7F49 { 86 <public point> } } */
            uint8_t *data = apdu.data, *end = data + apdu.nc;
            size_t len = 0;
            if (mbedtls_asn1_get_tag(&data, end, &len, 0xA6) != 0) {
                return SW_WRONG_DATA();
            }
            if (data >= end || *data++ != 0x7f) {
                return SW_WRONG_DATA();
            }
            if (mbedtls_asn1_get_tag(&data, end, &len,
                                     0x49) != 0 ||
                mbedtls_asn1_get_tag(&data, end, &len, 0x86) != 0 || len == 0 || len > 255) {
                return SW_WRONG_DATA();
            }
            /* the key loader checks the stored record and wipes it */
            mbedtls_ecp_keypair kp;
            mbedtls_ecp_keypair_init(&kp);
            r = load_private_key_ecdsa(&kp, ef, KEY_MODE_DEK);
            if (r != PICOKEY_OK) {
                mbedtls_ecp_keypair_free(&kp);
                return SW_EXEC_ERROR();
            }
            /* the key must be of the curve the attributes announce */
            if (algo_len < 2 || kp.grp.id != get_ec_group_id_from_attr(algo + 1, algo_len - 1)) {
                mbedtls_ecp_keypair_free(&kp);
                return SW_CONDITIONS_NOT_SATISFIED();
            }
            mbedtls_ecdh_context ctx;
            mbedtls_ecdh_init(&ctx);
            r = mbedtls_ecdh_setup(&ctx, kp.grp.id);
            if (r == 0) {
                r = mbedtls_mpi_copy(&ctx.ctx.mbed_ecdh.d, &kp.d);
            }
            mbedtls_ecp_keypair_free(&kp);
            if (r != 0) {
                mbedtls_ecdh_free(&ctx);
                return SW_DATA_INVALID();
            }
            /* TLS ECPoint: the length byte just before the point */
            r = mbedtls_ecdh_read_public(&ctx, data - 1, len + 1);
            if (r != 0) {
                mbedtls_ecdh_free(&ctx);
                return SW_DATA_INVALID();
            }
            size_t olen = 0;
            r = mbedtls_ecdh_calc_secret(&ctx,
                                         &olen,
                                         res_APDU,
                                         MBEDTLS_ECP_MAX_BYTES,
                                         random_gen,
                                         NULL);
            mbedtls_ecdh_free(&ctx);
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            res_APDU_size = olen;
        }
    }
    else {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    return SW_OK();
}
