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

#include "openpgp.h"
#include "do.h"
#include "mbedtls/platform_util.h"

int cmd_internal_aut() {
    if (P1(apdu) != 0x00 || P2(apdu) != 0x00) {
        return SW_WRONG_P1P2();
    }
    /* PW1 in mode 82 (OpenPGP card 3.4, 7.2.13); PW3 does not use keys */
    if (!has_pw2) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    file_t *algo_ef = search_by_fid(algo_aut, NULL, SPECIFY_EF);
    if (!algo_ef) {
        return SW_REFERENCE_NOT_FOUND();
    }
    const uint8_t *algo = algorithm_attr_rsa2k + 1;
    uint16_t algo_len = algorithm_attr_rsa2k[0];
    if (algo_ef && algo_ef->data) {
        algo = file_get_data(algo_ef);
        algo_len = file_get_size(algo_ef);
    }
    (void) algo_len;                /* used by the Curve25519 branch only */
    file_t *ef = search_by_fid(pk_aut, NULL, SPECIFY_EF);
    if (!ef) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (wait_button_pressed_fid(EF_UIF_AUT) == true) {
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
        size_t olen = 0;
        r = rsa_sign(&ctx, apdu.data, apdu.nc, res_APDU, &olen);
        mbedtls_rsa_free(&ctx);
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
        res_APDU_size = olen;
    }
#ifdef OPGP_LF_25519
    else if (lf25519_attr_curve(algo, algo_len) != 0) {
        /* EdDSA over the data as given; an X25519 key cannot sign */
        uint8_t seed[32];
        if (lf25519_attr_curve(algo, algo_len) != LF_CURVE_ED25519) {
            return SW_CONDITIONS_NOT_SATISFIED();
        }
        if (lf25519_load(ef, LF_CURVE_ED25519, seed, KEY_MODE_DEK) != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
        r = lf_ed25519_sign(res_APDU, apdu.data, apdu.nc, seed, NULL);
        mbedtls_platform_zeroize(seed, sizeof(seed));
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
        res_APDU_size = LF_ED25519_SIG_LEN;
    }
#endif
    else if (algo[0] == ALGO_ECDH || algo[0] == ALGO_ECDSA || algo[0] == ALGO_EDDSA) {
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
    }
    return SW_OK();
}
