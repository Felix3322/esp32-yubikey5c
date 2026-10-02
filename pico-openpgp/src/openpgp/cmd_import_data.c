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
#include "random.h"
#include "do.h"
#include "mbedtls/platform_util.h"

/* BER length at *p (short form, 81 or 82), within lim. */
static int tag_len(uint8_t **p, const uint8_t *lim, uint16_t *out) {
    if (*p >= lim) {
        return -1;
    }
    uint8_t b = *(*p)++;
    if (b < 0x80) {
        *out = b;
    }
    else if (b == 0x81 && lim - *p >= 1) {
        *out = *(*p)++;
    }
    else if (b == 0x82 && lim - *p >= 2) {
        *out = (uint16_t) (((*p)[0] << 8) | (*p)[1]);
        *p += 2;
    }
    else {
        return -1;
    }
    return 0;
}

/* Extended header list (OpenPGP card 3.4, 4.4.3.12):
 * 4D { CRT (B6/B8/A4), 7F48 { tag len ... }, 5F48 { values } }. Every
 * length is checked against what the host sent. */
int cmd_import_data() {
    file_t *ef = NULL;
    uint16_t fid = 0x0;
    if (P1(apdu) != 0x3F || P2(apdu) != 0xFF) {
        return SW_WRONG_P1P2();
    }
    if (apdu.nc < 5) {
        return SW_WRONG_LENGTH();
    }
    if (!has_pw3) {                 /* key import needs the admin PIN */
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t *start = apdu.data;
    const uint8_t *lim = apdu.data + apdu.nc;
    uint16_t tgl = 0;
    if (*start++ != 0x4D || tag_len(&start, lim, &tgl) != 0 || tgl > lim - start) {
        return SW_WRONG_DATA();
    }
    lim = start + tgl;
    if (start >= lim) {
        return SW_WRONG_DATA();
    }
    if (*start == 0xB6) {
        fid = EF_PK_SIG;
    }
    else if (*start == 0xB8) {
        fid = EF_PK_DEC;
    }
    else if (*start == 0xA4) {
        fid = EF_PK_AUT;
    }
    else {
        return SW_WRONG_DATA();
    }
    start++;
    if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (tag_len(&start, lim, &tgl) != 0 || tgl > lim - start) {    /* CRT content */
        return SW_WRONG_DATA();
    }
    start += tgl;
    if (lim - start < 2 || start[0] != 0x7F || start[1] != 0x48) {
        return SW_WRONG_DATA();
    }
    start += 2;
    if (tag_len(&start, lim, &tgl) != 0 || tgl > lim - start) {
        return SW_WRONG_DATA();
    }
    /* 91 e, 92 p, 93 q, 94-97 CRT parts, 99 public key: in the order given */
    uint8_t *end = start + tgl, *p[9] = { 0 }, order[9];
    uint16_t len[9] = { 0 }, seen = 0;
    uint32_t sum = 0;
    int ntags = 0;
    while (start < end) {
        uint8_t tag = *start++;
        uint16_t l = 0;
        if (!((tag >= 0x91 && tag <= 0x97) || tag == 0x99) || tag_len(&start, end, &l) != 0) {
            return SW_WRONG_DATA();
        }
        uint8_t t = tag - 0x91;
        if (seen & (1 << t) || l > 512) {
            return SW_WRONG_DATA();
        }
        seen |= 1 << t;
        len[t] = l;
        order[ntags++] = t;
        sum += l;
    }
    if (lim - start < 2 || start[0] != 0x5F || start[1] != 0x48) {
        return SW_WRONG_DATA();
    }
    start += 2;
    if (tag_len(&start, lim, &tgl) != 0 || tgl > lim - start || tgl != sum) {
        return SW_WRONG_DATA();
    }
    for (int i = 0; i < ntags; i++) {
        p[order[i]] = start;
        start += len[order[i]];
    }

    file_t *algo_ef = search_by_fid(fid - 0x0010, NULL, SPECIFY_EF);
    if (!algo_ef) {
        return SW_REFERENCE_NOT_FOUND();
    }
    const uint8_t *algo = algorithm_attr_rsa2k + 1;
    uint16_t algo_len = algorithm_attr_rsa2k[0];
    if (algo_ef && algo_ef->data) {
        algo = file_get_data(algo_ef);
        algo_len = file_get_size(algo_ef);
    }
    int r = 0;
    if (algo[0] == ALGO_RSA) {
        mbedtls_rsa_context rsa;
        if (algo_len < 3 || p[0] == NULL || len[0] == 0 || p[1] == NULL || len[1] == 0 ||
            p[2] == NULL || len[2] == 0) {
            return SW_WRONG_DATA();
        }
        size_t nbits = (algo[1] << 8) | algo[2];
        mbedtls_rsa_init(&rsa);
        r = mbedtls_mpi_read_binary(&rsa.E, p[0], len[0]);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        /* only P and Q are stored; the key is used with e = 65537 */
        if (mbedtls_mpi_cmp_int(&rsa.E, 65537) != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_WRONG_DATA();
        }
        r = mbedtls_mpi_read_binary(&rsa.P, p[1], len[1]);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_mpi_read_binary(&rsa.Q, p[2], len[2]);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_rsa_import(&rsa, NULL, &rsa.P, &rsa.Q, NULL, &rsa.E);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_rsa_complete(&rsa);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_rsa_check_privkey(&rsa);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        /* the modulus the algorithm attributes announce (store_keys() also
         * refuses primes too unbalanced for its P || Q record) */
        if (mbedtls_mpi_bitlen(&rsa.N) != nbits || nbits > 4096) {
            mbedtls_rsa_free(&rsa);
            return SW_WRONG_DATA();
        }
        r = store_keys(&rsa, ALGO_RSA, fid, KEY_MODE_DEK);
        make_rsa_response(&rsa);
        mbedtls_rsa_free(&rsa);
        if (r != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
    }
#ifdef OPGP_LF_25519
    else if (lf25519_attr_curve(algo, algo_len) != 0) {
        /* 92: the Ed25519 seed, or the cv25519 scalar as GnuPG keeps it (an
         * MPI: big endian); leading zero bytes may have been dropped. 99, if
         * given, is the public key (native form, possibly after 40) and must
         * be the one of the private key. */
        int curve = lf25519_attr_curve(algo, algo_len);
        uint8_t secret[32] = { 0 }, pub[32];
        if (p[1] == NULL || len[1] == 0 || len[1] > 32) {
            return SW_WRONG_DATA();
        }
        memcpy(secret + 32 - len[1], p[1], len[1]);
        if (curve == LF_CURVE_X25519) {
            for (int i = 0; i < 16; i++) {
                uint8_t t = secret[i];
                secret[i] = secret[31 - i];
                secret[31 - i] = t;
            }
        }
        r = lf25519_public(curve, secret, pub) == 0 ? PICOKEY_OK : PICOKEY_EXEC_ERROR;
        if (r == PICOKEY_OK && p[8] != NULL) {
            const uint8_t *q = p[8];
            uint16_t qlen = len[8];
            if (qlen == 33 && q[0] == 0x40) {
                q++;
                qlen--;
            }
            if (qlen != 32 || memcmp(q, pub, 32) != 0) {
                r = PICOKEY_WRONG_DATA;
            }
        }
        if (r == PICOKEY_OK) {
            r = lf25519_store(fid, curve, secret, KEY_MODE_DEK);
        }
        mbedtls_platform_zeroize(secret, sizeof(secret));
        if (r == PICOKEY_WRONG_DATA) {
            return SW_WRONG_DATA();
        }
        if (r != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
        make_25519_response(pub);
    }
#endif
    else if (algo[0] == ALGO_ECDSA || algo[0] == ALGO_ECDH || algo[0] == ALGO_EDDSA) {
        mbedtls_ecp_keypair ecdsa;
        if (p[1] == NULL || len[1] == 0 || len[1] > 66) {
            return SW_WRONG_DATA();
        }
        mbedtls_ecp_group_id gid = get_ec_group_id_from_attr(algo + 1, algo_len - 1);
        if (gid == MBEDTLS_ECP_DP_NONE) {
            return SW_FUNC_NOT_SUPPORTED();
        }
        mbedtls_ecp_keypair_init(&ecdsa);
        if (gid == MBEDTLS_ECP_DP_CURVE25519) {
            mbedtls_ecp_group_load(&ecdsa.grp, gid);
            r = mbedtls_mpi_read_binary(&ecdsa.d, p[1], len[1]);
        }
        else {
            r = mbedtls_ecp_read_key(gid, &ecdsa, p[1], len[1]);
        }
        if (r != 0) {
            mbedtls_ecp_keypair_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
#ifdef MBEDTLS_EDDSA_C
        if (ecdsa.grp.id == MBEDTLS_ECP_DP_ED25519) {
            r = mbedtls_ecp_point_edwards(&ecdsa.grp, &ecdsa.Q, &ecdsa.d, random_gen, NULL);
        }
        else
#endif
        {
            r = mbedtls_ecp_mul(&ecdsa.grp, &ecdsa.Q, &ecdsa.d, &ecdsa.grp.G, random_gen, NULL);
        }
        if (r != 0) {
            mbedtls_ecp_keypair_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        r = store_keys(&ecdsa, ALGO_ECDSA, fid, KEY_MODE_DEK);
        make_ecdsa_response(&ecdsa);
        mbedtls_ecp_keypair_free(&ecdsa);
        if (r != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
    }
    else {
        return SW_FUNC_NOT_SUPPORTED();
    }
    if (fid == EF_PK_SIG) {
        reset_sig_count();
    }
    file_t *pbef = search_by_fid(fid + 3, NULL, SPECIFY_EF);
    if (!pbef) {
        return SW_REFERENCE_NOT_FOUND();
    }
    r = file_put_data(pbef, res_APDU, res_APDU_size);
    if (r != PICOKEY_OK) {
        return SW_EXEC_ERROR();
    }
    res_APDU_size = 0; //make_*_response sets a response. we need to overwrite
    return SW_OK();
}
