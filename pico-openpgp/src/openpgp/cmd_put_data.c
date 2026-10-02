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

/* Algorithm attributes the card implements (OpenPGP card 3.4, 4.4.3.9):
 * RSA 1024-4096 (P and Q are what IMPORT DATA reads), or a curve known to
 * get_ec_group_id_from_attr() with an algorithm that fits it and the key. */
static bool algo_attr_valid(uint16_t tag, const uint8_t *a, uint16_t len) {
    if (len < 1 || len > 16) {
        return false;
    }
    if (a[0] == ALGO_RSA) {
        if (len != 5 && len != 6) {
            return false;
        }
        uint16_t nbits = (a[1] << 8) | a[2], ebits = (a[3] << 8) | a[4];
        return (nbits == 1024 || nbits == 2048 || nbits == 3072 || nbits == 4096) &&
               ebits >= 17 && ebits <= 32 && (len == 5 || a[5] <= 3);
    }
#ifdef OPGP_LF_25519
    /* EdDSA ed25519 for signing and authentication, ECDH cv25519 for
     * decryption (and, as other ECDH keys, the authentication key MSE can
     * make the decryption key) */
    int lc = lf25519_attr_curve(a, len);
    if (lc == LF_CURVE_ED25519) {
        return tag != EF_ALGO_DEC;
    }
    if (lc == LF_CURVE_X25519) {
        return tag != EF_ALGO_SIG;
    }
#endif
    mbedtls_ecp_group_id gid = get_ec_group_id_from_attr(a + 1, len - 1);
    if (gid == MBEDTLS_ECP_DP_NONE) {
        return false;
    }
    bool mont = (gid == MBEDTLS_ECP_DP_CURVE25519 || gid == MBEDTLS_ECP_DP_CURVE448), edw = false;
#ifdef MBEDTLS_EDDSA_C
    edw = (gid == MBEDTLS_ECP_DP_ED25519 || gid == MBEDTLS_ECP_DP_ED448);
#endif
    switch (a[0]) {
        case ALGO_ECDH:
            return !edw && tag != EF_ALGO_SIG;
        case ALGO_ECDSA:
            return !edw && !mont && tag != EF_ALGO_DEC;
        case ALGO_EDDSA:
            return edw && tag != EF_ALGO_DEC;
    }
    return false;
}

/* A new algorithm makes the key of the slot unusable: it goes, with its
 * public key, fingerprint and generation time. */
static int invalidate_key(uint16_t algo_tag) {
    uint16_t off = algo_tag - EF_ALGO_SIG;
    const uint16_t fids[] = { EF_PK_SIG + off, EF_PB_SIG + off, EF_FP_SIG + off, EF_TS_SIG + off };
    for (size_t i = 0; i < sizeof(fids) / sizeof(fids[0]); i++) {
        file_t *ef = search_by_fid(fids[i], NULL, SPECIFY_EF);
        if (file_has_data(ef)) {
            int r = flash_clear_file(ef);
            if (r != PICOKEY_OK) {
                return r;
            }
        }
    }
    return PICOKEY_OK;
}

/* C4: only byte 1, "PW1 valid for one or several signatures"; the retry
 * counters of the record are never written by the host. */
static int put_pw_status(void) {
    if (apdu.nc != 1 && apdu.nc != 4) {
        return SW_WRONG_LENGTH();
    }
    if (apdu.data[0] > 1) {
        return SW_WRONG_DATA();
    }
    if (openpgp_pw_status_set(0, apdu.data[0]) != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    low_flash_available();
    return SW_OK();
}

/* D3: sets the Reset Code (8 to 127 bytes), or removes it (no data). */
static int put_reset_code(void) {
    file_t *rc = search_by_fid(EF_RC, NULL, SPECIFY_EF);
    if (!rc) {
        return SW_REFERENCE_NOT_FOUND();
    }
    has_rc = false;
    mbedtls_platform_zeroize(session_rc, sizeof(session_rc));
    int r = PICOKEY_OK;
    if (apdu.nc == 0) {
        /* the code first: a stale slot without its code is harmless */
        if (file_has_data(rc)) {
            r = flash_clear_file(rc);
        }
        if (r == PICOKEY_OK) {
            r = dek_store_slot(2, 1, NULL);
        }
        if (r == PICOKEY_OK) {
            r = openpgp_pw_status_set(3 + (EF_RC & 0xf), 0);
        }
    }
    else {
        if (apdu.nc < 8 || apdu.nc > 127) {
            return SW_WRONG_LENGTH();
        }
        /* the data key from PW3's slot; the record marked as written by
         * this firmware (RC_MARK) */
        r = pw_replace(rc, 2, 1, apdu.data, (uint16_t) apdu.nc, (uint8_t) (apdu.nc | RC_MARK), NULL);
        if (r == PICOKEY_OK) {
            r = pin_reset_retries(rc, true);
        }
    }
    if (r == PICOKEY_NO_LOGIN) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (r != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    low_flash_available();
    return SW_OK();
}

/* Length of a DO value (no data deletes the DO). */
static bool do_len_ok(uint16_t tag, size_t len) {
    if (len == 0) {
        return true;
    }
    switch (tag) {
        case EF_CH_NAME:
            return len <= 39;
        case EF_LANG_PREF:
            return len <= 8;
        case EF_SEX:
            return len == 1;
        case EF_LOGIN_DATA: case EF_URI_URL: case EF_KDF:
            return len <= 255;      /* extended capabilities: special DOs */
        case EF_CH_CERT:
            return len <= 2048;     /* extended capabilities: certificate */
        case EF_FP_SIG: case EF_FP_DEC: case EF_FP_AUT:
        case EF_FP_CA1: case EF_FP_CA2: case EF_FP_CA3:
            return len == 20;
        case EF_TS_SIG: case EF_TS_DEC: case EF_TS_AUT:
            return len == 4;
    }
    return false;
}

int cmd_put_data() {
    uint16_t tag = (P1(apdu) << 8) | P2(apdu);
    /* Only OpenPGP data objects: the file table also holds the PIV and FIDO
     * files and search_by_fid() answers the device files, none of which may
     * ever be written from here. */
    if (!openpgp_do_writable(tag)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!has_pw3) {                 /* OpenPGP card 3.4, 7.2.8 */
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (tag == EF_PW_STATUS) {
        return put_pw_status();
    }
    if (tag == EF_RESET_CODE) {
        return put_reset_code();
    }
    file_t *ef = NULL;
    bool is_algo = (tag == EF_ALGO_SIG || tag == EF_ALGO_DEC || tag == EF_ALGO_AUT);
    bool is_uif = (tag == EF_UIF_SIG || tag == EF_UIF_DEC || tag == EF_UIF_AUT);
    if (tag == EF_CH_CERT) {
        ef = openpgp_ch_cert_file();    /* instance chosen by SELECT DATA */
    }
    else {
        ef = search_by_fid(is_algo ? (tag | 0x1000) : tag, NULL, SPECIFY_EF);
    }
    if (!ef || !(ef->type & FILE_DATA_FLASH)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    int r = PICOKEY_OK;
    if (is_algo) {
        if (!algo_attr_valid(tag, apdu.data, (uint16_t) apdu.nc)) {
            return SW_WRONG_DATA();
        }
        const uint8_t *cur = algorithm_attr_rsa2k + 1;
        uint16_t cur_len = algorithm_attr_rsa2k[0];
        if (file_has_data(ef)) {
            cur = file_get_data(ef);
            cur_len = file_get_size(ef);
        }
        if (cur_len != apdu.nc || memcmp(cur, apdu.data, cur_len) != 0) {
            r = invalidate_key(tag);
        }
    }
    else if (is_uif) {
        /* 0 off, 1 on, 2 permanently on, 3/4 cached (a touch every time
         * here); then the button feature 0x20 */
        if (apdu.nc != 2 || apdu.data[0] > 4 || apdu.data[1] != 0x20) {
            return SW_WRONG_DATA();
        }
        if (file_has_data(ef) && (file_get_data(ef)[0] == 2 || file_get_data(ef)[0] == 4) &&
            file_get_data(ef)[0] != apdu.data[0]) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
    }
    else if (!do_len_ok(tag, apdu.nc)) {
        return SW_WRONG_LENGTH();
    }
    if (r == PICOKEY_OK) {
        if (apdu.nc > 0) {
            r = file_put_data(ef, apdu.data, (uint16_t) apdu.nc);
        }
        else if (file_has_data(ef)) {
            r = flash_clear_file(ef);           /* no data: the DO goes */
        }
    }
    if (r != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    low_flash_available();
    return SW_OK();
}
