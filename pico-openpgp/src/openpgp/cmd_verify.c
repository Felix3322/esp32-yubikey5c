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
#include "mbedtls/platform_util.h"

/* The record of the PW a VERIFY names (EF_PW1 or EF_PW3), NULL (6A88) when
 * the card has none or no PW status record to count its retries in. */
static file_t *verify_pw_file(uint16_t fid) {
    file_t *pw = search_by_fid(fid, NULL, SPECIFY_EF);
    if (!file_has_data(pw) || !search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF)) {
        return NULL;
    }
    return pw;
}

int openpgp_verify_pw3(const uint8_t *pin, size_t len) {
    file_t *pw = verify_pw_file(EF_PW3);
    if (!pw) {
        return SW_REFERENCE_NOT_FOUND();
    }
    return check_pin(pw, pin, len);
}

int cmd_verify() {
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);

    if (p1 == 0xFF) {
        if (apdu.nc != 0) {
            return SW_WRONG_DATA();
        }
        if (p2 == 0x81) {
            has_pw1 = false;
        }
        else if (p2 == 0x82) {
            has_pw2 = false;
        }
        else if (p2 == 0x83) {
            has_pw3 = false;
            mbedtls_platform_zeroize(session_pw3, sizeof(session_pw3));
        }
        else {
            return SW_WRONG_P1P2();
        }
        if (!has_pw1 && !has_pw2) {
            mbedtls_platform_zeroize(session_pw1, sizeof(session_pw1));
        }
        if (!has_pw1 && !has_pw2 && !has_pw3) {
            isUserAuthenticated = false;
        }
        return SW_OK();
    }
    else if (p1 != 0x0 || p2 < 0x81 || p2 > 0x83) {
        return SW_WRONG_P1P2();
    }
    /* 81 and 82 both name PW1 (for signing / for the other operations) */
    uint16_t fid = (p2 == 0x83) ? EF_PW3 : EF_PW1;
    file_t *pw = verify_pw_file(fid), *pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF);
    if (!pw) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (apdu.nc > 0) {
        return check_pin(pw, apdu.data, apdu.nc);
    }
    uint16_t idx = 3 + (fid & 0xf);
    if (idx >= file_get_size(pw_status)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint8_t retries = file_get_data(pw_status)[idx];
    if (retries == 0) {
        return SW_PIN_BLOCKED();
    }
    if ((p2 == 0x81 && has_pw1) || (p2 == 0x82 && has_pw2) || (p2 == 0x83 && has_pw3)) {
        return SW_OK();
    }
    return set_res_sw(0x63, 0xc0 | MIN(retries, 15));
}
