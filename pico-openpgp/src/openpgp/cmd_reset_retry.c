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

/* RESET RETRY COUNTER of PW1: P1 00 with Reset Code || new PW1, P1 02 with
 * the new PW1 after PW3. */
int cmd_reset_retry() {
    if (P2(apdu) != 0x81) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (P1(apdu) != 0x0 && P1(apdu) != 0x2) {
        return SW_INCORRECT_P1P2();
    }
    file_t *pw = search_by_fid(EF_PW1, NULL, SPECIFY_EF);
    if (!pw) {
        return SW_REFERENCE_NOT_FOUND();
    }
    size_t newpin_len = 0;
    uint8_t src = 2;
    if (P1(apdu) == 0x0) {
        file_t *rc = search_by_fid(EF_RC, NULL, SPECIFY_EF);
        if (!rc) {
            return SW_REFERENCE_NOT_FOUND();
        }
        /* no Reset Code set, or one of earlier firmware (its data key slot
         * has another form; it is dropped at the next selection) */
        uint8_t rec[PW_REC_LEN];
        if (!file_has_data(rc) || pw_rec_read(rc, rec) != PICOKEY_OK || !(rec[0] & RC_MARK)) {
            mbedtls_platform_zeroize(rec, sizeof(rec));
            return SW_PIN_BLOCKED();
        }
        uint8_t pin_len = rec[0] & ~RC_MARK;
        mbedtls_platform_zeroize(rec, sizeof(rec));
        src = 1;
        if (pin_len == 0 || apdu.nc <= pin_len) {
            return SW_WRONG_LENGTH();
        }
        newpin_len = apdu.nc - pin_len;
        if (newpin_len < 6 || newpin_len > 127) {
            return SW_WRONG_LENGTH();
        }
        /* only the Reset Code opens the data key here */
        openpgp_logout();
        uint16_t r = check_pin(rc, apdu.data, pin_len);
        if (r != 0x9000) {
            return r;
        }
        has_rc = true;
        hash_multi(apdu.data, pin_len, session_rc);
    }
    else {
        if (!has_pw3) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        newpin_len = apdu.nc;
        if (newpin_len < 6 || newpin_len > 127) {
            return SW_WRONG_LENGTH();
        }
    }
    /* the data key from the Reset Code's or PW3's slot into PW1's */
    int r = pw_replace(pw, src, 0, apdu.data + (apdu.nc - newpin_len), (uint16_t) newpin_len,
                       (uint8_t) newpin_len, NULL);
    if (r == PICOKEY_OK) {
        r = pin_reset_retries(pw, true);
    }
    /* the Reset Code session ends here; PW1 is not verified by this */
    has_rc = has_pw1 = has_pw2 = false;
    mbedtls_platform_zeroize(session_rc, sizeof(session_rc));
    mbedtls_platform_zeroize(session_pw1, sizeof(session_pw1));
    if (r != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    low_flash_available();
    return SW_OK();
}
