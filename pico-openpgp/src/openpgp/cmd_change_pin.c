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

/* CHANGE REFERENCE DATA: old || new PW1 (P2 81) or PW3 (P2 83). */
int cmd_change_pin() {
    if (P1(apdu) != 0x0 || (P2(apdu) != 0x81 && P2(apdu) != 0x83)) {
        return SW_WRONG_P1P2();
    }
    bool is_pw3 = (P2(apdu) == 0x83);
    file_t *pw = search_by_fid(is_pw3 ? EF_PW3 : EF_PW1, NULL, SPECIFY_EF);
    uint8_t rec[PW_REC_LEN];
    if (!file_has_data(pw) || pw_rec_read(pw, rec) != PICOKEY_OK) {
        return SW_REFERENCE_NOT_FOUND();
    }
    /* the stored length splits the data into old and new PW */
    uint8_t pin_len = rec[0];
    mbedtls_platform_zeroize(rec, sizeof(rec));
    if (pin_len == 0 || apdu.nc <= pin_len) {
        return SW_WRONG_LENGTH();
    }
    size_t new_len = apdu.nc - pin_len;
    if (new_len < (is_pw3 ? 8 : 6) || new_len > 127) {
        return SW_WRONG_LENGTH();
    }
    uint16_t r = check_pin(pw, apdu.data, pin_len);
    if (r != 0x9000) {
        return r;
    }
    /* The data key comes from the slot of the PW just verified, and goes
     * back under the new PW; the session goes on with the new PW. If the PW
     * record cannot be written, pw_replace() puts the data key file back:
     * the old PW keeps opening its slot. */
    int slot = is_pw3 ? 2 : 0;
    int ret = pw_replace(pw, slot, slot, apdu.data + pin_len, (uint16_t) new_len, (uint8_t) new_len,
                         is_pw3 ? session_pw3 : session_pw1);
    if (ret != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    low_flash_available();
    return SW_OK();
}
