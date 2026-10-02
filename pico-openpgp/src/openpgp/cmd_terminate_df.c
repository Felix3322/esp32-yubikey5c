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

int cmd_terminate_df() {
    if (P1(apdu) != 0x0 || P2(apdu) != 0x0) {
        return SW_INCORRECT_P1P2();
    }
    file_t *retries;
    if (!(retries = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF)) || file_get_size(retries) < 7) {
        return SW_REFERENCE_NOT_FOUND();
    }
    /* PW3, or PW3 blocked */
    if (!has_pw3 && *(file_get_data(retries) + 6) > 0) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }
    /* A reset destroys the keys: a physical press, whatever presence
     * policy the profile has for OpenPGP. */
    if (wait_button() == true) {
        return SW_SECURE_MESSAGE_EXEC_ERROR();
    }
    /* The OpenPGP application only (formerly the whole key store). */
    if (openpgp_reset() != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    return SW_OK();
}
