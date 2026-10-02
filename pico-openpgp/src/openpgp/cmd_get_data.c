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
#include "asn1.h"

/* File of the cardholder certificate instance chosen by SELECT DATA (the
 * first one by default). */
file_t *openpgp_ch_cert_file(void) {
    if (currentEF && currentEF->fid >= EF_CH_1 && currentEF->fid <= EF_CH_3) {
        return currentEF;
    }
    return search_by_fid(EF_CH_1, NULL, SPECIFY_EF);
}

int cmd_get_data() {
    if (apdu.nc > 0) {
        return SW_WRONG_LENGTH();
    }
    uint16_t fid = (P1(apdu) << 8) | P2(apdu);
    file_t *ef;
    /* The file table also holds the PIV and FIDO files, and search_by_fid()
     * answers the device-level files (root key, ...): only OpenPGP data
     * objects are ever looked up here. */
    if (!openpgp_do_readable(fid) || !(ef = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!authenticate_action(ef, ACL_OP_READ_SEARCH)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (fid == EF_CH_CERT) {
        /* the certificate as stored by PUT DATA, like other OpenPGP cards */
        file_t *cf = openpgp_ch_cert_file();
        res_APDU_size = file_get_size(cf);
        if (res_APDU_size > 0) {
            memcpy(res_APDU, file_get_data(cf), res_APDU_size);
        }
        return SW_OK();
    }
    select_file(ef);
    if (ef->data) {
        uint16_t fids[] = { 1, fid };
        uint16_t data_len = parse_do(fids, 1);
        uint8_t *p = NULL;
        uint16_t tg = 0;
        uint16_t tg_len = 0;
        asn1_ctx_t ctxi;
        asn1_ctx_init(res_APDU, data_len, &ctxi);
        if (walk_tlv(&ctxi, &p, &tg, &tg_len, NULL)) {
            uint8_t dec = 2;
            if ((tg & 0x1f) == 0x1f) {
                dec++;
            }
            if ((res_APDU[dec - 1] & 0xF0) == 0x80) {
                dec += (res_APDU[dec - 1] & 0x0F);
            }
            if (tg_len + dec == data_len) {
                memmove(res_APDU, res_APDU + dec, data_len - dec);
                data_len -= dec;
                res_APDU_size -= dec;
            }
        }
        /* A constructed DO (BER: bit 0x20 of the first tag byte, e.g.
         * Application Related Data 6E, Cardholder Related Data 65, Security
         * Support Template 7A, Cardholder Certificate 7F21) is returned with
         * its own tag, a simple DO as its value only, for every client alike
         * (formerly the tag depended on which applet had been selected
         * before, which broke yubikit and anything else parsing 6E). */
        if (((P1(apdu) ? P1(apdu) : P2(apdu)) & 0x20) != 0) {
            uint8_t off = 2;
            if (P1(apdu) > 0x0) {
                off++;
            }
            if (data_len >= 128) {
                off++;
            }
            if (data_len >= 256) {
                off++;
            }
            memmove(res_APDU + off, res_APDU, data_len);
            off = 0;
            if (P1(apdu) > 0x0) {
                res_APDU[off++] = P1(apdu);
                res_APDU[off++] = P2(apdu);
            }
            else {
                res_APDU[off++] = P2(apdu);
            }
            if (data_len >= 256) {
                res_APDU[off++] = 0x82;
                res_APDU[off++] = (data_len >> 8) & 0xff;
                res_APDU[off++] = data_len & 0xff;
            }
            else if (data_len >= 128) {
                res_APDU[off++] = 0x81;
                res_APDU[off++] = data_len;
            }
            else {
                res_APDU[off++] = data_len;
            }
            res_APDU_size += off;
        }
        // if (apdu.ne > data_len)
        //     apdu.ne = data_len;
    }
    return SW_OK();
}

/* Next instance of the cardholder certificate (the only DO with several). */
int cmd_get_next_data() {
    file_t *ef = NULL;
    if (apdu.nc > 0) {
        return SW_WRONG_LENGTH();
    }
    uint16_t fid = (P1(apdu) << 8) | P2(apdu);
    if (fid != EF_CH_CERT) {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint16_t cur = openpgp_ch_cert_file() ? openpgp_ch_cert_file()->fid : EF_CH_1;
    if (cur >= EF_CH_3) {
        return SW_RECORD_NOT_FOUND();
    }
    if (!(ef = search_by_fid(cur + 1, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    select_file(ef);
    return cmd_get_data();
}
