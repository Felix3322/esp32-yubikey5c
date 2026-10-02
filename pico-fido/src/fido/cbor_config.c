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
#include "credential.h"
#include "random.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/sha256.h"
#include "file.h"

extern uint8_t keydev_dec[32];
extern bool has_keydev_dec;
extern void resetPersistentPinUvAuthToken();
extern void resetPinUvAuthToken();

int cbor_config(const uint8_t *data, size_t len) {
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    uint64_t subcommand = 0, pinUvAuthProtocol = 0, vendorCommandId = 0, newMinPinLength = 0, vendorParamInt = 0;
    CborByteString pinUvAuthParam = { 0 }, vendorParamByteString = { 0 };
    CborCharString minPinLengthRPIDs[32] = { 0 }, vendorParamTextString = { 0 };
    size_t resp_size = 0, raw_subpara_len = 0, minPinLengthRPIDs_len = 0;
    CborEncoder encoder;
    //CborEncoder mapEncoder;
    uint8_t *raw_subpara = NULL;
    const bool *forceChangePin = NULL;

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
            CBOR_FIELD_GET_UINT(subcommand, 1);
        }
        else if (val_u == 0x02) {
            uint64_t subpara = 0;
            raw_subpara = (uint8_t *) cbor_value_get_next_byte(&_f1);
            /* Every entry is consumed (key and value) whatever the
             * subcommand, or the loop would never reach the end. */
            CBOR_PARSE_MAP_START(_f1, 2)
            {
                if (subcommand == 0xFF) { // Vendor
                    CBOR_FIELD_GET_UINT(subpara, 2);
                    if (subpara == 0x01) {
                        CBOR_FIELD_GET_UINT(vendorCommandId, 2);
                    }
                    else if (subpara == 0x02) {
                        CBOR_FIELD_GET_BYTES(vendorParamByteString, 2);
                    }
                    else if (subpara == 0x03) {
                        CBOR_FIELD_GET_UINT(vendorParamInt, 2);
                    }
                    else if (subpara == 0x04) {
                        CBOR_FIELD_GET_TEXT(vendorParamTextString, 2);
                    }
                    else {
                        CBOR_ADVANCE(2);
                    }
                }
                else if (subcommand == 0x03) { // Extensions
                    CBOR_FIELD_GET_UINT(subpara, 2);
                    if (subpara == 0x01) {
                        CBOR_FIELD_GET_UINT(newMinPinLength, 2);
                    }
                    else if (subpara == 0x02) {
                        CBOR_PARSE_ARRAY_START(_f2, 3)
                        {
                            CBOR_FIELD_GET_TEXT(minPinLengthRPIDs[minPinLengthRPIDs_len], 3);
                            minPinLengthRPIDs_len++;
                            if (minPinLengthRPIDs_len >= 32) {
                                CBOR_ERROR(CTAP2_ERR_KEY_STORE_FULL);
                            }
                        }
                        CBOR_PARSE_ARRAY_END(_f2, 3);
                    }
                    else if (subpara == 0x03) {
                        CBOR_FIELD_GET_BOOL(forceChangePin, 2);
                    }
                    else {
                        CBOR_ADVANCE(2);
                    }
                }
                else { // no parameters defined: skip key and value
                    CBOR_ADVANCE(2);
                    CBOR_ADVANCE(2);
                }
            }
            CBOR_PARSE_MAP_END(_f1, 2);
            raw_subpara_len = cbor_value_get_next_byte(&_f1) - raw_subpara;
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

    if (pinUvAuthParam.present == false) {
        CBOR_ERROR(CTAP2_ERR_PUAT_REQUIRED);
    }
    if (pinUvAuthProtocol == 0) {
        CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
    }
    if (pinUvAuthProtocol != 1 && pinUvAuthProtocol != 2) {
        CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
    }
    if (32 + 1 + 1 + raw_subpara_len > UINT16_MAX) {
        CBOR_ERROR(CTAP1_ERR_INVALID_LEN);
    }

    uint8_t *verify_payload = (uint8_t *) calloc(1, 32 + 1 + 1 + raw_subpara_len);
    if (verify_payload == NULL) {
        CBOR_ERROR(CTAP2_ERR_PROCESSING);
    }
    memset(verify_payload, 0xff, 32);
    verify_payload[32] = 0x0d;
    verify_payload[33] = (uint8_t)subcommand;
    if (raw_subpara_len > 0) {
        memcpy(verify_payload + 34, raw_subpara, raw_subpara_len);
    }
    error = verify((uint8_t)pinUvAuthProtocol, paut.data, verify_payload, (uint16_t)(32 + 1 + 1 + raw_subpara_len), pinUvAuthParam.data, pinUvAuthParam.len);
    free(verify_payload);
    if (error != CborNoError) {
        CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
    }

    if (!(paut.permissions & CTAP_PERMISSION_ACFG)) {
        CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
    }

    if (subcommand == 0xFF) {
#ifndef ENABLE_EMULATION
        const bool is_phy = (vendorCommandId == CTAP_CONFIG_PHY_VIDPID ||
            vendorCommandId == CTAP_CONFIG_PHY_LED_GPIO ||
            vendorCommandId == CTAP_CONFIG_PHY_LED_BTNESS ||
            vendorCommandId == CTAP_CONFIG_PHY_OPTS);
        /* The settings in force before this command: put back when the
         * change is not recorded, so RAM never claims it happened. */
        const phy_data_t phy_before = phy_data;
        bool phy_pressed = false;
#endif
        if (vendorCommandId == CTAP_CONFIG_AUT_DISABLE){
            /* The device key goes back to its normal format (0x01); the
             * RAM copy is dropped, so nothing derives from a stale key. */
            int ret = keydev_unprotect();
            if (ret != 0) {
                CBOR_ERROR(ret);
            }
        }
        else if (vendorCommandId == CTAP_CONFIG_AUT_ENABLE) {
            /* vendorParam: the 32-byte host key, encrypted over MSE. The
             * real device key is sealed, and the blob checked, before the
             * plain copy is removed. */
            int ret = keydev_protect(vendorParamByteString.data, vendorParamByteString.present ? vendorParamByteString.len : 0);
            if (ret != 0) {
                CBOR_ERROR(ret);
            }
        }

#ifndef ENABLE_EMULATION
        else if (vendorCommandId == CTAP_CONFIG_PHY_VIDPID) {
            phy_data.vid = (vendorParamInt >> 16) & 0xFFFF;
            phy_data.pid = vendorParamInt & 0xFFFF;
            phy_data.vidpid_present = true;
        }
        else if (vendorCommandId == CTAP_CONFIG_PHY_LED_GPIO) {
            phy_data.led_gpio = (uint8_t)vendorParamInt;
            phy_data.led_gpio_present = true;
        }
        else if (vendorCommandId == CTAP_CONFIG_PHY_LED_BTNESS) {
            phy_data.led_brightness = (uint8_t)vendorParamInt;
            phy_data.led_brightness_present = true;
        }
        else if (vendorCommandId == CTAP_CONFIG_PHY_OPTS) {
            uint16_t opts = (uint16_t)vendorParamInt;
            /* Switching off the power-up window of authenticatorReset is
             * confirmed with a physical press: the acfg token alone must
             * not remove the condition the token holder is bound by. */
            if ((opts & ~phy_data.opts) & PHY_OPT_DISABLE_POWER_RESET) {
                if (fido_wait_physical_press() == true) {
                    CBOR_ERROR(fido_up_error());
                }
                phy_pressed = true;
            }
            phy_data.opts = opts;
        }
#endif
        else if (vendorCommandId == CTAP_CONFIG_EA_UPLOAD) {
            if (vendorParamByteString.present == false) {
                CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
            }
            file_t *ef_ee_ea = search_by_fid(EF_EE_DEV_EA, NULL, SPECIFY_EF);
            if (ef_ee_ea) {
                file_put_data(ef_ee_ea, vendorParamByteString.data, (uint16_t)vendorParamByteString.len);
            }
            low_flash_available();
        }
        /* CTAP_CONFIG_PIN_POLICY is gone: it stored a policy URL and made
         * getInfo report pinComplexityPolicy = true, but setPIN/changePIN
         * never enforced any complexity rule. */
        else {
            CBOR_ERROR(CTAP2_ERR_INVALID_SUBCOMMAND);
        }
#ifndef ENABLE_EMULATION
        if (is_phy) {
            /* phy_save() refuses (PICOKEY_ERR_BLOCKED) outside a normal boot,
             * once the free changes of this boot are used up without a touch,
             * and while a restart is scheduled. The press above confirms its
             * change. Refused or failed: an error, and the old settings. */
            int pret = phy_pressed ? phy_save_confirmed() : phy_save();
            if (pret != PICOKEY_OK) {
                phy_data = phy_before;
                CBOR_ERROR(pret == PICOKEY_ERR_BLOCKED ? CTAP2_ERR_OPERATION_DENIED : CTAP2_ERR_PROCESSING);
            }
        }
#endif
        goto err;
    }
    else if (subcommand == 0x03) {
        uint8_t currentMinPinLen = 4;
        bool pendingForceChange = false;
        file_t *ef_minpin = search_by_fid(EF_MINPINLEN, NULL, SPECIFY_EF);
        if (file_has_data(ef_minpin)) {
            currentMinPinLen = *file_get_data(ef_minpin);
            pendingForceChange = file_get_size(ef_minpin) >= 2 && file_get_data(ef_minpin)[1] == 1;
        }
        if (newMinPinLength == 0) {
            newMinPinLength = currentMinPinLen;
        }
        else if (newMinPinLength < currentMinPinLen) {
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        /* Stored in one byte, and no PIN is longer than 63 bytes: a larger
         * value would wrap (and lower the minimum) or lock the PIN out. */
        if (newMinPinLength > 63) {
            CBOR_ERROR(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        if (forceChangePin == ptrue && !file_has_data(ef_pin)) {
            CBOR_ERROR(CTAP2_ERR_PIN_NOT_SET);
        }
        if (file_has_data(ef_pin) && file_get_data(ef_pin)[1] < newMinPinLength) {
            forceChangePin = ptrue;
        }
        if (forceChangePin == ptrue) {
            resetPersistentPinUvAuthToken();
            resetPinUvAuthToken();
        }
        uint8_t *dataf = (uint8_t *) calloc(1, 2 + minPinLengthRPIDs_len * 32);
        if (dataf == NULL) {
            CBOR_ERROR(CTAP2_ERR_PROCESSING);
        }
        dataf[0] = (uint8_t)newMinPinLength;
        /* Only changePIN clears a pending forced PIN change. */
        dataf[1] = (forceChangePin == ptrue || pendingForceChange) ? 1 : 0;
        for (size_t m = 0; m < minPinLengthRPIDs_len; m++) {
            mbedtls_sha256((uint8_t *) minPinLengthRPIDs[m].data, minPinLengthRPIDs[m].len, dataf + 2 + m * 32, 0);
        }
        file_put_data(ef_minpin, dataf, (uint16_t)(2 + minPinLengthRPIDs_len * 32));
        low_flash_available();
        free(dataf);
        goto err; //No return
    }
    else if (subcommand == 0x01) {
        set_opts(get_opts() | FIDO2_OPT_EA);
        goto err;
    }
    else {
        CBOR_ERROR(CTAP2_ERR_UNSUPPORTED_OPTION);
    }
    //CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    //resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);

err:
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);
    CBOR_FREE_BYTE_STRING(vendorParamByteString);
    CBOR_FREE_BYTE_STRING(vendorParamTextString);
    for (size_t i = 0; i < minPinLengthRPIDs_len; i++) {
        CBOR_FREE_BYTE_STRING(minPinLengthRPIDs[i]);
    }

    if (error != CborNoError) {
        if (error == CborErrorImproperValue) {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        return error;
    }
    res_APDU_size = (uint16_t)resp_size;
    return 0;
}
