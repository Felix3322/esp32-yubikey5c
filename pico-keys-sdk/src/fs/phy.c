/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
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
#include "file.h"
#include "otp.h"
#include "board_config.h"
#ifdef LF_STORE_V2
#include "lf_boot.h"
#include "lf_profile.h"
#include "lf_sys.h"
#endif

/* The emulator has no board hardware, but LibreFido 2 keeps the board
 * settings in the system area there too (management BOARD_SET, tests). */
#if !defined(ENABLE_EMULATION) || defined(LF_STORE_V2)

phy_data_t phy_data;
static bool phy_loaded = false;

int phy_serialize_data(const phy_data_t *phy, uint8_t *data, uint16_t *len) {
    if (!phy || !data || !len) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    uint8_t *p = data;
    if (phy->vidpid_present) {
        *p++ = PHY_VIDPID;
        *p++ = 4;
        *p++ = phy->vidpid[1];
        *p++ = phy->vidpid[0];
        *p++ = phy->vidpid[3];
        *p++ = phy->vidpid[2];
    }
    if (phy->led_gpio_present) {
        *p++ = PHY_LED_GPIO;
        *p++ = 1;
        *p++ = phy->led_gpio;
    }
    if (phy->led_brightness_present) {
        *p++ = PHY_LED_BTNESS;
        *p++ = 1;
        *p++ = phy->led_brightness;
    }
    *p++ = PHY_OPTS;
    *p++ = 2;
    p += put_uint16_t_be(phy->opts, p);
    if (phy->up_btn_present) {
        *p++ = PHY_UP_BTN;
        *p++ = 1;
        *p++ = phy->up_btn;
    }
    if (phy->usb_product_present) {
        *p++ = PHY_USB_PRODUCT;
        *p++ = (uint8_t)strlen(phy->usb_product) + 1;
        strcpy((char *)p, phy->usb_product);
        p += strlen(phy->usb_product);
        *p++ = '\0';
    }
    if (phy->enabled_curves_present) {
        *p++ = PHY_ENABLED_CURVES;
        *p++ = 4;
        p += put_uint32_t_be(phy->enabled_curves, p);
    }
    if (phy->enabled_usb_itf_present) {
        *p++ = PHY_ENABLED_USB_ITF;
        *p++ = 1;
        *p++ = phy->enabled_usb_itf;
    }
    if (phy->led_driver_present) {
        *p++ = PHY_LED_DRIVER;
        *p++ = 1;
        *p++ = phy->led_driver;
    }

    *len = (uint8_t)(p - data);
    return PICOKEY_OK;
}

int phy_unserialize_data(const uint8_t *data, uint16_t len, phy_data_t *phy) {
    if (!phy || !data || !len) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    const uint8_t *p = data;
    uint8_t tag, tlen;
    /* Validate the whole TLV list first so a truncated or malformed record
     * can never be partially applied or read past its end. */
    for (const uint8_t *q = data; q < data + len; ) {
        if (data + len - q < 2 || q[1] > data + len - q - 2) {
            return PICOKEY_WRONG_DATA;
        }
        q += 2 + q[1];
    }
    while (p < data + len) {
        tag = *p++;
        tlen = *p++;
        const uint8_t *next = p + tlen;
        switch (tag) {
            case PHY_VIDPID:
                if (tlen == 4) {
                    memcpy(phy->vidpid, p, 4);
                    phy->vidpid[1] = *p++;
                    phy->vidpid[0] = *p++;
                    phy->vidpid[3] = *p++;
                    phy->vidpid[2] = *p++;
                    phy->vidpid_present = true;
                }
                break;
            case PHY_LED_GPIO:
                /* A LED on the flash/USB pins would brick the next boot. */
                if (tlen == 1 && board_gpio_is_safe(*p)) {
                    phy->led_gpio = *p++;
                    phy->led_gpio_present = true;
                }
                break;
            case PHY_LED_BTNESS:
                if (tlen == 1) {
                    phy->led_brightness = *p++;
                    phy->led_brightness_present = true;
                }
                break;
            case PHY_OPTS:
                if (tlen == 2) {
                    phy->opts = get_uint16_t_be(p);
                    p += 2;
                }
                break;
            case PHY_UP_BTN:
                if (tlen == 1) {
                    phy->up_btn = *p++;
                    phy->up_btn_present = true;
                }
                break;
            case PHY_USB_PRODUCT:
                if (tlen > 0 && tlen <= sizeof(phy->usb_product)) {
                    /* The value is not trusted to be NUL terminated. */
                    memset(phy->usb_product, 0, sizeof(phy->usb_product));
                    memcpy(phy->usb_product, p, MIN((size_t) tlen, sizeof(phy->usb_product) - 1));
                    phy->usb_product_present = true;
                }
                break;
            case PHY_ENABLED_CURVES:
                if (tlen == 4) {
                    phy->enabled_curves = get_uint32_t_be(p);
                    p += 4;
                    phy->enabled_curves_present = true;
                }
                break;

            case PHY_ENABLED_USB_ITF:
                if (tlen == 1) {
                    phy->enabled_usb_itf = *p++;
                    phy->enabled_usb_itf_present = true;
                }
                break;
            case PHY_LED_DRIVER:
                if (tlen == 1) {
                    phy->led_driver = *p++;
                    phy->led_driver_present = true;
                }
                break;
            default:
                break;
        }
        p = next;
    }
    return PICOKEY_OK;
}

int phy_init() {
    memset(&phy_data, 0, sizeof(phy_data_t));
    phy_loaded = true;
    return phy_load();
}

void phy_ensure_loaded(void) {
    if (!phy_loaded) {
        phy_init();
    }
}

/* Every writer of the board settings (rescue, authenticatorConfig, the
 * YubiKey-compatible management WRITE CONFIG, the LibreFido management
 * applet) ends here, so the protection of the system area lives here. */
static int phy_commit(bool confirmed) {
    uint8_t tmp[PHY_MAX_SIZE] = {0};
    uint16_t tmp_len = 0;
    int ret = phy_serialize_data(&phy_data, tmp, &tmp_len);
    if (ret != PICOKEY_OK) {
        return ret;
    }
#ifdef LF_STORE_V2
    /* Board settings are device wide: they live in the system area. Only
     * after a normal boot: otherwise the settings in RAM were never read
     * from it, and writing them would drop the recorded ones (or, with an
     * unreadable area, record a profile table without profiles). */
    if (lf_boot_status() != LF_BOOT_OK) {
        return PICOKEY_ERR_BLOCKED;
    }
    if (tmp_len > LF_BOARD_MAX) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    lf_sys_t *s = lf_sys();
    /* Compare settings, not bytes: the stored record is parsed and
     * serialized again (an empty record serializes with the default
     * options field, unknown tags are dropped), so an unchanged save never
     * counts as a change or wears the system area. */
    phy_data_t cur;
    uint8_t cur_ser[PHY_MAX_SIZE] = {0};
    uint16_t cur_len = 0;
    memset(&cur, 0, sizeof(cur));
    if (s->board_len > 0 && s->board_len <= LF_BOARD_MAX) {
        phy_unserialize_data(s->board, s->board_len, &cur);
    }
    if (phy_serialize_data(&cur, cur_ser, &cur_len) == PICOKEY_OK && cur_len == tmp_len &&
        memcmp(cur_ser, tmp, tmp_len) == 0) {
        return PICOKEY_OK;              /* nothing changes: nothing is written */
    }
    if (confirmed) {
        lf_sys_change_confirmed();
    }
    else if (!lf_sys_change_allowed()) {
        phy_init();                     /* the refused change is not kept either */
        return PICOKEY_ERR_BLOCKED;
    }
    uint8_t old[LF_BOARD_MAX];
    uint16_t old_len = s->board_len <= LF_BOARD_MAX ? s->board_len : 0;
    memcpy(old, s->board, old_len);
    memcpy(s->board, tmp, tmp_len);
    s->board_len = tmp_len;
    ret = lf_sys_commit();
    if (ret != PICOKEY_OK) {
        /* The caller reports a failure: no later, unrelated commit may
         * write these settings behind its back, and they are not in force. */
        memset(s->board, 0, sizeof(s->board));
        memcpy(s->board, old, old_len);
        s->board_len = old_len;
        phy_init();
    }
    return ret;
#else
    (void) confirmed;
    file_put_data(ef_phy, tmp, tmp_len);
    low_flash_available();
    return PICOKEY_OK;
#endif
}

int phy_save() {
    return phy_commit(false);
}

int phy_save_confirmed() {
    return phy_commit(true);
}

int phy_load() {
#ifdef LF_STORE_V2
    if (lf_sys()->board_len > 0 && lf_sys()->board_len <= LF_BOARD_MAX) {
        return phy_unserialize_data(lf_sys()->board, lf_sys()->board_len, &phy_data);
    }
#else
    if (file_has_data(ef_phy)) {
        return phy_unserialize_data(file_get_data(ef_phy), file_get_size(ef_phy), &phy_data);
    }
#endif
    return PICOKEY_OK;
}
#endif
