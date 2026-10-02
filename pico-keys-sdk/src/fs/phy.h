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

#ifndef _PHY_H_
#define _PHY_H_

#define EF_PHY       0xE020

#define PHY_VIDPID      0x0
#define PHY_LED_GPIO    0x4
#define PHY_LED_BTNESS  0x5
#define PHY_OPTS        0x6
#define PHY_UP_BTN      0x8
#define PHY_USB_PRODUCT 0x9
#define PHY_ENABLED_CURVES 0xA
#define PHY_ENABLED_USB_ITF 0xB
#define PHY_LED_DRIVER  0xC

#define PHY_OPT_WCID    0x1
#define PHY_OPT_DIMM    0x2
#define PHY_OPT_DISABLE_POWER_RESET 0x4
#define PHY_OPT_LED_STEADY 0x8

#define PHY_CURVE_SECP256R1  0x1
#define PHY_CURVE_SECP384R1  0x2
#define PHY_CURVE_SECP521R1  0x4
#define PHY_CURVE_SECP256K1 0x8
#define PHY_CURVE_BP256R1 0x10
#define PHY_CURVE_BP384R1 0x20
#define PHY_CURVE_BP512R1 0x40
#define PHY_CURVE_ED25519 0x80
#define PHY_CURVE_ED448 0x100
#define PHY_CURVE_CURVE25519 0x200
#define PHY_CURVE_CURVE448 0x400

#define PHY_USB_ITF_CCID 0x1
#define PHY_USB_ITF_WCID 0x2
#define PHY_USB_ITF_HID 0x4
#define PHY_USB_ITF_KB 0x8

#define PHY_LED_DRIVER_PICO     0x1
#define PHY_LED_DRIVER_PIMORONI 0x2
#define PHY_LED_DRIVER_WS2812   0x3
#ifdef CYW43_WL_GPIO_LED_PIN
#define PHY_LED_DRIVER_CYW43    0x4
#endif
#ifdef ESP_PLATFORM
#define PHY_LED_DRIVER_NEOPIXEL  0x5
#endif

#define PHY_LED_DRIVER_NONE     0xFF

#include <stdint.h>
#include <stdbool.h>

typedef struct phy_data {
    union {
        struct {
            uint16_t vid;
            uint16_t pid;
        };
        uint8_t vidpid[4];
    };

    uint32_t enabled_curves;

    char usb_product[32];

    uint16_t opts;

    uint8_t led_gpio;
    uint8_t led_brightness;
    uint8_t up_btn;
    uint8_t enabled_usb_itf;
    uint8_t led_driver;

    bool vidpid_present;
    bool led_gpio_present;
    bool led_brightness_present;
    bool up_btn_present;
    bool usb_product_present;
    bool enabled_curves_present;
    bool enabled_usb_itf_present;
    bool led_driver_present;

} phy_data_t;

#define PHY_MAX_SIZE    ((2+4)+(2+4)+(2+32)+(2+2)+(2+1)+(2+1)+(2+1)+(2+1)+(2+1))

/* Also in the emulator, which always uses the LibreFido 2 store (board
 * settings in the system area; pico_keys.h defines LF_STORE_V2 only after
 * this header). */
extern int phy_serialize_data(const phy_data_t *phy, uint8_t *data, uint16_t *len);
extern int phy_unserialize_data(const uint8_t *data, uint16_t len, phy_data_t *phy);
/* Loads the recorded settings into phy_data (boot). */
extern int phy_init();
/* Loads them unless phy_init() already ran (the emulator never calls it). */
extern void phy_ensure_loaded(void);
/* Records phy_data. LibreFido 2: only after a normal boot (else
 * PICOKEY_ERR_BLOCKED), nothing is written when nothing changed, a change
 * counts against the free allowance of lf_sys_change_allowed() (a touch
 * once it is used up, PICOKEY_ERR_BLOCKED without one), and a refused or
 * failed change is dropped from phy_data too. */
extern int phy_save();
/* The same for a change the caller already confirmed with a touch. */
extern int phy_save_confirmed();
extern int phy_load();
extern phy_data_t phy_data;

#endif // _PHY_H_
