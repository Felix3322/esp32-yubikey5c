/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
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

/*
 * Board definition: user-presence button and status LED.
 *
 * ESP-IDF builds take the values from Kconfig (menu "LibreFido board"), so a
 * generic ESP32-S3 N16R8 board is described entirely in sdkconfig. Other
 * platforms keep their historical wiring (RP2 BOOTSEL button, board LED).
 */

#ifndef _BOARD_CONFIG_H_
#define _BOARD_CONFIG_H_

#include <stdbool.h>
#include <stdint.h>

#if defined(ESP_PLATFORM)
#include "sdkconfig.h"
#endif

/* ---- User presence button ---------------------------------------------- */
#if defined(CONFIG_LIBREFIDO_UP_BUTTON_GPIO)
#define BOARD_UP_BUTTON_GPIO        CONFIG_LIBREFIDO_UP_BUTTON_GPIO
#elif defined(ESP_PLATFORM)
#define BOARD_UP_BUTTON_GPIO        0       /* BOOT button of Espressif devkits */
#else
#define BOARD_UP_BUTTON_GPIO        (-1)    /* platform specific (RP2: BOOTSEL) */
#endif

#if defined(CONFIG_LIBREFIDO_UP_BUTTON_ACTIVE_HIGH)
#define BOARD_UP_BUTTON_ACTIVE_LOW  0
#else
#define BOARD_UP_BUTTON_ACTIVE_LOW  1
#endif

#if defined(CONFIG_LIBREFIDO_UP_BUTTON_PULL_NONE)
#define BOARD_UP_BUTTON_PULL        0
#elif defined(CONFIG_LIBREFIDO_UP_BUTTON_PULL_DOWN)
#define BOARD_UP_BUTTON_PULL        2
#else
#define BOARD_UP_BUTTON_PULL        1       /* pull-up */
#endif

#if defined(CONFIG_LIBREFIDO_UP_DEBOUNCE_MS)
#define BOARD_UP_DEBOUNCE_MS        CONFIG_LIBREFIDO_UP_DEBOUNCE_MS
#else
#define BOARD_UP_DEBOUNCE_MS        30
#endif

#if defined(CONFIG_LIBREFIDO_UP_TIMEOUT_S)
#define BOARD_UP_TIMEOUT_MS         (CONFIG_LIBREFIDO_UP_TIMEOUT_S * 1000)
#else
#define BOARD_UP_TIMEOUT_MS         (30 * 1000)
#endif

/* ---- Status LED -------------------------------------------------------- */
#if defined(CONFIG_LIBREFIDO_LED_GPIO)
#define BOARD_LED_GPIO              CONFIG_LIBREFIDO_LED_GPIO
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
#define BOARD_LED_GPIO              48      /* ESP32-S3-DevKitC-1 v1.0 RGB LED */
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
#define BOARD_LED_GPIO              15
#else
#define BOARD_LED_GPIO              (-1)
#endif

/* Returns false for pins that must never be driven or configured from the
 * runtime (USB, flash/PSRAM bus). Protects against a configuration command
 * pointing the LED driver at the flash bus and bricking the boot. */
extern bool board_gpio_is_safe(int gpio);

/* Idle hold that switches to the next profile (LibreFido 2 stores). */
#ifndef BOARD_UP_LONG_PRESS_MS
#define BOARD_UP_LONG_PRESS_MS      5000
#endif

#endif // _BOARD_CONFIG_H_
