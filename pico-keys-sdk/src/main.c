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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#if !defined(_MSC_VER) && !defined(PICO_PLATFORM)
#include <sys/time.h>
#endif
#include "pico_keys.h"
#if defined(LF_STORE_V2)
#include "lf_fw.h"
#endif

#if !defined(ENABLE_EMULATION)
#include "tusb.h"
#endif
#if defined(ENABLE_EMULATION)
#include "emulation.h"
#elif defined(ESP_PLATFORM)
#include "driver/gpio.h"
#include "tinyusb.h"
#include "esp_efuse.h"
#elif defined(PICO_PLATFORM)
#include "pico/stdlib.h"
#include "bsp/board.h"
#include "pico/aon_timer.h"
#include "hardware/gpio.h"
#include "hardware/sync.h"
#endif

#include "random.h"
#include "apdu.h"
#include "usb.h"
#include "up/up.h"
#include "security.h"
#include "mbedtls/sha256.h"
#ifdef LF_STORE_V2
#include "lf_boot.h"
#include "lf_profile.h"
#endif

extern void do_flash();
extern void low_flash_init();
extern void init_otp_files();

app_t apps[16];
uint8_t num_apps = 0;

app_t *current_app = NULL;

const uint8_t *ccid_atr = NULL;

/* AID match quality for SELECT by DF name (ISO 7816-4 5.3.1.1). */
enum {
    AID_NO_MATCH = 0,
    AID_TRUNCATED,      /* host sent a right-truncated AID (>= RID) */
    AID_EXTENDED,       /* host sent a longer AID (version / serial suffix) */
    AID_EXACT,
};

static int aid_match(const uint8_t *reg, const uint8_t *aid, size_t aid_len) {
    size_t reg_len = reg[0];
    if (aid_len == reg_len && memcmp(reg + 1, aid, aid_len) == 0) {
        return AID_EXACT;
    }
    if (aid_len > reg_len && memcmp(reg + 1, aid, reg_len) == 0) {
        return AID_EXTENDED;
    }
    if (aid_len >= 5 && aid_len < reg_len && memcmp(reg + 1, aid, aid_len) == 0) {
        return AID_TRUNCATED;
    }
    return AID_NO_MATCH;
}

/* Best match wins; ties keep registration order ("first occurrence"). */
app_t *find_app(const uint8_t *aid, size_t aid_len) {
    app_t *best = NULL;
    int best_q = AID_NO_MATCH;
    size_t best_len = 0;
    for (int a = 0; a < num_apps; a++) {
        int q = aid_match(apps[a].aid, aid, aid_len);
        if (q > best_q || (q == best_q && q == AID_EXTENDED && apps[a].aid[0] > best_len)) {
            best = &apps[a];
            best_q = q;
            best_len = apps[a].aid[0];
        }
    }
    return best;
}

bool app_exists(const uint8_t *aid, size_t aid_len) {
    return find_app(aid, aid_len) != NULL;
}

int register_app(int (*select_aid)(app_t *, uint8_t), const uint8_t *aid) {
    for (int a = 0; a < num_apps; a++) {
        if (aid_match(apps[a].aid, aid + 1, aid[0]) == AID_EXACT) {
            return 1;
        }
    }
    if (num_apps < sizeof(apps) / sizeof(app_t)) {
        apps[num_apps].select_aid = select_aid;
        apps[num_apps].aid = aid;
        num_apps++;
        return 1;
    }
    return 0;
}

int select_app(const uint8_t *aid, size_t aid_len) {
    app_t *app = find_app(aid, aid_len);
    if (!app) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    /* No chaining reset here: HID selects an application for every message,
     * and the chain belongs to the smart card interface (process_apdu()). */
    if (current_app == app) {
        return current_app->select_aid(current_app, 0) == PICOKEY_OK ? PICOKEY_OK : PICOKEY_ERR_FILE_NOT_FOUND;
    }
    /* Leaving an application drops its security state (PIN, admin auth). */
    if (current_app && current_app->unload) {
        current_app->unload();
    }
    current_app = app;
    if (current_app->select_aid(current_app, 1) == PICOKEY_OK) {
        return PICOKEY_OK;
    }
    current_app = NULL;
    return PICOKEY_ERR_FILE_NOT_FOUND;
}

int (*button_pressed_cb)(uint8_t) = NULL;

void execute_tasks();

bool is_req_button_pending() {
    return up_pending();
}

#ifdef _MSC_VER
#include <windows.h>
struct timezone
{
    __int32  tz_minuteswest; /* minutes W of Greenwich */
    bool  tz_dsttime;     /* type of dst correction */
};
int gettimeofday(struct timeval* tp, struct timezone* tzp)
{
    (void)tzp;
    // Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
    // This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
    // until 00:00:00 January 1, 1970
    static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

    SYSTEMTIME  system_time;
    FILETIME    file_time;
    uint64_t    time;

    GetSystemTime(&system_time);
    SystemTimeToFileTime(&system_time, &file_time);
    time = ((uint64_t)file_time.dwLowDateTime);
    time += ((uint64_t)file_time.dwHighDateTime) << 32;

    tp->tv_sec = (long)((time - EPOCH) / 10000000L);
    tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
    return 0;
}
#endif

/* Application hook run once after the store and USB are up. */
__attribute__((weak)) int picokey_init() {
    return 0;
}

bool set_rtc = false;
#if !defined(PICO_PLATFORM) && !defined(ESP_PLATFORM)
/* The emulator never changes the host clock; it keeps an offset. */
static time_t rtc_offset = 0;
#endif

bool has_set_rtc() {
    return set_rtc;
}

void set_rtc_time(time_t t) {
#if defined(PICO_PLATFORM)
    struct timespec tv = {.tv_sec = t, .tv_nsec = 0};
    aon_timer_set_time(&tv);
#elif defined(ESP_PLATFORM)
    struct timeval tv = {.tv_sec = t, .tv_usec = 0};
    settimeofday(&tv, NULL);
#else
    rtc_offset = t - time(NULL);
#endif
    set_rtc = true;
}

time_t get_rtc_time() {
#if defined(PICO_PLATFORM)
    struct timespec tv;
    aon_timer_get_time(&tv);
    return tv.tv_sec;
#elif defined(ESP_PLATFORM)
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;
#else
    return time(NULL) + rtc_offset;
#endif
}

struct apdu apdu;

void init_rtc() {
#ifdef PICO_PLATFORM
    struct timespec tv = {0};
    tv.tv_sec = 1577836800; // 2020-01-01
    aon_timer_start(&tv);
#endif
}

extern void hwrng_task();
extern void usb_task();
void execute_tasks()
{
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
    tud_task(); // tinyusb device task
#endif
    usb_task();
    led_blinking_task();
}

/* Core 0 paths that commit flash or reboot run under usb_lock: commands start
 * and the keyboard OTP storage transaction runs from the USB callbacks (the
 * TinyUSB task on ESP32), which take it, so neither interleaves with them.
 * Lock order: usb_lock, then the flash locks (as the USB side). A command
 * running on the card thread (is_busy()) is left alone: do_flash() skips open
 * transactions, the others wait for !is_busy(). */
void core0_loop() {
    while (1) {
        execute_tasks();
        hwrng_task();
        usb_lock();
        do_flash();
        usb_unlock();
        up_tick();
#ifdef LF_STORE_V2
        /* Holding the button while idle switches to the next profile. */
        if (up_take_long_press() && lf_storage_ready()) {
            usb_lock();
            if (!is_busy() && lf_profile_select_next() == PICOKEY_OK) {
                led_set_profile_color(lf_profile_led_color(lf_active_profile()));
                lf_reboot_later(500);
            }
            usb_unlock();
        }
        usb_lock();
        lf_reboot_poll();       /* commits and reboots only while !is_busy() */
        usb_unlock();
#endif
        /* Idle presses (OTP typing) are only reported when no command runs
         * and no presence request is pending, see up.h. */
        if (button_pressed_cb && board_millis() > 1000 && !is_busy()) {
            uint8_t presses = up_take_idle_presses();
            if (presses > 0) {
                (*button_pressed_cb)(presses);
            }
        }
#ifdef ESP_PLATFORM
    vTaskDelay(pdMS_TO_TICKS(10));
#endif
    }
}

char pico_serial_str[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];
uint8_t pico_serial_hash[32];
pico_unique_board_id_t pico_serial;
pico_unique_board_id_t pico_chip_serial;

void pico_serial_set(const uint8_t id[PICO_UNIQUE_BOARD_ID_SIZE_BYTES]) {
    memcpy(pico_serial.id, id, sizeof(pico_serial.id));
    memset(pico_serial_str, 0, sizeof(pico_serial_str));
    for (size_t i = 0; i < sizeof(pico_serial); i++) {
        snprintf(&pico_serial_str[2 * i], 3, "%02X", pico_serial.id[i]);
    }
    mbedtls_sha256(pico_serial.id, sizeof(pico_serial.id), pico_serial_hash, false);
}
#ifdef ESP_PLATFORM
#define pico_get_unique_board_id(a) do { uint32_t value; esp_efuse_read_block(EFUSE_BLK1, &value, 0, 32); memcpy((uint8_t *)(a), &value, sizeof(uint32_t)); esp_efuse_read_block(EFUSE_BLK1, &value, 32, 32); memcpy((uint8_t *)(a)+4, &value, sizeof(uint32_t)); } while(0)
extern tinyusb_config_t tusb_cfg;
extern const uint8_t desc_config[];
extern char *string_desc_itf[4];
TaskHandle_t hcore0 = NULL, hcore1 = NULL;
int app_main() {
#else
#ifndef PICO_PLATFORM
extern void emu_chip_id(uint8_t id[8]);
#define pico_get_unique_board_id(a) emu_chip_id((a)->id)
#endif
int main(void) {
#if defined(LF_STORE_V2)
    /* Emulated bootloader: may exec() another firmware image. */
    lf_fw_emu_boot();
#endif
#endif
    pico_get_unique_board_id(&pico_chip_serial);
    /* Until a profile is mounted the device presents the chip serial. */
    pico_serial_set(pico_chip_serial.id);

#ifndef ENABLE_EMULATION
#ifdef PICO_PLATFORM
    board_init();
    stdio_init_all();
#endif

#else
    setvbuf(stdout, NULL, _IOLBF, 0);
    emul_init("127.0.0.1", 35963);
#endif

    random_init();

    low_flash_init();

#ifdef LF_STORE_V2
    /* System area, legacy migration, pending imports, active profile. */
    bool storage_ok = lf_storage_boot() == LF_BOOT_OK;
    if (!storage_ok) {
        printf("[storage] SAFE MODE: %s\n", lf_boot_status_str(lf_boot_status()));
    }
#else
    bool storage_ok = true;
#endif
    if (storage_ok) {
        scan_flash();
        /* Device root secret, chip security state, legacy eFuse keys. It must
         * see a fresh store before anything else writes to it. */
        security_init();
#ifdef LF_STORE_V2
        /* Serial (USB, card serials) of the active profile. */
        lf_identity_apply();
#endif
    }

    init_rtc();

#ifndef ENABLE_EMULATION
    if (storage_ok) {
        phy_init();
    }
#endif

    led_init();
#ifdef LF_STORE_V2
    if (storage_ok) {
        led_set_profile_color(lf_profile_led_color(lf_active_profile()));
    }
#endif

    up_init();

    usb_init();

    /* Application initialisation (file scans, key creation, OTP migration)
     * runs before the USB stack starts: on ESP32 tinyusb_driver_install()
     * starts the TinyUSB task, whose callbacks start commands on the card
     * task at once; nothing may meet half-initialised files. It needs
     * usb_init() (usb_lock) but no USB traffic. The emulator and the Pico
     * only serve USB from core0_loop(), which starts after it as well. */
    if (storage_ok) {
        picokey_init();
    }

#ifndef ENABLE_EMULATION
#ifdef ESP_PLATFORM
    tusb_cfg.string_descriptor[3] = pico_serial_str;
    if (phy_data.usb_product_present) {
        tusb_cfg.string_descriptor[2] = phy_data.usb_product;
    }
    static char tmps[4][32];
    for (int i = 4; i < tusb_cfg.string_descriptor_count; i++) {
        /* Interface n names itself with string n + 5 (usb_desc_setup());
         * usb_init() recorded which interface got which name. Without the
         * keyboard, the CCID reader was otherwise called "HID Keyboard
         * Interface" (Windows names readers after this string). */
        const char *name = i >= 5 && string_desc_itf[i - 5] ? string_desc_itf[i - 5] : tusb_cfg.string_descriptor[i];
        strlcpy(tmps[i-4], tusb_cfg.string_descriptor[2], sizeof(tmps[0]));
        strlcat(tmps[i-4], " ", sizeof(tmps[0]));
        strlcat(tmps[i-4], name, sizeof(tmps[0]));
        tusb_cfg.string_descriptor[i] = tmps[i-4];
    }
    tusb_cfg.configuration_descriptor = desc_config;

    tinyusb_driver_install(&tusb_cfg);
#else
    tusb_init();
#endif
#endif

#ifdef ESP_PLATFORM
    /* At least the stack of the former default interface set (3), also when
     * fewer interfaces are enabled (WCID is off by default). */
    xTaskCreatePinnedToCore(core0_loop, "core0", 4096*MAX(ITF_TOTAL, 3)*2, NULL, CONFIG_TINYUSB_TASK_PRIORITY - 1, &hcore0, ESP32_CORE0);
#else
    core0_loop();
#endif

    return 0;
}
