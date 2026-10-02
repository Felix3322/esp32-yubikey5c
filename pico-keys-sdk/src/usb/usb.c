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
#include "pico_keys.h"
#if defined(PICO_PLATFORM)
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/mutex.h"
#include "bsp/board.h"
#endif
#include "usb.h"
#include "apdu.h"
#include "up/up.h"
#ifndef ENABLE_EMULATION
#include "tusb.h"
#else
#include "emulation.h"
#endif

// For memcpy
#include <string.h>
#include <stdlib.h>

// Device specific functions
static uint32_t *timeout_counter = NULL;
static uint8_t card_locked_itf = 0; // no locked
static void *(*card_locked_func)(void *) = NULL;
static uint8_t up_waiting_itf = ITF_INVALID;
#ifndef ENABLE_EMULATION
static mutex_t mutex;
extern void usb_desc_setup();
#endif
#if !defined(PICO_PLATFORM) && !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#ifdef _MSC_VER
#include "pthread_win32.h"
#endif
pthread_t hcore0, hcore1;
#endif

/* Serializes the class state machines (HID/CCID buffers, CTAPHID channel
 * state, command setup) between the TinyUSB callback context and the core 0
 * loop. It is recursive and never held while waiting for the card thread. */
#if defined(ESP_PLATFORM)
static SemaphoreHandle_t usb_mtx = NULL;
void usb_lock(void) {
    if (usb_mtx) {
        xSemaphoreTakeRecursive(usb_mtx, portMAX_DELAY);
    }
}
void usb_unlock(void) {
    if (usb_mtx) {
        xSemaphoreGiveRecursive(usb_mtx);
    }
}
#elif defined(PICO_PLATFORM)
static recursive_mutex_t usb_mtx;
void usb_lock(void) {
    recursive_mutex_enter_blocking(&usb_mtx);
}
void usb_unlock(void) {
    recursive_mutex_exit(&usb_mtx);
}
#else
static pthread_mutex_t usb_mtx;
void usb_lock(void) {
    pthread_mutex_lock(&usb_mtx);
}
void usb_unlock(void) {
    pthread_mutex_unlock(&usb_mtx);
}
#endif

static void usb_lock_init(void) {
#if defined(ESP_PLATFORM)
    usb_mtx = xSemaphoreCreateRecursiveMutex();
#elif defined(PICO_PLATFORM)
    recursive_mutex_init(&usb_mtx);
#else
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&usb_mtx, &attr);
    pthread_mutexattr_destroy(&attr);
#endif
}

#ifdef USB_ITF_HID
    uint8_t ITF_HID_CTAP = ITF_INVALID, ITF_HID_KB = ITF_INVALID;
    uint8_t ITF_HID = ITF_INVALID, ITF_KEYBOARD = ITF_INVALID;
    uint8_t ITF_HID_TOTAL = 0;
    extern void hid_init();
#endif

#ifdef USB_ITF_CCID
    uint8_t ITF_SC_CCID = ITF_INVALID, ITF_SC_WCID = ITF_INVALID;
    uint8_t ITF_CCID = ITF_INVALID, ITF_WCID = ITF_INVALID;
    uint8_t ITF_SC_TOTAL = 0;
    extern void ccid_init();
#endif
uint8_t ITF_TOTAL = 0;

void usb_set_timeout_counter(uint8_t itf, uint32_t v) {
    if (itf < ITF_TOTAL) {
        timeout_counter[itf] = v;
    }
}

queue_t usb_to_card_q = {0};
queue_t card_to_usb_q = {0};

#ifndef ENABLE_EMULATION
extern tusb_desc_device_t desc_device;
extern char *string_desc_itf[4], *string_desc_arr[];
#endif

/* The keyboard interface is only exposed when requested: explicitly through
 * the PHY interface mask, or implicitly by the application (OTP slots that
 * type). A plain security key never enumerates as a keyboard. */
static bool (*keyboard_wanted_cb)(void) = NULL;
void usb_set_keyboard_policy(bool (*cb)(void)) {
    keyboard_wanted_cb = cb;
}

void usb_init()
{
    usb_lock_init();
#ifndef ENABLE_EMULATION
    /* A configured USB identity may be the user's own, never Yubico's
     * (VID 0x1050): LibreFido does not present itself as another vendor's
     * product, whatever the board settings say. */
    if (phy_data.vidpid_present && phy_data.vid == 0x1050) {
        printf("[usb] refusing VID 0x1050 (Yubico), using the default identity\n");
        phy_data.vidpid_present = false;
    }
    if (phy_data.vidpid_present) {
        desc_device.idVendor = phy_data.vid;
        desc_device.idProduct = phy_data.pid;
    }
    else {
        phy_data.vid = desc_device.idVendor;
        phy_data.pid = desc_device.idProduct;
        phy_data.vidpid_present = true;
    }
    mutex_init(&mutex);
#endif
    queue_init(&card_to_usb_q, sizeof(uint32_t), 64);
    queue_init(&usb_to_card_q, sizeof(uint32_t), 64);
    /* Every transport points res_APDU at its own buffer before a command;
     * until the first one it must still be a valid buffer, never NULL. */
    apdu.rdata = apdu_res_buf;
    apdu.rlen = 0;

    /* The WebUSB/WinUSB smart card interface (WCID) reaches the applications
     * outside the platform's smart card service, so it is only exposed when
     * the PHY interface mask asks for it. */
    uint8_t enabled_usb_itf = PHY_USB_ITF_CCID | PHY_USB_ITF_HID;
    if (keyboard_wanted_cb && keyboard_wanted_cb()) {
        enabled_usb_itf |= PHY_USB_ITF_KB;
    }
#ifndef ENABLE_EMULATION
    if (phy_data.enabled_usb_itf_present) {
        enabled_usb_itf = phy_data.enabled_usb_itf;
    }
#endif

#ifdef USB_ITF_HID
    ITF_HID_TOTAL = 0;
#endif
#ifdef USB_ITF_CCID
    ITF_SC_TOTAL = 0;
#endif
    ITF_TOTAL = 0;
#ifdef USB_ITF_HID
    if (enabled_usb_itf & PHY_USB_ITF_HID) {
        ITF_HID_CTAP = ITF_HID_TOTAL++;
        ITF_HID = ITF_TOTAL++;
#ifndef ENABLE_EMULATION
        string_desc_itf[ITF_TOTAL - 1] = string_desc_arr[5];
#endif
    }
    if (enabled_usb_itf & PHY_USB_ITF_KB) {
        ITF_HID_KB = ITF_HID_TOTAL++;
        ITF_KEYBOARD = ITF_TOTAL++;
#ifndef ENABLE_EMULATION
        string_desc_itf[ITF_TOTAL - 1] = string_desc_arr[6];
#endif
    }
#endif
#ifdef USB_ITF_CCID
    if (enabled_usb_itf & PHY_USB_ITF_CCID) {
        ITF_SC_CCID = ITF_SC_TOTAL++;
        ITF_CCID = ITF_TOTAL++;
#ifndef ENABLE_EMULATION
        string_desc_itf[ITF_TOTAL - 1] = string_desc_arr[7];
#endif
    }
    if (enabled_usb_itf & PHY_USB_ITF_WCID) {
        ITF_SC_WCID = ITF_SC_TOTAL++;
        ITF_WCID = ITF_TOTAL++;
#ifndef ENABLE_EMULATION
        string_desc_itf[ITF_TOTAL - 1] = string_desc_arr[8];
#endif
    }
#endif
#ifndef ENABLE_EMULATION
    /* The BOS (WebUSB, Microsoft OS 2.0 / WinUSB) only describes the WCID
     * interface and needs bcdUSB 2.1; CCID and HID bind by class. Without
     * WCID the device is plain USB 2.0, so no host asks for a BOS. */
    bool has_wcid = false;
#ifdef USB_ITF_CCID
    has_wcid = ITF_WCID != ITF_INVALID;
#endif
    if (!has_wcid && desc_device.bcdUSB > 0x0200) {
        desc_device.bcdUSB = 0x0200;
    }
#endif
    card_locked_itf = ITF_TOTAL;
    if (timeout_counter == NULL) {
        timeout_counter = (uint32_t *)calloc(ITF_TOTAL ? ITF_TOTAL : 1, sizeof(uint32_t));
    }
#ifdef USB_ITF_HID
    if (ITF_HID_TOTAL > 0) {
        hid_init();
    }
#endif
#ifdef USB_ITF_CCID
    if (ITF_SC_TOTAL > 0) {
        ccid_init();
    }
#endif
#ifdef ESP_PLATFORM
    usb_desc_setup();
#endif
}

uint32_t timeout = 0;
void timeout_stop() {
    timeout = 0;
}

void timeout_start() {
    timeout = board_millis();
    if (timeout == 0) {
        timeout = 1;
    }
}

bool is_busy() {
    return timeout > 0;
}

void usb_send_event(uint32_t flag) {
#ifndef ENABLE_EMULATION
    mutex_enter_blocking(&mutex);
#endif
    queue_add_blocking(&usb_to_card_q, &flag);
    if (flag == EV_CMD_AVAILABLE) {
        timeout_start();
    }
    uint32_t m;
    queue_remove_blocking(&card_to_usb_q , &m);
#ifndef ENABLE_EMULATION
    mutex_exit(&mutex);
#endif
}

/* Card thread side of a presence request (up.h): core 0 collects one fresh
 * press, or reports a timeout or cancel. Returns true when NO press was
 * collected, the historical wait_button() contract. */
bool wait_button(void) {
    uint32_t val = EV_PRESS_BUTTON;
    queue_try_add(&card_to_usb_q, &val);
    for (;;) {
        queue_remove_blocking(&usb_to_card_q, &val);
        if (val == EV_BUTTON_PRESSED) {
            return false;
        }
        if (val == EV_BUTTON_TIMEOUT) {
            return true;
        }
        if (val == EV_EXIT) {
            /* Left for the thread loop, which acknowledges it and exits. */
            queue_try_add(&usb_to_card_q, &val);
            return true;
        }
    }
}

extern void low_flash_init();
void card_init_core1() {
    low_flash_init_core1();
}

uint16_t finished_data_size = 0;

void card_start(uint8_t itf, void *(*func)(void *)) {
    timeout_start();
    if (card_locked_itf != itf || card_locked_func != func) {
        if (card_locked_itf != ITF_TOTAL || card_locked_func != NULL) {
            card_exit();
        }
        if (func) {
            multicore_reset_core1();
            multicore_launch_func_core1(func);
        }
        led_set_mode(MODE_MOUNTED);
        card_locked_itf = itf;
        card_locked_func = func;
    }
}

/* Only called while the card thread is idle (callers check is_busy()), so
 * the EXIT event is consumed promptly and cannot deadlock the USB side. */
void card_exit() {
    if (card_locked_itf != ITF_TOTAL || card_locked_func != NULL) {
        usb_send_event(EV_EXIT);
        uint32_t m;
        while (queue_is_empty(&usb_to_card_q) == false) {
            if (queue_try_remove(&usb_to_card_q, &m) == false) {
                break;
            }
        }
        while (queue_is_empty(&card_to_usb_q) == false) {
#ifndef ENABLE_EMULATION
            mutex_enter_blocking(&mutex);
#endif
            bool removed = queue_try_remove(&card_to_usb_q, &m);
#ifndef ENABLE_EMULATION
            mutex_exit(&mutex);
#endif
            if (!removed) {
                break;
            }
        }
        led_set_mode(MODE_SUSPENDED);
#ifdef ESP_PLATFORM
        hcore1 = NULL;
#endif
    }
    up_cancel();
    up_waiting_itf = ITF_INVALID;
    card_locked_itf = ITF_TOTAL;
    card_locked_func = NULL;
}

extern void hid_task();
extern void ccid_task();
extern void emul_task();
void usb_task() {
    usb_lock();
#ifdef USB_ITF_HID
    hid_task();
#endif
#ifdef ENABLE_EMULATION
    emul_task();
#else
#ifdef USB_ITF_CCID
    ccid_task();
#endif
#endif
    usb_unlock();
}

int card_status(uint8_t itf) {
    if (card_locked_itf == itf) {
        /* Deliver the outcome of a presence request the card thread waits for. */
        if (up_waiting_itf == itf) {
            up_result_t r = up_poll();
            if (r != UP_RESULT_PENDING) {
                uint32_t flag = (r == UP_RESULT_PRESSED) ? EV_BUTTON_PRESSED : EV_BUTTON_TIMEOUT;
                up_waiting_itf = ITF_INVALID;
                queue_try_add(&usb_to_card_q, &flag);
            }
        }
        uint32_t m = 0x0;
#ifndef ENABLE_EMULATION
        mutex_enter_blocking(&mutex);
#endif
        bool has_m = queue_try_remove(&card_to_usb_q, &m);
#ifndef ENABLE_EMULATION
        mutex_exit(&mutex);
#endif
        if (has_m) {
            if (m == EV_EXEC_FINISHED) {
                timeout_stop();
                led_set_mode(MODE_MOUNTED);
                return PICOKEY_OK;
            }
            else if (m == EV_PRESS_BUTTON) {
                up_request(up_timeout_ms());
                up_waiting_itf = itf;
            }
            return PICOKEY_ERR_FILE_NOT_FOUND;
        }
        else {
            if (timeout > 0 && itf < ITF_TOTAL) {
                if (timeout + timeout_counter[itf] < board_millis()) {
                    timeout = board_millis();
                    return PICOKEY_ERR_BLOCKED;
                }
            }
        }
    }
    return PICOKEY_ERR_FILE_NOT_FOUND;
}

uint8_t card_current_itf() {
    return card_locked_itf;
}

#ifndef USB_ITF_CCID
#include "device/usbd_pvt.h"
usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count) {
    *driver_count = 0;
    return NULL;
}
#endif
