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

#include "pico_keys.h"
#include "up.h"
#include "board_config.h"
#include "profile.h"
#include "usb.h"

#if defined(ESP_PLATFORM)
#include "driver/gpio.h"
#elif defined(PICO_PLATFORM)
#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "hardware/sync.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/structs/sio.h"
#elif defined(ENABLE_EMULATION)
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#endif

#define UP_OTP_GAP_MS 1000   /* presses closer than this are one multi-press */

static bool raw_last = false, stable = false;
static uint32_t raw_changed_ms = 0;

static bool req_active = false;
static bool req_need_release = false;
static volatile bool req_cancel = false;
static uint32_t req_start_ms = 0, req_timeout = 0;
static uint32_t led_mode_saved = 0;
static up_result_t last_result = UP_RESULT_PENDING;

static bool press_idle = false;
static uint8_t idle_presses = 0;
static uint32_t press_start_ms = 0;
static bool long_fired = false, long_pending = false;
static uint32_t idle_last_release_ms = 0;

/* ------------------------------------------------------------------------ */
/* Raw button access                                                        */
/* ------------------------------------------------------------------------ */

#if defined(ESP_PLATFORM)

static void button_hw_init(void) {
    if (BOARD_UP_BUTTON_GPIO < 0 || !board_gpio_is_safe(BOARD_UP_BUTTON_GPIO)) {
        return;
    }
    gpio_config_t cfg = {
        .pin_bit_mask = 1ULL << BOARD_UP_BUTTON_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = BOARD_UP_BUTTON_PULL == 1 ? GPIO_PULLUP_ENABLE : GPIO_PULLUP_DISABLE,
        .pull_down_en = BOARD_UP_BUTTON_PULL == 2 ? GPIO_PULLDOWN_ENABLE : GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&cfg);
}

static bool button_raw(void) {
    if (BOARD_UP_BUTTON_GPIO < 0) {
        return false;
    }
    int level = gpio_get_level(BOARD_UP_BUTTON_GPIO);
    return BOARD_UP_BUTTON_ACTIVE_LOW ? level == 0 : level != 0;
}

/* ESP32-S3: GPIO19/20 are USB, GPIO26..37 are the (octal) flash/PSRAM bus on
 * N16R8 modules, GPIO22..25 do not exist. */
bool board_gpio_is_safe(int gpio) {
#if defined(CONFIG_IDF_TARGET_ESP32S3)
    if (gpio < 0 || gpio > 48) {
        return false;
    }
    if (gpio == 19 || gpio == 20 || (gpio >= 22 && gpio <= 37)) {
        return false;
    }
    return true;
#else
    return GPIO_IS_VALID_GPIO(gpio);
#endif
}

#elif defined(PICO_PLATFORM)

static void button_hw_init(void) {
}

static bool __no_inline_not_in_flash_func(get_bootsel_button)(void) {
    const uint CS_PIN_INDEX = 1;
    /* Flash is unavailable while CS is overridden: no flash code, no IRQs. */
    uint32_t flags = save_and_disable_interrupts();
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_LOW << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);
    for (volatile int i = 0; i < 1000; ++i);
#if PICO_RP2040
    #define CS_BIT (1u << 1)
#else
    #define CS_BIT SIO_GPIO_HI_IN_QSPI_CSN_BITS
#endif
    bool button_state = !(sio_hw->gpio_hi_in & CS_BIT);
    hw_write_masked(&ioqspi_hw->io[CS_PIN_INDEX].ctrl,
                    GPIO_OVERRIDE_NORMAL << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
                    IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS);
    restore_interrupts(flags);
    return button_state;
}

static bool button_raw(void) {
    return get_bootsel_button();
}

bool board_gpio_is_safe(int gpio) {
    return gpio >= 0 && gpio < 30;
}

#else /* emulation */

/* Test hook: LF_EMU_UP=manual makes presence depend on a control socket
 * (127.0.0.1:35970, commands "down\n" / "up\n"); default "auto" answers
 * every request immediately so the functional suites run unattended. */
static bool emu_manual = false;
static bool emu_pressed = false;
static int emu_srv = -1, emu_cli = -1;

static void button_hw_init(void) {
    const char *m = getenv("LF_EMU_UP");
    emu_manual = m && strcmp(m, "manual") == 0;
    if (!emu_manual) {
        return;
    }
    emu_srv = socket(AF_INET, SOCK_STREAM, 0);
    fcntl(emu_srv, F_SETFD, FD_CLOEXEC);
    int yes = 1;
    setsockopt(emu_srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in a = { 0 };
    const char *env_port = getenv("LF_EMU_UP_PORT");
    a.sin_family = AF_INET;
    a.sin_port = htons(env_port && atoi(env_port) > 0 && atoi(env_port) < 65536 ? (uint16_t) atoi(env_port) : 35970);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(emu_srv, (struct sockaddr *) &a, sizeof(a)) != 0 || listen(emu_srv, 1) != 0) {
        close(emu_srv);
        emu_srv = -1;
        return;
    }
    fcntl(emu_srv, F_SETFL, fcntl(emu_srv, F_GETFL, 0) | O_NONBLOCK);
}

static bool button_raw(void) {
    if (!emu_manual) {
        return false;
    }
    if (emu_cli < 0 && emu_srv >= 0) {
        emu_cli = accept(emu_srv, NULL, NULL);
        if (emu_cli >= 0) {
            fcntl(emu_cli, F_SETFD, FD_CLOEXEC);
        }
        if (emu_cli >= 0) {
            fcntl(emu_cli, F_SETFL, fcntl(emu_cli, F_GETFL, 0) | O_NONBLOCK);
        }
    }
    if (emu_cli >= 0) {
        char buf[64];
        ssize_t n = recv(emu_cli, buf, sizeof(buf) - 1, 0);
        if (n == 0) {
            close(emu_cli);
            emu_cli = -1;
        }
        else if (n > 0) {
            buf[n] = 0;
            /* the last command in the chunk wins */
            char *down = strstr(buf, "down"), *upc = strstr(buf, "up");
            if (down && (!upc || down > upc)) {
                emu_pressed = true;
            }
            else if (upc) {
                emu_pressed = false;
            }
        }
    }
    return emu_pressed;
}

bool board_gpio_is_safe(int gpio) {
    return gpio >= 0 && gpio < 64;
}

#endif

/* ------------------------------------------------------------------------ */

static bool auto_accept(void) {
#if defined(ENABLE_EMULATION)
    if (!emu_manual) {
        return true;
    }
#endif
    if (LF_UP_AUTO_ACCEPT) {
        return true;
    }
#if defined(LF_PROFILE_DEVELOPMENT) && !defined(ENABLE_EMULATION)
    /* Legacy opt-out, honoured only by development builds: up_btn = 0. */
    if (phy_data.up_btn_present && phy_data.up_btn == 0) {
        return true;
    }
#endif
    return false;
}

static uint32_t long_press_ms(void) {
#if defined(ENABLE_EMULATION)
    /* Tests shorten the gesture instead of holding a button for 5 s. */
    const char *e = getenv("LF_EMU_LONGPRESS_MS");
    if (e && *e) {
        return (uint32_t) strtoul(e, NULL, 10);
    }
#endif
    return BOARD_UP_LONG_PRESS_MS;
}

bool up_take_long_press(void) {
    if (long_pending) {
        long_pending = false;
        return true;
    }
    return false;
}

void up_init(void) {
    button_hw_init();
    raw_last = stable = button_raw();
    raw_changed_ms = board_millis();
    req_active = false;
    req_cancel = false;
}

uint32_t up_timeout_ms(void) {
#if defined(ENABLE_EMULATION)
    const char *e = getenv("LF_EMU_UP_TIMEOUT_MS");
    if (e && *e) {
        return (uint32_t) strtoul(e, NULL, 10);
    }
#endif
#if !defined(ENABLE_EMULATION)
    /* The PHY option only tunes the timeout; 0 does not disable presence. */
    if (phy_data.up_btn_present && phy_data.up_btn > 0) {
        return (uint32_t) phy_data.up_btn * 1000;
    }
#endif
    return BOARD_UP_TIMEOUT_MS;
}

void up_tick(void) {
    uint32_t now = board_millis();
    bool raw = button_raw();
    if (raw != raw_last) {
        raw_last = raw;
        raw_changed_ms = now;
        return;
    }
    if (stable && press_idle && !long_fired && !req_active && !is_busy() &&
        now - press_start_ms >= long_press_ms()) {
        long_fired = true;
        long_pending = true;
    }
    if (raw == stable || now - raw_changed_ms < BOARD_UP_DEBOUNCE_MS) {
        return;
    }
    stable = raw;
    if (stable) {
        /* A press only counts for idle consumers if nothing is going on. */
        press_idle = !req_active && !is_busy();
        press_start_ms = now;
        long_fired = false;
    }
    else {
        if (press_idle && !req_active && !long_fired) {
            idle_presses++;
            idle_last_release_ms = now;
        }
        press_idle = false;
        long_fired = false;
    }
}

bool up_button_pressed(void) {
    return stable;
}

void up_request(uint32_t timeout_ms) {
    up_tick();
    req_active = true;
    req_cancel = false;
    /* A press in progress (or stuck) must be released first. */
    req_need_release = stable;
    press_idle = false;
    long_pending = false;
    req_start_ms = board_millis();
    req_timeout = timeout_ms ? timeout_ms : up_timeout_ms();
    led_mode_saved = led_get_mode();
    led_set_mode(MODE_BUTTON);
}

static up_result_t up_finish(up_result_t r) {
    req_active = false;
    req_cancel = false;
    last_result = r;
    led_set_mode(led_mode_saved);
    return r;
}

up_result_t up_poll(void) {
    if (!req_active) {
        return UP_RESULT_PENDING;
    }
    up_tick();
    if (req_cancel) {
        return up_finish(UP_RESULT_CANCELLED);
    }
    if (auto_accept()) {
        return up_finish(UP_RESULT_PRESSED);
    }
    if (req_need_release) {
        if (!stable) {
            req_need_release = false;
        }
    }
    else if (stable) {
        return up_finish(UP_RESULT_PRESSED);
    }
    if (board_millis() - req_start_ms > req_timeout) {
        return up_finish(UP_RESULT_TIMEOUT);
    }
    return UP_RESULT_PENDING;
}

void up_cancel(void) {
    if (req_active) {
        req_cancel = true;
    }
}

bool up_pending(void) {
    return req_active;
}

up_result_t up_last_result(void) {
    return last_result;
}

uint8_t up_take_idle_presses(void) {
    if (idle_presses == 0 || stable || req_active) {
        return 0;
    }
    if (board_millis() - idle_last_release_ms < UP_OTP_GAP_MS) {
        return 0;
    }
    uint8_t n = idle_presses;
    idle_presses = 0;
    return n;
}
