"""Resolve the board Kconfig, then run the real ESP GPIO presence path on
host GPIO/time stubs. No USB device, emulator, credentials or keys needed.

    pip install pytest kconfiglib
    python -m pytest -q tests/unit/test_up_button.py
"""

import os
from pathlib import Path
import shutil
import subprocess

import kconfiglib
import pytest

REPO = Path(__file__).resolve().parents[2]
SDK_SRC = REPO / "pico-keys-sdk" / "src"


@pytest.mark.parametrize("overlays,gpio", [
    ([], 0),
    (["sdkconfig.4mb"], 0),
    (["sdkconfig.4mb", "sdkconfig.atoms3u"], 41),
])
def test_esp_button_presence(tmp_path, overlays, gpio):
    cc = os.environ.get("CC") or shutil.which("cc")
    if not cc:
        pytest.skip("no host C compiler")

    # Use the project's actual Kconfig defaults and board overlay, rather
    # than hard-coding the GPIO/polarity passed into the firmware compiler.
    config = kconfiglib.Kconfig(str(REPO / "src/fido2/Kconfig.projbuild"), warn=False)
    config.load_config(str(REPO / "sdkconfig.defaults"))
    for overlay in overlays:
        config.load_config(str(REPO / overlay), replace=False)
    config.write_autoconf(str(tmp_path / "sdkconfig.h"))

    (tmp_path / "pico_keys.h").write_text('''
#include <stdbool.h>
#include <stdint.h>
#include "led/led.h"
extern struct phy_stub { bool up_btn_present; uint8_t up_btn; } phy_data;
uint32_t board_millis(void);
''')
    (tmp_path / "usb.h").write_text('''
#include <stdbool.h>
bool is_busy(void);
''')
    (tmp_path / "driver").mkdir()
    (tmp_path / "driver/gpio.h").write_text('''
#include <stdint.h>
typedef struct {
    uint64_t pin_bit_mask;
    int mode, pull_up_en, pull_down_en, intr_type;
} gpio_config_t;
enum { GPIO_MODE_INPUT = 1, GPIO_PULLUP_DISABLE = 0, GPIO_PULLUP_ENABLE = 1,
       GPIO_PULLDOWN_DISABLE = 0, GPIO_PULLDOWN_ENABLE = 1, GPIO_INTR_DISABLE = 0 };
int gpio_config(const gpio_config_t *cfg);
int gpio_get_level(int pin);
''')
    harness = tmp_path / "button.c"
    harness.write_text('''
#include <assert.h>
#include "pico_keys.h"
#include "board_config.h"
#include "up.h"
#include "driver/gpio.h"

_Static_assert(BOARD_UP_BUTTON_GPIO == EXPECT_GPIO, "button mapping");
_Static_assert(BOARD_UP_BUTTON_ACTIVE_LOW == 1, "active low");
_Static_assert(BOARD_UP_BUTTON_PULL == 1, "pull-up");

struct phy_stub phy_data;
static uint32_t now;
static int levels[49];
static gpio_config_t configured;
uint32_t board_millis(void) { return now; }
bool is_busy(void) { return false; }
uint32_t led_get_mode(void) { return 0; }
void led_set_mode(uint32_t mode) { (void)mode; }
int gpio_config(const gpio_config_t *cfg) { configured = *cfg; return 0; }
int gpio_get_level(int pin) { assert(pin == EXPECT_GPIO); return levels[pin]; }

static void sample(int pin, int level, uint32_t elapsed) {
    levels[pin] = level;
    now += elapsed;
    up_tick();
}
static void settle(int pin, int level) {
    sample(pin, level, 1);
    sample(pin, level, BOARD_UP_DEBOUNCE_MS);
}
int main(void) {
    for (int pin = 0; pin < 49; ++pin) levels[pin] = 1;
    assert(board_gpio_is_safe(EXPECT_GPIO));
    up_init();
    assert(configured.pin_bit_mask == (1ULL << EXPECT_GPIO));
    assert(configured.mode == GPIO_MODE_INPUT);
    assert(configured.pull_up_en == GPIO_PULLUP_ENABLE);
    assert(configured.pull_down_en == GPIO_PULLDOWN_DISABLE);
    assert(configured.intr_type == GPIO_INTR_DISABLE);
    assert(!up_button_pressed());

    up_request(1000);
    assert(up_poll() == UP_RESULT_PENDING);  /* no automatic presence */
    int other = EXPECT_GPIO == 41 ? 0 : 41;
    settle(other, 0);
    assert(up_poll() == UP_RESULT_PENDING);  /* the other board's button */
    sample(EXPECT_GPIO, 0, 1);
    sample(EXPECT_GPIO, 0, BOARD_UP_DEBOUNCE_MS - 1);
    assert(up_poll() == UP_RESULT_PENDING);  /* bounce / short pulse */
    settle(EXPECT_GPIO, 1);
    assert(up_poll() == UP_RESULT_PENDING);
    settle(EXPECT_GPIO, 0);
    assert(up_poll() == UP_RESULT_PRESSED);
    assert(!up_pending());
    assert(up_take_idle_presses() == 0);     /* not also an OTP press */

    up_request(1000);                       /* still held from last request */
    assert(up_poll() == UP_RESULT_PENDING);
    sample(EXPECT_GPIO, 0, 100);
    assert(up_poll() == UP_RESULT_PENDING);
    settle(EXPECT_GPIO, 1);
    assert(up_poll() == UP_RESULT_PENDING);
    settle(EXPECT_GPIO, 0);
    assert(up_poll() == UP_RESULT_PRESSED);  /* released, then pressed again */

    settle(EXPECT_GPIO, 1);
    up_request(100);
    now += 101;
    assert(up_poll() == UP_RESULT_TIMEOUT);
    up_request(100);
    up_cancel();
    assert(up_poll() == UP_RESULT_CANCELLED);
    return 0;
}
''')
    binary = tmp_path / "button"
    subprocess.run([
        cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-DESP_PLATFORM", "-DCONFIG_IDF_TARGET_ESP32S3", f"-DEXPECT_GPIO={gpio}",
        "-I" + str(tmp_path), "-I" + str(SDK_SRC), "-I" + str(SDK_SRC / "up"),
        str(SDK_SRC / "up/up.c"), str(harness), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True)
