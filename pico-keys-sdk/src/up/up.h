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
 * User presence (UP) collection.
 *
 * Security invariants:
 *  - Presence is only ever derived from the physical button; no USB command
 *    can set it (the rescue/PHY configuration can only change the timeout).
 *  - A request is satisfied by a debounced press that STARTS after the
 *    request was issued. A button already held when the request starts must
 *    be released first, so a stale or stuck press never authorizes anything.
 *  - One press satisfies exactly one request.
 *  - Presses that overlap a request or a running command are never reported
 *    to the idle-press (OTP typing) consumer.
 *
 * All functions except up_cancel() run in the USB/core0 loop context.
 */

#ifndef _UP_H_
#define _UP_H_

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    UP_RESULT_PENDING = 0,
    UP_RESULT_PRESSED,
    UP_RESULT_TIMEOUT,
    UP_RESULT_CANCELLED,
} up_result_t;

extern void up_init(void);
/* Samples and debounces the button; call periodically (>= every 10 ms). */
extern void up_tick(void);
/* Starts collecting presence; any previous request is abandoned. */
extern void up_request(uint32_t timeout_ms);
/* Result of the current request; returns PENDING while waiting. A final
 * result is returned once and clears the request. */
extern up_result_t up_poll(void);
/* Aborts the pending request (CTAPHID_CANCEL, interface reset). */
extern void up_cancel(void);
extern bool up_pending(void);
/* Final result of the last finished request (lets FIDO report CANCEL vs
 * timeout); read by the card thread after being woken up. */
extern up_result_t up_last_result(void);
/* Effective timeout: board default, overridable (not disableable) by PHY. */
extern uint32_t up_timeout_ms(void);
/* Number of short presses completed while idle (0 if none ready yet). */
extern uint8_t up_take_idle_presses(void);
/* True once for each press held for BOARD_UP_LONG_PRESS_MS while idle (the
 * profile switch gesture). Such a press is never counted as a short press
 * and can never satisfy a presence request. */
extern bool up_take_long_press(void);
extern bool up_button_pressed(void);

#endif // _UP_H_
