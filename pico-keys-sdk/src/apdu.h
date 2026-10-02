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

#ifndef _APDU_H_
#define _APDU_H_

#include <stdlib.h>
#if defined(PICO_PLATFORM)
#include "pico/stdlib.h"
#endif
#include "compat.h"
#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>

typedef struct app {
    const uint8_t *aid;
    int (*process_apdu)();
    int (*select_aid)(struct app *, uint8_t);
    int (*unload)();
} app_t;

extern bool app_exists(const uint8_t *aid, size_t aid_len);
extern int register_app(int (*)(app_t *, uint8_t), const uint8_t *);
extern int select_app(const uint8_t *aid, size_t aid_len);
/* The registered application a SELECT by this AID would pick, or NULL. */
extern app_t *find_app(const uint8_t *aid, size_t aid_len);

typedef struct cmd {
    uint8_t ins;
    int (*cmd_handler)();
} cmd_t;

extern uint8_t num_apps;
extern app_t apps[16];
extern app_t *current_app;

PACK(struct apdu {
    uint8_t *header;
    uint32_t nc;
    uint32_t ne;
    uint8_t *data;
    uint16_t sw;
    uint8_t *rdata;
    uint16_t rlen;

});

#define CLA(a) a.header[0]
#define INS(a) a.header[1]
#define P1(a) a.header[2]
#define P2(a) a.header[3]

#define res_APDU (apdu.rdata)
#define res_APDU_size (apdu.rlen)

extern struct apdu apdu;

/* Largest command data accepted through command chaining (PIV objects are up
 * to ~3 KB). Handlers may extend command data in place (padding), so every
 * buffer apdu.data can point to keeps APDU_DATA_SLACK spare bytes. */
#define APDU_CHAIN_MAX      4096
#define APDU_DATA_SLACK     512

/* Size of the buffer that holds a response (data + SW) built by a handler. */
#define APDU_RES_BUF_SIZE   (4096 + 16)

extern uint8_t apdu_res_buf[APDU_RES_BUF_SIZE];

extern uint16_t set_res_sw(uint8_t sw1, uint8_t sw2);
extern int process_apdu();
extern int process_apdu_txn();
extern void apdu_reset_chaining();
/* Selects the application context of the interface a command arrived on
 * (before dispatch) and saves it back once the command finished. Over HID the
 * CTAPHID_OTP messages (OATH) have a context of their own, so switching
 * between U2F/FIDO and OATH messages never unloads (and resets) OATH. */
extern void apdu_bind_itf(uint8_t itf);
extern void apdu_bind_hid(bool otp);
extern void apdu_unbind_itf();
/* USB interface of the application slot bound right now (while a command
 * runs, or while an application is selected or unloaded outside one: HID
 * transport, card reset, interface switch): ITF_HID, ITF_KEYBOARD, or the
 * smart card interface (ITF_CCID / ITF_WCID) whose client owns that slot. */
extern uint8_t apdu_bound_itf(void);
/* itf is the USB interface the command arrived on (ITF_HID, ITF_CCID,
 * ITF_WCID), never a class-local index; apdu.rdata must point at that
 * interface's response buffer. Returns 1 when the card thread must run the
 * command, 0 when it was answered here (GET RESPONSE). */
extern uint16_t apdu_process(uint8_t itf, const uint8_t *buffer, uint16_t buffer_size);
extern void apdu_finish();
extern uint16_t apdu_next();
extern void *apdu_thread(void *);

/* Drops (and wipes) the response data an interface left for GET RESPONSE. */
extern void apdu_discard_response(uint8_t itf);
/* Card reset / power change requested on smart card interface itf (ITF_CCID,
 * ITF_WCID): the smart card GET RESPONSE data, command chain and application
 * state go, if itf's client owns them (the interface of the last smart card
 * command; the other interface's client lost them when that one took the
 * slot). Deferred while a command runs, never skipped. When a command
 * finishes, its transport checks apdu_card_reset_pending(itf of the command):
 * if that interface was reset meanwhile, the answer belongs to the ended
 * session and is not delivered; otherwise it is delivered as usual. Then it
 * calls apdu_card_reset_poll(), which performs the deferred reset. */
extern void apdu_card_reset(uint8_t itf);
extern bool apdu_card_reset_pending(uint8_t itf);
extern void apdu_card_reset_poll(void);
/* The smart card interfaces (CCID, WCID) share one command chain and one
 * response buffer. True while the other one owns an open chain or a response
 * left for GET RESPONSE (and still uses it): a command from itf must then be
 * refused (slot busy) instead of breaking that state. */
extern bool apdu_sc_blocked(uint8_t itf);
/* True if [p, p + len) lies inside apdu_res_buf. */
extern bool apdu_res_span_ok(const uint8_t *p, size_t len);

#endif
