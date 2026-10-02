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

#include "apdu.h"
#include "pico_keys.h"
#include "usb.h"
#include "low_flash.h"
#include "mbedtls/platform_util.h"
#include <stdio.h>
#ifdef ESP_PLATFORM
#include "esp_compat.h"
#endif
#ifdef ENABLE_EMULATION
#include "emulation.h"
#endif

extern uint32_t timeout;

/* Response buffer for smart card transports (data + SW). */
uint8_t apdu_res_buf[APDU_RES_BUF_SIZE];

bool apdu_res_span_ok(const uint8_t *p, size_t len) {
    return p >= apdu_res_buf && p <= apdu_res_buf + APDU_RES_BUF_SIZE &&
           len <= (size_t) (apdu_res_buf + APDU_RES_BUF_SIZE - p);
}

/* Command chaining (ISO 7816-4 5.3.3). The chain is assembled in its own
 * buffer; the transport buffer is never written past the received data.
 * Chaining is a smart card feature: the chain belongs to the smart card
 * interface that opened it (chain_itf). HID traffic can neither extend, use
 * nor reset it; the other smart card interface is refused while the owner
 * uses it (apdu_sc_blocked()). If the other interface takes over a chain
 * its owner left unused, the owner's next chained blocks fail with 6883
 * instead of silently starting a new, truncated chain.
 * The chain holds command data (keys, PINs): it is wiped when it goes. */
bool is_chaining = false;
static uint8_t chain_buf[APDU_CHAIN_MAX + APDU_DATA_SLACK];
static uint16_t chain_len = 0;
static uint8_t chain_ins = 0;
static uint8_t chain_itf = ITF_INVALID;
static uint8_t broken_itf = ITF_INVALID;    /* owner of a chain another interface ended */
static uint8_t broken_ins = 0;
static bool chain_used = false;             /* chain_buf is the running command's data */
static bool apdu_malformed = false;

void apdu_reset_chaining() {
    is_chaining = false;
    chain_len = 0;
    chain_itf = ITF_INVALID;
    mbedtls_platform_zeroize(chain_buf, sizeof(chain_buf));
}

/* The chain of chain_itf ends because the other interface took over. */
static void chain_break(void) {
    if (is_chaining) {
        broken_itf = chain_itf;
        broken_ins = chain_ins;
    }
    apdu_reset_chaining();
}

/* The selected application is tracked per interface family, so a browser
 * using FIDO over HID never deselects (and logs out) the application a
 * smart card client has selected over CCID, and vice versa. Over HID the
 * transport picks the application (U2F, FIDO, OATH) and a SELECT may only
 * confirm it (process_apdu()), so the HID slots never hold, unload or
 * re-initialise a smart card application. */
enum { APP_SLOT_CCID = 0, APP_SLOT_HID, APP_SLOT_HID_OTP, APP_SLOT_KB, APP_SLOTS };
static app_t *slot_app[APP_SLOTS] = { NULL };
static uint8_t bound_slot = APP_SLOT_CCID;

static uint8_t slot_of(uint8_t itf) {
#ifdef USB_ITF_HID
    if (itf == ITF_HID) {
        return APP_SLOT_HID;
    }
    if (itf == ITF_KEYBOARD) {
        return APP_SLOT_KB;
    }
#endif
    (void) itf;
    return APP_SLOT_CCID;
}

/* Smart card interface whose client uses the smart card slot's application. */
static uint8_t sc_app_itf = ITF_INVALID;

void apdu_bind_itf(uint8_t itf) {
    bound_slot = slot_of(itf);
    current_app = slot_app[bound_slot];
    if (bound_slot == APP_SLOT_CCID && itf != sc_app_itf) {
        /* CCID and WCID share this slot, but security state (PIN, access
         * code, management key) belongs to one client: a command from the
         * other interface finds the application unloaded (logged out) and has
         * to select it again. */
        if (current_app && current_app->unload) {
            current_app->unload();
        }
        current_app = NULL;
        slot_app[APP_SLOT_CCID] = NULL;
        sc_app_itf = itf;
    }
}

void apdu_bind_hid(bool otp) {
    bound_slot = otp ? APP_SLOT_HID_OTP : APP_SLOT_HID;
    current_app = slot_app[bound_slot];
}

uint8_t apdu_bound_itf(void) {
#ifdef USB_ITF_HID
    if (bound_slot == APP_SLOT_HID || bound_slot == APP_SLOT_HID_OTP) {
        return ITF_HID;
    }
    if (bound_slot == APP_SLOT_KB) {
        return ITF_KEYBOARD;
    }
#endif
    /* The smart card slot: the interface whose client owns it (also while
     * its application is unloaded because the other interface takes over). */
    if (sc_app_itf != ITF_INVALID) {
        return sc_app_itf;
    }
#ifdef USB_ITF_CCID
    return ITF_CCID;
#else
    return ITF_INVALID;
#endif
}

void apdu_unbind_itf() {
    slot_app[bound_slot] = current_app;
}

/* Response data a command left for GET RESPONSE (ISO 7816-4 5.3.4). It is kept
 * per interface family, like the selected application, and is only ever
 * handed to the interface that issued the command. It goes once delivered, on
 * any other command of that interface (a new SELECT included) and on a card
 * reset. The data stays in the command's response buffer; the two response
 * bytes under the 61xx status word are kept in bk. */
typedef struct {
    uint8_t *base;      /* response buffer of the command (its apdu.rdata) */
    uint16_t total;     /* size of the whole response, SW included */
    uint16_t off;       /* first byte not delivered yet */
    uint16_t left;      /* data bytes not delivered yet, SW excluded */
    uint16_t bk;        /* response bytes replaced by the 61xx status word */
    uint8_t itf;        /* interface the command came from */
    bool pending;
} apdu_resp_t;
static apdu_resp_t resp_slot[APP_SLOTS];

/* Interface of the command handed to the card thread and the largest response
 * one transfer of that interface carries. */
static uint8_t cmd_itf = ITF_INVALID;
static uint16_t cmd_max_resp = USB_CCID_MAX_RESP_DATA;

static uint16_t max_resp_of(uint8_t itf) {
#ifdef USB_ITF_HID
    if (itf == ITF_HID) {
        return USB_HID_MAX_RESP_DATA;
    }
#endif
    /* CCID; the emulator's vpcd link uses the same limit as the hardware. */
    (void) itf;
    return USB_CCID_MAX_RESP_DATA;
}

static void resp_clear(apdu_resp_t *r) {
    mbedtls_platform_zeroize(r, sizeof(*r));
}

/* Undelivered data is wiped. Delivered data was wiped by the transport once
 * it copied or transmitted it. */
static void resp_drop(apdu_resp_t *r) {
    if (r->pending && r->base) {
        mbedtls_platform_zeroize(r->base, r->total);
    }
    resp_clear(r);
}

void apdu_discard_response(uint8_t itf) {
    resp_drop(&resp_slot[slot_of(itf)]);
}

/* Hands a response chunk to the driver of the interface it belongs to. */
static void resp_send(uint8_t itf, uint16_t size, uint16_t off) {
#ifdef USB_ITF_HID
    if (itf == ITF_HID) {
        driver_exec_finished_cont_hid(ITF_HID_CTAP, size, off);
        return;
    }
#endif
#if defined(ENABLE_EMULATION)
    driver_exec_finished_cont_emul(itf, size, off);
#elif defined(USB_ITF_CCID)
    if (itf == ITF_CCID) {
        driver_exec_finished_cont_ccid(ITF_SC_CCID, size, off);
    }
    else if (itf == ITF_WCID) {
        driver_exec_finished_cont_ccid(ITF_SC_WCID, size, off);
    }
#else
    (void) itf;
    (void) size;
    (void) off;
#endif
}

/* The reset and ownership functions below run in the USB context (usb_lock
 * held, or the emulator loop). State the card thread also uses (the chain,
 * the response slots, current_app) is only touched there while no command
 * runs (!is_busy()): the card thread is then idle, and the command queues
 * order its writes before ours. */

/* Smart card interfaces (bit per USB interface) reset while a command ran. */
static uint8_t card_reset_req = 0;

static uint8_t itf_bit(uint8_t itf) {
    return itf < 8 ? (uint8_t) (1u << itf) : 0;
}

/* The shared smart card state: the chain or the pending response (never both
 * with different owners: any command of an interface drops the response the
 * slot holds). The owner's last command, for the hold time. */
#define APDU_SC_HOLD_MS 2000
static uint32_t sc_last_ms = 0;

static uint8_t sc_owner(void) {
    if (is_chaining) {
        return chain_itf;
    }
    if (resp_slot[APP_SLOT_CCID].pending) {
        return resp_slot[APP_SLOT_CCID].itf;
    }
    return ITF_INVALID;
}

bool apdu_sc_blocked(uint8_t itf) {
    uint8_t owner = sc_owner();
    /* Chained blocks and GET RESPONSE follow each other at once; state the
     * owner left alone for APDU_SC_HOLD_MS is abandoned. */
    return owner != ITF_INVALID && owner != itf && board_millis() - sc_last_ms < APDU_SC_HOLD_MS;
}

static void sc_reset(uint8_t req) {
    if (sc_app_itf != ITF_INVALID && !(req & itf_bit(sc_app_itf))) {
        /* Only the other smart card interface was reset. The session (its
         * application, chain and GET RESPONSE data) belongs to the client of
         * sc_app_itf; the other client's session already ended when this one
         * took the slot over (apdu_bind_itf()). */
        return;
    }
    apdu_reset_chaining();
    resp_drop(&resp_slot[APP_SLOT_CCID]);
    mbedtls_platform_zeroize(apdu_res_buf, sizeof(apdu_res_buf));
    bound_slot = APP_SLOT_CCID;
    current_app = slot_app[APP_SLOT_CCID];
    if (current_app && current_app->unload) {
        current_app->unload();
    }
    current_app = NULL;
    slot_app[APP_SLOT_CCID] = NULL;
}

void apdu_card_reset(uint8_t itf) {
    card_reset_req |= itf_bit(itf);
    if (is_busy()) {
        /* The card thread and the command state belong to the running
         * command; the reset happens as soon as it finished. */
        return;
    }
    uint8_t req = card_reset_req | itf_bit(itf);
    card_reset_req = 0;
    sc_reset(req);
}

bool apdu_card_reset_pending(uint8_t itf) {
    return (card_reset_req & itf_bit(itf)) != 0;
}

void apdu_card_reset_poll(void) {
    if (card_reset_req && !is_busy()) {
        uint8_t req = card_reset_req;
        card_reset_req = 0;
        sc_reset(req);
    }
}

int process_apdu() {
    led_set_mode(MODE_PROCESSING);
    bool sc = bound_slot == APP_SLOT_CCID;
    if (apdu_malformed) {
        if (sc) {
            apdu_reset_chaining();
        }
        return SW_WRONG_LENGTH();
    }
    if (sc && broken_itf == cmd_itf) {
        /* This interface's chain was ended by another one: its remaining
         * blocks must not start a new chain or run as a whole command. The
         * first command outside the chain clears this. */
        bool rest = (CLA(apdu) & 0x10) || INS(apdu) == broken_ins;
        if (!(CLA(apdu) & 0x10)) {
            broken_itf = ITF_INVALID;
        }
        if (rest) {
            return set_res_sw(0x68, 0x83);
        }
    }
    if (!sc) {
        /* HID transports carry whole messages (up to 7609 bytes). */
        if (CLA(apdu) & 0x10) {
            return set_res_sw(0x68, 0x84); /* command chaining not supported */
        }
    }
    else if (CLA(apdu) & 0x10) {
        if (!is_chaining) {
            chain_len = 0;
            chain_ins = INS(apdu);
            chain_itf = cmd_itf;
        }
        else if (INS(apdu) != chain_ins) {
            apdu_reset_chaining();
            return set_res_sw(0x68, 0x83); /* last command of the chain expected */
        }
        if ((uint32_t) chain_len + apdu.nc > APDU_CHAIN_MAX) {
            apdu_reset_chaining();
            return SW_WRONG_LENGTH();
        }
        memcpy(chain_buf + chain_len, apdu.data, apdu.nc);
        chain_len += (uint16_t) apdu.nc;
        is_chaining = true;
        return SW_OK();
    }
    else if (is_chaining) {
        if (INS(apdu) != chain_ins) {
            apdu_reset_chaining();
            if (INS(apdu) != 0xA4 || P1(apdu) != 0x04) {
                return set_res_sw(0x68, 0x83);
            }
            /* A new SELECT by AID ends the unfinished chain and runs. */
        }
        else {
            if ((uint32_t) chain_len + apdu.nc > APDU_CHAIN_MAX) {
                apdu_reset_chaining();
                return SW_WRONG_LENGTH();
            }
            memcpy(chain_buf + chain_len, apdu.data, apdu.nc);
            apdu.data = chain_buf;
            apdu.nc += chain_len;
            is_chaining = false;
            chain_len = 0;
            chain_itf = ITF_INVALID;
            chain_used = true;      /* wiped once the command finished */
        }
    }
    if (INS(apdu) == 0xA4 && P1(apdu) == 0x04 && (P2(apdu) == 0x00 || P2(apdu) == 0x4)) { //select by AID
        if (!sc && find_app(apdu.data, apdu.nc) != current_app) {
            /* Over HID the transport picked the application; a SELECT may
             * only confirm it. Selecting another one would unload it or
             * re-initialise one a smart card client uses: security state is
             * global per application. */
            return SW_FILE_NOT_FOUND();
        }
        if (select_app(apdu.data, apdu.nc) == PICOKEY_OK) {
            return SW_OK();
        }
        return SW_FILE_NOT_FOUND();
    }
    if (current_app && current_app->process_apdu) {
        return current_app->process_apdu();
    }
    return SW_FILE_NOT_FOUND();
}

/* Runs one command as a storage transaction: everything it wrote is durable
 * before the caller releases the response. A failed commit turns a success
 * status into "memory failure" so the host never sees a false success. */
int process_apdu_txn() {
    low_flash_txn_begin();
    int r = process_apdu();
    if (low_flash_txn_end() != PICOKEY_OK && apdu.sw == 0x9000) {
        r = SW_MEMORY_FAILURE();
    }
    return r;
}

/* Parses the command header per ISO 7816-3 12.1 cases 1..4 (short and
 * extended). Any mismatch between the encoded lengths and the received size
 * marks the command as malformed; process_apdu() then answers 6700. */
uint16_t apdu_process(uint8_t itf, const uint8_t *buffer, uint16_t buffer_size) {
    apdu.header = (uint8_t *) buffer;
    apdu.nc = apdu.ne = 0;
    apdu.data = (uint8_t *) buffer + MIN(buffer_size, 5);
    apdu_malformed = false;
    if (buffer_size < 4) {
        apdu_malformed = true;
        apdu.data = (uint8_t *) buffer;
    }
    else if (buffer_size == 4) {             /* case 1: lenient, allow a response */
        apdu.ne = 256;
    }
    else if (buffer_size == 5) {             /* case 2S */
        apdu.ne = apdu.header[4];
        if (apdu.ne == 0) {
            apdu.ne = 256;
        }
    }
    else if (apdu.header[4] == 0x0 && buffer_size >= 7) {
        if (buffer_size == 7) {              /* case 2E */
            apdu.ne = get_uint16_t_be(apdu.header + 5);
            if (apdu.ne == 0) {
                apdu.ne = 65536;
            }
        }
        else {
            apdu.nc = get_uint16_t_be(apdu.header + 5);
            apdu.data = apdu.header + 7;
            if (apdu.nc == 0) {
                /* U2F raw messages encode "no data" as Lc = 00 00 followed
                 * by a 2 byte Le (FIDO U2F Raw Message Formats 3.1.1). */
                if (buffer_size == 9) {
                    apdu.ne = get_uint16_t_be(apdu.header + 7);
                    if (apdu.ne == 0) {
                        apdu.ne = 65536;
                    }
                }
                else {
                    apdu_malformed = true;
                }
            }
            else if (apdu.nc + 7 == buffer_size) {      /* case 3E */
                apdu.ne = 0;
            }
            else if (apdu.nc + 7 + 2 == buffer_size) {  /* case 4E */
                apdu.ne = get_uint16_t_be(apdu.header + buffer_size - 2);
                if (apdu.ne == 0) {
                    apdu.ne = 65536;
                }
            }
            else {
                apdu_malformed = true;
            }
        }
    }
    else {
        apdu.nc = apdu.header[4];
        apdu.data = apdu.header + 5;
        if (apdu.nc + 5 == buffer_size) {               /* case 3S */
            apdu.ne = 0;
        }
        else if (apdu.nc + 5 + 1 == buffer_size) {      /* case 4S */
            apdu.ne = apdu.header[buffer_size - 1];
            if (apdu.ne == 0) {
                apdu.ne = 256;
            }
        }
        else {
            apdu_malformed = true;
        }
    }
    if (apdu_malformed) {
        apdu.nc = 0;
    }
    //printf("apdu.nc %u, apdu.ne %u\n",apdu.nc,apdu.ne);
    bool sc = slot_of(itf) == APP_SLOT_CCID;
    if (sc) {
        sc_last_ms = board_millis();
    }
    apdu_resp_t *r = &resp_slot[slot_of(itf)];
    /* GET RESPONSE, or OATH SEND REMAINING (00 A5 00 00, yubikit), for data
     * this interface's previous command left: answered here. */
    bool get_response = !apdu_malformed &&
                        (INS(apdu) == 0xC0 ||
                         (INS(apdu) == 0xA5 && CLA(apdu) == 0x00 && P1(apdu) == 0x00 && P2(apdu) == 0x00 && apdu.nc == 0));
    if (get_response && r->pending && r->itf == itf && r->base == apdu.rdata) {
        timeout_stop();
        uint32_t ne = apdu.ne ? apdu.ne : 256;
        if (ne > max_resp_of(itf)) {
            ne = max_resp_of(itf);
        }
        uint16_t off = r->off, size;
        bool last = r->left <= ne;
        put_uint16_t_be(r->bk, r->base + off);
        if (last) {
            size = (uint16_t)(r->left + 2);     /* the rest, with the command's SW */
        }
        else {
            uint16_t next = (uint16_t)(off + ne);
            r->left -= (uint16_t) ne;
            r->off = next;
            r->bk = get_uint16_t_be(r->base + next);
            r->base[next] = 0x61;
            r->base[next + 1] = r->left >= 256 ? 0 : (uint8_t) r->left;
            size = (uint16_t)(ne + 2);
        }
        if (last) {
            /* Delivered: the transport wipes the data once it has sent it. */
            resp_clear(r);
        }
        resp_send(itf, size, off);
        return 0;
    }
    /* Any other command (and a GET RESPONSE with nothing pending for this
     * interface, which the application answers) ends what was pending. */
    resp_drop(r);
    if (sc && is_chaining && chain_itf != itf) {
        /* The other smart card interface left its chain unused for
         * APDU_SC_HOLD_MS (apdu_sc_blocked() let this command through). */
        chain_break();
    }
    cmd_itf = itf;
    cmd_max_resp = max_resp_of(itf);
    if (apdu.ne > cmd_max_resp) {
        apdu.ne = cmd_max_resp;
    }
    apdu.sw = 0;
    apdu.rlen = 0;
    return 1;
}

uint16_t set_res_sw(uint8_t sw1, uint8_t sw2) {
    apdu.sw = make_uint16_t_be(sw1, sw2);
    if (sw1 != 0x90) {
        res_APDU_size = 0;
    }
    return make_uint16_t_be(sw1, sw2);
}

void *apdu_thread(void *arg) {
    (void)arg;
    card_init_core1();
    while (1) {
        uint32_t m = 0;
        queue_remove_blocking(&usb_to_card_q, &m);
        uint32_t flag = m + 1;
        queue_add_blocking(&card_to_usb_q, &flag);

        if (m == EV_VERIFY_CMD_AVAILABLE || m == EV_MODIFY_CMD_AVAILABLE) {
            set_res_sw(0x6f, 0x00);
            goto done;
        }
        else if (m == EV_EXIT) {
            break;
        }
        else if (m != EV_CMD_AVAILABLE) {
            /* Stale button events must not be taken for a command. */
            continue;
        }

        process_apdu_txn();
        if (chain_used) {
            /* The command ran on the assembled chain: keys and PINs do not
             * stay in chain_buf. */
            chain_used = false;
            mbedtls_platform_zeroize(chain_buf, sizeof(chain_buf));
        }

done:   ;
        apdu_finish();

        finished_data_size = apdu_next();
        flag = EV_EXEC_FINISHED;
        queue_add_blocking(&card_to_usb_q, &flag);
#ifdef ESP_PLATFORM
        vTaskDelay(pdMS_TO_TICKS(10));
#endif
    }
    /* The thread only exits to be replaced by another interface's or
     * command type's thread (card_start()). It must not unload current_app:
     * by then it is the application the next command's interface selected,
     * and each interface keeps its own. The HID slots only ever hold the
     * applications the HID transport selects (U2F, FIDO, OATH), so HID
     * traffic never unloads or re-selects an application of the smart card
     * slot; card resets unload the smart card application. (Session state an
     * application keeps globally, e.g. OATH's, is that application's.) */
    return NULL;
}

void apdu_finish() {
    put_uint16_t_be(apdu.sw, apdu.rdata + apdu.rlen);
    // timeout_stop();
#ifndef ENABLE_EMULATION
    /* It was fixed in the USB handling. Keep it just in case */
    //if ((apdu.rlen + 2 + 10) % 64 == 0) {     // FIX for strange behaviour with PSCS and multiple of 64
    //    apdu.ne = apdu.rlen - 2;
    //}
#endif
}

/* Runs in the card thread once the command finished: returns the size of the
 * first transfer and keeps the rest for GET RESPONSE. */
uint16_t apdu_next() {
    if (slot_of(cmd_itf) == APP_SLOT_CCID) {
        sc_last_ms = board_millis();    /* the hold counts from the answer */
    }
    if (apdu_res_span_ok(apdu.rdata, (size_t) apdu.rlen + 2)) {
        /* Whatever the smart card response buffer holds past this response
         * (handler scratch such as the CTAP-over-CCID encoding, older
         * responses) is not delivered: wipe it. */
        uint8_t *end = apdu.rdata + apdu.rlen + 2;
        mbedtls_platform_zeroize(end, (size_t) (apdu_res_buf + APDU_RES_BUF_SIZE - end));
    }
    if (apdu.sw != 0) {
        /* Handlers may raise ne (up to the whole response); one transfer
         * never carries more than the command's interface allows, the rest
         * is chained with 61xx. */
        if (apdu.ne > cmd_max_resp) {
            apdu.ne = cmd_max_resp;
        }
        if (apdu.rlen <= apdu.ne) {
            return apdu.rlen + 2;
        }
        /* A case 3 command (ne == 0) that produced data answers 61xx and the
         * data is fetched with GET RESPONSE (ISO 7816-4 5.3.4). */
        apdu_resp_t *r = &resp_slot[slot_of(cmd_itf)];
        r->base = apdu.rdata;
        r->total = (uint16_t)(apdu.rlen + 2);
        r->off = (uint16_t) apdu.ne;
        r->left = (uint16_t)(apdu.rlen - apdu.ne);
        r->bk = get_uint16_t_be(apdu.rdata + r->off);
        r->itf = cmd_itf;
        r->pending = true;
        apdu.rdata[r->off] = 0x61;
        apdu.rdata[r->off + 1] = r->left >= 256 ? 0 : (uint8_t) r->left;
        return (uint16_t)(apdu.ne + 2);
    }
    return 0;
}
