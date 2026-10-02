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

/*
 * CTAPHID transport (FIDO Client to Authenticator Protocol, section 11.2).
 *
 * Invariants:
 *  - One command executes at a time on the whole device (is_busy()). Frames
 *    for other channels are answered with CHANNEL_BUSY and never touch the
 *    running command's buffers: receive reassembly, command response and
 *    immediate replies use separate storage.
 *  - Every CTAPHID_INIT on the broadcast channel allocates a new CID.
 *  - CTAPHID_CANCEL on the running channel aborts a pending user presence
 *    request; the command then answers CTAP2_ERR_KEEPALIVE_CANCEL itself.
 *  - A message is dispatched to the card thread only if no command (of any
 *    interface) runs when it completes, not only when its first frame came.
 *  - The response ring is wiped once transmitted; frames are sent from a
 *    padded copy, never with bytes past the response.
 */

#include "pico_keys.h"
#ifndef ENABLE_EMULATION
#include "tusb.h"
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#elif defined(ESP_PLATFORM)
static portMUX_TYPE mutex = portMUX_INITIALIZER_UNLOCKED;
#endif
#else
#include "emulation.h"
#endif
#include "ctap_hid.h"
#include "pico_keys_version.h"
#include "apdu.h"
#include "usb.h"
#include "up/up.h"
#include "random.h"
#include "mbedtls/platform_util.h"

bool is_nk = false;
uint8_t (*get_version_major)() = NULL;
uint8_t (*get_version_minor)() = NULL;

static usb_buffer_t *hid_rx = NULL, *hid_tx = NULL;

PACK(
typedef struct msg_packet {
    uint16_t len;
    uint16_t current_len;
    uint8_t data[CTAP_MAX_PACKET_SIZE + APDU_DATA_SLACK];
}) msg_packet_t;

msg_packet_t msg_packet = { 0 };

static uint16_t *send_buffer_size = NULL;
static write_status_t *last_write_result = NULL;

/* ctap_req: frame being parsed. ctap_resp: response of the running command
 * (the CBOR layer encodes into ctap_resp->init.data + 1). tx_frame: frame
 * currently being transmitted from the response ring. */
CTAPHID_FRAME *ctap_req = NULL, *ctap_resp = NULL;
static CTAPHID_FRAME *tx_frame = NULL;

/* Small FIFO for single frame replies (errors, INIT, keepalive, ...). */
#define URGENT_FRAMES 4
static uint8_t urgent[URGENT_FRAMES][64];
static uint8_t urgent_head = 0, urgent_count = 0;

/* TinyUSB reports completion with its own copy of the report, so remember
 * whether the single outstanding write came from the response ring. */
static bool pending_from_ring = false;

static uint32_t msg_cid = 0;            /* channel of the message being received */
static uint32_t cmd_cid = 0;            /* channel of the command in the card thread */
static uint32_t apdu_cid = 0;           /* channel of the last CTAPHID_MSG/OTP command */
static uint32_t slot_cid[2] = { 0 };    /* last channel of the HID app slots (U2F/FIDO, OATH) */
static bool cmd_discard = false;        /* channel re-synchronized: drop the answer */
static uint32_t next_cid = 0;

void send_keepalive();
int driver_process_usb_packet_hid(uint16_t read);
int driver_write_hid(uint8_t itf, const uint8_t *buffer, uint16_t buffer_size);
int driver_process_usb_nopacket_hid();

void hid_init() {
    if (ITF_HID_TOTAL == 0) {
        return;
    }
    if (send_buffer_size == NULL) {
        send_buffer_size = (uint16_t *)calloc(ITF_HID_TOTAL, sizeof(uint16_t));
    }
    if (last_write_result == NULL) {
        last_write_result = (write_status_t *)calloc(ITF_HID_TOTAL, sizeof(write_status_t));
    }
    if (hid_rx == NULL) {
        hid_rx = (usb_buffer_t *)calloc(ITF_HID_TOTAL, sizeof(usb_buffer_t));
    }
    if (hid_tx == NULL) {
        hid_tx = (usb_buffer_t *)calloc(ITF_HID_TOTAL, sizeof(usb_buffer_t));
    }
    ctap_resp = (CTAPHID_FRAME *) hid_tx[ITF_HID_CTAP].buffer;
    tx_frame = ctap_resp;
    do {
        random_gen(NULL, (uint8_t *) &next_cid, sizeof(next_cid));
    } while (next_cid == 0 || next_cid == CID_BROADCAST);
}

/* CTAP carried in an APDU (U2F applet INS 10/41): points the CBOR encoder
 * (ctap_resp) at scratch space; the caller copies the result to res_APDU.
 * Over HID that is the HID response buffer the command answers in. Over a
 * smart card interface it is the upper part of apdu_res_buf, never the HID
 * buffer: that one may hold another client's response, in flight or left
 * for GET RESPONSE. Runs in the card thread; ctap_resp belongs to the
 * running command (the USB context only sets it before dispatching a HID
 * command, never while one runs). */
#define CTAP_SCRATCH_SIZE (7 + 1 + CTAP_MAX_CBOR_PAYLOAD)
_Static_assert(APDU_RES_BUF_SIZE - CTAP_SCRATCH_SIZE >= 1 + CTAP_MAX_CBOR_PAYLOAD + 2,
               "the CBOR scratch must not overlap the APDU response it is copied to");

int driver_init_hid() {
    if (apdu_res_span_ok(apdu.rdata, 1)) {
        ctap_resp = (CTAPHID_FRAME *) (apdu_res_buf + APDU_RES_BUF_SIZE - CTAP_SCRATCH_SIZE);
    }
    else {
        ctap_resp = (CTAPHID_FRAME *) (hid_tx[ITF_HID_CTAP].buffer);
    }
    memset(ctap_resp, 0, sizeof(CTAPHID_FRAME));
    return 0;
}

uint16_t *get_send_buffer_size(uint8_t itf) {
    return &send_buffer_size[itf];
}

//--------------------------------------------------------------------+
// USB HID
//--------------------------------------------------------------------+

/* Application hooks for GET_REPORT / SET_REPORT (OTP keyboard feature
 * reports). They run in the USB context under usb_lock, also while the card
 * thread runs a command (is_busy()): then they must not touch the command
 * state (apdu, res_APDU, current_app) and must not run a command; they serve
 * their own buffers and cached status only (pico-fido otp.c does). */
uint16_t (*hid_get_report_cb)(uint8_t, uint8_t, hid_report_type_t, uint8_t *, uint16_t) = NULL;
// Invoked when received GET_REPORT control request
// Application must fill buffer report's content and return its length.
// Return zero will cause the stack to STALL request

uint16_t tud_hid_get_report_cb(uint8_t itf, uint8_t report_id, hid_report_type_t report_type, uint8_t *buffer, uint16_t reqlen) {
    memset(buffer, 0, reqlen);
    usb_lock();
    if (hid_get_report_cb) {
        hid_get_report_cb(itf, report_id, report_type, buffer, reqlen);
    }
    usb_unlock();
    return reqlen;
}

static bool tx_busy(void) {
    return hid_tx[ITF_HID_CTAP].w_ptr > hid_tx[ITF_HID_CTAP].r_ptr;
}

uint32_t hid_write_offset(uint16_t size, uint16_t offset) {
    if (hid_tx[ITF_HID_CTAP].buffer[offset] != 0x81) {
        DEBUG_PAYLOAD(&hid_tx[ITF_HID_CTAP].buffer[offset], size);
    }
    hid_tx[ITF_HID_CTAP].w_ptr += size + offset;
    hid_tx[ITF_HID_CTAP].r_ptr += offset;
    tx_frame = (CTAPHID_FRAME *) (hid_tx[ITF_HID_CTAP].buffer + hid_tx[ITF_HID_CTAP].r_ptr);
    return size;
}

uint32_t hid_write(uint16_t size) {
    return hid_write_offset(size, 0);
}

static void hid_send_frame(const CTAPHID_FRAME *f) {
    if (urgent_count == URGENT_FRAMES) {
        return; /* host is not reading; replies are best effort */
    }
    memcpy(urgent[(urgent_head + urgent_count) % URGENT_FRAMES], f, 64);
    urgent_count++;
}

#ifndef ENABLE_EMULATION
static uint8_t keyboard_buffer[256];
static uint8_t keyboard_buffer_len = 0;
static const uint8_t conv_table[128][2] =  { HID_ASCII_TO_KEYCODE };
static uint8_t keyboard_w = 0;
static bool sent_key = false;
static bool keyboard_encode = false;

void add_keyboard_buffer(const uint8_t *data, size_t data_len, bool encode) {
    keyboard_buffer_len = (uint8_t)MIN(sizeof(keyboard_buffer) - 1, data_len);
    memcpy(keyboard_buffer, data, keyboard_buffer_len);
    keyboard_w = 0;
    sent_key = false;
    keyboard_encode = encode;
}

void append_keyboard_buffer(const uint8_t *data, size_t data_len) {
    if (keyboard_buffer_len + data_len < sizeof(keyboard_buffer)) {
        memcpy(keyboard_buffer + keyboard_buffer_len, data, MIN(sizeof(keyboard_buffer) - keyboard_buffer_len, data_len));
        keyboard_buffer_len += (uint8_t)MIN(sizeof(keyboard_buffer) - keyboard_buffer_len, data_len);
    }
}

static void send_hid_report(uint8_t report_id) {
    if (!tud_hid_ready()) {
        return;
    }

    switch (report_id) {
        case REPORT_ID_KEYBOARD: {
            if (keyboard_w < keyboard_buffer_len) {
                if (sent_key == false) {
                    uint8_t keycode[6] = { 0 };
                    uint8_t modifier = 0;
                    uint8_t chr = keyboard_buffer[keyboard_w];
                    if (keyboard_encode) {
                        chr &= 0x7f;
                        if (conv_table[chr][0]) {
                            modifier = KEYBOARD_MODIFIER_LEFTSHIFT;
                        }
                        keycode[0] = conv_table[chr][1];
                    }
                    else {
                        if (chr & 0x80) {
                            modifier = KEYBOARD_MODIFIER_LEFTSHIFT;
                        }
                        keycode[0] = chr & 0x7f;
                    }
                    if (tud_hid_n_keyboard_report(ITF_HID_KB, REPORT_ID_KEYBOARD, modifier, keycode) == true) {
                        sent_key = true;
                    }
                }
                else {
                    if (tud_hid_n_keyboard_report(ITF_HID_KB, REPORT_ID_KEYBOARD, 0, NULL) == true) {
                        keyboard_w++;
                        sent_key = false;

                    }
                }
            }
            else if (keyboard_w == keyboard_buffer_len && keyboard_buffer_len > 0) {
                /* Never leave typed secrets (static passwords, OTPs) in RAM. */
                memset(keyboard_buffer, 0, sizeof(keyboard_buffer));
                keyboard_w = keyboard_buffer_len = 0;
            }
        }
        break;

        default: break;
    }
}
#endif

void tud_hid_report_complete_cb(uint8_t instance, uint8_t const *report, uint16_t len) {
    //printf("report_complete %d %d %d\n", instance, len, send_buffer_size[instance]);
    if (instance == ITF_HID_CTAP && len > 0) {
        usb_lock();
#ifdef ESP_PLATFORM
        taskENTER_CRITICAL(&mutex);
#endif
        const CTAPHID_FRAME *req = (const CTAPHID_FRAME *) report;
        bool from_ring = pending_from_ring;
        pending_from_ring = false;
        if (last_write_result[instance] == WRITE_PENDING) {
            last_write_result[instance] = WRITE_SUCCESS;
            if (from_ring) {
                if (FRAME_TYPE(req) == TYPE_INIT) {
                    send_buffer_size[instance] -= MIN(64 - 7, send_buffer_size[instance]);
                }
                else {
                    send_buffer_size[instance] -= MIN(64 - 5, send_buffer_size[instance]);
                }
            }
        }
        if (from_ring && last_write_result[instance] == WRITE_SUCCESS) {
            /* Continuation frames are built in place: the 5 byte header
             * overwrites payload bytes that were already transmitted. */
            if (send_buffer_size[instance] > 0) {
                uint32_t cid = req->cid;
                uint8_t seq = FRAME_TYPE(req) == TYPE_INIT ? 0 : FRAME_SEQ(req) + 1;
                tx_frame = (CTAPHID_FRAME *) ((uint8_t *) tx_frame + 64 - 5);
                tx_frame->cid = cid;
                tx_frame->cont.seq = seq;
                hid_tx[ITF_HID_CTAP].r_ptr += 64 - 5;
            }
            else {
                hid_tx[ITF_HID_CTAP].r_ptr += 64;
            }
        }
        if (hid_tx[ITF_HID_CTAP].r_ptr >= hid_tx[ITF_HID_CTAP].w_ptr) {
            /* The response left the device: do not keep it in RAM. Data a
             * command left for GET RESPONSE lies after w_ptr and stays. */
            mbedtls_platform_zeroize(hid_tx[ITF_HID_CTAP].buffer, MIN(hid_tx[ITF_HID_CTAP].w_ptr, USB_BUFFER_SIZE));
            hid_tx[ITF_HID_CTAP].r_ptr = hid_tx[ITF_HID_CTAP].w_ptr = 0;
            tx_frame = (CTAPHID_FRAME *) hid_tx[ITF_HID_CTAP].buffer;
        }
#ifdef ESP_PLATFORM
        taskEXIT_CRITICAL(&mutex);
#endif
        usb_unlock();
    }
}

int driver_write_hid(uint8_t itf, const uint8_t *buffer, uint16_t buffer_size) {
    if (last_write_result[itf] == WRITE_PENDING) {
        return 0;
    }
    bool r = tud_hid_n_report(itf, 0, buffer, buffer_size);
    last_write_result[itf] = r ? WRITE_PENDING : WRITE_FAILED;
    if (last_write_result[itf] == WRITE_FAILED) {
        return 0;
    }
#ifdef ENABLE_EMULATION
    tud_hid_report_complete_cb(ITF_HID_CTAP, buffer, buffer_size);
#endif
    return MIN(64, buffer_size);
}

int (*hid_set_report_cb)(uint8_t, uint8_t, hid_report_type_t, uint8_t const *, uint16_t) = NULL;
// Invoked when received SET_REPORT control request or
// received data on OUT endpoint ( Report ID = 0, Type = 0 )

void tud_hid_set_report_cb(uint8_t itf, uint8_t report_id, hid_report_type_t report_type, uint8_t const *buffer, uint16_t bufsize) {
    usb_lock();
    /* The feature report hook refuses to run a command while one runs (see
     * hid_get_report_cb); CTAPHID output reports are arbitrated below. */
    if (!hid_set_report_cb || hid_set_report_cb(itf, report_id, report_type, buffer, bufsize) == 0) {
        /* CTAPHID reports are exactly 64 bytes; anything else is dropped. */
        if (itf == ITF_HID_CTAP && bufsize == 64) {
            if (hid_rx[itf].w_ptr + bufsize > USB_BUFFER_SIZE) {
                hid_rx[itf].r_ptr = hid_rx[itf].w_ptr = 0;
            }
            memcpy(hid_rx[itf].buffer + hid_rx[itf].w_ptr, buffer, bufsize);
            hid_rx[itf].w_ptr += bufsize;
            int proc_pkt = driver_process_usb_packet_hid(64);
            if (proc_pkt == 0) {
                driver_process_usb_nopacket_hid();
            }
            if (hid_rx[itf].w_ptr == 0) {
                /* Parsed: commands run from msg_packet, never from here. */
                mbedtls_platform_zeroize(hid_rx[itf].buffer, 64);
            }
        }
    }
    usb_unlock();
}

uint32_t last_cmd_time = 0, last_packet_time = 0;

static void ctap_error_cid(uint32_t cid, uint8_t error) {
    CTAPHID_FRAME f;
    memset(&f, 0, sizeof(f));
    f.cid = cid;
    f.init.cmd = CTAPHID_ERROR;
    f.init.bcntl = 1;
    f.init.data[0] = error;
    hid_send_frame(&f);
}

/* Answers the frame being parsed. It never touches the message being
 * received: an error for another channel (CHANNEL_BUSY) must not stop that
 * message's inter-frame timeout, and errors that end it call msg_reset(). */
int ctap_error(uint8_t error) {
    ctap_error_cid(ctap_req->cid, error);
    return 0;
}

uint8_t last_cmd = 0;
uint8_t last_seq = 0;
uint32_t lock = 0;
static uint32_t lock_cid = 0;

uint8_t thread_type = 0; //1 is APDU, 2 is CBOR
extern int cbor_process(uint8_t last_cmd, const uint8_t *data, size_t len);

static void msg_reset(void) {
    msg_packet.len = msg_packet.current_len = 0;
    msg_cid = 0;
    last_packet_time = 0;
}

int driver_process_usb_nopacket_hid() {
    uint32_t now = board_millis();
    if (last_packet_time > 0 && now - last_packet_time > CTAPHID_TRANS_TIMEOUT) {
        printf("[hid] message timeout on cid %08x after %u ms (%u of %u bytes)\n", (unsigned) msg_cid,
               (unsigned) (now - last_packet_time), (unsigned) msg_packet.current_len, (unsigned) msg_packet.len);
        ctap_error_cid(msg_cid, CTAP1_ERR_MSG_TIMEOUT);
        msg_reset();
    }
    return 0;
}

extern const uint8_t fido_aid[], u2f_aid[], oath_aid[];
extern void *cbor_thread(void *);

#ifdef ENABLE_OATH_APP
#define HID_OTP_AID oath_aid
#else
#define HID_OTP_AID NULL
#endif

/* Selects the application a HID message runs in (the transport picks it, not
 * a SELECT command). Its SELECT answer is not wanted and goes to a scratch
 * buffer, never to a response buffer that may hold data left for GET RESPONSE
 * (the HID one, or apdu_res_buf of the smart card interface). The caller
 * points res_APDU at the HID response buffer afterwards. */
static uint8_t hid_sel_sink[256];

/* Binds the HID app slot of a message (OATH for CTAPHID_OTP, U2F/FIDO
 * otherwise) and selects its application. Applications keep their security
 * state (OATH VALIDATE / VERIFY PIN) globally, and a CTAPHID channel is one
 * client: when the slot was last used by another channel, its application is
 * unloaded first, so the new client starts logged out (select with force). */
static void hid_select(uint32_t cid, bool otp, const uint8_t *aid) {
    apdu_bind_hid(otp);
    if (cid != slot_cid[otp]) {
        if (current_app && current_app->unload) {
            current_app->unload();
        }
        current_app = NULL;
        slot_cid[otp] = cid;
    }
    apdu.rdata = hid_sel_sink;
    apdu.rlen = 0;
    if (aid) {
        select_app(aid + 1, aid[0]);
    }
    /* Saved now: a GET RESPONSE is answered without a card command. */
    apdu_unbind_itf();
    mbedtls_platform_zeroize(hid_sel_sink, sizeof(hid_sel_sink));
    apdu.rlen = 0;
}

static uint32_t alloc_cid(void) {
    uint32_t cid = next_cid++;
    if (next_cid == 0 || next_cid == CID_BROADCAST) {
        next_cid = 1;
    }
    return cid;
}

/* Answers a command that needs no card thread with a single frame. */
static void reply_small(uint32_t cid, uint8_t cmd, const uint8_t *data, uint16_t len) {
    CTAPHID_FRAME f;
    memset(&f, 0, sizeof(f));
    f.cid = cid;
    f.init.cmd = cmd;
    f.init.bcnth = len >> 8;
    f.init.bcntl = len & 0xff;
    if (len) {
        memcpy(f.init.data, data, MIN(len, sizeof(f.init.data)));
    }
    hid_send_frame(&f);
}

int driver_process_usb_packet_hid(uint16_t read) {
    int apdu_sent = 0;
    if (read < 5) {
        return 0;
    }
    ctap_req = (CTAPHID_FRAME *) (hid_rx[ITF_HID_CTAP].buffer + hid_rx[ITF_HID_CTAP].r_ptr);
    hid_rx[ITF_HID_CTAP].r_ptr += 64;
    if (hid_rx[ITF_HID_CTAP].r_ptr >= hid_rx[ITF_HID_CTAP].w_ptr) {
        hid_rx[ITF_HID_CTAP].r_ptr = hid_rx[ITF_HID_CTAP].w_ptr = 0;
    }
    DEBUG_PAYLOAD((uint8_t *)ctap_req, 64);
    uint32_t cid = ctap_req->cid;
    bool is_init_frame = FRAME_TYPE(ctap_req) == TYPE_INIT;

    if (cid == 0x0 || (cid == CID_BROADCAST && (!is_init_frame || ctap_req->init.cmd != CTAPHID_INIT))) {
        return ctap_error(CTAP1_ERR_INVALID_CHANNEL);
    }

    /* CANCEL never gets a reply of its own (CTAP 2.1, 11.2.9.1.5). */
    if (is_init_frame && ctap_req->init.cmd == CTAPHID_CANCEL) {
        if (is_busy() && cid == cmd_cid) {
            up_cancel();
        }
        if (msg_cid == cid) {
            msg_reset();
        }
        return 0;
    }

    /* INIT is always served, also while another channel is busy. */
    if (is_init_frame && ctap_req->init.cmd == CTAPHID_INIT) {
        if (MSG_LEN(ctap_req) != INIT_NONCE_SIZE) {
            return ctap_error(CTAP1_ERR_INVALID_LEN);
        }
        uint32_t new_cid = cid;
        if (cid == CID_BROADCAST) {
            new_cid = alloc_cid();
        }
        else if (is_busy() && cmd_cid == cid) {
            /* Resynchronize this channel: abandon its running command. */
            up_cancel();
            cmd_discard = true;
        }
        /* INIT resynchronizes its own channel only (CTAP 2.1, 11.2.9.1.3): it
         * drops that channel's half received message. Another client's
         * message is left to complete, or to time out after
         * CTAPHID_TRANS_TIMEOUT. (msg_cid is never the broadcast channel.) */
        if (cid == msg_cid) {
            msg_reset();
        }
        uint8_t payload[sizeof(CTAPHID_INIT_RESP)];
        CTAPHID_INIT_RESP *resp = (CTAPHID_INIT_RESP *) payload;
        memcpy(resp->nonce, ctap_req->init.data, sizeof(resp->nonce));
        resp->cid = new_cid;
        resp->versionInterface = CTAPHID_IF_VERSION;
        resp->versionMajor = get_version_major ? get_version_major() : PICO_KEYS_SDK_VERSION_MAJOR;
        resp->versionMinor = get_version_minor ? get_version_minor() : PICO_KEYS_SDK_VERSION_MINOR;
        resp->versionBuild = 0;
        resp->capFlags = CAPFLAG_WINK | CAPFLAG_CBOR;
        reply_small(cid, CTAPHID_INIT, payload, sizeof(payload));
        return 0;
    }

    if (board_millis() < lock && cid != lock_cid) {
        return ctap_error(CTAP1_ERR_CHANNEL_BUSY);
    }

    if (is_init_frame) {
        if (MSG_LEN(ctap_req) > CTAP_MAX_PACKET_SIZE) {
            return ctap_error(CTAP1_ERR_INVALID_LEN);
        }
        if (msg_packet.len > 0 && msg_cid != 0) {
            /* A message is being received: other channels are busy, the
             * same channel restarting mid-message is a sequence error. */
            if (msg_cid != cid) {
                return ctap_error(CTAP1_ERR_CHANNEL_BUSY);
            }
            msg_reset();
            return ctap_error(CTAP1_ERR_INVALID_SEQ);
        }
        if (is_busy() || tx_busy()) {
            return ctap_error(CTAP1_ERR_CHANNEL_BUSY);
        }
        msg_packet.len = msg_packet.current_len = 0;
        if (MSG_LEN(ctap_req) > 64 - 7) {
            msg_packet.len = MSG_LEN(ctap_req);
            memcpy(msg_packet.data, ctap_req->init.data, 64 - 7);
            msg_packet.current_len = 64 - 7;
            msg_cid = cid;
            last_packet_time = board_millis();
        }
        last_cmd = ctap_req->init.cmd;
        last_seq = 0;
        last_cmd_time = board_millis();
    }
    else {
        if (msg_packet.len == 0 || msg_cid == 0) { //Received a cont without a prior init pkt
            return 0;
        }
        if (cid != msg_cid) {
            return ctap_error(CTAP1_ERR_CHANNEL_BUSY);
        }
        if (last_seq != FRAME_SEQ(ctap_req)) {
            msg_reset();
            return ctap_error(CTAP1_ERR_INVALID_SEQ);
        }
        uint16_t chunk = MIN(64 - 5, msg_packet.len - msg_packet.current_len);
        memcpy(msg_packet.data + msg_packet.current_len, ctap_req->cont.data, chunk);
        msg_packet.current_len += chunk;
        last_seq++;
        last_packet_time = board_millis();
        if (msg_packet.current_len < msg_packet.len) {
            return 0;
        }
    }

    if (msg_packet.len > 0 && msg_packet.current_len < msg_packet.len) {
        return 0; /* wait for the continuation frames */
    }

    /* A complete message is available. It always runs from msg_packet: the
     * receive slot (hid_rx) is overwritten by the next frame of any channel,
     * while the card thread may still read the command. msg_packet.data is
     * only written by an accepted first frame (nothing runs then) and by
     * continuation frames of a message being received. */
    uint16_t payload_len = msg_packet.len > 0 ? msg_packet.len : MSG_LEN(ctap_req);
    if (msg_packet.len == 0) {
        memcpy(msg_packet.data, ctap_req->init.data, payload_len);     /* <= 57 bytes */
    }
    const uint8_t *payload = msg_packet.data;

    if (last_cmd == CTAPHID_WINK) {
        if (payload_len != 0) {
            msg_reset();
            return ctap_error(CTAP1_ERR_INVALID_LEN);
        }
        reply_small(cid, CTAPHID_WINK, NULL, 0);
    }
    else if (last_cmd == CTAPHID_PING || last_cmd == CTAPHID_SYNC) {
        if (payload_len <= 64 - 7) {
            reply_small(cid, last_cmd, payload, payload_len);
        }
        else {
            if (payload_len > USB_BUFFER_SIZE - 7) {
                msg_reset();
                return ctap_error(CTAP1_ERR_INVALID_LEN);
            }
            if (is_busy()) {
                /* A smart card command started while this message was being
                 * received; it may be CTAP over CCID, which must never meet
                 * the HID response buffer being rewritten. */
                msg_reset();
                return ctap_error(CTAP1_ERR_CHANNEL_BUSY);
            }
            /* The echo overwrites the HID response buffer. The global
             * ctap_resp is left alone: it belongs to commands. */
            apdu_discard_response(ITF_HID);
            CTAPHID_FRAME *echo = (CTAPHID_FRAME *) hid_tx[ITF_HID_CTAP].buffer;
            hid_tx[ITF_HID_CTAP].r_ptr = hid_tx[ITF_HID_CTAP].w_ptr = 0;
            memcpy(echo->init.data, payload, payload_len);
            cmd_cid = cid;
            driver_exec_finished_cont_hid(ITF_HID_CTAP, payload_len, 0);
            cmd_cid = 0;
        }
    }
    else if (last_cmd == CTAPHID_LOCK) {
        if (payload_len != 1 || payload[0] > 10) {
            msg_reset();
            return ctap_error(payload_len != 1 ? CTAP1_ERR_INVALID_LEN : CTAP1_ERR_INVALID_PARAMETER);
        }
        lock = board_millis() + payload[0] * 1000;
        lock_cid = cid;
        reply_small(cid, CTAPHID_LOCK, NULL, 0);
    }
    else if (last_cmd == CTAPHID_UUID) {
        /* 16 bytes identifying the key (profile): the serial is only 8, the
         * old code read past it into unrelated RAM. */
        reply_small(cid, CTAPHID_UUID, pico_serial_hash, 16);
    }
    else if (last_cmd == CTAPHID_VERSION) {
        uint8_t v[4] = { PICO_KEYS_SDK_VERSION_MAJOR, PICO_KEYS_SDK_VERSION_MINOR, 0, 0 };
        reply_small(cid, CTAPHID_VERSION, v, sizeof(v));
    }
    else if (last_cmd == CTAPHID_ADMIN) {
        if (payload_len > 0 && payload[0] == 0x80) { // Status
            reply_small(cid, CTAPHID_ADMIN, (const uint8_t *) "\x00\xff\xff\xff\x00", 5);
        }
        else {
            reply_small(cid, CTAPHID_ADMIN, NULL, 0);
        }
    }
    else if (last_cmd == CTAPHID_MSG || last_cmd == CTAPHID_OTP) {
        if (is_busy()) {
            /* A smart card command started while this message was being
             * received: it owns the command state until it finished. */
            msg_reset();
            return ctap_error(CTAP1_ERR_CHANNEL_BUSY);
        }
        apdu_card_reset_poll();
        if (cid != apdu_cid) {
            /* Data an APDU left for GET RESPONSE belongs to its channel. */
            apdu_discard_response(ITF_HID);
            apdu_cid = cid;
        }
        /* The ring is idle (checked on the first frame) and was wiped once
         * sent; data left for GET RESPONSE in it must survive. */
        ctap_resp = (CTAPHID_FRAME *) hid_tx[ITF_HID_CTAP].buffer;
        hid_tx[ITF_HID_CTAP].r_ptr = hid_tx[ITF_HID_CTAP].w_ptr = 0;
        is_nk = last_cmd == CTAPHID_OTP;
        hid_select(cid, is_nk, is_nk ? HID_OTP_AID : u2f_aid);
        thread_type = 1;
        apdu.rdata = ctap_resp->init.data;
        usb_set_timeout_counter(ITF_HID, 200);
        cmd_cid = cid;          /* a GET RESPONSE is answered right away */
        apdu_sent = apdu_process(ITF_HID, payload, payload_len);
        if (apdu_sent <= 0) {
            /* Answered here (its chunk is queued, framed already): no
             * command runs, so the Nitrokey framing ends now as well. */
            cmd_cid = 0;
            is_nk = false;
        }
        DEBUG_PAYLOAD(apdu.data, (int) apdu.nc);
    }
    else if (last_cmd == CTAPHID_CBOR || last_cmd >= CTAPHID_VENDOR_FIRST) {
        if (is_busy()) {
            msg_reset();
            return ctap_error(CTAP1_ERR_CHANNEL_BUSY);
        }
        apdu_card_reset_poll();
        apdu_discard_response(ITF_HID);
        ctap_resp = (CTAPHID_FRAME *) hid_tx[ITF_HID_CTAP].buffer;
        hid_tx[ITF_HID_CTAP].r_ptr = hid_tx[ITF_HID_CTAP].w_ptr = 0;
        memset(ctap_resp, 0, sizeof(CTAPHID_FRAME));
        is_nk = false;
        hid_select(cid, false, fido_aid);
        thread_type = 2;
        apdu.rdata = ctap_resp->init.data;
        usb_set_timeout_counter(ITF_HID, 200);
        apdu_sent = cbor_process(last_cmd, payload, payload_len);
        if (apdu_sent < 0) {
            msg_reset();
            return ctap_error((uint8_t)(-apdu_sent));
        }
    }
    else {
        msg_reset();
        return ctap_error(CTAP1_ERR_INVALID_CMD);
    }
    msg_reset();

    if (apdu_sent > 0) {
        cmd_cid = cid;
        cmd_discard = false;
        if (apdu_sent == 1) {
            card_start(ITF_HID, apdu_thread);
        }
        else if (apdu_sent == 2) {
            card_start(ITF_HID, cbor_thread);
        }
        usb_send_event(EV_CMD_AVAILABLE);
        if (thread_type == 2) {
            send_keepalive();
        }
    }
    return apdu_sent;
}

void send_keepalive() {
    if (thread_type == 1 || cmd_cid == 0) {
        return;
    }
    CTAPHID_FRAME f;
    memset(&f, 0, sizeof(f));
    f.cid = cmd_cid;
    f.init.cmd = CTAPHID_KEEPALIVE;
    f.init.bcntl = 1;
    f.init.data[0] = up_pending() ? KEEPALIVE_STATUS_UPNEEDED : KEEPALIVE_STATUS_PROCESSING;
    hid_send_frame(&f);
}

/* The command's answer is not sent from the response buffer: wipe what the
 * command wrote there (and what it left for GET RESPONSE). */
static void hid_drop_response(void) {
    apdu_discard_response(ITF_HID);
    mbedtls_platform_zeroize(hid_tx[ITF_HID_CTAP].buffer, USB_BUFFER_SIZE);
}

void driver_exec_finished_hid(uint16_t size_next) {
    if (cmd_discard) {
        /* The channel was re-initialized while the command ran. */
        cmd_discard = false;
        hid_drop_response();
    }
    else if (size_next > 0) {
        if (thread_type == 2 && apdu.sw != 0) {
            ctap_error_cid(cmd_cid, apdu.sw & 0xff);
            hid_drop_response();
        }
        else {
            driver_exec_finished_cont_hid(ITF_HID_CTAP, size_next, 0);
        }
    }
    apdu.sw = 0;
    cmd_cid = 0;
    /* The Nitrokey framing lasts for exactly one CTAPHID_OTP command. */
    is_nk = false;
    /* The command ran from msg_packet (PINs, challenges): wipe it. */
    mbedtls_platform_zeroize(msg_packet.data, sizeof(msg_packet.data));
    apdu_unbind_itf();
}

/* Queues size_next response bytes starting offset bytes after apdu.rdata
 * (the data area of the first frame, hid_tx + 7) as one CTAPHID message. Its
 * 7 byte header is built over the bytes before them: the header area, or
 * response bytes already sent (GET RESPONSE chunks). */
void driver_exec_finished_cont_hid(uint8_t itf, uint16_t size_next, uint16_t offset) {
    uint32_t cid = cmd_cid ? cmd_cid : (ctap_req ? ctap_req->cid : 0);
    if (cid == 0 || cid == CID_BROADCAST) {
        return;
    }
    if ((uint32_t) offset + 7 + size_next > USB_BUFFER_SIZE) {
        ctap_error_cid(cid, CTAP1_ERR_OTHER);
        return;
    }
    if (is_nk && thread_type == 1 && last_cmd == CTAPHID_OTP && size_next >= 2) {
        /* CTAPHID_OTP (Nitrokey) answers carry the status word first: the
         * chunk's own SW (9000, or 61xx when more is left for GET RESPONSE)
         * moves in front. The two bytes it moves into are the chunk's SW
         * position: the command's SW, or the 61xx overlay whose original
         * bytes apdu.c keeps aside. */
        uint8_t *d = hid_tx[itf].buffer + 7 + offset;
        uint16_t sw = get_uint16_t_be(d + size_next - 2);
        memmove(d + 2, d, size_next - 2);
        put_uint16_t_be(sw, d);
    }
    CTAPHID_FRAME *f = (CTAPHID_FRAME *) (hid_tx[itf].buffer + offset);
    f->cid = cid;
    f->init.bcnth = size_next >> 8;
    f->init.bcntl = size_next & 0xff;
    send_buffer_size[itf] = size_next;
    f->init.cmd = last_cmd;
    hid_write_offset(size_next + 7, offset);
}

void hid_task() {
#ifdef ENABLE_EMULATION
    uint16_t rx_len = emul_read(ITF_HID);
    if (rx_len) {
        uint16_t rptr = 0;
        while (rx_len >= 64) {
            tud_hid_set_report_cb(ITF_HID, 0, 0, emul_rx + rptr, 64);
            rx_len -= 64;
            rptr += 64;
        }
        emul_rx_size = 0;
    }
#endif
    driver_process_usb_nopacket_hid();
    int status = card_status(ITF_HID);
    if (status == PICOKEY_OK) {
        driver_exec_finished_hid(finished_data_size);
    }
    else if (status == PICOKEY_ERR_BLOCKED) {
        send_keepalive();
    }
    if (last_write_result[ITF_HID_CTAP] != WRITE_PENDING) {
        if (urgent_count > 0) {
            pending_from_ring = false;
            if (driver_write_hid(ITF_HID_CTAP, urgent[urgent_head], 64) > 0) {
                urgent_head = (urgent_head + 1) % URGENT_FRAMES;
                urgent_count--;
            }
        }
        else if (tx_busy()) {
            /* The last frame is padded with zeros, never with the buffer
             * bytes after the response (or after the buffer). */
            static uint8_t frame[64];
            uint16_t avail = hid_tx[ITF_HID_CTAP].w_ptr - hid_tx[ITF_HID_CTAP].r_ptr;
            memset(frame, 0, sizeof(frame));
            memcpy(frame, tx_frame, MIN(avail, sizeof(frame)));
            pending_from_ring = true;
            if (driver_write_hid(ITF_HID_CTAP, frame, 64) == 0) {
                pending_from_ring = false;
            }
        }
    }
#ifndef ENABLE_EMULATION
    /* Keyboard ITF */
    // Poll every 10ms
    const uint32_t interval_ms = 10;
    static uint32_t start_ms = 0;

    if (board_millis() - start_ms < interval_ms) {
        return;
    }
    start_ms += interval_ms;

    // Remote wakeup
    if (tud_suspended() && keyboard_buffer_len > 0) {
        tud_remote_wakeup();
    }
    else if (ITF_HID_KB != ITF_INVALID) {
        send_hid_report(REPORT_ID_KEYBOARD);
    }
#endif
}
