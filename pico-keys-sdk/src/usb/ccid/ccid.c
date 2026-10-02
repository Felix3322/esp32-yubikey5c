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

#include "random.h"
#include "pico_keys.h"
#ifdef PICO_PLATFORM
#include "bsp/board.h"
#endif
#ifndef ENABLE_EMULATION
#include "tusb.h"
#include "device/usbd_pvt.h"
#else
#include "emulation.h"
#endif
#include "ccid.h"
#include "usb_descriptors.h"
#include "apdu.h"
#include "usb.h"
#include "mbedtls/platform_util.h"

#if MAX_RES_APDU_DATA_SIZE > MAX_CMD_APDU_DATA_SIZE
#define USB_BUF_SIZE (MAX_RES_APDU_DATA_SIZE + 20 + 9)
#else
#define USB_BUF_SIZE (MAX_CMD_APDU_DATA_SIZE + 20 + 9)
#endif

#define CCID_SET_PARAMS         0x61 /* non-ICCD command  */
#define CCID_POWER_ON           0x62
#define CCID_POWER_OFF          0x63
#define CCID_SLOT_STATUS        0x65 /* non-ICCD command */
#define CCID_SECURE             0x69 /* non-ICCD command */
#define CCID_GET_PARAMS         0x6C /* non-ICCD command */
#define CCID_RESET_PARAMS       0x6D /* non-ICCD command */
#define CCID_XFR_BLOCK          0x6F
#define CCID_DATA_BLOCK_RET     0x80
#define CCID_SLOT_STATUS_RET    0x81 /* non-ICCD result */
#define CCID_PARAMS_RET         0x82 /* non-ICCD result */
#define CCID_SETDATARATEANDCLOCKFREQUENCY 0x73
#define CCID_SETDATARATEANDCLOCKFREQUENCY_RET 0x84

#define CCID_MSG_SEQ_OFFSET     6
#define CCID_MSG_STATUS_OFFSET  7
#define CCID_MSG_ERROR_OFFSET   8
#define CCID_MSG_CHAIN_OFFSET   9
#define CCID_MSG_DATA_OFFSET    10  /* == CCID_MSG_HEADER_SIZE */
#define CCID_MAX_MSG_DATA_SIZE  USB_BUF_SIZE

#define CCID_STATUS_RUN     0x00
#define CCID_STATUS_PRESENT 0x01
#define CCID_STATUS_NOTPRESENT  0x02
#define CCID_CMD_STATUS_OK  0x00
#define CCID_CMD_STATUS_ERROR   0x40
#define CCID_CMD_STATUS_TIMEEXT 0x80

#define CCID_ERROR_XFR_OVERRUN  0xFC

/*
 * Since command-byte is at offset 0,
 * error with offset 0 means "command not supported".
 */
#define CCID_OFFSET_CMD_NOT_SUPPORTED 0
#define CCID_OFFSET_DATA_LEN 1
#define CCID_OFFSET_PARAM 8

#define CCID_THREAD_TERMINATED 0xffff
#define CCID_ACK_TIMEOUT 0x6600

PACK(
typedef struct {
    uint8_t bMessageType;
    uint32_t dwLength;
    uint8_t bSlot;
    uint8_t bSeq;
    uint8_t abRFU0;
    uint16_t abRFU1;
    uint8_t apdu; //Actually it is an array
}) ccid_header_t;

uint8_t ccid_status = 1;
#ifndef ENABLE_EMULATION
static uint8_t itf_num;
#endif

static usb_buffer_t *ccid_rx = NULL, *ccid_tx = NULL;

#define CCID_ERROR_CMD_SLOT_BUSY 0xE0
#define CCID_ERROR_ICC_MUTE      0xFE
/* Largest APDU response carried in one RDR_to_PC_DataBlock (10 byte header);
 * apdu_next() chains longer ones with 61xx. */
#define CCID_MAX_RESP_DATA USB_CCID_MAX_RESP_DATA

int driver_process_usb_packet_ccid(uint8_t itf, uint16_t rx_read);
int ccid_write_fast(uint8_t itf, const uint8_t *buffer, uint16_t buffer_size);

/* A command is copied out of the receive ring before the card thread runs,
 * so traffic arriving meanwhile can never alter the APDU being processed. */
static uint8_t ccid_cmd_buf[USB_BUFFER_SIZE + APDU_DATA_SLACK];

void ccid_write_offset(uint8_t itf, uint16_t size, uint16_t offset) {
    (void) offset;
    ccid_tx[itf].w_ptr += size;
}

void ccid_write(uint8_t itf, uint16_t size) {
    ccid_write_offset(itf, size, 0);
}

ccid_header_t **ccid_response = NULL;
ccid_header_t **ccid_resp_fast = NULL;
ccid_header_t **ccid_header = NULL;
static uint8_t ccid_cur_seq[4] = { 0 };

uint8_t sc_itf_to_usb_itf(uint8_t itf) {
    if (itf == ITF_SC_CCID) {
        return ITF_CCID;
    }
    else if (itf == ITF_SC_WCID) {
        return ITF_WCID;
    }
    return itf;
}

void ccid_init_buffers() {
    if (ITF_SC_TOTAL == 0) {
        return;
    }
    if (ccid_rx == NULL) {
        ccid_rx = (usb_buffer_t *)calloc(ITF_SC_TOTAL, sizeof(usb_buffer_t));
    }
    if (ccid_tx == NULL) {
        ccid_tx = (usb_buffer_t *)calloc(ITF_SC_TOTAL, sizeof(usb_buffer_t));
    }
    if (ccid_header == NULL) {
        ccid_header = (ccid_header_t **)calloc(ITF_SC_TOTAL, sizeof(ccid_header_t *));
    }
    if (ccid_response == NULL) {
        ccid_response = (ccid_header_t **)calloc(ITF_SC_TOTAL, sizeof(ccid_header_t *));
    }
    if (ccid_resp_fast == NULL) {
        ccid_resp_fast = (ccid_header_t **)calloc(ITF_SC_TOTAL, sizeof(ccid_header_t *));
    }
}

int driver_init_ccid(uint8_t itf) {
    ccid_header[itf] = (ccid_header_t *) (ccid_rx[itf].buffer + ccid_rx[itf].r_ptr);
    ccid_resp_fast[itf] = (ccid_header_t *) (ccid_tx[itf].buffer + sizeof(ccid_tx[itf].buffer) - 64);
//    apdu.header = &ccid_header->apdu;

    ccid_response[itf] = (ccid_header_t *) (ccid_tx[itf].buffer + ccid_tx[itf].w_ptr);

    usb_set_timeout_counter(sc_itf_to_usb_itf(itf), 1500);

    //ccid_tx[itf].w_ptr = ccid_tx[itf].r_ptr = 0;

    return PICOKEY_OK;
}

void tud_vendor_rx_cb(uint8_t itf, const uint8_t *buffer, uint16_t bufsize) {
    (void) buffer;
    (void) bufsize;
    usb_lock();
    uint32_t len = tud_vendor_n_available(itf);
    while (len > 0) {
        if (ccid_rx[itf].w_ptr >= USB_BUFFER_SIZE) {
            /* No valid message is larger than the buffer (dwMaxCCIDMessageLength):
             * the host is out of sync. Drop the partial message. */
            ccid_rx[itf].r_ptr = ccid_rx[itf].w_ptr = 0;
        }
        uint32_t space = USB_BUFFER_SIZE - ccid_rx[itf].w_ptr;
        uint16_t tlen = (uint16_t)MIN(len, space);
        tlen = (uint16_t)tud_vendor_n_read(itf, ccid_rx[itf].buffer + ccid_rx[itf].w_ptr, tlen);
        if (tlen == 0) {
            break;
        }
        ccid_rx[itf].w_ptr += tlen;
        driver_process_usb_packet_ccid(itf, tlen);
        len -= tlen;
    }
    usb_unlock();
}

/* Card (application) state must not survive an ICC power cycle or reset:
 * middleware relies on SCardDisconnect(SCARD_RESET_CARD) to log out. Neither
 * does a response left for GET RESPONSE or a command chain. While a command
 * runs (of any interface) the reset is deferred, never skipped. */
static void ccid_card_reset(uint8_t itf) {
    apdu_card_reset(sc_itf_to_usb_itf(itf));
}

/* A DataBlock without data for a failed command (bmCommandStatus failed). */
static void ccid_reply_error(uint8_t itf, uint8_t seq, uint8_t error) {
    ccid_resp_fast[itf]->bMessageType = CCID_DATA_BLOCK_RET;
    ccid_resp_fast[itf]->dwLength = 0;
    ccid_resp_fast[itf]->bSlot = 0;
    ccid_resp_fast[itf]->bSeq = seq;
    ccid_resp_fast[itf]->abRFU0 = CCID_CMD_STATUS_ERROR | ccid_status;
    ccid_resp_fast[itf]->abRFU1 = error; /* bError, bChainParameter = 0 */
    ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 10);
}

static int ccid_usb_write(uint8_t itf, const uint8_t *tx_buffer, uint16_t buffer_size) {
    if (*tx_buffer != 0x81) {
        DEBUG_PAYLOAD(tx_buffer, buffer_size);
    }
    int r = tud_vendor_n_write(itf, tx_buffer, buffer_size);
    if (r > 0) {
        tud_vendor_n_flush(itf);
    }
#ifdef ENABLE_EMULATION
    tud_vendor_tx_cb(itf, r);
#endif
    return r;
}

/* Sends queued ring data; only a successful write advances the ring. */
int driver_write_ccid(uint8_t itf, const uint8_t *tx_buffer, uint16_t buffer_size) {
    int r = ccid_usb_write(itf, tx_buffer, buffer_size);
    if (r > 0) {
        ccid_tx[itf].r_ptr += (uint16_t)r;
        if (ccid_tx[itf].r_ptr >= ccid_tx[itf].w_ptr) {
            /* Sent: responses do not stay in RAM. */
            mbedtls_platform_zeroize(ccid_tx[itf].buffer, ccid_tx[itf].w_ptr);
            ccid_tx[itf].r_ptr = ccid_tx[itf].w_ptr = 0;
        }
    }
    return r;
}

/* Immediate replies built in the reserved tail of the tx buffer; they are not
 * part of the ring and must not move its pointers. */
int ccid_write_fast(uint8_t itf, const uint8_t *buffer, uint16_t buffer_size) {
    return ccid_usb_write(itf, buffer, buffer_size);
}

int driver_process_usb_packet_ccid(uint8_t itf, uint16_t rx_read) {
    (void) rx_read;
    if (ccid_rx[itf].w_ptr - ccid_rx[itf].r_ptr >= 10) {
        driver_init_ccid(itf);
        if (ccid_header[itf]->dwLength > USB_BUFFER_SIZE - 10) {
            //Invalid length
            ccid_rx[itf].r_ptr = ccid_rx[itf].w_ptr = 0;

            ccid_resp_fast[itf]->bMessageType = CCID_DATA_BLOCK_RET;
            ccid_resp_fast[itf]->dwLength = 2;
            ccid_resp_fast[itf]->bSlot = 0;
            ccid_resp_fast[itf]->bSeq = ccid_header[itf]->bSeq;
            ccid_resp_fast[itf]->abRFU0 = ccid_status;
            ccid_resp_fast[itf]->abRFU1 = 0;
            memcpy(&ccid_resp_fast[itf]->apdu, "\x6F\x00", 2);
            ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 12);
            return 0;
        }
        //printf("ccid_process %ld %d %x %x %d\n",ccid_header[itf]->dwLength,rx_read-10,ccid_header[itf]->bMessageType,ccid_header[itf]->bSeq,ccid_rx[itf].w_ptr - ccid_rx[itf].r_ptr - 10);
        if (ccid_header[itf]->dwLength <= (uint32_t)(ccid_rx[itf].w_ptr - ccid_rx[itf].r_ptr - 10)){
            ccid_rx[itf].r_ptr += (uint16_t)(ccid_header[itf]->dwLength + 10);
            if (ccid_rx[itf].r_ptr >= ccid_rx[itf].w_ptr) {
                ccid_rx[itf].r_ptr = ccid_rx[itf].w_ptr = 0;
            }

            size_t apdu_sent = 0;
            if (ccid_header[itf]->bMessageType != CCID_SLOT_STATUS) {
                DEBUG_PAYLOAD((uint8_t *)ccid_header[itf], ccid_header[itf]->dwLength + 10);
            }
            if (ccid_header[itf]->bMessageType == CCID_SLOT_STATUS) {
                ccid_resp_fast[itf]->bMessageType = CCID_SLOT_STATUS_RET;
                ccid_resp_fast[itf]->dwLength = 0;
                ccid_resp_fast[itf]->bSlot = 0;
                ccid_resp_fast[itf]->bSeq = ccid_header[itf]->bSeq;
                ccid_resp_fast[itf]->abRFU0 = ccid_status;
                ccid_resp_fast[itf]->abRFU1 = 0;
                ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 10);
            }
            else if (ccid_header[itf]->bMessageType == CCID_POWER_ON) {
                ccid_card_reset(itf);
                size_t size_atr = (ccid_atr ? ccid_atr[0] : 0);
                ccid_resp_fast[itf]->bMessageType = CCID_DATA_BLOCK_RET;
                ccid_resp_fast[itf]->dwLength = (uint32_t)size_atr;
                ccid_resp_fast[itf]->bSlot = 0;
                ccid_resp_fast[itf]->bSeq = ccid_header[itf]->bSeq;
                ccid_resp_fast[itf]->abRFU0 = 0;
                ccid_resp_fast[itf]->abRFU1 = 0;
                //printf("1 %x %x %x || %x %x %x\n",ccid_resp_fast->apdu,apdu.rdata,ccid_resp_fast,ccid_header,ccid_header->apdu,apdu.data);
                memcpy(&ccid_resp_fast[itf]->apdu, ccid_atr + 1, size_atr);
                if (ccid_status == 1) {
                    //card_start(apdu_thread);
                }
                ccid_status = 0;
                ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], (uint16_t)(size_atr + 10));

                led_set_mode(MODE_MOUNTED);
            }
            else if (ccid_header[itf]->bMessageType == CCID_POWER_OFF) {
                ccid_card_reset(itf);
                ccid_status = 1;
                ccid_resp_fast[itf]->bMessageType = CCID_SLOT_STATUS_RET;
                ccid_resp_fast[itf]->dwLength = 0;
                ccid_resp_fast[itf]->bSlot = 0;
                ccid_resp_fast[itf]->bSeq = ccid_header[itf]->bSeq;
                ccid_resp_fast[itf]->abRFU0 = ccid_status;
                ccid_resp_fast[itf]->abRFU1 = 0;
                ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 10);

                led_set_mode(MODE_SUSPENDED);
            }
            else if (ccid_header[itf]->bMessageType == CCID_SET_PARAMS ||
                     ccid_header[itf]->bMessageType == CCID_GET_PARAMS ||
                     ccid_header[itf]->bMessageType == CCID_RESET_PARAMS) {
                /* Values from gnuk. Not specified in ICCD spec. */
                const uint8_t params[] =  {
                    0x11, /* bmFindexDindex */
                    0x10, /* bmTCCKST1 */
                    0xFE, /* bGuardTimeT1 */
                    0x55, /* bmWaitingIntegersT1 */
                    0x03, /* bClockStop */
                    0xFE, /* bIFSC */
                    0    /* bNadValue */
                };
                ccid_resp_fast[itf]->bMessageType = CCID_PARAMS_RET;
                ccid_resp_fast[itf]->dwLength = sizeof(params);
                ccid_resp_fast[itf]->bSlot = 0;
                ccid_resp_fast[itf]->bSeq = ccid_header[itf]->bSeq;
                ccid_resp_fast[itf]->abRFU0 = ccid_status;
                ccid_resp_fast[itf]->abRFU1 = 0x0100;
                memcpy(&ccid_resp_fast[itf]->apdu, params, sizeof(params));
                ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], sizeof(params) + 10);
            }
            else if (ccid_header[itf]->bMessageType == CCID_SETDATARATEANDCLOCKFREQUENCY) {
                ccid_resp_fast[itf]->bMessageType = CCID_SETDATARATEANDCLOCKFREQUENCY_RET;
                ccid_resp_fast[itf]->dwLength = 8;
                ccid_resp_fast[itf]->bSlot = 0;
                ccid_resp_fast[itf]->bSeq = ccid_header[itf]->bSeq;
                ccid_resp_fast[itf]->abRFU0 = ccid_status;
                ccid_resp_fast[itf]->abRFU1 = 0;
                memset(&ccid_resp_fast[itf]->apdu, 0, 8);
                ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 18);
            }
            else if (ccid_header[itf]->bMessageType == CCID_XFR_BLOCK) {
                if (is_busy()) {
                    /* One command at a time across all interfaces: the card
                     * thread, apdu and response buffers are shared. */
                    ccid_reply_error(itf, ccid_header[itf]->bSeq, CCID_ERROR_CMD_SLOT_BUSY);
                    return 0;
                }
                apdu_card_reset_poll();
                if (apdu_sc_blocked(sc_itf_to_usb_itf(itf))) {
                    /* The other smart card interface is in the middle of a
                     * command chain or of fetching a response: CCID and WCID
                     * share that state. */
                    ccid_reply_error(itf, ccid_header[itf]->bSeq, CCID_ERROR_CMD_SLOT_BUSY);
                    return 0;
                }
                uint16_t cmd_len = (uint16_t)ccid_header[itf]->dwLength;
                memcpy(ccid_cmd_buf, &ccid_header[itf]->apdu, cmd_len);
                ccid_cur_seq[itf] = ccid_header[itf]->bSeq;
                apdu_bind_itf(sc_itf_to_usb_itf(itf));
                apdu.rdata = apdu_res_buf;
                /* apdu_process() keys the GET RESPONSE state by USB interface
                 * and limits apdu.ne to CCID_MAX_RESP_DATA. */
                apdu_sent = apdu_process(sc_itf_to_usb_itf(itf), ccid_cmd_buf, cmd_len);
#ifndef ENABLE_EMULATION
                if (apdu_sent > 0) {
                    card_start(sc_itf_to_usb_itf(itf), apdu_thread);
                    usb_send_event(EV_CMD_AVAILABLE);
                }
#endif
            }
            return (uint16_t)apdu_sent;
        }
    }
    return 0;
}

void driver_exec_timeout_ccid(uint8_t itf) {
    ccid_resp_fast[itf]->bMessageType = CCID_DATA_BLOCK_RET;
    ccid_resp_fast[itf]->dwLength = 0;
    ccid_resp_fast[itf]->bSlot = 0;
    ccid_resp_fast[itf]->bSeq = ccid_cur_seq[itf];
    ccid_resp_fast[itf]->abRFU0 = CCID_CMD_STATUS_TIMEEXT;
    ccid_resp_fast[itf]->abRFU1 = 0;
    ccid_write_fast(itf, (const uint8_t *)ccid_resp_fast[itf], 10);
}

void driver_exec_finished_ccid(uint8_t itf, uint16_t size_next) {
    driver_exec_finished_cont_ccid(itf, size_next, 0);
}

/* Queues an RDR_to_PC_DataBlock carrying size_next bytes of the response
 * buffer starting at offset (GET RESPONSE chunks use offset > 0). The bytes
 * copied are wiped from the response buffer: only the data still left for
 * GET RESPONSE stays there. */
void driver_exec_finished_cont_ccid(uint8_t itf, uint16_t size_next, uint16_t offset) {
    if (size_next > CCID_MAX_RESP_DATA + 2 || ccid_tx[itf].w_ptr + CCID_MSG_DATA_OFFSET + size_next > USB_BUFFER_SIZE - 64) {
        /* The tx ring only drains between commands; never overrun it. */
        mbedtls_platform_zeroize(ccid_tx[itf].buffer, ccid_tx[itf].w_ptr);
        ccid_tx[itf].w_ptr = ccid_tx[itf].r_ptr = 0;
    }
    ccid_response[itf] = (ccid_header_t *) (ccid_tx[itf].buffer + ccid_tx[itf].w_ptr);
    if (size_next > CCID_MAX_RESP_DATA + 2 || !apdu_res_span_ok(apdu.rdata + offset, size_next)) {
        /* apdu_next() never produces this; answer an error, not memory. */
        memcpy(&ccid_response[itf]->apdu, "\x6F\x00", 2);
        size_next = 2;
    }
    else {
        memcpy(&ccid_response[itf]->apdu, apdu.rdata + offset, size_next);
        mbedtls_platform_zeroize(apdu.rdata + offset, size_next);
    }
    ccid_response[itf]->bMessageType = CCID_DATA_BLOCK_RET;
    ccid_response[itf]->dwLength = size_next;
    ccid_response[itf]->bSlot = 0;
    ccid_response[itf]->bSeq = ccid_cur_seq[itf];
    ccid_response[itf]->abRFU0 = ccid_status;
    ccid_response[itf]->abRFU1 = 0;
    ccid_write_offset(itf, size_next + 10, 0);
}

void ccid_task() {
    for (int itf = 0; itf < ITF_SC_TOTAL; itf++) {
        int status = card_status(sc_itf_to_usb_itf(itf));
        if (status == PICOKEY_OK) {
            apdu_unbind_itf();
            if (apdu_card_reset_pending(sc_itf_to_usb_itf(itf))) {
                /* This interface was reset or powered off while its command
                 * ran: the answer belongs to the ended session. CCID still
                 * gets one DataBlock per XfrBlock, a failed one. */
                ccid_reply_error(itf, ccid_cur_seq[itf], CCID_ERROR_ICC_MUTE);
            }
            else {
                /* Also when the other smart card interface was reset
                 * meanwhile: the command completed before that reset. */
                driver_exec_finished_ccid(itf, finished_data_size);
            }
            apdu_card_reset_poll();
        }
        else if (status == PICOKEY_ERR_BLOCKED) {
            driver_exec_timeout_ccid(itf);
        }
        if (ccid_tx[itf].w_ptr > ccid_tx[itf].r_ptr) {
            if (driver_write_ccid(itf, ccid_tx[itf].buffer + ccid_tx[itf].r_ptr, ccid_tx[itf].w_ptr - ccid_tx[itf].r_ptr) > 0) {

            }
        }
    }
    /* A reset deferred while a HID command ran. */
    apdu_card_reset_poll();
}

void ccid_init() {
    ccid_init_buffers();
}

#ifndef ENABLE_EMULATION

void tud_vendor_tx_cb(uint8_t itf, uint32_t sent_bytes) {
    (void) sent_bytes;
    tud_vendor_n_write_flush(itf);
}

static void ccid_init_cb(void) {
    vendord_init();
}

static void ccid_reset_cb(uint8_t rhport) {
    itf_num = 0;
    vendord_reset(rhport);
}

static uint16_t ccid_open(uint8_t rhport, tusb_desc_interface_t const *itf_desc, uint16_t max_len) {
    uint8_t *itf_vendor = (uint8_t *) malloc(sizeof(uint8_t) * max_len);
    TU_VERIFY( itf_desc->bInterfaceClass == TUSB_CLASS_SMART_CARD && itf_desc->bInterfaceSubClass == 0 && itf_desc->bInterfaceProtocol == 0, 0);

    //vendord_open expects a CLASS_VENDOR interface class
    uint16_t const drv_len = sizeof(tusb_desc_interface_t) + sizeof(struct ccid_class_descriptor) + TUSB_SMARTCARD_CCID_EPS * sizeof(tusb_desc_endpoint_t);
    memcpy(itf_vendor, itf_desc, sizeof(uint8_t) * max_len);
    ((tusb_desc_interface_t *) itf_vendor)->bInterfaceClass = TUSB_CLASS_VENDOR_SPECIFIC;
#if TUSB_SMARTCARD_CCID_EPS == 3
    ((tusb_desc_interface_t *) itf_vendor)->bNumEndpoints -= 1;
    vendord_open(rhport, (tusb_desc_interface_t *)itf_vendor, max_len - sizeof(tusb_desc_endpoint_t));
    tusb_desc_endpoint_t const *desc_ep = (tusb_desc_endpoint_t const *)((uint8_t *)itf_desc + drv_len - sizeof(tusb_desc_endpoint_t));
    TU_ASSERT(usbd_edpt_open(rhport, desc_ep), 0);
    uint8_t msg[] = { 0x50, 0x03 };
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
    usbd_edpt_xfer(rhport, desc_ep->bEndpointAddress, msg, sizeof(msg));
#else
    usbd_edpt_xfer(rhport, desc_ep->bEndpointAddress, msg, sizeof(msg), sizeof(msg));
#endif
#else
    vendord_open(rhport, (tusb_desc_interface_t *)itf_vendor, max_len);
#endif
    free(itf_vendor);

    TU_VERIFY(max_len >= drv_len, 0);

    itf_num = itf_desc->bInterfaceNumber;
    return drv_len;
}

// Support for parameterized reset via vendor interface control request
static bool ccid_control_xfer_cb(uint8_t __unused rhport,
                                 uint8_t stage,
                                 tusb_control_request_t const *request) {
    // nothing to do with DATA & ACK stage
    TU_LOG2("-------- CCID CTRL XFER\n");
    if (stage != CONTROL_STAGE_SETUP) {
        return true;
    }

    if (request->wIndex == itf_num) {
        TU_LOG2("-------- bmRequestType %x, bRequest %x, wValue %x, wLength %x\n",
                request->bmRequestType,
                request->bRequest,
                request->wValue,
                request->wLength);
/*
 #if PICO_STDIO_USB_RESET_INTERFACE_SUPPORT_RESET_TO_BOOTSEL
        if (request->bRequest == RESET_REQUEST_BOOTSEL) {
 #ifdef PICO_STDIO_USB_RESET_BOOTSEL_ACTIVITY_LED
            uint gpio_mask = 1u << PICO_STDIO_USB_RESET_BOOTSEL_ACTIVITY_LED;
 #else
            uint gpio_mask = 0u;
 #endif
 #if !PICO_STDIO_USB_RESET_BOOTSEL_FIXED_ACTIVITY_LED
            if (request->wValue & 0x100) {
                gpio_mask = 1u << (request->wValue >> 9u);
            }
 #endif
            reset_usb_boot(gpio_mask, (request->wValue & 0x7f) | PICO_STDIO_USB_RESET_BOOTSEL_INTERFACE_DISABLE_MASK);
            // does not return, otherwise we'd return true
        }
 #endif
 #if PICO_STDIO_USB_RESET_INTERFACE_SUPPORT_RESET_TO_FLASH_BOOT
        if (request->bRequest == RESET_REQUEST_FLASH) {
            watchdog_reboot(0, 0, PICO_STDIO_USB_RESET_RESET_TO_FLASH_DELAY_MS);
            return true;
        }
 #endif
 */
        return true;
    }
    return false;
}

static bool ccid_xfer_cb(uint8_t rhport,
                         uint8_t ep_addr,
                         xfer_result_t result,
                         uint32_t xferred_bytes) {
    //printf("------ CALLED XFER_CB\n");
    return vendord_xfer_cb(rhport, ep_addr, result, xferred_bytes);
    //return true;
}

static const usbd_class_driver_t ccid_driver = {
#if CFG_TUSB_DEBUG >= 2
    .name = "CCID",
#endif
    .init             = ccid_init_cb,
    .reset            = ccid_reset_cb,
    .open             = ccid_open,
    .control_xfer_cb  = ccid_control_xfer_cb,
    .xfer_cb          = ccid_xfer_cb,
    .sof              = NULL
};

// Implement callback to add our custom driver
usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count) {
    *driver_count = 1;
    return &ccid_driver;
}
#endif
