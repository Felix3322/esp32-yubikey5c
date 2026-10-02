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

#include "pico_keys.h"
#include "emulation.h"
#include <stdio.h>
#ifndef _MSC_VER
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <netinet/tcp.h>
typedef int socket_t;
#include <fcntl.h>
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#else
#include <ws2tcpip.h>
#define O_NONBLOCK _O_NONBLOCK
#define close closesocket
typedef SOCKET socket_t;
typedef int socklen_t;
#define msleep Sleep
#pragma comment(lib, "Ws2_32.lib")
#endif
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include "apdu.h"
#include "usb.h"
#include "ccid/ccid.h"
#include "hid/ctap_hid.h"
#include "mbedtls/platform_util.h"

socket_t ccid_sock = 0;
socket_t hid_server_sock = 0;
socket_t hid_client_sock = INVALID_SOCKET;
extern uint8_t thread_type;
extern const uint8_t *cbor_data;
extern size_t cbor_len;
extern uint8_t cmd;
uint8_t emul_rx[USB_BUFFER_SIZE], emul_tx[USB_BUFFER_SIZE];
/* Command copy handed to the card thread (with room for in-place padding). */
static uint8_t emul_cmd[USB_BUFFER_SIZE + APDU_DATA_SLACK];
uint16_t emul_rx_size = 0, emul_tx_size = 0;
extern int cbor_parse(uint8_t cmd, const uint8_t *data, size_t len);
pthread_t hcore0, hcore1;

#ifndef _MSC_VER
int msleep(long msec) {
    struct timespec ts;
    int res;

    if (msec < 0) {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}
#endif

/* Reads exactly len bytes (the sockets may be non-blocking). */
static int recv_all(socket_t sock, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        int n = recv(sock, (char *)buf + got, (int)(len - got), 0);
        if (n > 0) {
            got += (size_t) n;
        }
        else if (n == 0) {
            return -1;
        }
        else {
#ifndef _MSC_VER
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                return -1;
            }
#endif
            msleep(1);
        }
    }
    return (int) got;
}

int emul_init(char *host, uint16_t port) {
    struct sockaddr_in serv_addr;
    fprintf(stderr, "\n Starting emulation envionrment\n");
    /* Test harness: several emulators side by side, each with its own vpcd
     * port (the CTAPHID server listens on vpcd port - 1). */
    const char *env_port = getenv("LF_EMU_VPCD_PORT");
    if (env_port && atoi(env_port) > 1 && atoi(env_port) < 65536) {
        port = (uint16_t) atoi(env_port);
    }
#ifdef _MSC_VER
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("winsock initialization failure\n");
    }
#endif
    if ((ccid_sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        perror("socket");
        return -1;
    }
#ifndef _MSC_VER
    fcntl(ccid_sock, F_SETFD, FD_CLOEXEC);   /* not inherited by a re-exec reboot */
#endif

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, host, &serv_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(ccid_sock);
        return -1;
    }

    if (connect(ccid_sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        /* No vpcd: keep going with CTAPHID only. */
        perror("connect (vpcd, CCID disabled)");
        close(ccid_sock);
        ccid_sock = INVALID_SOCKET;
    }
    else {
#ifdef _MSC_VER
        unsigned long on = 1;
        if (0 != ioctlsocket(ccid_sock, FIONBIO, &on)) {
            perror("ioctlsocket FIONBIO");
        }
#else
        int x = fcntl(ccid_sock, F_GETFL, 0);
        fcntl(ccid_sock, F_SETFL, x | O_NONBLOCK);
        int flag = 1;
        setsockopt(ccid_sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
#endif
    }

    // HID server

    socklen_t yes = 1;
    uint16_t hid_port = port - 1;
    struct sockaddr_in server_sockaddr;

    if ((hid_server_sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        perror("socket");
        return -1;
    }

    if (setsockopt(hid_server_sock, SOL_SOCKET, SO_REUSEADDR, (void *) &yes, sizeof yes) != 0) {
        perror("setsockopt");
        close(hid_server_sock);
        return 1;
    }

#if defined(HAVE_DECL_SO_NOSIGPIPE)
    if (setsockopt(hid_server_sock, SOL_SOCKET, SO_NOSIGPIPE, (void *) &yes, sizeof yes) != 0) {
        perror("setsockopt");
        close(hid_server_sock);
        return 1;
    }
#endif

    memset(&server_sockaddr, 0, sizeof server_sockaddr);
    server_sockaddr.sin_family = PF_INET;
    server_sockaddr.sin_port = htons(hid_port);
    /* The emulated key must never be reachable from the network. */
    server_sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifndef _MSC_VER
    fcntl(hid_server_sock, F_SETFD, FD_CLOEXEC);
#endif

    if (bind(hid_server_sock, (struct sockaddr *) &server_sockaddr,
             sizeof server_sockaddr) != 0) {
        /* Another emulator owns the port: talking to it by accident would
         * silently use its flash file. */
        fprintf(stderr, "HID port %u unavailable: ", (unsigned) hid_port);
        perror("bind");
        exit(2);
    }

    if (listen(hid_server_sock, 0) != 0) {
        perror("listen");
        close(hid_server_sock);
        return 1;
    }
    return 0;
}

socket_t get_sock_itf(uint8_t itf) {
#ifdef USB_ITF_CCID
    if (itf == ITF_CCID) {
        return ccid_sock;
    }
#endif
#ifdef USB_ITF_HID
    if (itf == ITF_HID) {
        return hid_client_sock;
    }
#endif
    return INVALID_SOCKET;
}

uint32_t tud_vendor_n_write(uint8_t itf, const uint8_t *buffer, uint32_t n) {
    uint16_t ret = driver_write_emul(ITF_CCID, buffer, (uint16_t)n);
    tud_vendor_tx_cb(itf, ret);
    return ret;
}

#ifdef USB_ITF_HID
bool tud_hid_n_report(uint8_t itf, uint8_t report_id, const uint8_t *buffer, uint32_t n) {
    (void) itf;
    (void) report_id;
    uint16_t ret = driver_write_emul(ITF_HID, buffer, (uint16_t)n);
    return ret > 0;
}
#endif

/* Sends all bytes; a vanished peer is not fatal (no SIGPIPE, no endless retry). */
static int send_all(socket_t sock, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    int retries = 0;
    while (sent < len) {
#ifdef MSG_NOSIGNAL
        int r = send(sock, (const char *)buf + sent, (int)(len - sent), MSG_NOSIGNAL);
#else
        int r = send(sock, (const char *)buf + sent, (int)(len - sent), 0);
#endif
        if (r > 0) {
            sent += (size_t) r;
            continue;
        }
#ifndef _MSC_VER
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) && retries++ < 1000) {
            msleep(1);
            continue;
        }
#endif
        return -1;
    }
    return (int) sent;
}

uint16_t driver_write_emul(uint8_t itf, const uint8_t *buffer, uint16_t buffer_size) {
    uint16_t size = htons(buffer_size);
    socket_t sock = get_sock_itf(itf);
    if (sock == INVALID_SOCKET) {
        return 0;
    }
    if (send_all(sock, (const uint8_t *)&size, sizeof(size)) < 0 || send_all(sock, buffer, buffer_size) < 0) {
        return 0;
    }
    emul_tx_size = buffer_size;
    return buffer_size;
}

/* Sends size_next bytes of the response buffer starting at offset (GET
 * RESPONSE chunks use offset > 0). Over vpcd the bytes are wiped once sent:
 * only the data still left for GET RESPONSE stays in the buffer. */
void driver_exec_finished_cont_emul(uint8_t itf, uint16_t size_next, uint16_t offset) {
#ifdef USB_ITF_HID
    if (itf == ITF_HID) {
        driver_exec_finished_cont_hid(ITF_HID_CTAP, size_next, offset);
    }
#endif
#ifdef USB_ITF_CCID
    if (itf == ITF_CCID) {
        if (size_next > USB_CCID_MAX_RESP_DATA + 2 || !apdu_res_span_ok(apdu.rdata + offset, size_next)) {
            /* apdu_next() never produces this; answer an error, not memory. */
            driver_write_emul(itf, (const uint8_t *) "\x6F\x00", 2);
            return;
        }
        driver_write_emul(itf, apdu.rdata + offset, size_next);
        mbedtls_platform_zeroize(apdu.rdata + offset, size_next);
    }
#endif
}

uint16_t emul_read(uint8_t itf) {
    /* First we look for a client */
#ifdef USB_ITF_HID
    if (itf == ITF_HID) {
        struct sockaddr_in client_sockaddr;
        socklen_t client_socklen = sizeof client_sockaddr;

        int timeout;
        struct pollfd pfd;

        pfd.fd = hid_server_sock;
        pfd.events = POLLIN;
        pfd.revents = 0;

        timeout = (0 * 1000 + 1000 / 1000);

        if (poll(&pfd, 1, timeout) == -1) {
            return 0;
        }

        if (pfd.revents & POLLIN) {
            if (hid_client_sock > 0) {
                close(hid_client_sock);
            }
            hid_client_sock = accept(hid_server_sock, (struct sockaddr *) &client_sockaddr, &client_socklen);
#ifndef _MSC_VER
            if (hid_client_sock != INVALID_SOCKET) {
                fcntl(hid_client_sock, F_SETFD, FD_CLOEXEC);   /* not inherited by a re-exec reboot */
            }
#endif
            if (hid_client_sock != INVALID_SOCKET) {
                printf("hid_client connected! %d\n", hid_client_sock);
            }
        }
        /*if (send_buffer_size > 0) {
            last_write_result[itf] = WRITE_PENDING;
            tud_hid_report_complete_cb(ITF_HID, complete_report, complete_len);
        }*/
    }
#endif
    socket_t sock = get_sock_itf(itf);
    if (sock == INVALID_SOCKET) {
        return emul_rx_size;
    }
    //printf("get_sockt itf %d - %d\n", itf, sock);
    uint16_t len = 0;
    fd_set input;
    FD_ZERO(&input);
#ifdef _WIN32
    __pragma(warning(push))
    __pragma(warning(disable:4548))
#endif
    FD_SET(sock, &input);
#ifdef _WIN32
    __pragma(warning(pop))
#endif
    struct timeval timeout;
    int valread = 0;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0 * 1000;
    int n = select((int)(sock + 1), &input, NULL, NULL, &timeout);
    if (n == -1) {
        //printf("read wrong [itf:%d]\n", itf);
        //something wrong
    }
    else if (n == 0) {
        //printf("read timeout [itf:%d]\n", itf);
    }
    if (FD_ISSET(sock, &input)) {
        valread = recv_all(sock, (uint8_t *)&len, sizeof(len));
        if (valread <= 0) {
            return emul_rx_size;
        }
#ifdef TCP_QUICKACK
        /* vpcd sends a frame as two writes: a delayed ACK here would stall
         * every command ~40 ms (Nagle on its side). Linux clears the flag
         * after use, so it is set again for every frame. */
        {
            int one = 1;
            setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, (char *) &one, sizeof(one));
        }
#endif
        len = ntohs(len);
        if (len > sizeof(emul_rx) - emul_rx_size) {
            /* Oversized frame: drain and drop it. */
            uint8_t sink[256];
            while (len > 0) {
                uint16_t n = MIN(len, (uint16_t) sizeof(sink));
                if (recv_all(sock, sink, n) <= 0) {
                    break;
                }
                len -= n;
            }
#ifdef USB_ITF_CCID
            if (itf == ITF_CCID) {
                driver_write_emul(itf, (const uint8_t *) "\x67\x00", 2);
            }
#endif
            return emul_rx_size;
        }
        if (len > 0) {
            valread = recv_all(sock, emul_rx + emul_rx_size, len);
            if (valread == len) {
                if (len == 1) {
                    /* vpcd control: 0 power off, 1 power on, 2 reset, 4 ATR */
                    uint8_t c = emul_rx[emul_rx_size];
                    if (c == 4) {
                        driver_write_emul(itf, ccid_atr ? ccid_atr + 1 : NULL, ccid_atr ? ccid_atr[0] : 0);
                    }
#ifdef USB_ITF_CCID
                    else if (itf == ITF_CCID && (c == 0 || c == 1 || c == 2)) {
                        /* Power off/on, reset: the session's application
                         * state, chain and GET RESPONSE data go (deferred
                         * while a command runs, never skipped). */
                        apdu_card_reset(ITF_CCID);
                    }
#endif
                }
#ifdef USB_ITF_CCID
                else if (itf == ITF_CCID) {
                    /* Same path as real CCID: the card thread runs the
                     * command, emul_task() sends the answer when done. */
                    DEBUG_PAYLOAD(emul_rx, len);
                    if (is_busy()) {
                        driver_write_emul(itf, (const uint8_t *) "\x6F\x00", 2);
                        return emul_rx_size;
                    }
                    memcpy(emul_cmd, emul_rx, len);
                    apdu_card_reset_poll();
                    apdu_bind_itf(ITF_CCID);
                    apdu.rdata = apdu_res_buf;
                    if (apdu_process(ITF_CCID, emul_cmd, len) > 0) {
                        card_start(ITF_CCID, apdu_thread);
                        usb_send_event(EV_CMD_AVAILABLE);
                    }
                }
#endif
                else {
                    emul_rx_size += valread;
                }
            }
            return (uint16_t)emul_rx_size;
        }
    }
    //else
    //    printf("no input for sock %d - %d\n", itf, sock);
    return emul_rx_size;
}

void emul_task() {
#ifdef USB_ITF_CCID
    emul_read(ITF_CCID);
    if (card_status(ITF_CCID) == PICOKEY_OK) {
        apdu_unbind_itf();
        /* vpcd has one link: a reset on it while the command ran ended the
         * session the answer belongs to, and vpcd no longer waits for it
         * (sending it would answer the next command). */
        if (!apdu_card_reset_pending(ITF_CCID)) {
            DEBUG_PAYLOAD(apdu.rdata, finished_data_size);
            driver_exec_finished_cont_emul(ITF_CCID, finished_data_size, 0);
        }
    }
    /* A reset deferred while a command ran. */
    apdu_card_reset_poll();
#endif
#ifdef USB_ITF_HID
    emul_read(ITF_HID);
#endif
}
