/*
 * Host harness for Ed25519 / X25519 (pico-keys-sdk/src/crypto/lf_25519.c):
 * the RFC 7748 iteration test, timings and the stack high-water mark of the
 * public functions (run on a thread whose stack is painted beforehand).
 *
 * Built and driven by tests/unit/test_25519.py.
 */

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "lf_25519.h"

/* RFC 7748 5.2: k = X25519(k, u), u = old k, n times. */
int h_x25519_iterate(uint8_t k[32], uint8_t u[32], unsigned n) {
    uint8_t r[32];
    for (unsigned i = 0; i < n; i++) {
        if (lf_x25519(r, k, u) != 0) {
            return -1;
        }
        memcpy(u, k, 32);
        memcpy(k, r, 32);
    }
    return 0;
}

enum { OP_NONE, OP_PUB, OP_SIGN, OP_SIGN_NOPUB, OP_VERIFY, OP_X25519, OP_X25519_PUB };

static const uint8_t seed[32] = { 0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
                                  0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
                                  0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
                                  0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60 };
static uint8_t pub[32], sig[64], msg[64], xout[32];

static int run(int op) {
    switch (op) {
        case OP_PUB:
            return lf_ed25519_public_key(pub, seed);
        case OP_SIGN:
            return lf_ed25519_sign(sig, msg, sizeof(msg), seed, pub);
        case OP_SIGN_NOPUB:
            return lf_ed25519_sign(sig, msg, sizeof(msg), seed, NULL);
        case OP_VERIFY:
            return lf_ed25519_verify(sig, msg, sizeof(msg), pub);
        case OP_X25519:
            return lf_x25519(xout, seed, pub);
        case OP_X25519_PUB:
            return lf_x25519_public_key(xout, seed);
        default:
            return 0;
    }
}

static int prepare(void) {
    memset(msg, 0x5a, sizeof(msg));
    if (lf_ed25519_public_key(pub, seed) != 0 || lf_ed25519_sign(sig, msg, sizeof(msg), seed, pub) != 0) {
        return -1;
    }
    return 0;
}

/* Microseconds per call, -1 on error. */
double h_bench(int op, unsigned n) {
    struct timespec a, b;
    if (prepare() != 0) {
        return -1;
    }
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (unsigned i = 0; i < n; i++) {
        if (run(op) != 0) {
            return -1;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &b);
    return ((double) (b.tv_sec - a.tv_sec) * 1e6 + (double) (b.tv_nsec - a.tv_nsec) / 1e3) / n;
}

#define STACK_SIZE (256 * 1024)
#define PAINT 0xA5
#define MARGIN 256

static uint8_t *stack;

/* Paints the free part of the stack below this frame, runs the operation,
 * and returns how far below the frame it wrote. */
static void *thread_main(void *arg) {
    long *op = (long *) arg;
    volatile uint8_t mark = 0;
    size_t here = (size_t) ((uintptr_t) &mark - (uintptr_t) stack), i = 0;
    memset(stack, PAINT, here - MARGIN);
    op[1] = run((int) op[0]);
    while (i < here - MARGIN && stack[i] == PAINT) {
        i++;
    }
    op[2] = (long) (here - i);
    return NULL;
}

/* Bytes of stack an operation uses below its caller, -1 on error. */
long h_stack(int op) {
    pthread_attr_t attr;
    pthread_t th;
    long arg[3] = { op, -1, -1 };
    stack = aligned_alloc(4096, STACK_SIZE);
    if (!stack || prepare() != 0) {
        free(stack);
        return -1;
    }
    pthread_attr_init(&attr);
    if (pthread_attr_setstack(&attr, stack, STACK_SIZE) == 0 &&
        pthread_create(&th, &attr, thread_main, arg) == 0) {
        pthread_join(th, NULL);
    }
    pthread_attr_destroy(&attr);
    free(stack);
    return arg[1] == 0 ? arg[2] : -1;
}
