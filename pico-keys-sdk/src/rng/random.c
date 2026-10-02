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

#define HWRNG_PRE_LOOP 32

#include <stdlib.h>
#if defined(PICO_PLATFORM)
#include "pico/stdlib.h"
#elif defined(ESP_PLATFORM)
#include "esp_random.h"
#elif defined(ENABLE_EMULATION)
#include <unistd.h>
#include <sys/random.h>
#endif
#include <string.h>

#include "hwrng.h"

#define RANDOM_BYTES_LENGTH 32
static uint32_t random_word[RANDOM_BYTES_LENGTH / sizeof(uint32_t)];

void random_init(void) {
    hwrng_init(random_word, RANDOM_BYTES_LENGTH / sizeof(uint32_t));

    for (int i = 0; i < HWRNG_PRE_LOOP; i++) {
        hwrng_get();
    }
}

/*
 * Free pointer to random 32-byte
 */
void random_bytes_free(const uint8_t *p) {
    (void) p;
    memset(random_word, 0, RANDOM_BYTES_LENGTH);
    hwrng_flush();
}

/*
 * Return pointer to random 32-byte
 */
#define MAX_RANDOM_BUFFER 1024
const uint8_t *random_bytes_get(size_t len) {
    if (len > MAX_RANDOM_BUFFER) {
        return NULL;
    }
    static uint32_t return_word[MAX_RANDOM_BUFFER / sizeof(uint32_t)];
#if defined(ESP_PLATFORM) || defined(ENABLE_EMULATION)
    extern int random_gen(void *arg, unsigned char *out, size_t out_len);
    random_gen(NULL, (unsigned char *) return_word, len);
    return (const uint8_t *) return_word;
#endif
    for (size_t ix = 0; ix < len; ix += RANDOM_BYTES_LENGTH) {
        hwrng_wait_full();
        memcpy(return_word + ix / sizeof(uint32_t), random_word, RANDOM_BYTES_LENGTH);
        random_bytes_free((const uint8_t *) random_word);
    }
    return (const uint8_t *) return_word;
}

/*
 * Random byte iterator
 */
int random_gen(void *arg, unsigned char *out, size_t out_len) {
#if defined(ESP_PLATFORM)
    /* The hardware RNG is thread safe and, with the entropy source enabled at
     * boot (bootloader_random_enable), a true RNG. The shared ring buffer below
     * is filled by core 0 while the card thread consumes it on core 1, which
     * could hand out the same bytes twice; never use it here. */
    (void) arg;
    esp_fill_random(out, out_len);
    return 0;
#elif defined(ENABLE_EMULATION)
    (void) arg;
    while (out_len > 0) {
        size_t n = out_len > 256 ? 256 : out_len;
        if (getentropy(out, n) != 0) {
            abort();
        }
        out += n;
        out_len -= n;
    }
    return 0;
#endif
    uint8_t *index_p = (uint8_t *) arg;
    uint8_t index = index_p ? *index_p : 0;
    uint8_t n;

    while (out_len) {
        hwrng_wait_full();

        n = RANDOM_BYTES_LENGTH - index;
        if (n > out_len) {
            n = (uint8_t)out_len;
        }

        memcpy(out, ((unsigned char *) random_word) + index, n);
        out += n;
        out_len -= n;
        index += n;

        if (index >= RANDOM_BYTES_LENGTH) {
            index = 0;
            hwrng_flush();
        }
    }

    if (index_p) {
        *index_p = index;
    }

    return 0;
}

#ifdef ENABLE_PQC
void randombytes(uint8_t *buf, size_t n) {
    random_gen(NULL, buf, n);
}
#endif
