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

#ifndef _BOARD_H_
#define _BOARD_H_

#include <stdint.h>

/* Milliseconds since an arbitrary start, for timeouts only. It must be
 * monotonic: a wall clock step (NTP, VM time sync) would otherwise fire or
 * stretch every protocol timeout. */
#ifdef _MSC_VER
#include <windows.h>
static inline uint32_t board_millis() {
    return (uint32_t) GetTickCount64();
}
#else
#include <time.h>
static inline uint32_t board_millis() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t) ((uint64_t) ts.tv_sec * 1000u + (uint64_t) ts.tv_nsec / 1000000u);
}
#endif

#endif // _BOARD_H_
