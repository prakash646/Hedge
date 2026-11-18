/* Host benchmark driver. Reports wall-clock nanoseconds (CLOCK_MONOTONIC_RAW).
 * These are HOST numbers for development only; the paper reports the Pico build.
 * SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "bench_core.h"

uint64_t bench_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
const char *bench_unit(void) { return "ns"; }

int main(int argc, char **argv)
{
    int rs = argc > 1 ? atoi(argv[1]) : 1001, rk = argc > 2 ? atoi(argv[2]) : 201;
    printf("HEDGE host benchmark (development reference, not the MCU results)\n");
    bench_run(rs, rk);
    return 0;
}
