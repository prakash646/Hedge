/* SPDX-License-Identifier: MIT */
#ifndef BENCH_CORE_H
#define BENCH_CORE_H
#include <stdint.h>
uint64_t bench_now(void);
const char *bench_unit(void);
void bench_run(int reps_sym, int reps_kem);
#endif
