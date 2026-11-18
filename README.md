# HEDGE — research artifact

Code, tests, benchmarks and formal model for the paper
**"HEDGE: An Algorithm-Hedged, Sign-Less Post-Quantum Authenticated Key Exchange and Record Layer for Microcontroller-Class IoT Devices"** (M. Prakash, 2026). Archived on Zenodo: DOI to be added at the first release.

Every cryptographic layer pairs two unrelated primitives and stays secure if either survives:

| Layer | Components | Combiner |
|---|---|---|
| Key encapsulation | ML-KEM-768 + X25519 | X-Wing |
| KDF / MAC | SHAKE256 ⊕ Ascon-CXOF128 | XOR |
| Transcript hash | SHAKE256 ‖ Ascon-Hash256 | concatenation |
| Record layer | Ascon-AEAD128 ∘ Romulus-N | tidy cascade |

## Layout

```
include/hedge.h        public API (no heap allocation)
src/                   our code (~600 lines): comb.c, kdf.c, xwing.c, handshake.c, prims.c
vendor/                pinned third-party sources (licenses inside each folder)
kat/                   official known-answer test files
tests/                 test_kat.c, test_comb.c, test_handshake.c
bench/                 platform-independent benchmark core + host driver
pico/                  Raspberry Pi Pico (RP2040, Cortex-M0+) firmware
stm32/                 STM32L475 (B-L475E-IOT01A, Cortex-M4) firmware + lab guide
ibex/                  Ibex RV32IMC benchmark program for the Verilator RTL simulation
tamarin/hedge.spthy    symbolic model; run_lemmas.sh proves each lemma
tools/                 X-Wing vector converter, KDF vector dump, independent Python check
results/               outputs produced in our environment (see below)
prebuilt/              ready-to-flash firmware: hedge_stm32l475{,_asm,_fast}.bin (STM32), hedge_bench.uf2 (Pico)
```

## 1. Build and test on a PC (Linux, macOS, or Windows via WSL2)

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/test_kat              # 4297 official vectors (Ascon, Romulus-N, SHA-3, X-Wing)
./build/test_comb 1000000     # record layer + 10^6-trial tidiness test (~40 s)
./build/test_handshake        # 42 checks incl. tampering, wrong key, MITM, replay
./build/bench_host            # development-host timings (NOT the paper's device numbers)
```

Constant-time check (Valgrind memcheck, ctgrind/TIMECOP method; secrets marked undefined,
public values declassified; includes a positive control that must be flagged):

```sh
sudo apt install valgrind
tools/ct_check.sh            # -O2 -Os -O3, HEDGE and baseline; writes results/ct_check.txt
```

Unhedged single-primitive baseline (paper Sec. VII-E; ML-KEM-768 + Ascon only, same message flow;
NOT the HEDGE protocol): built by the same CMake run as `test_handshake_unhedged` and
`bench_host_unhedged` (`-DHEDGE_UNHEDGED`).

Independent cross-check of H* and KDF against Python (`hashlib` + `pyascon`):

```sh
git clone https://github.com/meichlseder/pyascon /tmp/pyascon
./build/kdf_vectors > v.json && python3 tools/ref_check.py v.json /tmp/pyascon
```

## 2. Optional: Raspberry Pi Pico (Cortex-M0+)

Quick path, no toolchain needed:
1. Hold **BOOTSEL** on the Pico and plug it into USB. A drive called `RPI-RP2` appears.
2. Copy `prebuilt/hedge_bench.uf2` onto it. The Pico reboots and runs.
3. Open the Pico's serial port (Windows: COMx in PuTTY or the Arduino serial monitor; Linux: `screen /dev/ttyACM0`). Any baud rate.
4. Within about 10 seconds it prints `self-test ... PASS`, then the cycle counts and peak stack. Copy the whole output into `results/pico_run.txt`.

Rebuilding the firmware yourself:

```sh
git clone -b 2.1.1 https://github.com/raspberrypi/pico-sdk && (cd pico-sdk && git submodule update --init lib/tinyusb)
export PICO_SDK_PATH=$PWD/pico-sdk
cmake -S pico -B build-pico -DPICO_BOARD=pico && cmake --build build-pico -j
```

Needs `gcc-arm-none-eabi` (Ubuntu: `sudo apt install gcc-arm-none-eabi libnewlib-arm-none-eabi cmake`).

## 2a. Measure on the STM32 B-L475E-IOT01A Discovery kit (Cortex-M4, 80 MHz) — paper Tables IX and X

Three ready-to-flash builds in `prebuilt/` (all from `make -C stm32 [VARIANT=...]`):

| File | Build | Device handshake (our board) |
|---|---|---|
| `hedge_stm32l475.bin` | portable C everywhere (same sources as Ibex) | 9,592,781 cycles = 120 ms |
| `hedge_stm32l475_asm.bin` | + Armv7-M asm for Ascon (ascon-c) and SKINNY (lwc-finalists) | 9,403,900 cycles |
| `hedge_stm32l475_fast.bin` | + Armv7-M asm for Ascon and X25519 (Lenngren); SKINNY C | 6,141,675 cycles = 77 ms |

Each image checks itself first (X-Wing vector, full handshake, Ascon/Romulus-N/Ascon-Hash KATs),
then prints cycle counts (median, min, max), peak stack, single-component ablations, and a
per-primitive attribution of one device handshake (call wrapping via `bench/prof.c` and `ld --wrap`).
Our outputs: `results/stm32_c.txt`, `results/stm32_asm.txt`, `results/stm32_fast.txt`
(raw serial logs `*_raw.txt`; earlier images in `results/stm32_earlier/`).
Lab guide: `stm32/LAB-INSTRUCTIONS.txt` (drag-and-drop flashing, serial terminal at 115200 baud,
optional energy measurement at the IDD jumper). QEMU 9.2 (`-machine b-l475e-iot01a`) runs the images
for functional testing, but has no cycle counter.

**Reproducible builds.** With `gcc-arm-none-eabi` 13.2 (Ubuntu 24.04), `make -C stm32 VARIANT=...` rebuilds all
five images in `prebuilt/` bit for bit (compare with `prebuilt/SHA256SUMS`); the assembly variants first need
`tools/fetch_third_party.sh`.

## 2b. Cycle-accurate measurement on the Ibex RISC-V core (no hardware needed)

Fills the "Ibex RV32IMC" column of paper Table IX. Runs the real Ibex RTL in Verilator.

```sh
sudo apt install verilator gcc-riscv64-unknown-elf picolibc-riscv64-unknown-elf libelf-dev srecord
pip install fusesoc==2.4.3
git clone https://github.com/lowRISC/ibex ~/ibex && cd ~/ibex      # we used commit 1b29dae
fusesoc --cores-root=. run --target=sim --setup --build lowrisc:ibex:ibex_simple_system \
        $(python3 util/ibex_config.py small fusesoc_opts)
cd <this artifact>/ibex
make IBEX=~/ibex run                      # full benchmark, ~25 min of simulation
make clean && make IBEX=~/ibex run EXTRA=-DSTACK_ONLY   # peak-stack report only, ~5 min
make clean && make IBEX=~/ibex run EXTRA=-DHEDGE_UNHEDGED # unhedged baseline benchmark
make clean && make IBEX=~/ibex run EXTRA=-DATTR_ONLY     # ablation + per-primitive attribution
```

The simulator normally writes a per-instruction trace that grows to many gigabytes;
`make run` links it to `/dev/null`. Our outputs: `results/ibex_run_bench.txt`, `results/ibex_run_stack.txt`.

## 3. Formal verification (Tamarin)

```sh
# Tamarin 1.10.0 and Maude 3.5
cd tamarin && ./run_lemmas.sh hedge.spthy 3600   # all lemmas of the main model, ~90 min, writes results_hedge.txt
./prove_one.sh hedge_s1.spthy sanity_fs_attack_exists 600   # sanity check S1 (handshake-only model)
```

See `results/tamarin_results.txt` for our run. Run one prover at a time: parallel runs were killed for lack of memory on an 8 GB machine. The three `sanity_*` lemmas are **expected to be falsified**: they show the break rules are effective and that the conditions in the main lemmas cannot be dropped.

## What has and has not been run

| Item | Status |
|---|---|
| Known-answer tests, tidiness test, handshake tests, Python cross-check | run, outputs in `results/` |
| Host benchmark | run (Xeon 2.8 GHz VM), development reference only |
| Tamarin: 12 security lemmas verified, 3 sanity attacks found | run, `results/tamarin_results.txt` |
| Ibex RV32IMC cycle-accurate benchmark + stack | run, `results/ibex_run_*.txt` |
| STM32L475 (Cortex-M4), three builds: cycles, stack, ablation, attribution | run on hardware, `results/stm32_*.txt` |
| Constant-time check (Valgrind), HEDGE + baseline, -O2/-Os/-O3 | run, `results/ct_check.txt` |
| Unhedged baseline: host tests + Ibex cycle-accurate benchmark | run, `results/ibex_baseline_bench.txt` |
| Ibex per-primitive attribution | run, `results/ibex_attribution.txt` |
| Unhedged baseline on STM32 (`make -C stm32 VARIANT=base` / `basefast`) | run on hardware, `results/stm32_baseline_{c,fast}.txt` |
| Pico firmware | cross-compiled, not run (optional) |
| Energy (multimeter at IDD jumper) | not yet done |

## Third-party sources

`vendor/` holds the exact third-party files the default builds need, with their licenses.
The STM32 assembly builds (`VARIANT=asm`, `fast`, `basefast`) and the vector-conversion tools
also need the full upstream repositories at pinned commits:

```sh
tools/fetch_third_party.sh     # clones into third_party/ (not tracked in git)
```

## Citing

See `CITATION.cff`. Please cite the paper and, for the artifact itself, the Zenodo record.

## Third-party code (pinned)

| Component | Source | Commit |
|---|---|---|
| Ascon-AEAD128 / Hash256 / CXOF128 (ref) | github.com/ascon/ascon-c | 446347f |
| Romulus-N, SKINNY-128-384+ | github.com/rweather/lwc-finalists | 77b23e6 |
| ML-KEM-768 | github.com/pq-code-package/mlkem-native | 7da6bd1 |
| X25519 | github.com/LoupVaillant/Monocypher | e65d277 |
| SHA3-256 / SHAKE256 | github.com/mjosaarinen/tiny_sha3 | dcbb319 |
| X-Wing test vectors and reference | github.com/dconnolly/draft-connolly-cfrg-xwing-kem | 984c2f7 |
| X25519 Cortex-M4 assembly (fast build only) | github.com/Emill/X25519-Cortex-M4 (vendor/x25519-m4, BSD-style license) | e85f816 |
| Ascon armv7m assembly (asm/fast builds) | github.com/ascon/ascon-c (third_party/ascon-c) | 446347f |

Our code in `src/`, `include/`, `tests/`, `bench/`, `pico/`, `tools/`, `tamarin/` is MIT-licensed. The vendored code keeps its own license (see each `vendor/*` folder).
