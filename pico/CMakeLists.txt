# Raspberry Pi Pico (RP2040, Cortex-M0+) benchmark firmware for HEDGE.
# Build:  export PICO_SDK_PATH=/path/to/pico-sdk
#         cmake -S pico -B build-pico -DPICO_BOARD=pico && cmake --build build-pico
# Flash:  hold BOOTSEL, plug in, copy build-pico/hedge_bench.uf2 to the RPI-RP2 drive.
cmake_minimum_required(VERSION 3.13)
include(pico_sdk_import.cmake)
project(hedge_pico C CXX ASM)
set(CMAKE_C_STANDARD 11)
pico_sdk_init()

set(R ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(V ${R}/vendor)

add_library(p_ascon_aead128 STATIC ${V}/ascon/aead128/aead.c)
target_include_directories(p_ascon_aead128 PRIVATE ${V}/ascon/aead128 ${V}/ascon)
target_compile_definitions(p_ascon_aead128 PRIVATE crypto_aead_encrypt=ascon_aead128_encrypt crypto_aead_decrypt=ascon_aead128_decrypt)
add_library(p_ascon_hash256 STATIC ${V}/ascon/hash256/hash.c)
target_include_directories(p_ascon_hash256 PRIVATE ${V}/ascon/hash256 ${V}/ascon)
target_compile_definitions(p_ascon_hash256 PRIVATE crypto_hash=ascon_hash256)
add_library(p_ascon_cxof128 STATIC ${V}/ascon/cxof128/hash.c)
target_include_directories(p_ascon_cxof128 PRIVATE ${V}/ascon/cxof128 ${V}/ascon)
target_compile_definitions(p_ascon_cxof128 PRIVATE crypto_cxof=ascon_cxof128 crypto_hash=ascon_cxof128_hash_unused)

set(HEDGE_SRC
  ${R}/src/prims.c ${R}/src/comb.c ${R}/src/kdf.c ${R}/src/xwing.c ${R}/src/handshake.c
  ${V}/romulus/romulus-n-aead.c ${V}/romulus/internal-romulus.c
  ${V}/romulus/internal-skinny-plus.c ${V}/romulus/internal-util.c
  ${V}/mlkem/mlkem_native.c ${V}/monocypher/monocypher.c ${V}/sha3/sha3.c)

add_executable(hedge_bench main_pico.c ${R}/bench/bench_core.c ${HEDGE_SRC})
target_include_directories(hedge_bench PRIVATE ${R}/include ${R}/bench ${R}/tests
  ${V}/romulus ${V}/mlkem ${V}/monocypher ${V}/sha3)
target_compile_definitions(hedge_bench PRIVATE MLK_CONFIG_PARAMETER_SET=768)
target_compile_options(hedge_bench PRIVATE -O2)
target_link_libraries(hedge_bench pico_stdlib pico_rand hardware_clocks hardware_exception
  p_ascon_aead128 p_ascon_hash256 p_ascon_cxof128)

pico_enable_stdio_usb(hedge_bench 1)
pico_enable_stdio_uart(hedge_bench 0)
pico_add_extra_outputs(hedge_bench)

# Energy-measurement firmware: runs without USB, LED + GP15 mark the active phase.
add_executable(hedge_energy main_energy.c ${HEDGE_SRC})
target_include_directories(hedge_energy PRIVATE ${R}/include ${R}/tests
  ${V}/romulus ${V}/mlkem ${V}/monocypher ${V}/sha3)
target_compile_definitions(hedge_energy PRIVATE MLK_CONFIG_PARAMETER_SET=768)
target_compile_options(hedge_energy PRIVATE -O2)
target_link_libraries(hedge_energy pico_stdlib pico_rand hardware_clocks
  p_ascon_aead128 p_ascon_hash256 p_ascon_cxof128)
pico_enable_stdio_usb(hedge_energy 0)
pico_enable_stdio_uart(hedge_energy 0)
pico_add_extra_outputs(hedge_energy)
