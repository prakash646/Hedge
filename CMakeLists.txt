cmake_minimum_required(VERSION 3.13)
project(hedge C)

set(CMAKE_C_STANDARD 99)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_C_FLAGS_RELEASE "-O2")

set(V ${CMAKE_CURRENT_SOURCE_DIR}/vendor)

# ---------------- vendored primitives ----------------
# Ascon reference code exports crypto_* names; rename per variant to avoid clashes.
add_library(ascon_aead128 STATIC ${V}/ascon/aead128/aead.c)
target_include_directories(ascon_aead128 PRIVATE ${V}/ascon/aead128 ${V}/ascon)
target_compile_definitions(ascon_aead128 PRIVATE
  crypto_aead_encrypt=ascon_aead128_encrypt crypto_aead_decrypt=ascon_aead128_decrypt)

add_library(ascon_hash256 STATIC ${V}/ascon/hash256/hash.c)
target_include_directories(ascon_hash256 PRIVATE ${V}/ascon/hash256 ${V}/ascon)
target_compile_definitions(ascon_hash256 PRIVATE crypto_hash=ascon_hash256)

add_library(ascon_cxof128 STATIC ${V}/ascon/cxof128/hash.c)
target_include_directories(ascon_cxof128 PRIVATE ${V}/ascon/cxof128 ${V}/ascon)
target_compile_definitions(ascon_cxof128 PRIVATE
  crypto_cxof=ascon_cxof128 crypto_hash=ascon_cxof128_hash_unused)

add_library(romulus STATIC
  ${V}/romulus/romulus-n-aead.c ${V}/romulus/internal-romulus.c
  ${V}/romulus/internal-skinny-plus.c ${V}/romulus/internal-util.c)
target_include_directories(romulus PUBLIC ${V}/romulus)

add_library(mlkem768 STATIC ${V}/mlkem/mlkem_native.c)
target_include_directories(mlkem768 PUBLIC ${V}/mlkem)
target_compile_definitions(mlkem768 PUBLIC MLK_CONFIG_PARAMETER_SET=768)

add_library(monocypher STATIC ${V}/monocypher/monocypher.c)
target_include_directories(monocypher PUBLIC ${V}/monocypher)

add_library(sha3 STATIC ${V}/sha3/sha3.c)
target_include_directories(sha3 PUBLIC ${V}/sha3)

# ---------------- HEDGE ----------------
add_library(hedge STATIC src/prims.c src/comb.c src/kdf.c src/xwing.c src/handshake.c)
target_include_directories(hedge PUBLIC include)
target_compile_options(hedge PRIVATE -Wall -Wextra)
target_link_libraries(hedge PUBLIC ascon_aead128 ascon_hash256 ascon_cxof128 romulus mlkem768 monocypher sha3)

add_library(hedge_rng_host STATIC src/random_host.c)
target_include_directories(hedge_rng_host PUBLIC include)

# ---------------- tests and benchmarks (host) ----------------
enable_testing()
foreach(t test_kat test_comb test_handshake)
  add_executable(${t} tests/${t}.c)
  target_include_directories(${t} PRIVATE tests)
  target_compile_definitions(${t} PRIVATE KAT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/kat")
  target_link_libraries(${t} PRIVATE hedge hedge_rng_host)
  add_test(NAME ${t} COMMAND ${t})
endforeach()

add_executable(bench_host bench/bench_host.c bench/bench_core.c)
target_include_directories(bench_host PRIVATE bench)
target_link_libraries(bench_host PRIVATE hedge hedge_rng_host)

add_executable(kdf_vectors tools/kdf_vectors.c)
target_link_libraries(kdf_vectors PRIVATE hedge hedge_rng_host)

# ---------------- single-primitive baseline (paper Sec. VII-E), NOT the HEDGE protocol ----------------
add_library(hedge_unhedged STATIC src/prims.c src/comb.c src/kdf.c src/xwing.c src/handshake.c)
target_include_directories(hedge_unhedged PUBLIC include)
target_compile_definitions(hedge_unhedged PUBLIC HEDGE_UNHEDGED)
target_compile_options(hedge_unhedged PRIVATE -Wall -Wextra)
target_link_libraries(hedge_unhedged PUBLIC ascon_aead128 ascon_hash256 ascon_cxof128 romulus mlkem768 monocypher sha3)
add_executable(test_handshake_unhedged tests/test_handshake.c)
target_include_directories(test_handshake_unhedged PRIVATE tests)
target_link_libraries(test_handshake_unhedged PRIVATE hedge_unhedged hedge_rng_host)
add_executable(bench_host_unhedged bench/bench_host.c bench/bench_core.c)
target_include_directories(bench_host_unhedged PRIVATE bench)
target_link_libraries(bench_host_unhedged PRIVATE hedge_unhedged hedge_rng_host)
