# Build the HEDGE benchmark for the Ibex simple system (RV32IMC).
#   make IBEX=/path/to/ibex          -> hedge_ibex.elf / .vmem
#   make IBEX=/path/to/ibex run      -> runs the Verilator model, writes ibex_run.log
IBEX ?= $(HOME)/ibex
R    := ..
V    := $(R)/vendor
SS   := $(IBEX)/examples/sw/simple_system/common
SIM  := $(IBEX)/build/lowrisc_ibex_ibex_simple_system_0/sim-verilator/Vibex_simple_system
CC   := riscv64-unknown-elf-gcc
OBJCOPY := riscv64-unknown-elf-objcopy
PICO := /usr/lib/picolibc/riscv64-unknown-elf
ARCH := -march=rv32imc_zicsr -mabi=ilp32
CFLAGS := $(ARCH) -O2 $(EXTRA) -static -mcmodel=medany -ffreestanding -fno-builtin-printf \
  -isystem $(PICO)/include -I$(SS) -I$(R)/include -I$(R)/bench -I$(R)/tests \
  -I$(V)/romulus -I$(V)/mlkem -I$(V)/monocypher -I$(V)/sha3 -DMLK_CONFIG_PARAMETER_SET=768
LIBS := $(PICO)/lib/rv32im/ilp32/libc.a $(shell $(CC) -march=rv32im -mabi=ilp32 -print-libgcc-file-name)

SRCS := main_ibex.c $(R)/bench/bench_core.c \
  $(R)/src/prims.c $(R)/src/comb.c $(R)/src/kdf.c $(R)/src/xwing.c $(R)/src/handshake.c \
  $(V)/romulus/romulus-n-aead.c $(V)/romulus/internal-romulus.c \
  $(V)/romulus/internal-skinny-plus.c $(V)/romulus/internal-util.c \
  $(V)/mlkem/mlkem_native.c $(V)/monocypher/monocypher.c $(V)/sha3/sha3.c \
  $(SS)/simple_system_common.c

all: hedge_ibex.vmem

ascon_aead.o: $(V)/ascon/aead128/aead.c
	$(CC) $(CFLAGS) -I$(V)/ascon/aead128 -I$(V)/ascon -Dcrypto_aead_encrypt=ascon_aead128_encrypt -Dcrypto_aead_decrypt=ascon_aead128_decrypt -c $< -o $@
ascon_hash.o: $(V)/ascon/hash256/hash.c
	$(CC) $(CFLAGS) -I$(V)/ascon/hash256 -I$(V)/ascon -Dcrypto_hash=ascon_hash256 -c $< -o $@
ascon_cxof.o: $(V)/ascon/cxof128/hash.c
	$(CC) $(CFLAGS) -I$(V)/ascon/cxof128 -I$(V)/ascon -Dcrypto_cxof=ascon_cxof128 -Dcrypto_hash=ascon_cxof128_hash_unused -c $< -o $@
crt0.o: $(SS)/crt0.S
	$(CC) $(ARCH) -c $< -o $@

ifneq ($(findstring ATTR_ONLY,$(EXTRA)),)
SRCS += $(R)/bench/bench_ablation.c $(R)/bench/prof.c
WRAP := $(shell sed -n '/PROF_WRAP_FLAGS/,/endif/p' $(R)/bench/prof.h | grep -o -- '-Wl,--wrap=[a-z0-9_]*' | tr '\n' ' ')
endif

hedge_ibex.elf: $(SRCS) ascon_aead.o ascon_hash.o ascon_cxof.o crt0.o link.ld
	$(CC) $(CFLAGS) $(WRAP) -nostdlib -nostartfiles -T link.ld crt0.o $(SRCS) ascon_aead.o ascon_hash.o ascon_cxof.o $(LIBS) -o $@
	riscv64-unknown-elf-size $@

hedge_ibex.vmem: hedge_ibex.elf
	$(OBJCOPY) -O binary $< hedge_ibex.bin
	srec_cat hedge_ibex.bin -binary -offset 0x0000 -byte-swap 4 -o $@ -vmem

# The simulator writes a per-instruction trace (many GB); send it to /dev/null.
run: hedge_ibex.elf
	ln -sf /dev/null trace_core_00000000.log
	$(SIM) --meminit=ram,hedge_ibex.elf > sim_stdout.txt 2>&1; cp ibex_simple_system.log ibex_run.log; cat ibex_run.log

clean:
	rm -f *.o *.elf *.bin *.vmem *.log sim_stdout.txt
