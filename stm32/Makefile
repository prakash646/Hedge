# HEDGE benchmark firmware for B-L475E-IOT01A (STM32L475VG, Cortex-M4).
#   make                -> hedge_stm32l475.bin      portable C everywhere (paper Table IX)
#   make VARIANT=asm    -> hedge_stm32l475_asm.bin  Armv7-M assembly for Ascon (ascon-c armv7m)
#                                                   and SKINNY-128-384+ (lwc-finalists full-armv7m)
#   make VARIANT=fast   -> hedge_stm32l475_fast.bin Armv7-M assembly for Ascon and X25519
#                                                   (E. Lenngren); SKINNY stays C (its asm was slower)
#   make VARIANT=base     -> baseline_stm32l475.bin      UNHEDGED baseline (ML-KEM + Ascon only), portable C
#   make VARIANT=basefast -> baseline_stm32l475_fast.bin UNHEDGED baseline, Ascon assembly
# Drag the .bin onto the DIS_L4IOT USB drive.
R  := ..
V  := $(R)/vendor
TP := $(R)/third_party
CC := arm-none-eabi-gcc
CPU := -mcpu=cortex-m4 -mthumb -mfloat-abi=soft
WRAP := $(shell sed -n '/PROF_WRAP_FLAGS/,/endif/p' $(R)/bench/prof.h | grep -o -- '-Wl,--wrap=[a-z0-9_]*' | tr '\n' ' ')

ifeq ($(VARIANT),asm)
  OUT    := hedge_stm32l475_asm
  VFLAGS := -DHEDGE_VARIANT='"Armv7-M assembly for Ascon and SKINNY; ML-KEM, X25519, SHA-3 portable C"'
  AEAD_DIR := $(TP)/ascon-c/crypto_aead/asconaead128/armv7m
  HASH_DIR := $(TP)/ascon-c/crypto_hash/asconhash256/armv7m
  AEAD_SRC := $(AEAD_DIR)/aead.c $(AEAD_DIR)/permutations.c
  HASH_SRC := $(HASH_DIR)/hash.c $(HASH_DIR)/permutations.c
  SKINNY_ASM := $(TP)/lwc-finalists/src/individual/Romulus/internal-skinny-full-armv7m.S
else ifeq ($(VARIANT),fast)
  OUT    := hedge_stm32l475_fast
  VFLAGS := -DSKINNY_PLUS_FORCE_C -DHEDGE_VARIANT='"Armv7-M assembly for Ascon and X25519; ML-KEM, SHA-3, SKINNY portable C"'
  AEAD_DIR := $(TP)/ascon-c/crypto_aead/asconaead128/armv7m
  HASH_DIR := $(TP)/ascon-c/crypto_hash/asconhash256/armv7m
  AEAD_SRC := $(AEAD_DIR)/aead.c $(AEAD_DIR)/permutations.c
  HASH_SRC := $(HASH_DIR)/hash.c $(HASH_DIR)/permutations.c
  SKINNY_ASM :=
  X25519_FAST := 1
else ifeq ($(VARIANT),base)
  OUT    := baseline_stm32l475
  VFLAGS := -DSKINNY_PLUS_FORCE_C -DHEDGE_UNHEDGED -DHEDGE_VARIANT='"UNHEDGED BASELINE (ML-KEM-768 + Ascon only), portable C"'
  AEAD_DIR := $(V)/ascon/aead128
  HASH_DIR := $(V)/ascon/hash256
  AEAD_SRC := $(AEAD_DIR)/aead.c
  HASH_SRC := $(HASH_DIR)/hash.c
  SKINNY_ASM :=
else ifeq ($(VARIANT),basefast)
  OUT    := baseline_stm32l475_fast
  VFLAGS := -DSKINNY_PLUS_FORCE_C -DHEDGE_UNHEDGED -DHEDGE_VARIANT='"UNHEDGED BASELINE (ML-KEM-768 + Ascon only), Ascon assembly"'
  AEAD_DIR := $(TP)/ascon-c/crypto_aead/asconaead128/armv7m
  HASH_DIR := $(TP)/ascon-c/crypto_hash/asconhash256/armv7m
  AEAD_SRC := $(AEAD_DIR)/aead.c $(AEAD_DIR)/permutations.c
  HASH_SRC := $(HASH_DIR)/hash.c $(HASH_DIR)/permutations.c
  SKINNY_ASM :=
else
  OUT    := hedge_stm32l475
  VFLAGS := -DSKINNY_PLUS_FORCE_C
  AEAD_DIR := $(V)/ascon/aead128
  HASH_DIR := $(V)/ascon/hash256
  AEAD_SRC := $(AEAD_DIR)/aead.c
  HASH_SRC := $(HASH_DIR)/hash.c
  SKINNY_ASM :=
endif

CFLAGS := $(CPU) -O2 $(EXTRA) $(VFLAGS) -ffunction-sections -fdata-sections -fno-builtin-printf \
  -I$(R)/include -I$(R)/bench -I$(R)/tests -I$(V)/romulus -I$(V)/mlkem -I$(V)/monocypher -I$(V)/sha3 \
  -DMLK_CONFIG_PARAMETER_SET=768
LDFLAGS := $(CPU) -T link.ld -nostartfiles --specs=nano.specs --specs=nosys.specs -Wl,--gc-sections \
  -Wl,-Map=$(OUT).map $(WRAP)

SRCS := main_stm32.c startup.c $(R)/bench/bench_core.c $(R)/bench/bench_ablation.c $(R)/bench/prof.c \
  $(R)/src/prims.c $(R)/src/comb.c $(R)/src/kdf.c $(R)/src/xwing.c $(R)/src/handshake.c \
  $(V)/romulus/romulus-n-aead.c $(V)/romulus/internal-romulus.c \
  $(V)/romulus/internal-skinny-plus.c $(V)/romulus/internal-util.c \
  $(V)/mlkem/mlkem_native.c $(V)/sha3/sha3.c $(SKINNY_ASM)

all: $(OUT).bin

O := obj-$(OUT)
$(O):
	mkdir -p $@
$(O)/ascon_aead.o: $(AEAD_SRC) | $(O)
	$(CC) $(CFLAGS) -I$(AEAD_DIR) -I$(V)/ascon -Dcrypto_aead_encrypt=ascon_aead128_encrypt -Dcrypto_aead_decrypt=ascon_aead128_decrypt \
	  -Dascon_permute=ascon_aead_permute -DP12=AEAD_P12 -DP8=AEAD_P8 -DP6=AEAD_P6 -r -nostdlib $(AEAD_SRC) -o $@
$(O)/ascon_hash.o: $(HASH_SRC) | $(O)
	$(CC) $(CFLAGS) -I$(HASH_DIR) -I$(V)/ascon -Dcrypto_hash=ascon_hash256 \
	  -Dascon_permute=ascon_hash_permute -DP12=HASH_P12 -DP8=HASH_P8 -DP6=HASH_P6 -r -nostdlib $(HASH_SRC) -o $@
$(O)/ascon_cxof.o: $(V)/ascon/cxof128/hash.c | $(O)
	$(CC) $(CFLAGS) -I$(V)/ascon/cxof128 -I$(V)/ascon -Dcrypto_cxof=ascon_cxof128 -Dcrypto_hash=ascon_cxof128_hash_unused -c $< -o $@

ASCON_OBJS := $(O)/ascon_aead.o $(O)/ascon_hash.o $(O)/ascon_cxof.o

$(O)/monocypher.o: $(V)/monocypher/monocypher.c | $(O)
	$(CC) $(CFLAGS) -c $< -o $@
ifeq ($(X25519_FAST),1)
	arm-none-eabi-objcopy --redefine-sym crypto_x25519=mono_x25519 \
	  --redefine-sym crypto_x25519_public_key=mono_x25519_public_key $@
ASCON_OBJS += $(V)/x25519-m4/x25519_shim.c $(V)/x25519-m4/x25519-cortex-m4-gcc.s
CFLAGS += -I$(V)/x25519-m4
endif
ASCON_OBJS += $(O)/monocypher.o

$(OUT).elf: $(SRCS) $(ASCON_OBJS) link.ld
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRCS) $(ASCON_OBJS) -o $@
	arm-none-eabi-size $@

$(OUT).bin: $(OUT).elf
	arm-none-eabi-objcopy -O binary $< $@

clean:
	rm -rf obj-* *.o *.elf *.bin *.map
