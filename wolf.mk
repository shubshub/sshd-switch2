# Builds wolfCrypt + wolfSSH into libwolf/lib/libwolf.a. Kept apart from the
# main Makefile because the devkitPro template flattens object names and both
# libraries have a misc.c / port.c.
include $(DEVKITPRO)/libounce/switch2_rules

CRYPT := aes asn coding curve25519 dh ecc ed25519 error fe_operations \
         ge_operations hash hmac kdf logging memory random rsa sha sha256 \
         sha512 signature sp_int wc_encrypt wc_port wolfmath
SSH   := internal io log port ssh wolfsftp ossh

SRCS  := $(CRYPT:%=lib/wolfssl/wolfcrypt/src/%.c) $(SSH:%=lib/wolfssh/src/%.c)
OBJS  := $(SRCS:lib/%.c=build-wolf/%.o)

CFLAGS := $(SWITCH2_CPU) -mtp=soft -fPIE -O2 -ffunction-sections -fdata-sections \
          -Wno-cpp -D__SWITCH__ -D__SWITCH2__ -DWOLFSSL_USER_SETTINGS \
          -Iinclude -Ilib/wolfssl -Ilib/wolfssh -I$(LIBNX)/include

libwolf/lib/libwolf.a: $(OBJS)
	@mkdir -p $(@D) && rm -f $@ && $(AR) rcs $@ $^ && echo "built ... $@"

build-wolf/%.o: lib/%.c include/user_settings.h
	@mkdir -p $(@D) && echo $(notdir $<) && $(CC) $(CFLAGS) -c $< -o $@
