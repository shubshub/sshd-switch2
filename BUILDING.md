# Building sshd

This is the source of `sshd.nro` as shipped: `source/main.c`, the wolfCrypt/wolfSSH
settings in `include/user_settings.h`, the app's `Makefile`, and `wolf.mk`, which
builds the two libraries.

## You need

- **devkitPro devkitA64, with ouncebrew's libounce installed through ounce-devkit**
  (https://github.com/ouncebrew/ounce-devkit). Use the devkitA64 release libounce
  itself was built with. A mismatched newlib makes the NRO crash before `main()`
  even runs.
- **wolfSSL** at tag `v5.9.4-stable` (commit `3c5eead`) in `lib/wolfssl`:
  https://github.com/wolfSSL/wolfssl
- **wolfSSH** at tag `v1.6.0-stable` (commit `8221e4e`) in `lib/wolfssh`:
  https://github.com/wolfSSL/wolfssh

Both libraries are git submodules of this repository, pinned to those commits: clone
with `git clone --recursive`, or run `git submodule update --init` in a clone.

## Build

```
export DEVKITPRO=/opt/devkitpro
make -f wolf.mk        # wolfCrypt + wolfSSH -> libwolf/lib/libwolf.a
make                   # sshd.nro
```

The settings build plain-C crypto (`WOLFSSL_NO_ASM`). They keep big temporaries off
the stack, because homebrew runs on the game's stack. They enable ECDSA host keys,
Ed25519/ECDSA/RSA client keys, Curve25519, AES-GCM/CTR and SHA-2.
