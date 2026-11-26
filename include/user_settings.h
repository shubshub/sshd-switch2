/* wolfCrypt + wolfSSH build settings for the Switch 2 (libounce, newlib). */
#ifndef SSHD_USER_SETTINGS_H
#define SSHD_USER_SETTINGS_H

/* wolfCrypt only: SSH needs no TLS. */
#define WOLFCRYPT_ONLY
#define WOLFSSL_WOLFSSH
#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_ASM             /* ponytail: plain C crypto; WOLFSSL_ARMASM if SFTP throughput matters */
#define WOLFSSL_IGNORE_FILE_WARN
#define WOLFSSL_SMALL_STACK        /* big-number temporaries on the heap: we run on the game's stack */
#define WOLFSSH_SMALL_STACK

/* Entropy: kernel-seeded CSPRNG from libnx/libounce (randomGet). */
#include <stdint.h>
int sshd_rand_seed(unsigned char* out, unsigned int sz);
#define CUSTOM_RAND_GENERATE_SEED sshd_rand_seed
#define HAVE_HASHDRBG

/* Math */
#define WOLFSSL_SP_MATH_ALL
#define SP_INT_BITS 4096
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* Host key generation (ECDSA P-256) */
#define HAVE_ECC
#define WOLFSSL_KEY_GEN

/* Client keys and key exchange */
#define HAVE_CURVE25519
#define HAVE_ED25519
#define HAVE_ED25519_SIGN
#define HAVE_ED25519_VERIFY
#define HAVE_ED25519_KEY_IMPORT
#define HAVE_ED25519_KEY_EXPORT
#define WOLFSSL_ED25519_STREAMING_VERIFY

/* Ciphers, hashes */
#define HAVE_AESGCM
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_BASE64_ENCODE

/* Not needed */
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_PSK
#define NO_OLD_TLS
#define NO_PWDBASED
#define NO_ASN_TIME                /* no certificates, so no clock checks */

/* wolfSSH */
#define WOLFSSH_SFTP
#define WOLFSSH_TERM               /* accept pty-req, so `ssh host` gets the shell */
#define NO_TERMIOS
#define WOLFSSH_NO_AGENT
#define DEFAULT_WINDOW_SZ (1024 * 1024)
#define WOLFSSH_MAX_SFTP_RW 65536

#endif
