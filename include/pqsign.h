/* pq-sign — post-quantum detached file signing.
 *
 * Public-ish internal header shared across the CLI translation units.
 * Signature schemes are provided by liboqs (ML-DSA / SLH-DSA); all
 * symmetric work (hashing, KDF, AEAD, RNG) is provided by OpenSSL.
 */
#ifndef PQSIGN_H
#define PQSIGN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define PQSIGN_VERSION "0.1.0"

/* Default algorithm when the user does not pass --alg. */
#define PQSIGN_DEFAULT_ALG "ML-DSA-65"

/* ------------------------------------------------------------------ *
 *  util.c — fatal errors, secure memory, encodings, file I/O
 * ------------------------------------------------------------------ */

/* Print "pq-sign: " + formatted message to stderr and exit(1). */
void die(const char *fmt, ...);

/* Print a warning to stderr (non-fatal). */
void warn(const char *fmt, ...);

/* Overwrite a buffer so the compiler cannot optimise the wipe away. */
void secure_wipe(void *p, size_t n);

/* xmalloc/xcalloc: allocate or die. */
void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t sz);

/* Fill buf with cryptographically secure random bytes (dies on failure). */
void random_bytes(uint8_t *buf, size_t n);

/* Constant-time comparison; returns true when equal. */
bool ct_equal(const void *a, const void *b, size_t n);

/* Read an entire file into a freshly malloc'd buffer. Caller frees.
 * Dies on error. *out_len receives the length. */
uint8_t *read_file(const char *path, size_t *out_len);

/* Write buf to path with the given mode (e.g. 0600). Dies on error. */
void write_file(const char *path, const uint8_t *buf, size_t len, int mode);

/* SHA-256 of (buf,len) into out[32]. */
void sha256(const uint8_t *buf, size_t len, uint8_t out[32]);

/* Streaming SHA-256 of a file (does not slurp it into memory). */
void sha256_file(const char *path, uint8_t out[32]);

/* Lowercase hex encode src[n] into dst (needs 2*n+1 bytes). */
void to_hex(const uint8_t *src, size_t n, char *dst);

/* Base64 (standard alphabet, padded). Caller frees the returned string. */
char *b64_encode(const uint8_t *src, size_t n);

/* Base64 decode. Returns malloc'd buffer, *out_len set. NULL on bad input. */
uint8_t *b64_decode(const char *src, size_t srclen, size_t *out_len);

/* Read a passphrase from the terminal with echo disabled. Caller frees. */
char *prompt_passphrase(const char *prompt, bool confirm);

/* ------------------------------------------------------------------ *
 *  keyfile.c — armored key containers (PEM-like text)
 * ------------------------------------------------------------------ */

typedef struct {
    char     alg[64];      /* liboqs algorithm identifier            */
    uint8_t *key;          /* raw key bytes (public or secret)       */
    size_t   key_len;
    bool     is_secret;
} pqsign_key;

/* Write a public key as armored text. */
void key_write_public(const char *path, const char *alg,
                      const uint8_t *pub, size_t pub_len);

/* Write a secret key as armored text. If passphrase is non-NULL the raw
 * key bytes are encrypted with Argon2id + AES-256-GCM before armoring. */
void key_write_secret(const char *path, const char *alg,
                      const uint8_t *sec, size_t sec_len,
                      const char *passphrase);

/* Load an armored key. For an encrypted secret key, prompt_cb may be used
 * to obtain the passphrase if one is needed (pass NULL to fail instead).
 * Caller frees out->key with free() after secure_wipe for secrets. */
void key_load(const char *path, pqsign_key *out);

/* Free and wipe a loaded key. */
void key_free(pqsign_key *k);

/* ------------------------------------------------------------------ *
 *  sigfile.c — detached signature container (binary)
 * ------------------------------------------------------------------ */

/* Build a detached signature blob for (alg, signer pubkey, signature).
 * Returns malloc'd buffer, *out_len set. */
uint8_t *sigfile_build(const char *alg, const uint8_t *pubkey,
                       size_t pubkey_len, const uint8_t *sig, size_t sig_len,
                       size_t *out_len);

/* Parsed view of a detached signature blob. Pointers alias into `raw`. */
typedef struct {
    char           alg[64];
    uint8_t        pub_fpr[32];   /* SHA-256 of signer public key */
    const uint8_t *sig;
    size_t         sig_len;
    uint8_t       *raw;           /* owning buffer; free() this    */
} pqsign_sigfile;

/* Parse a detached signature blob. Dies on malformed input. */
void sigfile_parse(const uint8_t *buf, size_t len, pqsign_sigfile *out);
void sigfile_free(pqsign_sigfile *s);

#endif /* PQSIGN_H */
