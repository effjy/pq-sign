/* util.c — fatal errors, secure memory, encodings, file I/O.
 * Symmetric primitives (SHA-256, RNG) come from OpenSSL. */
#define _GNU_SOURCE
#include "pqsign.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

void die(const char *fmt, ...)
{
    va_list ap;
    fputs("pq-sign: error: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

void warn(const char *fmt, ...)
{
    va_list ap;
    fputs("pq-sign: warning: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void secure_wipe(void *p, size_t n)
{
    if (p)
        OPENSSL_cleanse(p, n);
}

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p)
        die("out of memory (%zu bytes)", n);
    return p;
}

void *xcalloc(size_t n, size_t sz)
{
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p)
        die("out of memory");
    return p;
}

void random_bytes(uint8_t *buf, size_t n)
{
    if (RAND_bytes(buf, (int)n) != 1)
        die("CSPRNG failure");
}

bool ct_equal(const void *a, const void *b, size_t n)
{
    return CRYPTO_memcmp(a, b, n) == 0;
}

uint8_t *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        die("cannot open '%s': %s", path, strerror(errno));
    if (fseek(f, 0, SEEK_END) != 0)
        die("cannot seek '%s'", path);
    long sz = ftell(f);
    if (sz < 0)
        die("cannot size '%s'", path);
    rewind(f);

    uint8_t *buf = xmalloc((size_t)sz + 1);
    size_t got = fread(buf, 1, (size_t)sz, f);
    if (got != (size_t)sz)
        die("short read on '%s'", path);
    buf[sz] = '\0';
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

void write_file(const char *path, const uint8_t *buf, size_t len, int mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0)
        die("cannot create '%s': %s", path, strerror(errno));
    /* Tighten perms even if the file pre-existed with a looser umask. */
    if (fchmod(fd, mode) != 0)
        warn("could not set mode on '%s'", path);

    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            die("write to '%s' failed: %s", path, strerror(errno));
        }
        off += (size_t)w;
    }
    if (close(fd) != 0)
        die("close '%s' failed: %s", path, strerror(errno));
}

void sha256(const uint8_t *buf, size_t len, uint8_t out[32])
{
    unsigned int olen = 32;
    if (EVP_Digest(buf, len, out, &olen, EVP_sha256(), NULL) != 1)
        die("SHA-256 failed");
}

void sha256_file(const char *path, uint8_t out[32])
{
    FILE *f = fopen(path, "rb");
    if (!f)
        die("cannot open '%s': %s", path, strerror(errno));

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
        die("SHA-256 init failed");

    uint8_t chunk[64 * 1024];
    size_t got;
    while ((got = fread(chunk, 1, sizeof chunk, f)) > 0) {
        if (EVP_DigestUpdate(ctx, chunk, got) != 1)
            die("SHA-256 update failed");
    }
    if (ferror(f))
        die("read error on '%s'", path);

    unsigned int olen = 32;
    if (EVP_DigestFinal_ex(ctx, out, &olen) != 1)
        die("SHA-256 final failed");

    EVP_MD_CTX_free(ctx);
    secure_wipe(chunk, sizeof chunk);
    fclose(f);
}

void to_hex(const uint8_t *src, size_t n, char *dst)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        dst[2 * i]     = hx[src[i] >> 4];
        dst[2 * i + 1] = hx[src[i] & 0x0f];
    }
    dst[2 * n] = '\0';
}

char *b64_encode(const uint8_t *src, size_t n)
{
    /* 4 chars per 3 bytes, plus NUL. */
    size_t outcap = 4 * ((n + 2) / 3) + 1;
    char *out = xmalloc(outcap);
    int w = EVP_EncodeBlock((unsigned char *)out, src, (int)n);
    if (w < 0)
        die("base64 encode failed");
    out[w] = '\0';
    return out;
}

uint8_t *b64_decode(const char *src, size_t srclen, size_t *out_len)
{
    /* Strip whitespace first so wrapped armor bodies decode cleanly. */
    char *clean = xmalloc(srclen + 1);
    size_t c = 0;
    size_t pad = 0;
    for (size_t i = 0; i < srclen; i++) {
        char ch = src[i];
        if (ch == '\n' || ch == '\r' || ch == ' ' || ch == '\t')
            continue;
        clean[c++] = ch;
        if (ch == '=')
            pad++;
    }
    clean[c] = '\0';
    if (c == 0 || c % 4 != 0) {
        free(clean);
        return NULL;
    }

    uint8_t *out = xmalloc(c / 4 * 3 + 1);
    int w = EVP_DecodeBlock((unsigned char *)out, (unsigned char *)clean, (int)c);
    free(clean);
    if (w < 0) {
        free(out);
        return NULL;
    }
    /* EVP_DecodeBlock always reports a multiple of 3; correct for padding. */
    *out_len = (size_t)w - pad;
    return out;
}

char *prompt_passphrase(const char *prompt, bool confirm)
{
    struct termios old, raw;
    FILE *tty = fopen("/dev/tty", "r+");
    if (!tty)
        die("no controlling terminal for passphrase entry");

    int fd = fileno(tty);
    if (tcgetattr(fd, &old) != 0)
        die("tcgetattr failed");
    raw = old;
    raw.c_lflag &= ~(tcflag_t)ECHO;
    if (tcsetattr(fd, TCSAFLUSH, &raw) != 0)
        die("tcsetattr failed");

    fputs(prompt, tty);
    fflush(tty);

    char *line = NULL;
    size_t cap = 0;
    ssize_t n = getline(&line, &cap, tty);
    fputc('\n', tty);
    if (n < 0)
        die("failed to read passphrase");
    if (n > 0 && line[n - 1] == '\n')
        line[--n] = '\0';

    if (confirm) {
        fputs("Confirm passphrase: ", tty);
        fflush(tty);
        char *line2 = NULL;
        size_t cap2 = 0;
        ssize_t n2 = getline(&line2, &cap2, tty);
        fputc('\n', tty);
        if (n2 < 0)
            die("failed to read passphrase confirmation");
        if (n2 > 0 && line2[n2 - 1] == '\n')
            line2[--n2] = '\0';
        if (strcmp(line, line2) != 0) {
            secure_wipe(line, (size_t)n);
            secure_wipe(line2, (size_t)n2);
            free(line);
            free(line2);
            tcsetattr(fd, TCSAFLUSH, &old);
            fclose(tty);
            die("passphrases do not match");
        }
        secure_wipe(line2, (size_t)n2);
        free(line2);
    }

    tcsetattr(fd, TCSAFLUSH, &old);
    fclose(tty);
    return line;
}
