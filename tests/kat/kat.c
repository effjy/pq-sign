/* kat.c — known-answer and unit tests for pq-sign's deterministic core.
 *
 * Covers the pieces pq-sign owns or wires up directly: SHA-256, the strict
 * base64 codec (including malformed-input rejection), the Argon2id KDF as we
 * parameterise it, the domain-separated signed-message construction, the
 * detached-signature container, and the key-armor parse/decrypt path
 * (plaintext and encrypted, plus AEAD tamper detection).
 *
 * Post-quantum signature correctness itself lives in liboqs (which ships its
 * own KATs); the end-to-end sign/verify/tamper/wrong-key behaviour is covered
 * by tests/run.sh. This binary links the library objects, not main.o.
 *
 * Pinned vectors were generated once from the reference implementations and
 * are regression anchors: a change here means a behavioural change in our
 * crypto wiring, which must be deliberate.
 */
#include "pqsign.h"
#include "keyfile_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <argon2.h>

static int failures = 0;
static int checks   = 0;

static void check(bool cond, const char *what)
{
    checks++;
    if (cond) {
        printf("  \033[32mPASS\033[0m %s\n", what);
    } else {
        printf("  \033[31mFAIL\033[0m %s\n", what);
        failures++;
    }
}

/* Parse "deadbeef..." into bytes; returns count. */
static size_t unhex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0;
    for (; hex[0] && hex[1] && n < cap; hex += 2, n++) {
        unsigned v;
        sscanf(hex, "%2x", &v);
        out[n] = (uint8_t)v;
    }
    return n;
}

static bool eq_hex(const uint8_t *got, size_t got_len, const char *want_hex)
{
    uint8_t want[64];
    size_t wn = unhex(want_hex, want, sizeof want);
    return wn == got_len && memcmp(got, want, got_len) == 0;
}

/* ------------------------------------------------------------------ */

static void test_sha256(void)
{
    printf("[sha256]\n");
    uint8_t d[32];
    sha256((const uint8_t *)"abc", 3, d);
    check(eq_hex(d, 32,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        "sha256(\"abc\") matches NIST vector");
}

static void test_base64(void)
{
    printf("[base64]\n");
    struct { const char *raw, *b64; } v[] = {
        { "f", "Zg==" }, { "fo", "Zm8=" }, { "foo", "Zm9v" },
        { "foob", "Zm9vYg==" }, { "fooba", "Zm9vYmE=" },
        { "foobar", "Zm9vYmFy" },
    };
    bool all = true;
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        char *enc = b64_encode((const uint8_t *)v[i].raw, strlen(v[i].raw));
        if (strcmp(enc, v[i].b64) != 0) all = false;
        size_t ol;
        uint8_t *dec = b64_decode(v[i].b64, strlen(v[i].b64), &ol);
        if (!dec || ol != strlen(v[i].raw) ||
            memcmp(dec, v[i].raw, ol) != 0) all = false;
        free(enc); free(dec);
    }
    check(all, "RFC 4648 encode/decode vectors round-trip");

    /* A 4 KiB round-trip exercises multi-quantum decoding. */
    uint8_t buf[4096];
    for (size_t i = 0; i < sizeof buf; i++) buf[i] = (uint8_t)(i * 31 + 7);
    char *e = b64_encode(buf, sizeof buf);
    size_t ol;
    uint8_t *d = b64_decode(e, strlen(e), &ol);
    check(d && ol == sizeof buf && memcmp(d, buf, sizeof buf) == 0,
          "4 KiB binary round-trip");
    free(e); free(d);

    /* Strict rejection of malformed input. */
    const char *bad[] = {
        "abc",      /* length not a multiple of 4               */
        "Zm9vYmE",  /* length 7                                 */
        "ab=c",     /* '=' not at the end                       */
        "a===",     /* three pads                               */
        "@@@@",     /* non-alphabet bytes                       */
        "Zm9*Ymny", /* embedded non-alphabet byte               */
    };
    bool rejected = true;
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        size_t bl;
        uint8_t *r = b64_decode(bad[i], strlen(bad[i]), &bl);
        if (r) { rejected = false; free(r); }
    }
    check(rejected, "malformed base64 is rejected");

    /* Whitespace inside a valid body is ignored. */
    size_t wl;
    uint8_t *w = b64_decode("Zm9v\n Ym Fy\t", 12, &wl);
    check(w && wl == 6 && memcmp(w, "foobar", 6) == 0,
          "whitespace in base64 body is ignored");
    free(w);
}

static void test_argon2id(void)
{
    printf("[argon2id]\n");
    /* Same parameters keyfile.c derive_key() uses (t=3, m=64MiB, p=1). */
    uint8_t salt[16];
    for (int i = 0; i < 16; i++) salt[i] = (uint8_t)i;
    uint8_t dek[32];
    int rc = argon2id_hash_raw(3, 65536, 1, "pq-sign-kat", 11,
                               salt, 16, dek, 32);
    check(rc == ARGON2_OK && eq_hex(dek, 32,
        "b07db674a8488191cff55d3886d354036650494a00e224162c94d3d843f839fe"),
        "Argon2id(t=3,m=65536,p=1) matches pinned vector");
}

static void test_signed_message(void)
{
    printf("[signed-message]\n");
    /* Mirrors main.c signed_message(): SHA256("pq-sign/v1" || SHA256(file)).
     * Pins the domain-separation construction for file content "hello\n". */
    uint8_t fdigest[32];
    sha256((const uint8_t *)"hello\n", 6, fdigest);
    uint8_t buf[10 + 32];
    memcpy(buf, "pq-sign/v1", 10);
    memcpy(buf + 10, fdigest, 32);
    uint8_t msg[32];
    sha256(buf, sizeof buf, msg);
    check(eq_hex(msg, 32,
        "3d916ae99afd41ba3d341cb618280051f76a51374715f7dc01574eb0f1b0c9aa"),
        "domain-separated signed message matches pinned vector");
}

static void test_sigfile(void)
{
    printf("[sigfile]\n");
    uint8_t pub[1952], sg[3309];
    for (size_t i = 0; i < sizeof pub; i++) pub[i] = (uint8_t)(i & 0xff);
    for (size_t i = 0; i < sizeof sg;  i++) sg[i]  = (uint8_t)(i * 5 + 1);

    size_t blen;
    uint8_t *blob = sigfile_build("ML-DSA-65", pub, sizeof pub,
                                  sg, sizeof sg, &blen);

    pqsign_sigfile sf;
    bool ok = sigfile_parse(blob, blen, &sf);
    uint8_t fpr[32];
    sha256(pub, sizeof pub, fpr);
    check(ok && strcmp(sf.alg, "ML-DSA-65") == 0 &&
          sf.sig_len == sizeof sg && memcmp(sf.sig, sg, sizeof sg) == 0 &&
          memcmp(sf.pub_fpr, fpr, 32) == 0,
          "build -> parse round-trips and binds the pubkey fingerprint");

    /* Tamper cases must all be rejected without aborting. */
    pqsign_sigfile junk;
    bool t1 = !sigfile_parse(blob, 4, &junk);              /* truncated   */
    uint8_t *bad = malloc(blen); memcpy(bad, blob, blen);
    bad[0] ^= 0xff;
    bool t2 = !sigfile_parse(bad, blen, &junk);            /* bad magic   */
    memcpy(bad, blob, blen);
    bool t3 = !sigfile_parse(bad, blen - 1, &junk);        /* missing byte*/
    check(t1 && t2 && t3, "truncated / bad-magic / short blobs rejected");

    free(bad);
    free(blob);
}

/* Write a secret key to a temp file, return its path (caller unlinks). */
static char *write_tmp_secret(const char *alg, const uint8_t *sec,
                              size_t sec_len, const uint8_t *pub,
                              size_t pub_len, const char *pass)
{
    static char path[256];
    snprintf(path, sizeof path, "/tmp/pqsign-kat-%d.key", (int)getpid());
    key_write_secret(path, alg, sec, sec_len, pub, pub_len, pass);
    return path;
}

static void test_keyarmor(void)
{
    printf("[key-armor]\n");
    uint8_t sec[4032], pub[1952];
    for (size_t i = 0; i < sizeof sec; i++) sec[i] = (uint8_t)(i * 3 + 9);
    for (size_t i = 0; i < sizeof pub; i++) pub[i] = (uint8_t)(i * 7 + 2);

    /* --- plaintext secret key --- */
    char *p = write_tmp_secret("ML-DSA-65", sec, sizeof sec,
                               pub, sizeof pub, NULL);
    size_t rlen; uint8_t *raw = read_file(p, &rlen);
    pqsign_armor a;
    bool parsed = key_armor_parse(raw, rlen, &a);
    uint8_t *k = NULL; size_t kl = 0;
    bool dec = parsed && key_decrypt(&a, NULL, &k, &kl);
    check(parsed && a.is_secret && !a.encrypted &&
          a.pub_len == sizeof pub && memcmp(a.pub, pub, sizeof pub) == 0 &&
          dec && kl == sizeof sec && memcmp(k, sec, sizeof sec) == 0,
          "plaintext secret key: parse + embedded pub + decrypt");
    secure_free(k, kl);
    armor_free(&a);
    free(raw);
    unlink(p);

    /* --- encrypted secret key --- */
    p = write_tmp_secret("ML-DSA-65", sec, sizeof sec,
                         pub, sizeof pub, "correct horse");
    raw = read_file(p, &rlen);
    parsed = key_armor_parse(raw, rlen, &a);

    uint8_t *k1 = NULL; size_t k1l = 0;
    bool good = parsed && key_decrypt(&a, "correct horse", &k1, &k1l) &&
                k1l == sizeof sec && memcmp(k1, sec, sizeof sec) == 0;
    check(parsed && a.encrypted && a.pub_len == sizeof pub && good,
          "encrypted secret key: parse + decrypt with right passphrase");
    secure_free(k1, k1l);

    uint8_t *k2 = NULL; size_t k2l = 0;
    bool wrong = !key_decrypt(&a, "wrong passphrase", &k2, &k2l);
    bool nopass = !key_decrypt(&a, NULL, &k2, &k2l);
    check(wrong && nopass,
          "encrypted secret key: wrong / missing passphrase rejected");

    /* AEAD binds the public key: flipping it must fail the tag. */
    a.pub[0] ^= 0x01;
    uint8_t *k3 = NULL; size_t k3l = 0;
    bool bound = !key_decrypt(&a, "correct horse", &k3, &k3l);
    check(bound, "tampering the embedded pubkey fails the GCM tag (AAD bind)");

    armor_free(&a);
    free(raw);
    unlink(p);
}

int main(void)
{
    test_sha256();
    test_base64();
    test_argon2id();
    test_signed_message();
    test_sigfile();
    test_keyarmor();

    printf("\nKAT results: %d passed, %d failed\n", checks - failures, failures);
    return failures == 0 ? 0 : 1;
}
