/* keyfile.c — armored (PEM-like) key containers.
 *
 * Public keys are stored as plain armored base64. Secret keys may be
 * encrypted at rest with Argon2id (key derivation) + AES-256-GCM (AEAD),
 * mirroring the symmetric stack used across the wider toolset.
 *
 * Armor layout:
 *   -----BEGIN PQSIGN <PUBLIC|SECRET> KEY-----
 *   Alg: ML-DSA-65
 *   Cipher: AES-256-GCM          (secret + encrypted only)
 *   KDF: Argon2id t=3 m=65536 p=1 (secret + encrypted only)
 *   Salt: <base64>               (secret + encrypted only)
 *   Nonce: <base64>              (secret + encrypted only)
 *   Tag: <base64>                (secret + encrypted only)
 *   <blank line>
 *   <base64 body>
 *   -----END PQSIGN <PUBLIC|SECRET> KEY-----
 */
#define _GNU_SOURCE
#include "pqsign.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <argon2.h>

/* Argon2id parameters — interactive but firm. */
#define ARGON2_T   3u            /* iterations          */
#define ARGON2_M   65536u        /* memory in KiB (64MiB)*/
#define ARGON2_P   1u            /* lanes/threads       */
#define SALT_LEN   16
#define NONCE_LEN  12
#define TAG_LEN    16
#define DEK_LEN    32            /* AES-256             */

static const char PUB_BEGIN[] = "-----BEGIN PQSIGN PUBLIC KEY-----";
static const char PUB_END[]   = "-----END PQSIGN PUBLIC KEY-----";
static const char SEC_BEGIN[] = "-----BEGIN PQSIGN SECRET KEY-----";
static const char SEC_END[]   = "-----END PQSIGN SECRET KEY-----";

/* Derive a 32-byte DEK from passphrase + salt via the reference Argon2id. */
static void derive_key(const char *pass, const uint8_t salt[SALT_LEN],
                       uint8_t dek[DEK_LEN])
{
    int rc = argon2id_hash_raw(ARGON2_T, ARGON2_M, ARGON2_P,
                               pass, strlen(pass),
                               salt, SALT_LEN,
                               dek, DEK_LEN);
    if (rc != ARGON2_OK)
        die("Argon2id derivation failed: %s", argon2_error_message(rc));
}

/* AES-256-GCM encrypt. AAD binds the algorithm string to the ciphertext. */
static uint8_t *gcm_encrypt(const uint8_t dek[DEK_LEN],
                            const uint8_t nonce[NONCE_LEN],
                            const char *aad,
                            const uint8_t *pt, size_t pt_len,
                            uint8_t tag[TAG_LEN])
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c)
        die("cipher context allocation failed");
    uint8_t *ct = xmalloc(pt_len);
    int len = 0;

    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(c, NULL, NULL, dek, nonce) != 1)
        die("AES-GCM init failed");

    int tmp = 0;
    if (EVP_EncryptUpdate(c, NULL, &tmp, (const uint8_t *)aad,
                          (int)strlen(aad)) != 1)
        die("AES-GCM AAD failed");
    if (EVP_EncryptUpdate(c, ct, &len, pt, (int)pt_len) != 1)
        die("AES-GCM encrypt failed");
    int final = 0;
    if (EVP_EncryptFinal_ex(c, ct + len, &final) != 1)
        die("AES-GCM finalize failed");
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1)
        die("AES-GCM tag failed");

    EVP_CIPHER_CTX_free(c);
    return ct;
}

/* AES-256-GCM decrypt + verify. Returns NULL on auth failure. */
static uint8_t *gcm_decrypt(const uint8_t dek[DEK_LEN],
                            const uint8_t nonce[NONCE_LEN],
                            const char *aad,
                            const uint8_t *ct, size_t ct_len,
                            const uint8_t tag[TAG_LEN])
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c)
        die("cipher context allocation failed");
    uint8_t *pt = xmalloc(ct_len);
    int len = 0;

    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(c, NULL, NULL, dek, nonce) != 1)
        die("AES-GCM init failed");

    int tmp = 0;
    if (EVP_DecryptUpdate(c, NULL, &tmp, (const uint8_t *)aad,
                          (int)strlen(aad)) != 1)
        die("AES-GCM AAD failed");
    if (EVP_DecryptUpdate(c, pt, &len, ct, (int)ct_len) != 1)
        die("AES-GCM decrypt failed");
    uint8_t tagcopy[TAG_LEN];   /* EVP_CTRL takes a non-const pointer */
    memcpy(tagcopy, tag, TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tagcopy) != 1)
        die("AES-GCM set tag failed");

    int final = 0;
    int ok = EVP_DecryptFinal_ex(c, pt + len, &final);
    EVP_CIPHER_CTX_free(c);
    if (ok != 1) {
        secure_wipe(pt, ct_len);
        free(pt);
        return NULL;   /* wrong passphrase or tampered key */
    }
    return pt;
}

/* --- armor writers --------------------------------------------------- */

static void write_armored(const char *path, const char *begin,
                          const char *end, char *headers,
                          const uint8_t *body, size_t body_len, int mode)
{
    char *b64 = b64_encode(body, body_len);

    /* Assemble the full text. */
    size_t cap = strlen(begin) + strlen(end) + strlen(headers) +
                 strlen(b64) + 64;
    char *out = xmalloc(cap);
    int n = snprintf(out, cap, "%s\n%s\n%s\n%s\n", begin, headers, b64, end);
    if (n < 0 || (size_t)n >= cap)
        die("armor formatting overflow");

    write_file(path, (const uint8_t *)out, (size_t)n, mode);
    free(b64);
    free(out);
}

void key_write_public(const char *path, const char *alg,
                      const uint8_t *pub, size_t pub_len)
{
    char headers[128];
    snprintf(headers, sizeof headers, "Alg: %s\n", alg);
    write_armored(path, PUB_BEGIN, PUB_END, headers, pub, pub_len, 0644);
}

void key_write_secret(const char *path, const char *alg,
                      const uint8_t *sec, size_t sec_len,
                      const char *passphrase)
{
    if (!passphrase) {
        char headers[128];
        snprintf(headers, sizeof headers, "Alg: %s\n", alg);
        write_armored(path, SEC_BEGIN, SEC_END, headers, sec, sec_len, 0600);
        return;
    }

    uint8_t salt[SALT_LEN], nonce[NONCE_LEN], tag[TAG_LEN], dek[DEK_LEN];
    random_bytes(salt, SALT_LEN);
    random_bytes(nonce, NONCE_LEN);
    derive_key(passphrase, salt, dek);

    uint8_t *ct = gcm_encrypt(dek, nonce, alg, sec, sec_len, tag);
    secure_wipe(dek, sizeof dek);

    char *b_salt  = b64_encode(salt, SALT_LEN);
    char *b_nonce = b64_encode(nonce, NONCE_LEN);
    char *b_tag   = b64_encode(tag, TAG_LEN);

    char headers[512];
    snprintf(headers, sizeof headers,
             "Alg: %s\n"
             "Cipher: AES-256-GCM\n"
             "KDF: Argon2id t=%u m=%u p=%u\n"
             "Salt: %s\n"
             "Nonce: %s\n"
             "Tag: %s\n",
             alg, ARGON2_T, ARGON2_M, ARGON2_P, b_salt, b_nonce, b_tag);

    write_armored(path, SEC_BEGIN, SEC_END, headers, ct, sec_len, 0600);

    free(b_salt); free(b_nonce); free(b_tag);
    secure_wipe(ct, sec_len);
    free(ct);
}

/* --- armor parsing --------------------------------------------------- */

/* Find a "Key: value" header line in the text region [text, end).
 * Returns a malloc'd copy of the trimmed value, or NULL if absent. */
static char *find_header(const char *text, const char *end, const char *key)
{
    size_t klen = strlen(key);
    const char *p = text;
    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t)(end - p));
        size_t linelen = eol ? (size_t)(eol - p) : (size_t)(end - p);
        if (linelen > klen + 1 &&
            strncmp(p, key, klen) == 0 && p[klen] == ':') {
            const char *v = p + klen + 1;
            while (v < p + linelen && (*v == ' ' || *v == '\t'))
                v++;
            size_t vlen = (size_t)(p + linelen - v);
            char *out = xmalloc(vlen + 1);
            memcpy(out, v, vlen);
            out[vlen] = '\0';
            return out;
        }
        if (!eol)
            break;
        p = eol + 1;
    }
    return NULL;
}

void key_load(const char *path, pqsign_key *out)
{
    size_t len;
    uint8_t *raw = read_file(path, &len);
    char *text = (char *)raw;

    bool secret = strstr(text, SEC_BEGIN) != NULL;
    bool public = strstr(text, PUB_BEGIN) != NULL;
    if (!secret && !public)
        die("'%s' is not a PQSIGN key file", path);

    const char *begin = secret ? SEC_BEGIN : PUB_BEGIN;
    const char *endm  = secret ? SEC_END : PUB_END;
    char *bp = strstr(text, begin);
    char *ep = strstr(text, endm);
    if (!bp || !ep || ep < bp)
        die("malformed armor in '%s'", path);

    /* Algorithm. */
    char *alg = find_header(bp, ep, "Alg");
    if (!alg)
        die("missing Alg header in '%s'", path);
    snprintf(out->alg, sizeof out->alg, "%s", alg);
    out->is_secret = secret;

    bool encrypted = secret && (find_header(bp, ep, "Cipher") != NULL);

    /* The body is everything after the first blank line up to the END line. */
    char *body = strstr(bp, "\n\n");
    if (!body || body > ep)
        die("malformed armor body in '%s'", path);
    body += 2;
    size_t body_str_len = (size_t)(ep - body);

    size_t blob_len = 0;
    uint8_t *blob = b64_decode(body, body_str_len, &blob_len);
    if (!blob)
        die("invalid base64 body in '%s'", path);

    if (!encrypted) {
        out->key = blob;
        out->key_len = blob_len;
    } else {
        char *b_salt  = find_header(bp, ep, "Salt");
        char *b_nonce = find_header(bp, ep, "Nonce");
        char *b_tag   = find_header(bp, ep, "Tag");
        if (!b_salt || !b_nonce || !b_tag)
            die("encrypted key '%s' missing Salt/Nonce/Tag", path);

        size_t sl, nl, tl;
        uint8_t *salt  = b64_decode(b_salt,  strlen(b_salt),  &sl);
        uint8_t *nonce = b64_decode(b_nonce, strlen(b_nonce), &nl);
        uint8_t *tag   = b64_decode(b_tag,   strlen(b_tag),   &tl);
        if (!salt || !nonce || !tag || sl != SALT_LEN ||
            nl != NONCE_LEN || tl != TAG_LEN)
            die("corrupt key parameters in '%s'", path);

        char *pass = prompt_passphrase("Passphrase: ", false);
        uint8_t dek[DEK_LEN];
        derive_key(pass, salt, dek);
        secure_wipe(pass, strlen(pass));
        free(pass);

        uint8_t *pt = gcm_decrypt(dek, nonce, out->alg, blob, blob_len, tag);
        secure_wipe(dek, sizeof dek);
        if (!pt)
            die("wrong passphrase or corrupted secret key");

        out->key = pt;
        out->key_len = blob_len;

        secure_wipe(blob, blob_len);
        free(blob);
        free(salt); free(nonce); free(tag);
        free(b_salt); free(b_nonce); free(b_tag);
    }

    free(alg);
    secure_wipe(raw, len);
    free(raw);
}

void key_free(pqsign_key *k)
{
    if (!k || !k->key)
        return;
    if (k->is_secret)
        secure_wipe(k->key, k->key_len);
    free(k->key);
    k->key = NULL;
    k->key_len = 0;
}
