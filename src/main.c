/* main.c — pq-sign command-line interface.
 *
 *   pq-sign keygen  --alg ML-DSA-65 --out alice [--encrypt]
 *   pq-sign sign    --key alice.key file [--out file.sig]
 *   pq-sign verify  --pub alice.pub file [--sig file.sig]
 *   pq-sign list
 *
 * Files are signed over their SHA-256 digest (domain-separated), so the
 * whole file never has to be resident in memory.
 */
#define _GNU_SOURCE
#include "pqsign.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

/* Domain-separation prefix mixed into every signed message. Bumping this
 * invalidates old signatures by construction. */
static const char DS_CONTEXT[] = "pq-sign/v1";

/* User-facing alias -> canonical liboqs identifier. */
struct alg_alias { const char *alias; const char *canonical; };
static const struct alg_alias ALIASES[] = {
    { "ml-dsa-44",   "ML-DSA-44" },
    { "ml-dsa-65",   "ML-DSA-65" },
    { "ml-dsa-87",   "ML-DSA-87" },
    { "slh-dsa-128f", "SPHINCS+-SHA2-128f-simple" },
    { "slh-dsa-192f", "SPHINCS+-SHA2-192f-simple" },
    { "slh-dsa-256f", "SPHINCS+-SHA2-256f-simple" },
    { NULL, NULL }
};

static const char *canonical_alg(const char *name)
{
    for (const struct alg_alias *a = ALIASES; a->alias; a++) {
        if (strcasecmp(name, a->alias) == 0)
            return a->canonical;
    }
    /* Accept a canonical liboqs name verbatim if it is enabled. */
    if (OQS_SIG_alg_is_enabled(name))
        return name;
    return NULL;
}

/* Build the message that is actually signed: SHA256( ctx || file_digest ). */
static void signed_message(const char *path, uint8_t out[32])
{
    uint8_t fdigest[32];
    sha256_file(path, fdigest);

    uint8_t buf[sizeof(DS_CONTEXT) - 1 + 32];
    memcpy(buf, DS_CONTEXT, sizeof(DS_CONTEXT) - 1);
    memcpy(buf + sizeof(DS_CONTEXT) - 1, fdigest, 32);
    sha256(buf, sizeof buf, out);
}

/* ----------------------------- commands ----------------------------- */

static int cmd_list(void)
{
    printf("Available signature algorithms:\n\n");
    printf("  %-14s %-28s %s\n", "alias", "canonical", "status");
    printf("  %-14s %-28s %s\n", "-----", "---------", "------");
    for (const struct alg_alias *a = ALIASES; a->alias; a++) {
        bool on = OQS_SIG_alg_is_enabled(a->canonical);
        printf("  %-14s %-28s %s\n", a->alias, a->canonical,
               on ? "enabled" : "DISABLED");
    }
    printf("\nDefault: %s\n", PQSIGN_DEFAULT_ALG);
    return 0;
}

static int cmd_keygen(int argc, char **argv)
{
    const char *alg = PQSIGN_DEFAULT_ALG;
    const char *out = NULL;
    bool encrypt = false;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--alg") == 0 && i + 1 < argc)
            alg = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
            out = argv[++i];
        else if (strcmp(argv[i], "--encrypt") == 0)
            encrypt = true;
        else
            die("keygen: unexpected argument '%s'", argv[i]);
    }
    if (!out)
        die("keygen: --out <basename> is required");

    const char *canon = canonical_alg(alg);
    if (!canon)
        die("keygen: unknown or disabled algorithm '%s' (try 'pq-sign list')",
            alg);

    OQS_SIG *sig = OQS_SIG_new(canon);
    if (!sig)
        die("keygen: failed to initialise %s", canon);

    uint8_t *pub = xmalloc(sig->length_public_key);
    uint8_t *sec = secure_alloc(sig->length_secret_key);
    if (OQS_SIG_keypair(sig, pub, sec) != OQS_SUCCESS)
        die("keygen: key generation failed");

    char *pass = NULL;
    if (encrypt)
        pass = prompt_passphrase("Passphrase for secret key: ", true);

    char pubpath[4096], secpath[4096];
    snprintf(pubpath, sizeof pubpath, "%s.pub", out);
    snprintf(secpath, sizeof secpath, "%s.key", out);

    key_write_public(pubpath, canon, pub, sig->length_public_key);
    key_write_secret(secpath, canon, sec, sig->length_secret_key,
                     pub, sig->length_public_key, pass);

    uint8_t fpr[32];
    char fprhex[65];
    sha256(pub, sig->length_public_key, fpr);
    to_hex(fpr, 32, fprhex);

    printf("Generated %s keypair\n", canon);
    printf("  public key:  %s\n", pubpath);
    printf("  secret key:  %s%s\n", secpath,
           encrypt ? "  (encrypted)" : "");
    printf("  fingerprint: %.16s\n", fprhex);

    if (pass) {
        secure_wipe(pass, strlen(pass));
        free(pass);
    }
    secure_free(sec, sig->length_secret_key);
    free(pub);
    OQS_SIG_free(sig);
    return 0;
}

static int cmd_sign(int argc, char **argv)
{
    const char *keypath = NULL, *out = NULL, *file = NULL;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
            keypath = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
            out = argv[++i];
        else if (argv[i][0] == '-')
            die("sign: unexpected option '%s'", argv[i]);
        else if (!file)
            file = argv[i];
        else
            die("sign: only one input file is supported");
    }
    if (!keypath)
        die("sign: --key <secret.key> is required");
    if (!file)
        die("sign: input file is required");

    pqsign_key sk = {0};
    key_load(keypath, &sk);
    if (!sk.is_secret)
        die("sign: '%s' is a public key, not a secret key", keypath);

    OQS_SIG *sig = OQS_SIG_new(sk.alg);
    if (!sig)
        die("sign: algorithm '%s' from key is unavailable", sk.alg);
    if (sk.key_len != sig->length_secret_key)
        die("sign: secret key size mismatch for %s", sk.alg);

    /* The signer's public key is embedded in the secret-key file, so the
     * signature can always carry the signer fingerprint — no companion
     * file lookup, no empty-fingerprint fallback. */
    if (!sk.pub || sk.pub_len != sig->length_public_key)
        die("sign: '%s' has no valid embedded public key; "
            "regenerate it with pq-sign %s", keypath, PQSIGN_VERSION);

    uint8_t msg[32];
    signed_message(file, msg);

    uint8_t *signature = xmalloc(sig->length_signature);
    size_t siglen = 0;
    if (OQS_SIG_sign(sig, signature, &siglen, msg, sizeof msg, sk.key)
        != OQS_SUCCESS)
        die("sign: signing failed");

    size_t blob_len = 0;
    uint8_t *blob = sigfile_build(sk.alg, sk.pub, sk.pub_len, signature, siglen,
                                  &blob_len);

    char outpath[4096];
    if (out)
        snprintf(outpath, sizeof outpath, "%s", out);
    else
        snprintf(outpath, sizeof outpath, "%s.sig", file);
    write_file(outpath, blob, blob_len, 0644);

    printf("Signed '%s' with %s\n", file, sk.alg);
    printf("  signature: %s (%zu bytes)\n", outpath, siglen);

    free(blob);
    secure_wipe(signature, sig->length_signature);
    free(signature);
    OQS_SIG_free(sig);
    key_free(&sk);
    return 0;
}

static int cmd_verify(int argc, char **argv)
{
    const char *pubpath = NULL, *sigpath = NULL, *file = NULL;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pub") == 0 && i + 1 < argc)
            pubpath = argv[++i];
        else if (strcmp(argv[i], "--sig") == 0 && i + 1 < argc)
            sigpath = argv[++i];
        else if (argv[i][0] == '-')
            die("verify: unexpected option '%s'", argv[i]);
        else if (!file)
            file = argv[i];
        else
            die("verify: only one input file is supported");
    }
    if (!pubpath)
        die("verify: --pub <public.pub> is required");
    if (!file)
        die("verify: input file is required");

    char sigguess[4096];
    if (!sigpath) {
        snprintf(sigguess, sizeof sigguess, "%s.sig", file);
        sigpath = sigguess;
    }

    pqsign_key pk = {0};
    key_load(pubpath, &pk);
    if (pk.is_secret)
        die("verify: '%s' is a secret key; pass the .pub", pubpath);

    size_t blob_len;
    uint8_t *blob = read_file(sigpath, &blob_len);
    pqsign_sigfile sf;
    if (!sigfile_parse(blob, blob_len, &sf)) {
        free(blob);
        die("verify: '%s' is not a valid pq-sign signature", sigpath);
    }
    sf.raw = blob;

    if (strcmp(sf.alg, pk.alg) != 0)
        die("verify: signature is %s but key is %s", sf.alg, pk.alg);

    /* Confirm the signature was made for *this* public key. v1.0 signatures
     * always carry a real fingerprint, so this binding is mandatory. */
    uint8_t fpr[32];
    sha256(pk.key, pk.key_len, fpr);
    if (!ct_equal(fpr, sf.pub_fpr, 32)) {
        printf("VERIFY FAILED: signature was made for a different key\n");
        sigfile_free(&sf);
        key_free(&pk);
        return 2;
    }

    OQS_SIG *sig = OQS_SIG_new(pk.alg);
    if (!sig)
        die("verify: algorithm '%s' is unavailable", pk.alg);
    if (pk.key_len != sig->length_public_key)
        die("verify: public key size mismatch for %s", pk.alg);

    uint8_t msg[32];
    signed_message(file, msg);

    OQS_STATUS rc = OQS_SIG_verify(sig, msg, sizeof msg,
                                   sf.sig, sf.sig_len, pk.key);

    int ret;
    if (rc == OQS_SUCCESS) {
        char fprhex[65];
        to_hex(fpr, 32, fprhex);
        printf("VERIFY OK: '%s'\n", file);
        printf("  algorithm:   %s\n", pk.alg);
        printf("  signer:      %.16s\n", fprhex);
        ret = 0;
    } else {
        printf("VERIFY FAILED: '%s' — signature is invalid\n", file);
        ret = 2;
    }

    OQS_SIG_free(sig);
    sigfile_free(&sf);
    key_free(&pk);
    return ret;
}

static void usage(FILE *f)
{
    fprintf(f,
"pq-sign %s — post-quantum detached file signing (ML-DSA / SLH-DSA)\n"
"\n"
"USAGE:\n"
"  pq-sign keygen --out <name> [--alg <alg>] [--encrypt]\n"
"  pq-sign sign   --key <name.key> <file> [--out <file.sig>]\n"
"  pq-sign verify --pub <name.pub> <file> [--sig <file.sig>]\n"
"  pq-sign list\n"
"\n"
"EXAMPLES:\n"
"  pq-sign keygen --out alice --alg ml-dsa-65 --encrypt\n"
"  pq-sign sign   --key alice.key report.pdf\n"
"  pq-sign verify --pub alice.pub report.pdf\n"
"\n"
"Run 'pq-sign list' to see available algorithms.\n",
            PQSIGN_VERSION);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(stderr);
        return 1;
    }
    const char *cmd = argv[1];
    int rest_argc = argc - 2;
    char **rest = argv + 2;

    if (strcmp(cmd, "keygen") == 0)
        return cmd_keygen(rest_argc, rest);
    if (strcmp(cmd, "sign") == 0)
        return cmd_sign(rest_argc, rest);
    if (strcmp(cmd, "verify") == 0)
        return cmd_verify(rest_argc, rest);
    if (strcmp(cmd, "list") == 0)
        return cmd_list();
    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0 ||
        strcmp(cmd, "help") == 0) {
        usage(stdout);
        return 0;
    }
    if (strcmp(cmd, "-v") == 0 || strcmp(cmd, "--version") == 0 ||
        strcmp(cmd, "version") == 0) {
        printf("pq-sign %s\n", PQSIGN_VERSION);
        return 0;
    }

    fprintf(stderr, "pq-sign: unknown command '%s'\n\n", cmd);
    usage(stderr);
    return 1;
}
