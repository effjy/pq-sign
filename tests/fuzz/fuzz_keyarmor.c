/* fuzz_keyarmor.c — libFuzzer target for the armored-key parser.
 *
 * key_armor_parse() is the untrusted-input surface of key loading: it scans
 * raw, not-necessarily-NUL-terminated bytes for armor markers, headers, and
 * base64 bodies. This driver feeds it arbitrary input under ASan/UBSan; it
 * must never read out of bounds, leak, or abort — only return false.
 *
 * On a successful parse we also run key_decrypt() with a fixed passphrase so
 * the (non-secret-dependent) decrypt path is exercised too.
 *
 *   make fuzz && ./fuzz_keyarmor -max_total_time=60
 */
#include "pqsign.h"
#include "keyfile_internal.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    pqsign_armor a;
    if (key_armor_parse(data, size, &a)) {
        uint8_t *key = NULL;
        size_t key_len = 0;
        if (key_decrypt(&a, "fuzz-passphrase", &key, &key_len)) {
            if (a.is_secret)
                secure_free(key, key_len);
            else
                free(key);
        }
        armor_free(&a);
    }
    return 0;
}
