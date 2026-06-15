/* fuzz_sigfile.c — libFuzzer target for the detached-signature parser.
 *
 * sigfile_parse() consumes fully attacker-controlled bytes (a .sig handed to
 * `verify`). This driver feeds it arbitrary input under ASan/UBSan; the
 * parser must never read out of bounds or abort — only return false.
 *
 *   make fuzz && ./fuzz_sigfile -max_total_time=60
 */
#include "pqsign.h"

#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    pqsign_sigfile sf;
    if (sigfile_parse(data, size, &sf)) {
        /* On success the parser promises sig points within [data, data+size)
         * and sig_len fits; touch it so a bad bound trips the sanitizer. */
        volatile uint8_t sink = 0;
        for (size_t i = 0; i < sf.sig_len; i++)
            sink ^= sf.sig[i];
        (void)sink;
    }
    return 0;
}
