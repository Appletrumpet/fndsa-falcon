/* Tests für shake256.c gegen hashlib, Längen rund um die Blockgrösse. */
#include <string.h>

#include "shake256.h"
#include "vectors.h"

int main(void)
{
    static uint8_t data[VEC_MAX_BYTES], expected[VEC_MAX_BYTES], out[VEC_MAX_BYTES];
    vec_file v;

    vec_open(&v, "shake256");
    while (vec_next(&v)) {
        size_t dlen = vec_bytes(&v, "data", data, sizeof data);
        size_t olen = vec_bytes(&v, "out", expected, sizeof expected);
        falcon_shake256_ctx ctx;

        /* Alles auf einmal */
        falcon_shake256_init(&ctx);
        falcon_shake256_inject(&ctx, data, dlen);
        falcon_shake256_flip(&ctx);
        falcon_shake256_extract(&ctx, out, olen);
        CHECK(memcmp(out, expected, olen) == 0, "Fall %zu, am Stück", v.index);

        /* Stückweise: Das Ergebnis darf nicht von der Aufteilung abhängen. */
        falcon_shake256_init(&ctx);
        for (size_t i = 0, step = 1; i < dlen; i += step, step = step % 17 + 1) {
            size_t m = (dlen - i < step) ? dlen - i : step;
            falcon_shake256_inject(&ctx, data + i, m);
            if (m < step) {
                break;
            }
        }
        falcon_shake256_flip(&ctx);
        for (size_t i = 0, step = 1; i < olen; i += step, step = step % 151 + 1) {
            size_t m = (olen - i < step) ? olen - i : step;
            falcon_shake256_extract(&ctx, out + i, m);
            if (m < step) {
                break;
            }
        }
        CHECK(memcmp(out, expected, olen) == 0, "Fall %zu, stückweise", v.index);
    }
    vec_close(&v);
    return test_summary("shake256");
}
