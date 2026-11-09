/* Tests für ntrugen.c, im Schnitt Sign nur recompute_G. */
#include "ntrugen.h"
#include "vectors.h"

int main(void)
{
    static int32_t f[VEC_MAX_LIST], g[VEC_MAX_LIST], F[VEC_MAX_LIST], G[VEC_MAX_LIST], expected[VEC_MAX_LIST];
    vec_file v;

    vec_open(&v, "ntrugen.recompute_G");
    while (vec_next(&v)) {
        size_t n = vec_ints(&v, "f", f, VEC_MAX_LIST);
        vec_ints(&v, "g", g, VEC_MAX_LIST);
        vec_ints(&v, "F", F, VEC_MAX_LIST);
        vec_ints(&v, "out", expected, VEC_MAX_LIST);
        CHECK(falcon_recompute_G(G, f, g, F, n) == FALCON_OK, "Fall %zu", v.index);
        CHECK(SAME_BITS(G, expected, n), "Fall %zu", v.index);
    }
    vec_close(&v);
    return test_summary("ntrugen");
}
