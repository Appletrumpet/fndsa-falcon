/* Tests für poly.c, im Schnitt Verify nur norm_sq. */
#include "poly.h"
#include "vectors.h"

int main(void)
{
    static int32_t a[VEC_MAX_LIST];
    vec_file v;

    vec_open(&v, "poly.norm_sq");
    while (vec_next(&v)) {
        size_t n = vec_ints(&v, "a", a, VEC_MAX_LIST);
        CHECK(falcon_norm_sq(a, n) == (uint64_t)vec_int(&v, "out"), "Fall %zu", v.index);
    }
    vec_close(&v);
    return test_summary("poly");
}
