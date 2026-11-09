#include "ntrugen.h"

#include "modq.h"

int falcon_recompute_G(int32_t *G, const int32_t *f, const int32_t *g, const int32_t *F, size_t n)
{
    int32_t gF[FALCON_MAX_N];
    int32_t G_mod[FALCON_MAX_N];

    if (falcon_mul_mod_q(gF, g, F, n) != FALCON_OK
        || falcon_div_mod_q(G_mod, gF, f, n) != FALCON_OK) {
        return FALCON_ERR_VALUE;
    }
    falcon_center_mod_q(G, G_mod, n);
    return FALCON_OK;
}
