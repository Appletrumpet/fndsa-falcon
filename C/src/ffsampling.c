#include "ffsampling.h"

#include "cplx.h"
#include "fft.h"

/* tmp bietet Platz für 4n Werte. */
static int rec(falcon_cplx *z0, falcon_cplx *z1, const falcon_cplx *t0, const falcon_cplx *t1,
               size_t n, const falcon_tree_node *node, const falcon_params *p,
               const falcon_rng *rng, falcon_cplx *tmp)
{
    if (n == 1) {
        int32_t a, b;
        int rc = falcon_sample_integer_gaussian(&a, t0[0].re, node->sigma, p, rng);
        if (rc != FALCON_OK) {
            return rc;
        }
        rc = falcon_sample_integer_gaussian(&b, t1[0].re, node->sigma, p, rng);
        if (rc != FALCON_OK) {
            return rc;
        }
        z0[0].re = (double)a;
        z0[0].im = 0.0;
        z1[0].re = (double)b;
        z1[0].im = 0.0;
        return FALCON_OK;
    }

    size_t h = n / 2;
    falcon_cplx *first = tmp;       /* n Werte */
    falcon_cplx *second = tmp + n;  /* n Werte */
    falcon_cplx *next = tmp + 2 * n;

    /* Rechter Teilbaum zuerst (Alg. 11). */
    (void)falcon_split_fft(first, first + h, t1, n);
    int rc = rec(second, second + h, first, first + h, h, node->right, p, rng, next);
    if (rc != FALCON_OK) {
        return rc;
    }
    (void)falcon_merge_fft(z1, second, second + h, h);

    /* t0' = t0 + (t1 - z1) * ell */
    for (size_t k = 0; k < n; k++) {
        falcon_cplx diff = falcon_c_sub(t1[k], z1[k]);
        first[k] = falcon_c_add(t0[k], falcon_c_mul(diff, node->ell[k]));
    }

    (void)falcon_split_fft(second, second + h, first, n);
    rc = rec(first, first + h, second, second + h, h, node->left, p, rng, next);
    if (rc != FALCON_OK) {
        return rc;
    }
    (void)falcon_merge_fft(z0, first, first + h, h);
    return FALCON_OK;
}

int falcon_ff_sampling_node(falcon_cplx *z0, falcon_cplx *z1, const falcon_cplx *t0,
                            const falcon_cplx *t1, size_t n, const falcon_tree_node *node,
                            const falcon_params *p, const falcon_rng *rng)
{
    falcon_cplx tmp[4 * FALCON_MAX_N];

    return rec(z0, z1, t0, t1, n, node, p, rng, tmp);
}

int falcon_ff_sampling(falcon_cplx *z0, falcon_cplx *z1, const falcon_cplx *t0, const falcon_cplx *t1,
                       size_t n, const falcon_tree *tree, const falcon_params *p,
                       const falcon_rng *rng)
{
    return falcon_ff_sampling_node(z0, z1, t0, t1, n, &tree->nodes[0], p, rng);
}
