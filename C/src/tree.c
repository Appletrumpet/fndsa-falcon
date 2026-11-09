#include "tree.h"

#include <math.h>
#include <string.h>

#include "cplx.h"
#include "fft.h"

void falcon_build_basis_fft(falcon_cplx *b00, falcon_cplx *b01, falcon_cplx *b10, falcon_cplx *b11,
                            const int32_t *f, const int32_t *g, const int32_t *F, const int32_t *G,
                            size_t n)
{
    double values[FALCON_MAX_N];

    falcon_ints_to_doubles(values, g, n);
    (void)falcon_fft(b00, values, n);
    /* Erst ganzzahlig negieren: -0 als ganze Zahl bleibt +0.0. */
    for (size_t i = 0; i < n; i++) {
        values[i] = (double)(-f[i]);
    }
    (void)falcon_fft(b01, values, n);
    falcon_ints_to_doubles(values, G, n);
    (void)falcon_fft(b10, values, n);
    for (size_t i = 0; i < n; i++) {
        values[i] = (double)(-F[i]);
    }
    (void)falcon_fft(b11, values, n);
}

void falcon_gram_matrix(const falcon_mat22 *out, const falcon_mat22 *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        falcon_cplx b00 = b->a00[i], b01 = b->a01[i], b10 = b->a10[i], b11 = b->a11[i];
        out->a00[i] = falcon_c_add(falcon_c_mul(b00, falcon_c_adj(b00)), falcon_c_mul(b01, falcon_c_adj(b01)));
        out->a01[i] = falcon_c_add(falcon_c_mul(b00, falcon_c_adj(b10)), falcon_c_mul(b01, falcon_c_adj(b11)));
        out->a10[i] = falcon_c_add(falcon_c_mul(b10, falcon_c_adj(b00)), falcon_c_mul(b11, falcon_c_adj(b01)));
        out->a11[i] = falcon_c_add(falcon_c_mul(b10, falcon_c_adj(b10)), falcon_c_mul(b11, falcon_c_adj(b11)));
    }
}

int falcon_ldl(falcon_cplx *L10, falcon_cplx *D00, falcon_cplx *D11, const falcon_mat22 *G, size_t n)
{
    if (falcon_fft_div(L10, G->a10, G->a00, n) != FALCON_OK) {
        return FALCON_ERR_VALUE;
    }
    memcpy(D00, G->a00, n * sizeof *D00);
    for (size_t i = 0; i < n; i++) {
        falcon_cplx m = falcon_c_mul(falcon_c_mul(L10[i], falcon_c_adj(L10[i])), G->a00[i]);
        D11[i] = falcon_c_sub(G->a11[i], m);
    }
    return FALCON_OK;
}

static falcon_tree_node *new_node(falcon_tree *t, falcon_cplx *ell)
{
    falcon_tree_node *node = &t->nodes[t->nnodes++];
    node->ell = ell;
    node->left = NULL;
    node->right = NULL;
    node->sigma = 0.0;
    return node;
}

static falcon_tree_node *new_leaf(falcon_tree *t, double value)
{
    falcon_tree_node *node = new_node(t, NULL);
    node->sigma = value;
    return node;
}

/* tmp bietet Platz für 7n Werte. Liefert NULL bei einem Fehler in ldl. */
static falcon_tree_node *ff_ldl_rec(falcon_tree *t, const falcon_mat22 *G, size_t n, falcon_cplx *tmp)
{
    falcon_cplx *L10 = &t->ell[t->nell];
    falcon_cplx *D00 = tmp;
    falcon_cplx *D11 = tmp + n;

    if (n == 1) {
        falcon_cplx single;
        if (falcon_ldl(&single, D00, D11, G, 1) != FALCON_OK) {
            return NULL;
        }
        return new_leaf(t, D00[0].re);
    }

    t->nell += n;
    falcon_tree_node *node = new_node(t, L10);
    if (falcon_ldl(L10, D00, D11, G, n) != FALCON_OK) {
        return NULL;
    }

    if (n == 2) {
        node->left = new_leaf(t, D00[0].re);
        node->right = new_leaf(t, D11[0].re);
        return node;
    }

    size_t h = n / 2;
    falcon_cplx *d0 = tmp + 2 * n;
    falcon_cplx *d1 = d0 + h;
    falcon_cplx *d1_adj = d1 + h;
    falcon_cplx *rest = d1_adj + h;

    (void)falcon_split_fft(d0, d1, D00, n);
    falcon_fft_adj(d1_adj, d1, h);
    falcon_mat22 left = {d0, d1, d1_adj, d0};
    node->left = ff_ldl_rec(t, &left, h, rest);

    (void)falcon_split_fft(d0, d1, D11, n);
    falcon_fft_adj(d1_adj, d1, h);
    falcon_mat22 right = {d0, d1, d1_adj, d0};
    node->right = ff_ldl_rec(t, &right, h, rest);

    return (node->left == NULL || node->right == NULL) ? NULL : node;
}

int falcon_ff_ldl(falcon_tree *t, const falcon_mat22 *G, size_t n)
{
    falcon_cplx tmp[7 * FALCON_MAX_N];

    if (n == 0 || n > FALCON_MAX_N || (n & (n - 1)) != 0) {
        return FALCON_ERR_VALUE;
    }
    t->nnodes = 0;
    t->nell = 0;
    return ff_ldl_rec(t, G, n, tmp) != NULL ? FALCON_OK : FALCON_ERR_VALUE;
}

void falcon_normalize_leaves(falcon_tree_node *node, size_t n, double sigma)
{
    if (n == 1) {
        node->sigma = sigma / sqrt(node->sigma);
        return;
    }
    falcon_normalize_leaves(node->left, n / 2, sigma);
    falcon_normalize_leaves(node->right, n / 2, sigma);
}

int falcon_build_falcon_tree(falcon_tree *t, const falcon_mat22 *basis, size_t n,
                             const falcon_params *p)
{
    falcon_cplx g[4 * FALCON_MAX_N];
    falcon_mat22 G = {g, g + n, g + 2 * n, g + 3 * n};

    falcon_gram_matrix(&G, basis, n);
    if (falcon_ff_ldl(t, &G, n) != FALCON_OK) {
        return FALCON_ERR_VALUE;
    }
    falcon_normalize_leaves(&t->nodes[0], n, p->sigma);
    return FALCON_OK;
}
