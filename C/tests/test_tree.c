/* Tests für tree.c gegen die Python-Vektoren, bitgenau. */
#include "tree.h"
#include "vectors.h"

static falcon_cplx m[8][FALCON_MAX_N], e[8][FALCON_MAX_N];
static int32_t f[VEC_MAX_LIST], g[VEC_MAX_LIST], F[VEC_MAX_LIST], G_[VEC_MAX_LIST];
static falcon_tree tree;
static double tokens[VEC_MAX_TREE_TOKENS], expected_tokens[VEC_MAX_TREE_TOKENS];

static size_t read_matrix(const vec_file *v, const char *name, falcon_cplx (*dst)[FALCON_MAX_N])
{
    char field[32];
    size_t n = 0;
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            snprintf(field, sizeof field, "%s%d%d", name, i, j);
            n = vec_cplx(v, field, dst[2 * i + j], FALCON_MAX_N);
        }
    }
    return n;
}

static int same_matrix(falcon_cplx (*a)[FALCON_MAX_N], falcon_cplx (*b)[FALCON_MAX_N], size_t n)
{
    return SAME_BITS(a[0], b[0], n) && SAME_BITS(a[1], b[1], n) && SAME_BITS(a[2], b[2], n)
           && SAME_BITS(a[3], b[3], n);
}

static falcon_mat22 as_mat22(falcon_cplx (*a)[FALCON_MAX_N])
{
    falcon_mat22 mat = {a[0], a[1], a[2], a[3]};
    return mat;
}

static void check_tree(const vec_file *v, const char *what, size_t n)
{
    size_t count = tree_tokens(tokens, &tree.nodes[0], n);
    size_t want = vec_doubles(v, "out", expected_tokens, VEC_MAX_TREE_TOKENS);
    CHECK(count == want && SAME_BITS(tokens, expected_tokens, count), "%s Fall %zu (n = %zu)", what, v->index, n);
}

int main(void)
{
    vec_file v;

    vec_open(&v, "tree.build_basis_fft");
    while (vec_next(&v)) {
        size_t n = vec_ints(&v, "f", f, VEC_MAX_LIST);
        vec_ints(&v, "g", g, VEC_MAX_LIST);
        vec_ints(&v, "F", F, VEC_MAX_LIST);
        vec_ints(&v, "G", G_, VEC_MAX_LIST);
        read_matrix(&v, "out", e);
        falcon_build_basis_fft(m[0], m[1], m[2], m[3], f, g, F, G_, n);
        CHECK(same_matrix(m, e, n), "build_basis_fft Fall %zu", v.index);
    }
    vec_close(&v);

    vec_open(&v, "tree.gram_matrix");
    while (vec_next(&v)) {
        size_t n = read_matrix(&v, "B", m);
        read_matrix(&v, "out", e);
        falcon_mat22 basis = as_mat22(m), out = as_mat22(m + 4);
        falcon_gram_matrix(&out, &basis, n);
        CHECK(same_matrix(m + 4, e, n), "gram_matrix Fall %zu", v.index);
    }
    vec_close(&v);

    vec_open(&v, "tree.ldl");
    while (vec_next(&v)) {
        size_t n = read_matrix(&v, "G", m);
        vec_cplx(&v, "L10", e[0], FALCON_MAX_N);
        vec_cplx(&v, "D00", e[1], FALCON_MAX_N);
        vec_cplx(&v, "D11", e[2], FALCON_MAX_N);
        falcon_mat22 gram = as_mat22(m);
        CHECK(falcon_ldl(m[4], m[5], m[6], &gram, n) == FALCON_OK, "ldl Fall %zu", v.index);
        CHECK(SAME_BITS(m[4], e[0], n) && SAME_BITS(m[5], e[1], n) && SAME_BITS(m[6], e[2], n), "ldl Fall %zu", v.index);
    }
    vec_close(&v);

    vec_open(&v, "tree.ff_ldl");
    while (vec_next(&v)) {
        size_t n = read_matrix(&v, "G", m);
        falcon_mat22 gram = as_mat22(m);
        CHECK(falcon_ff_ldl(&tree, &gram, n) == FALCON_OK, "ff_ldl Fall %zu", v.index);
        check_tree(&v, "ff_ldl", n);
    }
    vec_close(&v);

    vec_open(&v, "tree.normalize_leaves");
    while (vec_next(&v)) {
        size_t n = vec_tree(&v, "t", &tree);
        falcon_normalize_leaves(&tree.nodes[0], n, vec_double(&v, "sigma"));
        check_tree(&v, "normalize_leaves", n);
    }
    vec_close(&v);

    vec_open(&v, "tree.build_falcon_tree");
    while (vec_next(&v)) {
        size_t n = read_matrix(&v, "B", m);
        falcon_params p = vec_params(&v);
        falcon_mat22 basis = as_mat22(m);
        CHECK(falcon_build_falcon_tree(&tree, &basis, n, &p) == FALCON_OK, "build_falcon_tree Fall %zu", v.index);
        check_tree(&v, "build_falcon_tree", n);
    }
    vec_close(&v);

    return test_summary("tree");
}
