/* Tests für ffsampling.c gegen die Python-Vektoren, bitgenau und mit exaktem Zufallsverbrauch. */
#include "sampler.h"
#include "vectors.h"

/* ffsampling.c wird hier mit einem protokollierenden SamplerZ übersetzt, um die Zentren mu und
 * Breiten sigma' jedes Aufrufs bitgenau zu sehen. Am Produktcode ändert das nichts. */
static int traced_sampler(int32_t *out, double mu, double sigma_p, const falcon_params *p,
                          const falcon_rng *rng);
#define falcon_sample_integer_gaussian traced_sampler
#define falcon_ff_sampling traced_ff_sampling
#define falcon_ff_sampling_node traced_ff_sampling_node
#include "../src/ffsampling.c"
#undef falcon_sample_integer_gaussian

static double seen_mu[2 * FALCON_MAX_N], seen_sigma[2 * FALCON_MAX_N];
static size_t seen;

static int traced_sampler(int32_t *out, double mu, double sigma_p, const falcon_params *p,
                          const falcon_rng *rng)
{
    seen_mu[seen] = mu;
    seen_sigma[seen] = sigma_p;
    seen++;
    return falcon_sample_integer_gaussian(out, mu, sigma_p, p, rng);
}

static falcon_cplx t0[FALCON_MAX_N], t1[FALCON_MAX_N], z0[FALCON_MAX_N], z1[FALCON_MAX_N];
static falcon_cplx e0[FALCON_MAX_N], e1[FALCON_MAX_N];
static falcon_tree tree;
static uint8_t random_bytes[VEC_MAX_BYTES];

int main(void)
{
    vec_file v;

    vec_open(&v, "ffsampling.ff_sampling");
    while (vec_next(&v)) {
        size_t n = vec_cplx(&v, "t0", t0, FALCON_MAX_N);
        vec_cplx(&v, "t1", t1, FALCON_MAX_N);
        vec_cplx(&v, "out0", e0, FALCON_MAX_N);
        vec_cplx(&v, "out1", e1, FALCON_MAX_N);
        falcon_params p = vec_params(&v);
        size_t tree_n = vec_tree(&v, "tree", &tree);
        seen = 0;
        size_t len = vec_bytes(&v, "random", random_bytes, sizeof random_bytes);
        fixed_rng_state st;
        falcon_rng rng = fixed_rng(&st, random_bytes, len);

        CHECK(tree_n == n, "Fall %zu: Baumgrösse", v.index);
        CHECK(falcon_ff_sampling_node(z0, z1, t0, t1, n, &tree.nodes[0], &p, &rng) == FALCON_OK, "Fall %zu", v.index);
        CHECK(SAME_BITS(z0, e0, n) && SAME_BITS(z1, e1, n), "Fall %zu (n = %zu)", v.index, n);
        CHECK(st.pos == st.len, "Fall %zu: Verbrauch", v.index);

        static double want_mu[2 * FALCON_MAX_N], want_sigma[2 * FALCON_MAX_N];
        size_t calls = vec_doubles(&v, "mus", want_mu, 2 * FALCON_MAX_N);
        vec_doubles(&v, "sigmas", want_sigma, 2 * FALCON_MAX_N);
        CHECK(calls == seen && SAME_BITS(seen_mu, want_mu, calls), "Fall %zu: mu", v.index);
        CHECK(SAME_BITS(seen_sigma, want_sigma, calls), "Fall %zu: sigma", v.index);
    }
    vec_close(&v);
    return test_summary("ffsampling");
}
