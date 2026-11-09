/* Tests für sampler.c gegen die Python-Vektoren; jede Prüfung auch auf exakten Zufallsverbrauch. */
#include "sampler.h"
#include "vectors.h"

static uint8_t random_bytes[VEC_MAX_BYTES];

static falcon_rng rng_from_case(const vec_file *v, fixed_rng_state *st)
{
    size_t len = vec_bytes(v, "random", random_bytes, sizeof random_bytes);
    return fixed_rng(st, random_bytes, len);
}

int main(void)
{
    vec_file v;
    fixed_rng_state st;

    vec_open(&v, "sampler.uniform_bits");
    while (vec_next(&v)) {
        falcon_rng rng = rng_from_case(&v, &st);
        falcon_u72 u = {0, 0};
        int rc = falcon_uniform_bits(&u, (int)vec_int(&v, "k"), &rng);
        if (vec_status(&v) == VEC_STATUS_OK) {
            unsigned __int128 value = ((unsigned __int128)u.high << 8) | u.low;
            CHECK(rc == FALCON_OK && value == vec_u128(&v, "out"), "uniform_bits Fall %zu", v.index);
            CHECK(st.pos == st.len, "uniform_bits Fall %zu: Verbrauch", v.index);
        } else {
            CHECK(rc == FALCON_ERR_VALUE, "uniform_bits Fall %zu", v.index);
        }
    }
    vec_close(&v);

    vec_open(&v, "sampler.base_sampler");
    while (vec_next(&v)) {
        falcon_rng rng = rng_from_case(&v, &st);
        int z0 = falcon_base_sampler(&rng);
        CHECK(z0 == vec_int(&v, "out"), "base_sampler Fall %zu: %d", v.index, z0);
        CHECK(st.pos == st.len, "base_sampler Fall %zu: Verbrauch", v.index);
    }
    vec_close(&v);

    vec_open(&v, "sampler.approx_exp");
    while (vec_next(&v)) {
        uint64_t y = falcon_approx_exp(vec_double(&v, "x"), vec_double(&v, "ccs"));
        CHECK(y == vec_u128(&v, "out"), "approx_exp Fall %zu", v.index);
    }
    vec_close(&v);

    vec_open(&v, "sampler.ber_exp");
    while (vec_next(&v)) {
        falcon_rng rng = rng_from_case(&v, &st);
        int r = falcon_ber_exp(vec_double(&v, "x"), vec_double(&v, "ccs"), &rng);
        CHECK(r == vec_int(&v, "out"), "ber_exp Fall %zu", v.index);
        CHECK(st.pos == st.len, "ber_exp Fall %zu: Verbrauch", v.index);
    }
    vec_close(&v);

    vec_open(&v, "sampler.sample_integer_gaussian");
    while (vec_next(&v)) {
        falcon_rng rng = rng_from_case(&v, &st);
        falcon_params p = vec_params(&v);
        int32_t z = 0;
        int rc = falcon_sample_integer_gaussian(&z, vec_double(&v, "mu"), vec_double(&v, "sigma"), &p, &rng);
        if (vec_status(&v) == VEC_STATUS_OK) {
            CHECK(rc == FALCON_OK && z == vec_int(&v, "out"), "SamplerZ Fall %zu", v.index);
            CHECK(st.pos == st.len, "SamplerZ Fall %zu: Verbrauch", v.index);
        } else {
            CHECK(rc == FALCON_ERR_VALUE, "SamplerZ Fall %zu: rc = %d", v.index, rc);
        }
    }
    vec_close(&v);

    /* Zwischenwerte: In der Ausgabe des Samplers wären Rundungsfehler kaum sichtbar. */
    vec_open(&v, "sampler.ber_exp_z");
    while (vec_next(&v)) {
        uint64_t z = falcon_ber_exp_z(vec_double(&v, "x"), vec_double(&v, "ccs"));
        CHECK(z == vec_u128(&v, "out"), "ber_exp_z Fall %zu", v.index);
    }
    vec_close(&v);

    vec_open(&v, "sampler.samplerz_x");
    while (vec_next(&v)) {
        falcon_params p = vec_params(&v);
        double x = falcon_samplerz_x((int)vec_int(&v, "z"), (int)vec_int(&v, "z0"), vec_double(&v, "r"),
                                     vec_double(&v, "sigma"), &p);
        double want = vec_double(&v, "out");
        CHECK(memcmp(&x, &want, sizeof x) == 0, "samplerz_x Fall %zu", v.index);
    }
    vec_close(&v);

    return test_summary("sampler");
}
