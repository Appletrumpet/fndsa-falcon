/* Tests für params.c: Tab. 3.3, abgeleitete Grössen, Validierung (wie test_params.py). */
#include "params.h"
#include "vectors.h"

static falcon_params with(falcon_params p, size_t n)
{
    p.n = n;
    return p;
}

int main(void)
{
    CHECK(FALCON_512.n == 512 && FALCON_512.q == 12289 && FALCON_512.sig_bound == 34034726
              && FALCON_512.sig_bytelen == 666, "Tab. 3.3, 512");
    CHECK(FALCON_512.sigma == 165.736617183 && FALCON_512.sigma_min == 1.277833697
              && FALCON_512.sigma_max == 1.8205, "Tab. 3.3, 512, sigma");
    CHECK(FALCON_1024.n == 1024 && FALCON_1024.q == 12289 && FALCON_1024.sig_bound == 70265242
              && FALCON_1024.sig_bytelen == 1280, "Tab. 3.3, 1024");
    CHECK(FALCON_1024.sigma == 168.388571447 && FALCON_1024.sigma_min == 1.298280334
              && FALCON_1024.sigma_max == 1.8205, "Tab. 3.3, 1024, sigma");
    CHECK(falcon_pk_bytes(&FALCON_512) == 897 && falcon_pk_bytes(&FALCON_1024) == 1793, "pk_bytes");
    CHECK(falcon_sk_header_byte(&FALCON_512) == 0x59, "sk_header 512");
    CHECK(falcon_sk_header_byte(&FALCON_1024) == 0x5A, "sk_header 1024");

    CHECK(falcon_params_validate(&FALCON_512) == FALCON_OK, "512 gültig");
    CHECK(falcon_params_validate(&FALCON_1024) == FALCON_OK, "1024 gültig");
    for (int logn = 1; logn <= 10; logn++) {
        size_t n = (size_t)1 << logn;
        falcon_params p = with(FALCON_512, n);
        CHECK(falcon_logn(n) == logn, "logn %d", logn);
        CHECK(falcon_params_validate(&p) == FALCON_OK, "reduziert %d", logn);
        CHECK(falcon_pk_bytes(&p) == 1 + (14 * n + 7) / 8, "pk_bytes %d", logn);
        CHECK(falcon_sk_header_byte(&p) == (0x50 | logn), "sk_header %d", logn);
    }
    static const size_t bad_n[] = {0, 1, 3, 6, 1000, 1023, 1025, 2048};
    for (size_t i = 0; i < sizeof bad_n / sizeof bad_n[0]; i++) {
        falcon_params p = with(FALCON_512, bad_n[i]);
        CHECK(falcon_params_validate(&p) == FALCON_ERR_VALUE, "n = %zu", bad_n[i]);
    }

    falcon_params p;
    p = FALCON_512; p.sigma_min = 1.0;
    CHECK(falcon_params_validate(&p) == FALCON_OK, "sigma_min = 1");
    p = FALCON_512; p.sigma_min = 0.999;
    CHECK(falcon_params_validate(&p) == FALCON_ERR_VALUE, "sigma_min < 1");
    p = FALCON_512; p.sigma_min = p.sigma_max;
    CHECK(falcon_params_validate(&p) == FALCON_ERR_VALUE, "sigma_min = sigma_max");
    p = FALCON_512; p.sigma = 0.0;
    CHECK(falcon_params_validate(&p) == FALCON_ERR_VALUE, "sigma = 0");
    p = FALCON_512; p.sig_bound = 0;
    CHECK(falcon_params_validate(&p) == FALCON_ERR_VALUE, "sig_bound = 0");
    p = FALCON_512; p.sig_bytelen = 0;
    CHECK(falcon_params_validate(&p) == FALCON_ERR_VALUE, "sig_bytelen = 0");

    static const struct { int32_t q; size_t n; int ok; } q_cases[] = {
        {12289, 1024, 1}, {7681, 256, 1}, {17, 8, 1},
        {7681, 512, 0}, {17, 16, 0}, {12301, 4, 0},
        {12288, 512, 0}, {12290, 512, 0}, {1, 512, 0}, {0, 512, 0},
    };
    for (size_t i = 0; i < sizeof q_cases / sizeof q_cases[0]; i++) {
        p = with(FALCON_512, q_cases[i].n);
        p.q = q_cases[i].q;
        int expected = q_cases[i].ok ? FALCON_OK : FALCON_ERR_VALUE;
        CHECK(falcon_params_validate(&p) == expected, "q = %d, n = %zu", p.q, p.n);
    }
    return test_summary("params");
}
