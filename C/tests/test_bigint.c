/* Tests für bigint.c gegen Python-int: Rechenarten, Verschiebungen, Division mit Korrekturfällen. */
#include "bigint.h"
#include "vectors.h"

int main(void)
{
    falcon_big a, b, r, q, rem, want, want2, alias;
    uint8_t op[16];
    vec_file v;

    falcon_big_init(&a);
    falcon_big_init(&b);
    falcon_big_init(&r);
    falcon_big_init(&q);
    falcon_big_init(&rem);
    falcon_big_init(&want);
    falcon_big_init(&want2);
    falcon_big_init(&alias);

    vec_open(&v, "bigint");
    while (vec_next(&v)) {
        size_t op_len = vec_bytes(&v, "op", op, sizeof op - 1);
        op[op_len] = 0;
        const char *name = (const char *)op;
        vec_big(&v, "a", &a);
        vec_big(&v, "b", &b);
        vec_big(&v, "out0", &want);

        if (strcmp(name, "add") == 0) {
            falcon_big_add(&r, &a, &b);
            CHECK(falcon_big_cmp(&r, &want) == 0, "add Fall %zu", v.index);
            falcon_big_copy(&alias, &a);
            falcon_big_add(&alias, &alias, &b);
            CHECK(falcon_big_cmp(&alias, &want) == 0, "add (r = a) Fall %zu", v.index);
        } else if (strcmp(name, "sub") == 0) {
            falcon_big_sub(&r, &a, &b);
            CHECK(falcon_big_cmp(&r, &want) == 0, "sub Fall %zu", v.index);
            falcon_big_copy(&alias, &b);
            falcon_big_sub(&alias, &a, &alias);
            CHECK(falcon_big_cmp(&alias, &want) == 0, "sub (r = b) Fall %zu", v.index);
        } else if (strcmp(name, "mul") == 0) {
            falcon_big_mul(&r, &a, &b);
            CHECK(falcon_big_cmp(&r, &want) == 0, "mul Fall %zu", v.index);
            falcon_big_copy(&alias, &a);
            falcon_big_mul(&alias, &alias, &b);
            CHECK(falcon_big_cmp(&alias, &want) == 0, "mul (r = a) Fall %zu", v.index);
        } else if (strcmp(name, "divmod") == 0) {
            vec_big(&v, "out1", &want2);
            falcon_big_divmod_abs(&q, &rem, &a, &b);
            CHECK(falcon_big_cmp(&q, &want) == 0, "divmod q Fall %zu", v.index);
            CHECK(falcon_big_cmp(&rem, &want2) == 0, "divmod r Fall %zu", v.index);
        } else {
            int64_t k = vec_int(&v, "b");
            if (strcmp(name, "shl") == 0) {
                falcon_big_shl(&r, &a, (size_t)k);
                CHECK(falcon_big_cmp(&r, &want) == 0, "shl Fall %zu", v.index);
            } else if (strcmp(name, "shr") == 0) {
                falcon_big_shr_abs(&r, &a, (size_t)k);
                CHECK(falcon_big_cmp(&r, &want) == 0, "shr Fall %zu", v.index);
            } else {
                CHECK((int64_t)falcon_big_bit_length(&a) == vec_int(&v, "out0"), "bitlen Fall %zu", v.index);
            }
        }
    }
    vec_close(&v);

    falcon_big_set_i64(&a, INT64_MIN);
    CHECK(a.neg && falcon_big_bit_length(&a) == 64, "INT64_MIN");
    int32_t x = 1;
    falcon_big_set_i64(&a, INT32_MIN);
    CHECK(falcon_big_to_i32(&a, &x) && x == INT32_MIN, "to_i32 Minimum");
    falcon_big_set_i64(&a, (int64_t)INT32_MIN - 1);
    CHECK(!falcon_big_to_i32(&a, &x), "to_i32 zu klein");
    falcon_big_set_i64(&a, (int64_t)INT32_MAX + 1);
    CHECK(!falcon_big_to_i32(&a, &x), "to_i32 zu gross");

    falcon_big_free(&a);
    falcon_big_free(&b);
    falcon_big_free(&r);
    falcon_big_free(&q);
    falcon_big_free(&rem);
    falcon_big_free(&want);
    falcon_big_free(&want2);
    falcon_big_free(&alias);
    return test_summary("bigint");
}
