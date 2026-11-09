/* Erzeugt von Python/scripts/gen_c_tables.py, nicht von Hand ändern. */
#ifndef FALCON_SAMPLER_TABLE_H
#define FALCON_SAMPLER_TABLE_H

#include <stdint.h>

/* RCDT aus Tab. 3.1, 72-Bit-Werte als obere 64 und untere 8 Bit. */
typedef struct {
    uint64_t high;
    uint8_t low;
} falcon_u72;

static const falcon_u72 FALCON_RCDT[18] = {
    {0xa3f7f42ed3ac3918u, 0x02u},
    {0x54d32b181f3f7ddbu, 0x82u},
    {0x227dcdd0934829c1u, 0xffu},
    {0x0ad1754377c7994au, 0xe4u},
    {0x0295846caef33f1fu, 0x6fu},
    {0x00774ac754ed74bdu, 0x5fu},
    {0x001024dd542b776au, 0xe4u},
    {0x0001a1ffdc65ad63u, 0xdau},
    {0x00001f80d88a7b64u, 0x28u},
    {0x000001c3fdb2040cu, 0x69u},
    {0x00000012cf24d031u, 0xfbu},
    {0x00000000949f8b09u, 0x1fu},
    {0x0000000003665da9u, 0x98u},
    {0x00000000000ebf6eu, 0xbbu},
    {0x0000000000002f5du, 0x7eu},
    {0x0000000000000070u, 0x98u},
    {0x0000000000000000u, 0xc6u},
    {0x0000000000000000u, 0x01u},
};

/* Konstanten C[] aus Alg. 13. */
static const uint64_t FALCON_EXP_C[13] = {
    0x00000004741183a3u,
    0x00000036548cfc06u,
    0x0000024fdcbf140au,
    0x0000171d939de045u,
    0x0000d00cf58f6f84u,
    0x000680681cf796e3u,
    0x002d82d8305b0feau,
    0x011111110e066fd0u,
    0x0555555555070f00u,
    0x155555555581ff00u,
    0x400000000002b400u,
    0x7fffffffffff4800u,
    0x8000000000000000u,
};

/* math.log(2.0) */
#define FALCON_LOG2 (0x1.62e42fefa39efp-1)

#endif
