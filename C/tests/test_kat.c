/*
 * Known Answer Tests gegen die NIST-Dateien (unveränderliche Testschicht):
 * alle 100 Signaturen je Parametersatz, Falcon-1024 count = 82 inklusive.
 */
#include <stdlib.h>
#include <string.h>

#include "encoding.h"
#include "falcon.h"
#include "vectors.h"

static size_t parse_hex(const char *p, uint8_t *dst, size_t cap)
{
    size_t count = 0;
    for (;; p += 2) {
        unsigned value;
        if (p[0] == '\n' || p[0] == '\0' || p[0] == '\r') {
            return count;
        }
        if (count >= cap || sscanf(p, "%2X", &value) != 1) {
            fprintf(stderr, "Abbruch: Hex-Fehler in KAT-Datei\n");
            exit(2);
        }
        dst[count++] = (uint8_t)value;
    }
}

static void run(const char *file, const falcon_params *p)
{
    static uint8_t pk_bytes[4096], sm[32768], expected_msg[8192], tampered[8192];
    static falcon_public_key pk;
    static falcon_signature sig;
    char path[512];
    size_t len, records = 0;

    snprintf(path, sizeof path, "%s/kat/%s", FALCON_DATA_DIR, file);
    char *text = read_file(path, &len);

    const char *cur = text;
    while ((cur = strstr(cur, "\ncount = ")) != NULL) {
        const char *mlen_line = strstr(cur, "\nmsg = ");
        const char *pk_line = strstr(cur, "\npk = ");
        const char *sm_line = strstr(cur, "\nsm = ");
        size_t count = strtoul(cur + 9, NULL, 10);
        size_t n, mlen;
        const uint8_t *msg;

        size_t emlen = parse_hex(mlen_line + 7, expected_msg, sizeof expected_msg);
        size_t pklen = parse_hex(pk_line + 6, pk_bytes, sizeof pk_bytes);
        size_t smlen = parse_hex(sm_line + 6, sm, sizeof sm);

        CHECK(falcon_decode_pk(pk.h, &n, pk_bytes, pklen) == FALCON_OK && n == p->n, "%s count %zu: pk", file, count);
        pk.n = n;
        CHECK(falcon_decode_kat_message(&msg, &mlen, &sig, sm, smlen) == FALCON_OK, "%s count %zu: sm", file, count);
        CHECK(mlen == emlen && memcmp(msg, expected_msg, mlen) == 0, "%s count %zu: msg", file, count);
        CHECK(falcon_verify(&pk, msg, mlen, &sig, p) == 1, "%s count %zu: verify", file, count);

        /* Gegenprobe: veränderte Nachricht muss abgelehnt werden. */
        memcpy(tampered, msg, mlen);
        tampered[0] ^= 1;
        CHECK(falcon_verify(&pk, tampered, mlen, &sig, p) == 0, "%s count %zu: Gegenprobe", file, count);

        records++;
        cur = sm_line;
    }
    CHECK(records == 100, "%s: %zu Einträge", file, records);
    free(text);
}

int main(void)
{
    run("falcon512-KAT.rsp", &FALCON_512);
    run("falcon1024-KAT.rsp", &FALCON_1024);
    return test_summary("kat");
}
