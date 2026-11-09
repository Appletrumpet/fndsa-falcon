/*
 * Kompression und Byteformate für Schlüssel und Signaturen.
 *
 * Spec-Referenz: §3.11 (insbesondere §3.11.3 bis §3.11.6).
 *
 * Rückgabe FALCON_OK oder wie in Python FALCON_ERR_NONE (None) bzw.
 * FALCON_ERR_VALUE (ValueError). Ausgabepuffer stellt der Aufrufer bereit,
 * Grössen siehe datatypes.h; Polynome fassen FALCON_MAX_N Werte.
 */
#ifndef FALCON_ENCODING_H
#define FALCON_ENCODING_H

#include "datatypes.h"

/* Vorzeichen, 7 tiefe Bits, Rest unär, auf sig_bytelen - 41 Bytes auffüllen.
 * FALCON_ERR_NONE, wenn die Kodierung zu lang ist. Alg. 17. */
int falcon_compress(uint8_t *out, size_t *out_len, const int32_t *s, const falcon_params *p);

/* Umkehrung von compress; gepolstert (Alg. 18) oder ungepolstert (§3.11.3), höchstens
 * sig_bytelen - 40 Bytes (KAT Falcon-1024 count = 82). Teilweises Padding ist ungültig.
 * Werte können den Bereich von int16_t überschreiten. */
int falcon_decompress(int32_t *s, const uint8_t *b, size_t len, const falcon_params *p);

/* Header + 14 Bit pro Koeffizient. §3.11.4. */
int falcon_encode_pk(uint8_t *out, size_t *out_len, const int32_t *h, size_t n);
int falcon_decode_pk(int32_t *h, size_t *n, const uint8_t *b, size_t len);

/* Header + f, g, F mit fester Bitbreite. §3.11.5. */
int falcon_encode_sk(uint8_t *out, size_t *out_len, const int32_t *f, const int32_t *g,
                     const int32_t *F, size_t n);
int falcon_decode_sk(int32_t *f, int32_t *g, int32_t *F, size_t *n, const uint8_t *b, size_t len);

/* Header + Salt + komprimiertes s2. §3.11.3. */
int falcon_encode_sig(uint8_t *out, size_t *out_len, const falcon_signature *sig,
                      const falcon_params *p);
int falcon_decode_sig(falcon_signature *sig, const uint8_t *b, size_t len, const falcon_params *p);

/* KAT-Format der NIST-API; *msg zeigt in sm hinein. Nur für Tests. §3.11.6. */
int falcon_decode_kat_message(const uint8_t **msg, size_t *msg_len, falcon_signature *sig,
                              const uint8_t *sm, size_t sm_len);

#endif
