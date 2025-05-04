#ifndef MASKEDKECCAK_H
#define MASKEDKECCAK_H

#include <stddef.h>
#include <stdint.h>

#include "structs.h"
#include "params.h"



// For SHA3-256 output
void masked_sha3_256(
    masked_u8_32 *output,         // output
    const uint8_t *input,         // input
    size_t inlen,
    size_t in_msk_stride,         // masking stride
    size_t in_data_stride         // data stride
);

// For SHA3-512 output
void masked_sha3_512(
    uint8_t *output,              // output
    size_t out_msk_stride,        // output masking stride
    size_t out_data_stride,       // output data stride
    const uint8_t *input,         // input
    size_t inlen,
    size_t in_msk_stride,         // input masking stride
    size_t in_data_stride         // input data stride
);

unsigned int rej_uniform(int16_t *r,
                         unsigned int len,
                         const uint8_t *buf,
                         unsigned int buflen);


// === Kyber logical macros ===
// SHA3-256 for hash_h: output is 32 bytes
#define hash_h(OUT_PTR, IN, INBYTES)  masked_sha3_256((OUT_PTR), (IN), (INBYTES), MASKING_ORDER, 1)

// SHA3-512 for hash_g: output is 64 bytes
#define hash_g(OUT_PTR, IN, INBYTES) masked_sha3_512((OUT_PTR), 1, MASKING_ORDER, (IN), (INBYTES), MASKING_ORDER, 1)

#endif // MASKEDKECCAK_H
