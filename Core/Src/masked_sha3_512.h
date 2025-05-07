#ifndef MASKED_SHA3_512_H
#define MASKED_SHA3_512_H

#include <stdint.h>
#include <stddef.h>

void masked_sha3_512(uint8_t *output, const uint8_t *input, size_t input_len);

#endif
