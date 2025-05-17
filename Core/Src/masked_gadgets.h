#ifndef MASKED_GADGETS_H
#define MASKED_GADGETS_H

#include <stdint.h>
#include "masked_types.h"
#include "stm32f4xx_hal.h"  // For RNG

extern RNG_HandleTypeDef hrng;

void fill_random_matrix(uint64_t r[MASKING_N][MASKING_N]);

void masked_xor(masked_uint64_t *out,
                const masked_uint64_t *a,
                const masked_uint64_t *b);

void masked_and(masked_uint64_t *out,
                const masked_uint64_t *a,
                const masked_uint64_t *b,
                const uint64_t r[MASKING_N][MASKING_N]);

void masked_not(masked_uint64_t *dst, const masked_uint64_t *src) ;

#endif

