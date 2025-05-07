#ifndef MASKED_ABSORB_H
#define MASKED_ABSORB_H

#include <stdint.h>
#include <stddef.h>
#include "masked_types.h"

void masked_absorb(masked_uint64_t state[5][5], const uint8_t *input, size_t input_len);
void masked_value_set(masked_uint64_t *out, uint64_t value);
#endif
