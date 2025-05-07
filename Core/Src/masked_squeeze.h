#ifndef MASKED_SQUEEZE_H
#define MASKED_SQUEEZE_H

#include <stdint.h>
#include <stddef.h>
#include "masked_types.h"

void masked_squeeze(uint8_t *output, size_t output_len, masked_uint64_t state[5][5]);

#endif
