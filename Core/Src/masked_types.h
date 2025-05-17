#ifndef MASKED_TYPES_H
#define MASKED_TYPES_H

#include <stdint.h>
#include "params.h"

typedef struct {
    uint64_t share[MASKING_N];
} masked_uint64_t;

#endif // MASKED_TYPES_H
