#ifndef MASKED_TYPES_H
#define MASKED_TYPES_H

#include <stdint.h>

#define MASKING_ORDER 3 // Set your order here
#define MASKING_N (MASKING_ORDER + 1)

typedef struct {
    uint64_t share[MASKING_N];
} masked_uint64_t;

#endif // MASKED_TYPES_H
