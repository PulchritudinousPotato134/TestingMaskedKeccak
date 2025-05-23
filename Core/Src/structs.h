#ifndef STRUCTS_H
#define STRUCTS_H

#include <stdint.h>
#include <stddef.h>
#include "params.h"
#include "masked_types.h"
// === Keccak ===
typedef struct {
    uint64_t s[25];
    unsigned int pos;
} keccak_state;

// === Masking Structures ===

typedef struct {
    int16_t share[MASKING_N];
} masked_word16;


typedef struct {
    uint8_t share[MASKING_N];
} masked_u8;


typedef struct {
    masked_u8 bytes[32];
} masked_u8_32;

typedef struct {
    masked_u8 bytes[64];
} masked_u8_64;


typedef struct {
    masked_uint64_t state[5][5];
    size_t rate;
    size_t pos;
} masked_keccak_state;


#endif // STRUCTS_H
