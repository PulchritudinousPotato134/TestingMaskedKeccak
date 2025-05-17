#ifndef STRUCTS_H
#define STRUCTS_H

#include <stdint.h>
#include "params.h"

// === Keccak ===
typedef struct {
    uint64_t s[25];  // Keccak state
    uint8_t pos;
} keccak_state;


// === Masking Structures ===
#define MASKING_N (MASKING_ORDER + 1)

typedef struct {
    int16_t v[MASKING_N];
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

typedef struct {
    masked_u8 bytes[KYBER_SYMBYTES];
} masked_u8_symbytes;



#endif // STRUCTS_H
