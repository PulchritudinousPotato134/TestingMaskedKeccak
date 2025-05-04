#ifndef STRUCTS_H
#define STRUCTS_H

#include <stdint.h>
#include "params.h"

// === Keccak ===
typedef struct {
    uint64_t s[25];  // Keccak state
    uint8_t pos;
} keccak_state;

typedef struct {
    int16_t coeffs[KYBER_N];
} poly;

typedef struct {
    poly vec[KYBER_K];
} polyvec;


// === Masking Structures ===
#define MASKING_N (MASKING_ORDER + 1)

typedef struct {
    uint8_t buf[MASKING_N][KYBER_ETA2 * KYBER_N / 4];
} masked_u8_sampling;

typedef struct {
    int16_t v[MASKING_N];
} masked_word16;

typedef struct {
    int16_t coeffs[KYBER_N][MASKING_N];
} masked_poly;

typedef struct {
    masked_poly vec[KYBER_K];
} masked_polyvec;

typedef struct {
    uint8_t share[MASKING_N];
} masked_u8;

typedef struct {
    masked_u8 bytes[KYBER_SYMBYTES];
} masked_seed;

typedef struct {
    masked_u8 bytes[32];
} masked_u8_32;

typedef struct {
    masked_u8 bytes[64];
} masked_u8_64;
typedef struct {
    masked_u8 bytes[KYBER_INDCPA_MSGBYTES];
} masked_msg;

typedef struct {
    masked_u8 bytes[KYBER_SSBYTES];
} masked_ss;

typedef struct {
    masked_u8 bytes[KYBER_SYMBYTES];
} masked_u8_symbytes;



#endif // STRUCTS_H
