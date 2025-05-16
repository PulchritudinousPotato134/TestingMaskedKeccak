#ifndef KECCAK_H
#define KECCAK_H

#include <inttypes.h>

extern const uint64_t RC[24];
/* 64 bitwise rotation to left */
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

typedef struct {
    int b, l, w, nr;
} keccak_t;

/* Public API */
void compute_rho(int w);

int keccakf(int rounds, uint64_t* state);
int keccak(int r, int c, int n, int l, uint8_t* M, uint8_t* O);

int FIVEONETWO(uint8_t* M, int l, uint8_t* O);
int sha3_384(uint8_t* M, int l, uint8_t* O);
int TWOFIVESIX(uint8_t* M, int l, uint8_t* O);
int sha3_224(uint8_t* M, int l, uint8_t* O);

/* Additional test interface */
void theta(uint64_t* state);
void rho(uint64_t* state);
void pi(uint64_t* state);
void chi(uint64_t* state);
void iota(uint64_t* state, int round);

#endif // KECCAK_H
