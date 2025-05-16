#ifndef MASKED_THETA_H
#define MASKED_THETA_H

#include "masked_types.h"

// Round constants from the Keccak spec
extern const uint64_t RC[24];
// theta: masked parity mixing
void masked_theta(masked_uint64_t state[5][5]);

// rho: rotate each lane by offset
void masked_rho(masked_uint64_t state[5][5]);

// pi: permute lane positions
void masked_pi(masked_uint64_t state[5][5]);

// chi: nonlinear substitution (needs masked_and)
void masked_chi(masked_uint64_t out[5][5],
        const masked_uint64_t in[5][5],
        const uint64_t r[5][5][MASKING_N][MASKING_N]);

// iota: XOR round constant into lane 0, only into share[0]
void masked_iota(masked_uint64_t state[5][5], uint64_t rc);

void masked_keccakf_round(masked_uint64_t state[5][5], uint64_t rc, uint64_t r_chi[5][5][MASKING_N][MASKING_N]);



#endif
