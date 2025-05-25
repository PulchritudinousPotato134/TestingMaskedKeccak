#include "masked_gadgets.h"
#include "stm32f4xx_hal.h"
#include "debug_log.h"
#include "params.h"
#include "global_rng.h"
#include "unmasked_keccak.h"
#include "keccak.h"
/*
 * Keccak-F[1600] — Masked Round Transformations Summary

    Theta (θ)
    Mixes each bit with its column neighbors to propagate input differences across the state.
    -> Ensures inter-column diffusion. Preserves XOR masking.

    Rho (ρ)
    Rotates each 64-bit lane by a constant, lane-specific offset.
    -> Distributes bit influence. Same shift applied to all shares.

    Pi (π)
    Rearranges lanes on the 5×5 grid using modular arithmetic.
    -> Spatially mixes data. All shares move with their lane.

    Chi (χ)
    Non-linear row-wise transformation using AND and NOT.
    -> Introduces confusion. Requires secure masked AND with fresh randomness to prevent leakage.

    Iota (ι)
    Adds a round constant into lane (0,0) to break symmetry.
    -> Applied only to one share, followed by re-masking.

 *
 */

extern RNG_HandleTypeDef hrng;


//======Helper Methods======

/**
 * Fast rotate-left operation on 64-bit values.
 *
 * Used in Keccak's Rho step to shift each lane by a fixed offset.
 * Compiles down to a single `ROR` or `LSL/LSR` pair when `n` is constant.
 */
#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

//64-bit constants used in the Iota step to inject round-dependent asymmetry
//Without Iota, Keccak's permutation would be invariant under global XOR shifts
const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};



//Each value is a rotation offset used in the Rho step
//These offsets were precomputed during design using a linear recurrence formula
//based on LFSR traversal of the state.
static const uint8_t keccak_rho_offsets[5][5] = {
    {  0, 36,  3, 41, 18 },
    {  1, 44, 10, 45,  2 },
    { 62,  6, 43, 15, 61 },
    { 28, 55, 25, 21, 56 },
    { 27, 20, 39,  8, 14 }
};

//Performs a circular left shift (rotate-left) of a 64-bit word by n bits.
static inline uint64_t rol64(uint64_t x, unsigned int n) {
	n &= 63;
	return (x << n) | (x >> (64 - n));

}

#if MASKING_ORDER == 0
void masked_value_set(masked_uint64_t *out, uint64_t value) {
    out->share[0] = value;
}
#elif MASKING_ORDER == 1
void masked_value_set(masked_uint64_t *out, uint64_t value) {
    uint64_t r0 = get_random64();
    out->share[0] = r0;
    out->share[1] = value ^ r0;
}
#elif MASKING_ORDER == 2
void masked_value_set(masked_uint64_t *out, uint64_t value) {
    uint64_t r0 = get_random64();
    uint64_t r1 = get_random64();
    out->share[0] = r0;
    out->share[1] = r1;
    out->share[2] = value ^ r0 ^ r1;
}
#elif MASKING_ORDER == 3
void masked_value_set(masked_uint64_t *out, uint64_t value) {
    uint64_t r0 = get_random64();
    uint64_t r1 = get_random64();
    uint64_t r2 = get_random64();
    out->share[0] = r0;
    out->share[1] = r1;
    out->share[2] = r2;
    out->share[3] = value ^ r0 ^ r1 ^ r2;
}
#elif MASKING_ORDER == 4
void masked_value_set(masked_uint64_t *out, uint64_t value) {
    uint64_t r0 = get_random64();
    uint64_t r1 = get_random64();
    uint64_t r2 = get_random64();
    uint64_t r3 = get_random64();
    out->share[0] = r0;
    out->share[1] = r1;
    out->share[2] = r2;
    out->share[3] = r3;
    out->share[4] = value ^ r0 ^ r1 ^ r2 ^ r3;
}
#else
void masked_value_set(masked_uint64_t *out, uint64_t value) {
    uint64_t acc = value;

    // Generate MASKING_N - 1 random shares
    for (int i = 0; i < MASKING_N - 1; i++) {
        out->share[i] = get_random64();
        acc ^= out->share[i];
    }

    // Last share ensures that XOR of all shares == value
    out->share[MASKING_N - 1] = acc;
}
#endif


void masked_shake128_squeezeblocks(uint8_t *output, size_t nblocks,
                                   masked_keccak_state *ctx) {

    for (size_t block = 0; block < nblocks; block++) {
        // Extract full `rate` bytes from current state
        for (size_t i = 0; i < ctx->rate; i++) {
            size_t x = (i / 8) % 5;
            size_t y = (i / 8) / 5;
            size_t byte_pos = i % 8;

            uint64_t lane = 0;
            for (int j = 0; j < MASKING_N; j++) {
                lane ^= ctx->state[x][y].share[j];
            }

            output[block * ctx->rate + i] = (lane >> (8 * byte_pos)) & 0xFF;
        }

        // Permute to prepare next block
        masked_keccak_f1600(ctx->state);
    }
}
static void store64(uint8_t x[8], uint64_t u) {
  unsigned int i;

  for(i=0;i<8;i++)
    x[i] = u >> 8*i;
}

void unmasked_shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state) {
    while (nblocks) {
    	KeccakF1600_StatePermute(state->s);
        for (int i = 0; i < SHAKE128_RATE / 8; ++i) {
            store64(out + 8 * i, state->s[i]);
        }
        out += SHAKE128_RATE;
        nblocks--;
    }
}



//======Sponge Phases======

/**
 * Each block of input is XORed into the state, followed by a permutation.
 * Absorbs input bytes into a masked Keccak state.
 *
  *This is the first phase of the sponge construction.
 * Splits the input into rate-sized blocks and XORs them into the state.
 * Final block is padded using the Keccak domain-specific padding rule.
 *
 * @param state      5x5 masked state array to update
 * @param input      Pointer to message bytes
 * @param input_len  Length of the message in bytes
 * @param rate       Sponge bitrate in bytes (e.g. 136 for SHA3-256)
 */
void masked_absorb(masked_uint64_t state[5][5], const uint8_t *input, size_t input_len, size_t rate) {
    // === Initialize state to zero ===
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            for (int i = 0; i < MASKING_N; i++) {
                state[x][y].share[i] = 0;
            }
        }
    }

    size_t offset = 0;

    // === Process full input blocks ===
    while (input_len >= rate) {
        // Load up to rate no of bytes into the state
        for (int i = 0; i < rate; i += 8) {
            uint64_t lane = 0;

            // Pack 8 bytes into a 64-bit lane (little-endian)
            for (int j = 0; j < 8; j++) {
                lane |= ((uint64_t)input[offset + i + j]) << (8 * j);
            }

            size_t x = (i / 8) % 5;   // Determine x position in state grid
            size_t y = (i / 8) / 5;   // Determine y position

            // Mask the input lane securely before use
            masked_uint64_t masked_lane;
            masked_value_set(&masked_lane, lane);

            // XOR masked input into current state
            masked_xor(&state[x][y], &state[x][y], &masked_lane);
        }

        // Apply Keccak-f permutation to the masked state
        masked_keccak_f1600(state);

        offset += rate;
        input_len -= rate;
    }

    // === Final block with padding ===

    // Prepare a zeroed block and copy in remaining input
    uint8_t block[KECCAK_RATE] = {0};
    for (size_t i = 0; i < input_len; ++i) {
        block[i] = input[offset + i];
    }


    // Apply padding: 0x06 marks domain separation, 0x80 sets the final bit
    block[input_len] ^= 0x06;
    block[rate- 1] ^= 0x80;

    // Load final padded block into the state
    for (int i = 0; i < KECCAK_RATE; i += 8) {
        uint64_t lane = 0;

        // Convert each 8-byte chunk into a 64-bit word
        for (int j = 0; j < 8 && (i + j) < KECCAK_RATE; j++) {
            lane |= ((uint64_t)block[i + j]) << (8 * j);
        }

        size_t x = (i / 8) % 5;
        size_t y = (i / 8) / 5;

        masked_uint64_t masked_lane;
        masked_value_set(&masked_lane, lane);
        masked_xor(&state[x][y], &state[x][y], &masked_lane);
    }

    // Final permutation to finish absorption phase
    masked_keccak_f1600(state);
}

static uint64_t load64(const uint8_t x[8]) {
  unsigned int i;
  uint64_t r = 0;

  for(i=0;i<8;i++)
    r |= (uint64_t)x[i] << 8*i;

  return r;
}


void unmasked_absorb(keccak_state *state, const uint8_t *in, size_t inlen, size_t rate ) {
	  unsigned int i;

	  for (i = 0; i < 25; i++)
	    state->s[i] = 0;

	  while (inlen >= rate) {
	    for (i = 0; i < rate / 8; i++)
	      state->s[i] ^= load64(in + 8 * i);
	    in += rate;
	    inlen -= rate;
	    KeccakF1600_StatePermute(state->s);
	  }

	  for (i = 0; i < inlen; i++)
	    state->s[i / 8] ^= (uint64_t)in[i] << 8 * (i % 8);

	  state->s[i / 8] ^= (uint64_t)DOMAIN_SHAKE << 8 * (i % 8);
	  state->s[(rate - 1) / 8] ^= 1ULL << 63;
}

/**
 * Squeezes output bytes from a masked Keccak state.
 *
 * This is the final phase in sponge-based hashing or XOF like SHAKE.
 * Recombines masked lanes to extract real output bytes.
 * Applies Keccak-f permutations between squeezing rounds if more output is needed.
 *
 * @param output      Buffer to receive the output
 * @param output_len  Number of output bytes desired
 * @param state       5x5 masked state to squeeze from
 * @param rate        Sponge bitrate in bytes (e.g. 168 for SHAKE128)
 */
void masked_squeeze(uint8_t *output, size_t output_len, masked_uint64_t state[5][5], size_t rate) {
    size_t offset = 0;

    while (offset < output_len) {
        // Pull up to ratebytes per round.
        // This maps each byte of the output to a specific lane+byte within the state.
        for (int i = 0; i < rate&& offset < output_len; i++) {
            size_t x = (i / 8) % 5;       // X coordinate in the 5×5 grid
            size_t y = (i / 8) / 5;       // Y coordinate in the 5×5 grid
            size_t byte_pos = i % 8;      // Byte index within the 64-bit lane

            // === Recombine shares ===
            // Convert the masked lane back into a real value via XOR of all shares.
            uint64_t lane = 0;
            for (int j = 0; j < MASKING_N; j++) {
                lane ^= state[x][y].share[j];
            }

            // Extract the correct byte from the lane.
            output[offset++] = (lane >> (8 * byte_pos)) & 0xFF;
        }

        // === If we need more output ===
        // Keccak is a sponge — we re-permute the state to squeeze more bytes out.
        if (offset < output_len) {
            masked_keccak_f1600(state);
        }
    }
}

//======Five Main Round Functions======

/**
 * Apply the masked Theta step of Keccak.
 *
 * Theta mixes bits across columns using masked XORs to ensure diffusion.
 * Maintains share alignment (linear operation).
 */
void masked_theta(masked_uint64_t state[5][5]) {
    masked_uint64_t C[5] = {0};  // Column parity
    masked_uint64_t D[5] = {0};  // Parity difference per column

    // For each column, compute the parity across the 5 lanes.
    // We do this in masked space using XORs, which are safe.
    for (int x = 0; x < 5; x++) {
        C[x] = state[x][0];
        for (int y = 1; y < 5; y++) {
            masked_xor(&C[x], &C[x], &state[x][y]);
        }
    }

    // Compute the D[x] value used to mix columns with each other.
    // Rotate C[x+1] by 1 bit before XORing with C[x-1].
    // This step spreads influence between adjacent columns.
    for (int x = 0; x < 5; x++) {
        for (int i = 0; i < MASKING_N; i++) {
            uint64_t c_plus_1 = C[(x + 1) % 5].share[i];
            uint64_t rot = (c_plus_1 << 1) | (c_plus_1 >> 63);
            D[x].share[i] = C[(x + 4) % 5].share[i] ^ rot;
        }
    }

    // Apply D[x] to every lane in each column to complete the mixing.
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            for (int i = 0; i < MASKING_N; i++) {
                state[x][y].share[i] ^= D[x].share[i];
            }
        }
    }
}

/**
 * Apply the masked Rho step of Keccak.
 *
 * Rho rotates each lane by a fixed constant offset (same across shares),
 * spreading bits to neighboring positions while preserving the mask structure.
 */
void masked_rho(masked_uint64_t state[5][5]) {
    // Rho rotates each lane by a constant offset to scatter bits.
    // It’s important the same rotation is applied to every share
    // so the XOR mask relationship stays valid.
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            uint8_t r = keccak_rho_offsets[x][y];
			#if MASKING_N == 1
						state[x][y].share[0] = ROL64(state[x][y].share[0], r);
			#elif MASKING_N == 2
						state[x][y].share[0] = ROL64(state[x][y].share[0], r);
						state[x][y].share[1] = ROL64(state[x][y].share[1], r);
			#elif MASKING_N == 3
						state[x][y].share[0] = ROL64(state[x][y].share[0], r);
						state[x][y].share[1] = ROL64(state[x][y].share[1], r);
						state[x][y].share[2] = ROL64(state[x][y].share[2], r);
			#elif MASKING_N == 4
						state[x][y].share[0] = ROL64(state[x][y].share[0], r);
						state[x][y].share[1] = ROL64(state[x][y].share[1], r);
						state[x][y].share[2] = ROL64(state[x][y].share[2], r);
						state[x][y].share[3] = ROL64(state[x][y].share[3], r);
			#elif MASKING_N == 5
						state[x][y].share[0] = ROL64(state[x][y].share[0], r);
						state[x][y].share[1] = ROL64(state[x][y].share[1], r);
						state[x][y].share[2] = ROL64(state[x][y].share[2], r);
						state[x][y].share[3] = ROL64(state[x][y].share[3], r);
						state[x][y].share[3] = ROL64(state[x][y].share[4], r);
			#else
						for (int i = 0; i < MASKING_N; i++) {
							state[x][y].share[i] = ROL64(state[x][y].share[i], r);
						}
			#endif
        }
    }
}


/**
 * Apply the masked Pi step of Keccak.
 *
 * Pi rearranges lanes within the 5x5 grid using a predefined permutation.
 * All shares of a lane are moved together to preserve masking validity.
 */
void masked_pi(masked_uint64_t state[5][5]) {
    masked_uint64_t tmp[5][5];

    // Copy the full masked state first to keep original positions.
    for (int x = 0; x < 5; ++x)
        for (int y = 0; y < 5; ++y)
            tmp[x][y] = state[x][y];

    // Pi permutes the positions of lanes across the 5x5 grid.
    // All shares must move together with their corresponding lane
    // to keep the mask relationships correct.
    for (int x = 0; x < 5; ++x)
        for (int y = 0; y < 5; ++y) {
            int new_x = y;
            int new_y = (2 * x + 3 * y) % 5;
            state[new_x][new_y] = tmp[x][y];
        }
}


void masked_chi(masked_uint64_t out[5][5],
                const masked_uint64_t in[5][5],
                const uint64_t r[5][5][MASKING_N][MASKING_N]) {
    // Chi mixes bits in each row using a non-linear expression.
    // Since AND is not linear, it’s where leakage can happen — hence the use of
    // fresh randomness and secure masked AND gadgets.

    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
            const masked_uint64_t *a = &in[x][y];
            const masked_uint64_t *b = &in[(x + 1) % 5][y];
            const masked_uint64_t *c = &in[(x + 2) % 5][y];
            masked_uint64_t t1, t2;

            masked_not(&t1, b);
            masked_and_arithmetic(&t2, &t1, c, r[x][y]);
            masked_xor(&out[x][y], a, &t2);
        }
    }
}


/**
 * Apply the masked Iota step of Keccak.
 *
 * Injects the round constant into lane (0,0) to break symmetry.
 * Requires re-masking the result securely to maintain masking invariants.
 *
 * @param state Masked state to update
 * @param rc    Round constant for this permutation round
 */
void masked_iota(masked_uint64_t state[5][5], uint64_t rc) {
    // Iota introduces asymmetry by injecting a round constant into lane (0,0).
    // This breaks symmetry and helps distinguish rounds.
    // Because we’re masking, we must re-mask the lane after applying the constant.

    // Step 1: Recombine to get the true value of the lane.
    uint64_t value = 0;
    for (int i = 0; i < MASKING_N; ++i)
        value ^= state[0][0].share[i];

    // Step 2: XOR in the round constant.
    value ^= rc;

    // Step 3: Randomly re-mask it.
    uint64_t acc = value;
    for (int i = 1; i < MASKING_N; ++i) {
        state[0][0].share[i] = get_random64();
        acc ^= state[0][0].share[i];
    }
    state[0][0].share[0] = acc;
}


// Helper function (add this)
void print_recombined_state(masked_uint64_t state[5][5], const char *label) {
    printf("== %s (Recombined) ==\n", label);
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            uint64_t val = 0;
            for (int i = 0; i < MASKING_N; i++) {
                val ^= state[x][y].share[i];
            }
            uint32_t hi = (uint32_t)(val >> 32);
            uint32_t lo = (uint32_t)(val & 0xFFFFFFFF);
            printf("State[%d][%d]: %08X%08X\n", x, y, hi, lo);
        }
    }
}

void masked_keccak_round(masked_uint64_t S[5][5], uint64_t rc) {

    // Theta mixes each column’s bits into its neighbors to spread information.
    // For masking, we need to preserve XOR relationships between shares here.
    masked_theta(S);

    // Rho rotates each lane by a fixed offset.
    // Since we’re masking, we have to apply the same rotation to every share.
    masked_rho(S);

    // Pi moves lanes around — it's a shuffle of the 5×5 grid.
    // All shares for each lane must move together to keep masking valid.
    masked_pi(S);

    // Chi is non-linear, and this is where leakage can happen — we need fresh randomness.
    // One matrix of random values per lane to feed into masked ANDs.
    uint64_t r_chi[5][5][MASKING_N][MASKING_N];
    for (int y = 0; y < 5; ++y)
        for (int x = 0; x < 5; ++x)
            fill_random_matrix(r_chi[x][y]);

    // We build a new state instead of modifying in place — safer and avoids weird bugs.
    masked_uint64_t chi_out[5][5];

    // Chi mixes rows using NOT and AND.
    // Because we’re masking, this step is the trickiest and needs careful randomness.
    masked_chi(chi_out, S, r_chi);

    // Iota adds in the round constant — this breaks symmetry and keeps things unpredictable.
    // Only touch share[0] to avoid messing up the masking.
    masked_iota(chi_out, rc);

    // Move the updated state back into S so it's ready for the next round.
    for (int y = 0; y < 5; ++y)
        for (int x = 0; x < 5; ++x)
            S[x][y] = chi_out[x][y];
}

/**
 * Perform the full Keccak-f[1600] permutation on a masked state.
 *
 * Applies all 24 rounds of the Keccak permutation to the given masked state.
 * Each round applies the full sequence: Theta, Rho, Pi, Chi, Iota.
 *
 * state is the 5×5 masked Keccak state.
 */
void masked_keccak_f1600(masked_uint64_t state[5][5]) {
    for (int i = 0; i < 24; i++) {
        masked_keccak_round(state, RC[i]);
    }
}

void masked_theta_arithmetic(masked_uint64_t state[5][5]) {
    masked_uint64_t C[5] = {0};
    masked_uint64_t D[5] = {0};

    // Compute C[x] = A[x][0] + A[x][1] + A[x][2] + A[x][3] + A[x][4]
    for (int x = 0; x < 5; x++) {
        C[x] = state[x][0];
        for (int y = 1; y < 5; y++) {
            masked_add_arithmetic(&C[x], &C[x], &state[x][y]);
        }
    }

    // Compute D[x] = C[x-1] XOR ROT(C[x+1], 1)
    for (int x = 0; x < 5; x++) {
        uint64_t c_next = 0;
        for (int i = 0; i < MASKING_N; ++i)
            c_next = (c_next + C[(x + 1) % 5].share[i]) & 0xFFFFFFFFFFFFFFFFULL;

        uint64_t c_prev = 0;
        for (int i = 0; i < MASKING_N; ++i)
            c_prev = (c_prev + C[(x + 4) % 5].share[i]) & 0xFFFFFFFFFFFFFFFFULL;

        uint64_t rotated = (c_next << 1) | (c_next >> 63);
        uint64_t Dx = c_prev ^ rotated;

        // Re-mask Dx into D[x] (simple deterministic split)
        for (int i = 0; i < MASKING_N; ++i)
            D[x].share[i] = 0;
        D[x].share[MASKING_N - 1] = Dx;
    }

    // Apply D[x] to each word in the column: A[x][y] += D[x]
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            masked_uint64_t tmp;
            masked_add_arithmetic(&tmp, &state[x][y], &D[x]);
            state[x][y] = tmp;
        }
    }
}



void masked_rho_arithmetic(masked_uint64_t state[5][5]) {
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            uint8_t r = keccak_rho_offsets[x][y];
            for (int i = 0; i < MASKING_N; i++) {
                state[x][y].share[i] = ROL64(state[x][y].share[i], r);
            }
        }
    }
}

void masked_pi_arithmetic(masked_uint64_t state[5][5]) {
    masked_uint64_t tmp[5][5];
    for (int x = 0; x < 5; ++x)
        for (int y = 0; y < 5; ++y)
            tmp[x][y] = state[x][y];

    for (int x = 0; x < 5; ++x)
        for (int y = 0; y < 5; ++y) {
            int new_x = y;
            int new_y = (2 * x + 3 * y) % 5;
            state[new_x][new_y] = tmp[x][y];
        }
}

void masked_chi_arithmetic(masked_uint64_t out[5][5], const masked_uint64_t in[5][5],
                           const uint64_t r[5][5][MASKING_N][MASKING_N]) {
    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
            const masked_uint64_t *a = &in[x][y];
            const masked_uint64_t *b = &in[(x + 1) % 5][y];
            const masked_uint64_t *c = &in[(x + 2) % 5][y];
            masked_uint64_t t1, t2;

            masked_neg_arithmetic(&t1, b);
            masked_mul_arithmetic(&t2, &t1, c, r[x][y]);
            masked_add_arithmetic(&out[x][y], a, &t2);
        }
    }
}

void masked_iota_arithmetic(masked_uint64_t state[5][5], uint64_t rc) {
    uint64_t value = 0;
    for (int i = 0; i < MASKING_N; ++i)
        value += state[0][0].share[i];
    value += rc;

    uint64_t acc = value;
    for (int i = 1; i < MASKING_N; ++i) {
        state[0][0].share[i] = get_random64();
        acc -= state[0][0].share[i];
    }
    state[0][0].share[0] = acc;
}

void masked_keccak_round_arithmetic(masked_uint64_t state[5][5], uint64_t rc) {
    masked_theta_arithmetic(state);
    masked_rho_arithmetic(state);
    masked_pi_arithmetic(state);

    uint64_t r_chi[5][5][MASKING_N][MASKING_N];
    for (int y = 0; y < 5; ++y)
        for (int x = 0; x < 5; ++x)
            fill_random_matrix(r_chi[x][y]);

    masked_uint64_t chi_out[5][5];
    masked_chi_arithmetic(chi_out, state, r_chi);
    masked_iota_arithmetic(chi_out, rc);

    for (int y = 0; y < 5; ++y)
        for (int x = 0; x < 5; ++x)
            state[x][y] = chi_out[x][y];
}

void masked_keccak_f1600_arithmetic(masked_uint64_t state[5][5]) {
    for (int i = 0; i < 24; i++) {
        masked_keccak_round_arithmetic(state, RC[i]);
    }
}


void masked_absorb_arithmetic(masked_uint64_t state[5][5], const uint8_t *input, size_t input_len, size_t rate) {
    // TODO: Implement arithmetic-masked absorption phase
}

void masked_squeeze_arithmetic(uint8_t *output, size_t output_len, masked_uint64_t state[5][5], size_t rate) {
    // TODO: Implement arithmetic-masked squeezing phase
}


void print_recombined_state_arithmetic(masked_uint64_t state[5][5], const char *label) {
    // TODO: Print recombined arithmetic-masked state
}

void masked_value_set_arithmetic(masked_uint64_t *out, uint64_t value) {
    // TODO: Set arithmetic-masked value
}

