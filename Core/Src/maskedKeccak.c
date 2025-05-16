#include "masked_types.h"
#include "masked_gadgets.h"
#include "stm32f4xx_hal.h"
#include "debug_log.h"// for HAL_RNG
  // or your specific STM32 HAL header

extern RNG_HandleTypeDef hrng;

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

uint64_t get_random64(void) {
    uint32_t r1, r2;
    HAL_RNG_GenerateRandomNumber(&hrng, &r1);
    HAL_RNG_GenerateRandomNumber(&hrng, &r2);
    return ((uint64_t)r1 << 32) | r2;
}

// === THETA ===
void masked_theta(masked_uint64_t state[5][5]) {
    masked_uint64_t C[5] = {0};
    masked_uint64_t D[5] = {0};

    // === Compute C[x] = A[x][0] ^ A[x][1] ^ ... ^ A[x][4] ===
    for (int x = 0; x < 5; x++) {
        C[x] = state[x][0];
        for (int y = 1; y < 5; y++) {
            masked_xor(&C[x], &C[x], &state[x][y]);
        }
    }

    // === Compute D[x] = C[x-1] ^ ROTL(C[x+1], 1) ===
    for (int x = 0; x < 5; x++) {
        for (int i = 0; i < MASKING_N; i++) {
            uint64_t c_plus_1 = C[(x + 1) % 5].share[i];
            uint64_t rot = (c_plus_1 << 1) | (c_plus_1 >> (64 - 1));
            D[x].share[i] = C[(x + 4) % 5].share[i] ^ rot;
        }
    }

    // === Apply D[x] to all lanes in column x ===
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            for (int i = 0; i < MASKING_N; i++) {
                state[x][y].share[i] ^= D[x].share[i];
            }
        }
    }
}



// === RHO ===
static const uint8_t keccak_rho_offsets[5][5] = {
    {  0, 36,  3, 41, 18 },
    {  1, 44, 10, 45,  2 },
    { 62,  6, 43, 15, 61 },
    { 28, 55, 25, 21, 56 },
    { 27, 20, 39,  8, 14 }
};

static inline uint64_t rol64(uint64_t x, unsigned int n) {
    n %= 64;
    return (x << n) | (x >> ((64 - n) % 64));
}


void masked_rho(masked_uint64_t state[5][5]) {
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            uint8_t r = keccak_rho_offsets[x][y];
            for (int i = 0; i < MASKING_N; i++) {
                uint64_t value = state[x][y].share[i];
                state[x][y].share[i] = rol64(value, r);
            }
        }
    }
}

// === PI ===
void masked_pi(masked_uint64_t state[5][5])
{
    masked_uint64_t tmp[5][5];

    /* 1. copy ---------------------------------------------------------- */
    for (int x = 0; x < 5; ++x)
        for (int y = 0; y < 5; ++y)
            tmp[x][y] = state[x][y];

    /* 2. π permutation ------------------------------------------------- */
    for (int x = 0; x < 5; ++x)
        for (int y = 0; y < 5; ++y) {
            int new_x = y;                       /* u = y                 */
            int new_y = (2 * x + 3 * y) % 5;     /* v = 2x + 3y (mod 5)   */
            state[new_x][new_y] = tmp[x][y];     /* move ALL shares       */
        }
    /* nothing else! */
}




// === CHI ===
/* ─── tiny helper: masked bitwise NOT (Boolean shares) ───────────────── */
/* ─── Boolean-masked bitwise NOT ───────────────────────────────────────
   dst ← ¬src   (while preserving the XOR-mask invariant)              */
void masked_not(masked_uint64_t *dst,
                              const masked_uint64_t *src)
{
    /* 1.  Invert every share ------------------------------------------ */
    for (size_t i = 0; i < MASKING_N; ++i)
        dst->share[i] = ~src->share[i];

    /* 2.  Re-align the mask so that XOR(shares) == ¬XOR(original) ----- */
    uint64_t orig_parity = 0, inv_parity = 0;
    for (size_t i = 0; i < MASKING_N; ++i) {
        orig_parity ^= src->share[i];
        inv_parity  ^= dst->share[i];
    }
    /* delta is the amount by which the parity is off */
    uint64_t delta = inv_parity ^ ~orig_parity;

    /* flip ‘delta’ in ONE share (here: share 0) */
    dst->share[0] ^= delta;
}

/* ─── χ step with correct NOT ───────────────────────────────────────── */
void masked_chi(masked_uint64_t out[5][5],
                           const masked_uint64_t in[5][5],
                           const uint64_t r[5][5][MASKING_N][MASKING_N]) {
    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
            const masked_uint64_t *a = &in[x][y];
            const masked_uint64_t *b = &in[(x + 1) % 5][y];
            const masked_uint64_t *c = &in[(x + 2) % 5][y];
            masked_uint64_t t1, t2;

            masked_not(&t1, b);
            masked_and(&t2, &t1, c, r[x][y]);
            masked_xor(&out[x][y], a, &t2);
        }
    }
}




void masked_iota(masked_uint64_t state[5][5], uint64_t rc) {
    // 1. Recombine the lane value (x = 0, y = 0)
    uint64_t value = 0;
    for (int i = 0; i < MASKING_N; ++i)
        value ^= state[0][0].share[i];

    // 2. Apply round constant
    value ^= rc;

    // 3. Re-mask the new value randomly
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


void masked_keccak_round(masked_uint64_t state[5][5], uint64_t rc) {
    // Allocate fresh randomness for Chi step
    uint64_t r_chi[5][5][MASKING_N][MASKING_N];

    // Fill randomness for each (x, y) lane
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            fill_random_matrix(r_chi[x][y]);
        }
    }

    // Apply the five Keccak round steps
    print_recombined_state(state, "Before Theta");
    masked_theta(state);

    print_recombined_state(state, "After Theta");
    masked_rho(state);

    print_recombined_state(state, "After Rho");
    masked_pi(state);

    print_recombined_state(state, "After Pi");
    masked_uint64_t new_state[5][5];
    uint64_t rand_chi[5][5][MASKING_N][MASKING_N];
      for (int y = 0; y < 5; y++)
          for (int x = 0; x < 5; x++)
              fill_random_matrix(rand_chi[x][y]);

    masked_chi(new_state, state, rand_chi);

    print_recombined_state(new_state, "After Chi");
    masked_iota(new_state, rc);

    print_recombined_state(new_state, "After Iota");

    // Replace state with new_state after full round
    for (int x = 0; x < 5; x++)
        for (int y = 0; y < 5; y++)
            state[x][y] = new_state[x][y];



}

