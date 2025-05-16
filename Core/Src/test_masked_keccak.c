
#include <stdint.h>
#include <stddef.h>

#ifndef RNG64
//  User must provide a cryptographically secure RNG returning 64 random bits.
//  E.g.  #define RNG64()  random64_from_hwrng()
static uint64_t RNG64(void);
#endif

//  State type alias for readability (5×5 lanes × 2 shares).
typedef uint64_t keccak_masked_state_t[5][5][2];

// ─────────────────────────────────────────────────────────────────────────────
//  masked_not_share0()  –  linear NOT: simply flip share 0.
static inline void masked_not_share0(uint64_t lane[2])
{
    lane[0] = ~lane[0];
}

// ─────────────────────────────────────────────────────────────────────────────
//  AND gadget (first‑order, ISW).
//  Inputs  a[2], b[2]; output c[2]  with  c0 ⊕ c1 = (a0⊕a1) ∧ (b0⊕b1).
static inline void masked_and_ISW_1(const uint64_t a[2],
                                    const uint64_t b[2],
                                    uint64_t       c[2])
{
    // Pairwise products.
    uint64_t p00 = a[0] & b[0];
    uint64_t p01 = a[0] & b[1];
    uint64_t p10 = a[1] & b[0];
    uint64_t p11 = a[1] & b[1];

    // One fresh random value.
    uint64_t r = RNG64();

    c[0] = p00 ^ p01 ^ r;  // share 0
    c[1] = p10 ^ p11 ^ r;  // share 1
}

// ─────────────────────────────────────────────────────────────────────────────
//  chi_masked_build_new()  –  masked CHI producing a fresh state B.
//      A : input 5×5×2 state (unmodified)
//      B : output 5×5×2 state (may alias neither share of A)
//
//  Pseudocode correspondence – per (x,y):
//      a =  A[x, y]
//      b =  A[(x+1) mod 5, y]
//      c =  A[(x+2) mod 5, y]
//      B[x, y] = a  ⊕  (¬b ∧ c)
// ---------------------------------------------------------------------------
void chi_masked_build_new(const keccak_masked_state_t A,
                          keccak_masked_state_t       B)
{
    uint64_t not_b[2];
    uint64_t and_bc[2];

    for (size_t y = 0; y < 5; ++y) {
        // Copy the whole row once so we do not touch A while processing.
        uint64_t row[5][2];
        for (size_t x = 0; x < 5; ++x) {
            row[x][0] = A[x][y][0];
            row[x][1] = A[x][y][1];
        }

        // Now iterate over the 5 lanes of that row.
        for (size_t x = 0; x < 5; ++x) {
            // a = row[x]
            const uint64_t *a = row[x];

            // b = row[(x+1) mod 5]  → copy then NOT share 0
            not_b[0] = row[(x + 1) % 5][0];
            not_b[1] = row[(x + 1) % 5][1];
            masked_not_share0(not_b);

            // c = row[(x+2) mod 5]
            const uint64_t *c = row[(x + 2) % 5];

            // t = (¬b) ∧ c  (masked‑AND gadget)
            masked_and_ISW_1(not_b, c, and_bc);

            // B[x,y] = a ⊕ t  (share‑wise XOR)
            B[x][y][0] = a[0] ^ and_bc[0];
            B[x][y][1] = a[1] ^ and_bc[1];
        }
    }
}

// ----------------------------------------------------------------------------
//  Dummy RNG for illustration only – REPLACE in production.
// ----------------------------------------------------------------------------
#ifndef RNG64
#include <stdlib.h>
static uint64_t RNG64(void)
{
    uint64_t hi = (uint64_t)rand() << 32;
    uint64_t lo = (uint64_t)rand();
    return hi ^ lo;
}
#endif

// ----------------------------------------------------------------------------
//  End of masked_chi.c
// ----------------------------------------------------------------------------
