#include "masked_types.h"
#include "masked_gadgets.h"
#include "stm32f4xx_hal.h"
#include <stdio.h>
#include "maskedKeccak.h"



uint64_t masked_recombine(const masked_uint64_t *m) {
    uint64_t result = 0;
    for (int i = 0; i < MASKING_N; i++) {
        result ^= m->share[i];
    }
    return result;
}
void debug_print_masked_state(masked_uint64_t state[5][5]) {
    printf("=== Full Masked State (Shares + Recombined) ===\n");
    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
            printf("State[%d][%d]: ", x, y);
            for (int i = 0; i < MASKING_N; i++) {
                uint32_t hi = (uint32_t)(state[x][y].share[i] >> 32);
                uint32_t lo = (uint32_t)(state[x][y].share[i] & 0xFFFFFFFF);
                printf("S[%d]=0x%08X%08X ", i, hi, lo);
            }
            // Recombined value
            uint64_t val = 0;
            for (int i = 0; i < MASKING_N; i++) {
                val ^= state[x][y].share[i];
            }
            uint32_t r_hi = (uint32_t)(val >> 32);
            uint32_t r_lo = (uint32_t)(val & 0xFFFFFFFF);
            printf(" | R=0x%08X%08X\n", r_hi, r_lo);
        }
    }
}



extern void masked_keccak_round(masked_uint64_t state[5][5], uint64_t rc);


void masked_keccak_f1600(masked_uint64_t state[5][5]) {
	debug_print_masked_state(state);
	printf("== Before masked_keccak_f1600 ==\n");
	for (int x = 0; x < 5; x++) {
	    for (int y = 0; y < 5; y++) {
	        uint64_t recombined = masked_recombine(&state[x][y]);
	        uint32_t hi = (uint32_t)(recombined >> 32);
	        uint32_t lo = (uint32_t)(recombined & 0xFFFFFFFF);
	        printf("State[%d][%d]: %08X%08X\n", x, y, hi, lo);

	    }
	}


    for (int i = 0; i < 24; i++) {
        masked_keccak_round(state, RC[i]);
    }
    debug_print_masked_state(state);
    printf("== After masked_keccak_f1600 ==\n");
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            printf("State[%d][%d]:", x, y);
            for (int i = 0; i < MASKING_N; i++) {
                uint32_t hi = (uint32_t)(state[x][y].share[i] >> 32);
                uint32_t lo = (uint32_t)(state[x][y].share[i] & 0xFFFFFFFF);
                printf(" %08lX%08lX", hi, lo);
            }
            printf("\n");
        }
    }
}
