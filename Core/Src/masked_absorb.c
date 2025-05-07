#include <string.h>
#include "masked_types.h"
#include "masked_keccak_f1600.h"
#include "global_rng.h"
#include <stdio.h>

#include "stm32f4xx_hal.h"
#define KECCAK_RATE 168  // SHAKE128 rate in bytes



extern RNG_HandleTypeDef hrng;

void masked_value_set(masked_uint64_t *out, uint64_t value) {
    uint64_t acc = value;


    for (int i = 0; i < MASKING_N - 1; i++) {
        uint32_t lo = 0, hi = 0;
        	HAL_StatusTypeDef status1 = HAL_RNG_GenerateRandomNumber(&hrng, &lo);
           HAL_StatusTypeDef status2 = HAL_RNG_GenerateRandomNumber(&hrng, &hi);

        out->share[i] = ((uint64_t)hi << 32) | lo;
        acc ^= out->share[i];
    }

    out->share[MASKING_N - 1] = acc;
}
void masked_absorb(masked_uint64_t state[5][5], const uint8_t *input, size_t input_len) {
    // Zero the state
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            for (int i = 0; i < MASKING_N; i++) {
                state[x][y].share[i] = 0;
            }
        }
    }

    size_t offset = 0;
    while (input_len >= KECCAK_RATE) {
        for (int i = 0; i < KECCAK_RATE; i += 8) {
            uint64_t lane = 0;
            memcpy(&lane, input + offset + i, 8);

            size_t x = (i / 8) % 5;
            size_t y = (i / 8) / 5;

            masked_uint64_t masked_lane;
            masked_value_set(&masked_lane, lane);
            masked_xor(&state[x][y], &state[x][y], &masked_lane);
        }

        masked_keccak_f1600(state);
        offset += KECCAK_RATE;
        input_len -= KECCAK_RATE;
    }

    // Final block with padding
    uint8_t block[KECCAK_RATE] = {0};
    memcpy(block, input + offset, input_len);
    block[input_len] ^= 0x1;

    block[KECCAK_RATE - 1] ^= 0x80;

    for (int i = 0; i < KECCAK_RATE; i += 8) {
        uint64_t lane = 0;
        lane = 0;
        for (int j = 0; j < 8; j++) {
            lane |= ((uint64_t)block[i + j]) << (8 * j);
        }


        size_t x = (i / 8) % 5;
        size_t y = (i / 8) / 5;

        masked_uint64_t masked_lane;
        masked_value_set(&masked_lane, lane);
        masked_xor(&state[x][y], &state[x][y], &masked_lane);
    }

    masked_keccak_f1600(state);
}


