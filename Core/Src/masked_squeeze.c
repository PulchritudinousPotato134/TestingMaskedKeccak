#include "masked_types.h"
#include "masked_keccak_f1600.h"

#include <stddef.h>

#define KECCAK_RATE 168  // SHAKE128 rate in bytes

void masked_squeeze(uint8_t *output, size_t output_len, masked_uint64_t state[5][5]) {
    size_t offset = 0;

    while (offset < output_len) {
        // Squeeze up to KECCAK_RATE bytes per iteration
        for (int i = 0; i < KECCAK_RATE && offset < output_len; i++) {
            size_t x = (i / 8) % 5;
            size_t y = (i / 8) / 5;
            size_t byte_pos = i % 8;

            // Recombine shares to get the true output byte
            uint64_t lane = 0;
            for (int j = 0; j < MASKING_N; j++) {
                lane ^= state[x][y].share[j];
            }

            output[offset++] = (lane >> (8 * byte_pos)) & 0xFF;
        }

        // If we haven’t yet squeezed enough, permute again
        if (offset < output_len) {
            masked_keccak_f1600(state);
        }
    }
}
