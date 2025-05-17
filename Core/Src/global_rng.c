#include "global_rng.h"
#include "stm32f4xx_hal.h"

/**
 * Generate a fresh 64-bit random value using the STM32 hardware RNG.
 *
 * This function pulls two 32-bit words from the RNG and combines them
 * into a single 64-bit result. Used for generating random shares or
 * randomness matrices in secure masking.
 */

uint64_t get_random64(void) {
    uint32_t r1, r2;
    HAL_RNG_GenerateRandomNumber(&hrng, &r1);
    HAL_RNG_GenerateRandomNumber(&hrng, &r2);
    return ((uint64_t)r1 << 32) | r2;
}
