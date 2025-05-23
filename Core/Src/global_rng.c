#include "global_rng.h"
#include "stm32f4xx_hal.h"

extern RNG_HandleTypeDef hrng;  // defined in your HAL setup

uint64_t get_random64(void) {
    uint32_t r1, r2;
    if (HAL_RNG_GenerateRandomNumber(&hrng, &r1) != HAL_OK) {
        Error_Handler(); // or fail securely
    }
    if (HAL_RNG_GenerateRandomNumber(&hrng, &r2) != HAL_OK) {
        Error_Handler();
    }
    return ((uint64_t)r1 << 32) | r2;
}
